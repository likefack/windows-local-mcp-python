from __future__ import annotations

import ctypes
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
import uuid
from ctypes import wintypes
from multiprocessing.connection import Client, Listener
from pathlib import Path
from typing import Any

from .util import canonical_json
from .wfp_guard import (
    APP_ISOLATION_SUBLAYER_KEY,
    GUARD_POLICY_GENERATION,
    GUARD_SUBLAYER_KEY,
    GUARD_SUBLAYER_WEIGHT,
    GUARD_V4_FILTER_KEY,
    GUARD_V6_FILTER_KEY,
    GUARD_VERSION,
    TARGET_ACCOUNT,
    GuardVerification,
    WfpGuardError,
    ensure_codex_loopback_block,
    maintenance_remove_codex_loopback_block,
    new_windows_wfp_api,
    verify_codex_loopback_block,
)

_AUTH_ENV = "WLMCP_WFP_GUARD_AUTH"
_ELEVATED_WAIT_SECONDS = 60
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SW_HIDE = 0
_WAIT_OBJECT_0 = 0


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIconOrMonitor", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def ensure_runtime_codex_loopback_guard() -> GuardVerification:
    """Ensure/read back the fixed WFP boundary, elevating only the Guard if needed."""

    if os.name != "nt":
        raise WfpGuardError("The WFP Guard requires native Windows")
    try:
        # Correct static objects are normally readable and need no elevation or mutation.
        return verify_codex_loopback_block(new_windows_wfp_api())
    except Exception:  # noqa: BLE001 - elevated ensure re-checks all fields and still fails closed
        if _is_administrator():
            return ensure_codex_loopback_block(new_windows_wfp_api())
    return _run_elevated_ensure()


def _run_elevated_ensure() -> GuardVerification:
    pipe_name = rf"\\.\pipe\wlmcp-wfp-guard-{uuid.uuid4().hex}"
    authkey = secrets.token_bytes(32)
    listener = Listener(pipe_name, family="AF_PIPE", authkey=authkey)
    messages: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=1)

    def receive() -> None:
        try:
            connection = listener.accept()
            try:
                messages.put(connection.recv_bytes(), block=False)
            finally:
                connection.close()
        except BaseException as error:  # noqa: BLE001 - forwarded to the waiting preflight
            try:
                messages.put(error, block=False)
            except queue.Full:
                pass

    receiver = threading.Thread(target=receive, name="wlmcp-wfp-guard-ipc", daemon=True)
    receiver.start()
    previous_auth = os.environ.get(_AUTH_ENV)
    os.environ[_AUTH_ENV] = authkey.hex()
    process_handle: wintypes.HANDLE | None = None
    try:
        try:
            process_handle = _shell_execute_elevated(pipe_name)
        except Exception:
            listener.close()
            raise
    finally:
        if previous_auth is None:
            os.environ.pop(_AUTH_ENV, None)
        else:
            os.environ[_AUTH_ENV] = previous_auth

    try:
        try:
            received = messages.get(timeout=_ELEVATED_WAIT_SECONDS)
        except queue.Empty as error:
            raise WfpGuardError("Elevated WFP Guard did not return read-back evidence") from error
        if isinstance(received, BaseException):
            raise WfpGuardError(f"Elevated WFP Guard IPC failed: {received}") from received
        payload = json.loads(received.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            diagnostic = payload.get("error") if isinstance(payload, dict) else "invalid response"
            raise WfpGuardError(f"Elevated WFP Guard failed: {diagnostic}")
        report = payload.get("verification")
        if not isinstance(report, dict):
            raise WfpGuardError("Elevated WFP Guard returned no verification evidence")
        _wait_for_elevated_exit(process_handle)
        return _validated_report(report)
    finally:
        listener.close()
        if process_handle:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(process_handle)


def _shell_execute_elevated(pipe_name: str) -> wintypes.HANDLE:
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    parameters = subprocess.list2cmdline(
        ["-I", "-m", "windows_local_mcp.wfp_guard_runtime", "--elevated-ensure", pipe_name]
    )
    info = _ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = parameters
    info.lpDirectory = str(Path(sys.executable).resolve(strict=True).parent)
    info.nShow = _SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        raise WfpGuardError(
            f"Elevated WFP Guard could not start: WinError {ctypes.get_last_error()}"
        )
    return info.hProcess


def _wait_for_elevated_exit(process_handle: wintypes.HANDLE) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    result = kernel32.WaitForSingleObject(process_handle, 10_000)
    if result != _WAIT_OBJECT_0:
        raise WfpGuardError("Elevated WFP Guard did not exit after returning evidence")
    exit_code = wintypes.DWORD()
    if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
        raise WfpGuardError(
            f"Elevated WFP Guard exit status is unavailable: WinError {ctypes.get_last_error()}"
        )
    if exit_code.value != 0:
        raise WfpGuardError(f"Elevated WFP Guard exited with code {exit_code.value}")


def _validated_report(value: dict[str, Any]) -> GuardVerification:
    try:
        report = GuardVerification(**value)
    except (TypeError, ValueError) as error:
        raise WfpGuardError("Elevated WFP Guard report schema is invalid") from error
    if (
        report.guard_version != GUARD_VERSION
        or report.policy_generation != GUARD_POLICY_GENERATION
        or report.target_account != TARGET_ACCOUNT
        or report.app_isolation_sublayer_key != str(APP_ISOLATION_SUBLAYER_KEY)
        or report.guard_sublayer_key != str(GUARD_SUBLAYER_KEY)
        or report.guard_sublayer_weight != GUARD_SUBLAYER_WEIGHT
        or report.guard_sublayer_weight <= report.app_isolation_weight
        or report.v4_filter_key != str(GUARD_V4_FILTER_KEY)
        or report.v4_filter_id <= 0
        or report.v4_effective_weight is None
        or report.v6_filter_key != str(GUARD_V6_FILTER_KEY)
        or report.v6_filter_id <= 0
        or report.v6_effective_weight is None
        or report.static_nonpersistent is not True
        or report.dynamic_session is not False
        or report.persistent is not False
    ):
        raise WfpGuardError("Elevated WFP Guard report does not match the fixed policy")
    return report


def _is_administrator() -> bool:
    return bool(ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin())


def _elevated_main(pipe_name: str) -> int:
    auth = os.environ.get(_AUTH_ENV, "")
    try:
        authkey = bytes.fromhex(auth)
        if len(authkey) != 32:
            raise ValueError("invalid authentication key")
    except ValueError:
        return 2
    payload: dict[str, object]
    exit_code = 0
    try:
        if not _is_administrator():
            raise WfpGuardError("WFP Guard elevation was not established")
        verification = ensure_codex_loopback_block(new_windows_wfp_api())
        payload = {"ok": True, "verification": verification.as_dict()}
    except Exception as error:  # noqa: BLE001 - exact failure is returned to fail-closed caller
        payload = {"ok": False, "error": f"{type(error).__name__}: {error}"[:1000]}
        exit_code = 2
    try:
        connection = Client(pipe_name, family="AF_PIPE", authkey=authkey)
        try:
            connection.send_bytes(canonical_json(payload).encode("utf-8"))
        finally:
            connection.close()
    except (OSError, EOFError):
        return 3
    return exit_code


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 2 and arguments[0] == "--elevated-ensure":
        return _elevated_main(arguments[1])
    if arguments == ["--maintenance-verify"]:
        print(canonical_json(verify_codex_loopback_block(new_windows_wfp_api()).as_dict()))
        return 0
    if arguments == ["--maintenance-ensure"]:
        if not _is_administrator():
            raise SystemExit("Run maintenance ensure from an Administrator PowerShell")
        print(canonical_json(ensure_codex_loopback_block(new_windows_wfp_api()).as_dict()))
        return 0
    if arguments == ["--maintenance-cleanup"]:
        if not _is_administrator():
            raise SystemExit("Run maintenance cleanup from an Administrator PowerShell")
        maintenance_remove_codex_loopback_block(new_windows_wfp_api())
        print(canonical_json({"removed": True}))
        return 0
    raise SystemExit("This module only accepts the internal fixed Guard invocation")


if __name__ == "__main__":
    raise SystemExit(main())
