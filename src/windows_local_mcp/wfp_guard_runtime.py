from __future__ import annotations

import ctypes
import json
import os
import queue
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

_ELEVATED_WAIT_SECONDS = 60
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SW_HIDE = 0
_WAIT_OBJECT_0 = 0
_PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_PIPE_PROCEED = b"wlmcp-wfp-guard-proceed-v1"


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


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def ensure_runtime_codex_loopback_guard(
    *,
    force_elevated: bool = False,
    diagnostic_trace: dict[str, object] | None = None,
) -> GuardVerification:
    """Ensure/read back the fixed WFP boundary, elevating only the Guard if needed.

    ``force_elevated`` exists for the real-machine integration diagnostic. It makes
    that diagnostic exercise the production UAC/IPC path even when the fixed WFP
    objects already exist and can be read without elevation.
    """

    if os.name != "nt":
        raise WfpGuardError("The WFP Guard requires native Windows")
    if force_elevated:
        if _is_administrator():
            raise WfpGuardError(
                "The end-to-end WFP Guard diagnostic requires an unelevated caller"
            )
        return _run_elevated_ensure(diagnostic_trace=diagnostic_trace)
    try:
        # Correct static objects are normally readable and need no elevation or mutation.
        return verify_codex_loopback_block(new_windows_wfp_api())
    except Exception:  # noqa: BLE001 - elevated ensure re-checks all fields and still fails closed
        if _is_administrator():
            return ensure_codex_loopback_block(new_windows_wfp_api())
    return _run_elevated_ensure(diagnostic_trace=diagnostic_trace)


def _run_elevated_ensure(
    *, diagnostic_trace: dict[str, object] | None = None
) -> GuardVerification:
    pipe_name = rf"\\.\pipe\wlmcp-wfp-guard-{uuid.uuid4().hex}"
    listener = Listener(pipe_name, family="AF_PIPE")
    messages: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=1)
    process_handle: wintypes.HANDLE | None = None
    if diagnostic_trace is not None:
        diagnostic_trace.update(
            {
                "transport": "Windows named pipe (multiprocessing.connection.AF_PIPE)",
                "pipe_server_pid": os.getpid(),
                "shell_execute": {"api": "ShellExecuteExW", "verb": "runas"},
                "pipe_proceed_token_sent": False,
                "pipe_peer_identity_verified": False,
            }
        )
    try:
        try:
            if diagnostic_trace is None:
                process_handle = _shell_execute_elevated(pipe_name)
            else:
                process_handle = _shell_execute_elevated(
                    pipe_name, include_integration_evidence=True
                )
            elevated_pid = _process_id_from_handle(process_handle)
            if diagnostic_trace is not None:
                diagnostic_trace["runas_process_pid"] = elevated_pid
                diagnostic_trace["runas_process_executable"] = _process_executable_path(
                    elevated_pid
                )
        except Exception:
            listener.close()
            raise

        def receive() -> None:
            try:
                connection = listener.accept()
                try:
                    # UAC intentionally does not inherit the caller's environment. Bind the
                    # bootstrap pipe to the process returned by runas or the Python process
                    # directly launched by the Windows venv launcher represented by that handle.
                    client_pid = _named_pipe_client_process_id(connection.fileno())
                    peer_verified = _is_expected_pipe_client(client_pid, elevated_pid)
                    if diagnostic_trace is not None:
                        diagnostic_trace["pipe_client_pid"] = client_pid
                        diagnostic_trace["pipe_client_executable"] = _process_executable_path(
                            client_pid
                        )
                        diagnostic_trace["pipe_client_parent_pid"] = _process_parent_id(
                            client_pid
                        )
                        diagnostic_trace["pipe_peer_identity_verified"] = peer_verified
                    if not peer_verified:
                        raise WfpGuardError(
                            "Elevated WFP Guard IPC connected from an unexpected process"
                        )
                    # Keep the verified peer alive until its ancestry is checked, then release
                    # that same connection to perform the fixed privileged operation.
                    connection.send_bytes(_PIPE_PROCEED)
                    if diagnostic_trace is not None:
                        diagnostic_trace["pipe_proceed_token_sent"] = True
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
        if diagnostic_trace is not None:
            diagnostic_trace["elevated_guard_evidence"] = payload.get("elevated_process")
            diagnostic_trace["elevated_ensure_called"] = True
        report = payload.get("verification")
        if not isinstance(report, dict):
            raise WfpGuardError("Elevated WFP Guard returned no verification evidence")
        exit_code = _wait_for_elevated_exit(process_handle)
        validated = _validated_report(report)
        if diagnostic_trace is not None:
            diagnostic_trace["elevated_exit_code"] = exit_code
            diagnostic_trace["parent_readback_validation"] = True
        return validated
    finally:
        listener.close()
        if process_handle:
            _close_process_handle(process_handle)


def _shell_execute_elevated(
    pipe_name: str, *, include_integration_evidence: bool = False
) -> wintypes.HANDLE:
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    launcher_path = Path(_expected_venv_launcher_path())
    arguments = [
        "-I",
        "-m",
        "windows_local_mcp.wfp_guard_runtime",
        "--elevated-ensure",
        pipe_name,
    ]
    if include_integration_evidence:
        arguments.append("--integration-evidence")
    parameters = subprocess.list2cmdline(arguments)
    info = _ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = str(launcher_path)
    info.lpParameters = parameters
    info.lpDirectory = str(launcher_path.parent)
    info.nShow = _SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        raise WfpGuardError(
            f"Elevated WFP Guard could not start: WinError {ctypes.get_last_error()}"
        )
    return info.hProcess


def _wait_for_elevated_exit(process_handle: wintypes.HANDLE) -> int:
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
    return int(exit_code.value)


def _process_id_from_handle(process_handle: wintypes.HANDLE) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessId.restype = wintypes.DWORD
    process_id = int(kernel32.GetProcessId(process_handle))
    if process_id <= 0:
        raise WfpGuardError(
            f"Elevated WFP Guard process identity is unavailable: WinError {ctypes.get_last_error()}"
        )
    return process_id


def _named_pipe_client_process_id(pipe_handle: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetNamedPipeClientProcessId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.ULONG),
    ]
    kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    process_id = wintypes.ULONG()
    if not kernel32.GetNamedPipeClientProcessId(
        wintypes.HANDLE(pipe_handle), ctypes.byref(process_id)
    ):
        raise WfpGuardError(
            "Elevated WFP Guard IPC peer identity is unavailable: "
            f"WinError {ctypes.get_last_error()}"
        )
    return int(process_id.value)


def _same_executable_path(actual: str, expected: str) -> bool:
    try:
        actual_path = Path(actual).resolve(strict=True)
        expected_path = Path(expected).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    return os.path.normcase(str(actual_path)) == os.path.normcase(str(expected_path))


def _expected_venv_launcher_path() -> str:
    try:
        prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        executable = Path(sys.executable).resolve(strict=True)
        expected = (prefix / "Scripts" / "python.exe").resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise WfpGuardError(
            "The elevated WFP Guard requires a valid Python venv launcher"
        ) from error
    if prefix == base_prefix or not _same_executable_path(str(executable), str(expected)):
        raise WfpGuardError(
            "The elevated WFP Guard requires the repository .venv\\Scripts\\python.exe launcher"
        )
    return str(executable)


def _expected_base_python_path() -> str:
    _expected_venv_launcher_path()
    try:
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        configured_base = getattr(sys, "_base_executable", "") or str(base_prefix / "python.exe")
        base_executable = Path(configured_base).resolve(strict=True)
        expected = (base_prefix / "python.exe").resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise WfpGuardError(
            "The elevated WFP Guard requires a valid base Python executable"
        ) from error
    if not _same_executable_path(str(base_executable), str(expected)):
        raise WfpGuardError("The elevated WFP Guard requires the venv's base Python executable")
    return str(base_executable)


def _process_executable_path(process_id: int) -> str:
    if process_id <= 0:
        raise WfpGuardError("Elevated WFP Guard process identity is invalid")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    process_handle = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        process_id,
    )
    if not process_handle:
        raise WfpGuardError(
            "Elevated WFP Guard process executable is unavailable: "
            f"WinError {ctypes.get_last_error()}"
        )
    try:
        buffer_length = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(buffer_length.value)
        if (
            not kernel32.QueryFullProcessImageNameW(
                process_handle,
                0,
                buffer,
                ctypes.byref(buffer_length),
            )
            or buffer_length.value <= 0
        ):
            raise WfpGuardError(
                "Elevated WFP Guard process executable is unavailable: "
                f"WinError {ctypes.get_last_error()}"
            )
        try:
            return str(Path(buffer.value[: buffer_length.value]).resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as error:
            raise WfpGuardError("Elevated WFP Guard process executable path is invalid") from error
    finally:
        _close_process_handle(process_handle)


def _is_expected_pipe_client(client_pid: int, elevated_pid: int) -> bool:
    expected_launcher = _expected_venv_launcher_path()
    if not _same_executable_path(_process_executable_path(elevated_pid), expected_launcher):
        return False
    if client_pid == elevated_pid:
        return True
    # Python 3.14 venv executables are launchers: only their direct base-Python child
    # may import this module and open the pipe. A parent PID match alone is insufficient.
    if _process_parent_id(client_pid) != elevated_pid:
        return False
    return _same_executable_path(_process_executable_path(client_pid), _expected_base_python_path())


def _process_parent_id(process_id: int) -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == _INVALID_HANDLE_VALUE:
        raise WfpGuardError(
            f"Elevated WFP Guard process tree is unavailable: WinError {ctypes.get_last_error()}"
        )
    try:
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        has_entry = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while has_entry:
            if int(entry.th32ProcessID) == process_id:
                return int(entry.th32ParentProcessID)
            has_entry = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    raise WfpGuardError("Elevated WFP Guard IPC peer process is unavailable")


def _close_process_handle(process_handle: wintypes.HANDLE) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(process_handle)


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


def _local_process_evidence(*, is_administrator: bool) -> dict[str, object]:
    try:
        executable = str(Path(sys.executable).resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        executable = sys.executable
    return {
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "python_executable": executable,
        "is_administrator": is_administrator,
    }


def run_integration_diagnostic() -> dict[str, object]:
    """Exercise the real unelevated-to-elevated Guard route and return JSON evidence."""

    trace: dict[str, object] = {
        "diagnostic": "wlmcp-wfp-guard-integration-v1",
        "production_entrypoint": "ensure_runtime_codex_loopback_guard(force_elevated=True)",
        "required_route": [
            "unelevated WLMCP process",
            "ShellExecuteExW(runAs/UAC)",
            "elevated Guard",
            "named pipe IPC",
            "real WFP ensure/read-back",
        ],
    }
    try:
        if os.name != "nt":
            raise WfpGuardError("The integration diagnostic requires native Windows")
        normal_is_administrator = _is_administrator()
        trace["normal_process"] = _local_process_evidence(
            is_administrator=normal_is_administrator
        )
        if normal_is_administrator:
            raise WfpGuardError(
                "The integration diagnostic must be started by an unelevated Windows process"
            )
        verification = ensure_runtime_codex_loopback_guard(
            force_elevated=True,
            diagnostic_trace=trace,
        )
        trace["wfp"] = {
            "ensure_called_by_elevated_guard": True,
            "readback_validated_by_unelevated_parent": True,
            "verification": verification.as_dict(),
        }
        return {"success": True, "evidence": trace}
    except Exception as error:  # noqa: BLE001 - diagnostic must preserve failure evidence
        trace["failure"] = f"{type(error).__name__}: {error}"
        return {"success": False, "evidence": trace}


def _is_administrator() -> bool:
    return bool(ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin())


def _elevated_main(pipe_name: str, *, include_integration_evidence: bool = False) -> int:
    try:
        connection = Client(pipe_name, family="AF_PIPE")
        try:
            if connection.recv_bytes() != _PIPE_PROCEED:
                return 3
            payload: dict[str, object]
            exit_code = 0
            try:
                is_administrator = _is_administrator()
                elevated_process = _local_process_evidence(
                    is_administrator=is_administrator
                )
                if not is_administrator:
                    raise WfpGuardError("WFP Guard elevation was not established")
                verification = ensure_codex_loopback_block(new_windows_wfp_api())
                payload = {"ok": True, "verification": verification.as_dict()}
                if include_integration_evidence:
                    payload["elevated_process"] = elevated_process
            except Exception as error:  # noqa: BLE001 - exact failure returns to fail-closed caller
                payload = {"ok": False, "error": f"{type(error).__name__}: {error}"[:1000]}
                if include_integration_evidence:
                    payload["elevated_process"] = locals().get("elevated_process")
                exit_code = 2
            connection.send_bytes(canonical_json(payload).encode("utf-8"))
        finally:
            connection.close()
    except (OSError, EOFError):
        return 3
    return exit_code


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--integration-diagnostic"]:
        result = run_integration_diagnostic()
        print(canonical_json(result))
        return 0 if result.get("success") is True else 1
    if arguments[0:1] == ["--elevated-ensure"] and len(arguments) in {2, 3}:
        if len(arguments) == 3 and arguments[2] != "--integration-evidence":
            raise SystemExit("Invalid elevated Guard diagnostic argument")
        return _elevated_main(
            arguments[1], include_integration_evidence=len(arguments) == 3
        )
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
