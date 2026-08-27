from __future__ import annotations

import argparse
import ctypes
import json
import os
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .approval import verify_approval_bundle
from .approved_host_authority import (
    APPROVED_HOST_AUTHORITY_SERVICE_NAME,
    ApprovedHostAuthorityClient,
    _service_process_id,
    default_authority_state_root,
)
from .approved_host_service import _process_token_details
from .audit import TERMINAL_STATUSES
from .control_plane import verify_control_plane_generation
from .policy import approved_request_hash

_LIVE_CHILD_START_TIMEOUT_SECONDS = 120.0

if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _PROCESS_TERMINATE = 0x0001
    _PROCESS_CREATE_THREAD = 0x0002
    _PROCESS_VM_OPERATION = 0x0008
    _PROCESS_VM_WRITE = 0x0020
    _PROCESS_DUP_HANDLE = 0x0040
    _PROCESS_SET_INFORMATION = 0x0200
    _PROCESS_SUSPEND_RESUME = 0x0800
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _WRITE_DAC = 0x00040000
    _WRITE_OWNER = 0x00080000

    _THREAD_TERMINATE = 0x0001
    _THREAD_SUSPEND_RESUME = 0x0002
    _THREAD_SET_CONTEXT = 0x0010
    _THREAD_SET_INFORMATION = 0x0020
    _TH32CS_SNAPTHREAD = 0x00000004

    _TOKEN_ASSIGN_PRIMARY = 0x0001
    _TOKEN_DUPLICATE = 0x0002
    _TOKEN_IMPERSONATE = 0x0004
    _TOKEN_ADJUST_PRIVILEGES = 0x0020
    _TOKEN_ADJUST_DEFAULT = 0x0080

    _SC_MANAGER_CONNECT = 0x0001
    _SERVICE_CHANGE_CONFIG = 0x0002
    _SERVICE_QUERY_STATUS = 0x0004
    _SERVICE_STOP = 0x0020
    _DELETE = 0x00010000

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("dwOwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Thread32First.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_THREADENTRY32),
    ]
    _kernel32.Thread32First.restype = wintypes.BOOL
    _kernel32.Thread32Next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_THREADENTRY32),
    ]
    _kernel32.Thread32Next.restype = wintypes.BOOL
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.OpenSCManagerW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    _advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    _advapi32.OpenServiceW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    _advapi32.OpenServiceW.restype = wintypes.HANDLE
    _advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    _advapi32.CloseServiceHandle.restype = wintypes.BOOL


def _assert_handle_denied(handle: wintypes.HANDLE, label: str) -> None:
    if handle:
        _kernel32.CloseHandle(handle)
        raise AssertionError(f"runtime user unexpectedly obtained {label}")


def _assert_sensitive_process_rights_denied(pid: int, label: str) -> None:
    masks = {
        "PROCESS_TERMINATE": _PROCESS_TERMINATE,
        "PROCESS_CREATE_THREAD": _PROCESS_CREATE_THREAD,
        "PROCESS_VM_OPERATION": _PROCESS_VM_OPERATION,
        "PROCESS_VM_WRITE": _PROCESS_VM_WRITE,
        "PROCESS_DUP_HANDLE": _PROCESS_DUP_HANDLE,
        "PROCESS_SET_INFORMATION": _PROCESS_SET_INFORMATION,
        "PROCESS_SUSPEND_RESUME": _PROCESS_SUSPEND_RESUME,
        "WRITE_DAC": _WRITE_DAC,
        "WRITE_OWNER": _WRITE_OWNER,
    }
    for name, mask in masks.items():
        handle = _kernel32.OpenProcess(mask, False, pid)
        _assert_handle_denied(handle, f"{label} {name}")

    process = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if process:
        token = wintypes.HANDLE()
        try:
            sensitive_token = (
                _TOKEN_ASSIGN_PRIMARY
                | _TOKEN_DUPLICATE
                | _TOKEN_IMPERSONATE
                | _TOKEN_ADJUST_PRIVILEGES
                | _TOKEN_ADJUST_DEFAULT
                | _WRITE_DAC
                | _WRITE_OWNER
            )
            opened = _advapi32.OpenProcessToken(
                process,
                sensitive_token,
                ctypes.byref(token),
            )
            if opened:
                raise AssertionError(
                    f"runtime user unexpectedly obtained sensitive {label} token rights"
                )
        finally:
            if token:
                _kernel32.CloseHandle(token)
            _kernel32.CloseHandle(process)


def _thread_ids(pid: int) -> list[int]:
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if snapshot in (None, _INVALID_HANDLE_VALUE):
        raise RuntimeError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")
    result: list[int] = []
    try:
        entry = _THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        found = bool(_kernel32.Thread32First(snapshot, ctypes.byref(entry)))
        while found:
            if int(entry.dwOwnerProcessID) == pid:
                result.append(int(entry.th32ThreadID))
            found = bool(_kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
    finally:
        _kernel32.CloseHandle(snapshot)
    return result


def _assert_sensitive_thread_rights_denied(pid: int, label: str) -> None:
    mask = (
        _THREAD_TERMINATE
        | _THREAD_SUSPEND_RESUME
        | _THREAD_SET_CONTEXT
        | _THREAD_SET_INFORMATION
        | _WRITE_DAC
        | _WRITE_OWNER
    )
    threads = _thread_ids(pid)
    if not threads:
        raise AssertionError(f"{label} has no observable threads to test")
    for thread_id in threads:
        handle = _kernel32.OpenThread(mask, False, thread_id)
        _assert_handle_denied(handle, f"{label} sensitive thread rights")


def _assert_service_mutation_rights_denied() -> None:
    manager = _advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise RuntimeError(f"OpenSCManagerW failed: {ctypes.get_last_error()}")
    try:
        query = _advapi32.OpenServiceW(
            manager,
            APPROVED_HOST_AUTHORITY_SERVICE_NAME,
            _SERVICE_QUERY_STATUS,
        )
        if not query:
            raise AssertionError("runtime user cannot query Approved Host service status")
        _advapi32.CloseServiceHandle(query)
        for name, mask in {
            "SERVICE_STOP": _SERVICE_STOP,
            "SERVICE_CHANGE_CONFIG": _SERVICE_CHANGE_CONFIG,
            "DELETE": _DELETE,
            "WRITE_DAC": _WRITE_DAC,
            "WRITE_OWNER": _WRITE_OWNER,
        }.items():
            handle = _advapi32.OpenServiceW(
                manager,
                APPROVED_HOST_AUTHORITY_SERVICE_NAME,
                mask,
            )
            if handle:
                _advapi32.CloseServiceHandle(handle)
                raise AssertionError(
                    f"runtime user unexpectedly obtained service right {name}"
                )
    finally:
        _advapi32.CloseServiceHandle(manager)


def _assert_state_namespace_inaccessible(root: Path) -> None:
    try:
        list(root.iterdir())
    except (PermissionError, OSError):
        pass
    else:
        raise AssertionError("runtime user can enumerate SYSTEM-owned authority state")
    probe = root / "runtime-user-write-probe.txt"
    try:
        with probe.open("xb") as output:
            output.write(b"must-not-be-created")
    except (PermissionError, OSError):
        pass
    else:
        probe.unlink(missing_ok=True)
        raise AssertionError("runtime user can create files in authority state")


def _assert_child_keeps_requester_authority(child_pid: int, requester_sid: str) -> None:
    child_sid, elevated = _process_token_details(child_pid)
    if child_sid.casefold() != requester_sid.casefold():
        raise AssertionError(
            f"Approved Host child SID changed: requester={requester_sid}, child={child_sid}"
        )
    if elevated:
        raise AssertionError("Approved Host child unexpectedly received an elevated token")
    handle = _kernel32.OpenProcess(_PROCESS_TERMINATE, False, child_pid)
    if not handle:
        raise AssertionError(
            "runtime user cannot obtain PROCESS_TERMINATE on its own Approved Host child; "
            "ordinary user authority was not preserved"
        )
    _kernel32.CloseHandle(handle)


def _stage_and_launch_live_operation(cwd: str) -> tuple[Any, str]:
    from . import server

    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    ping = system_root / "System32" / "ping.exe"
    staged = server.request_host_command(
        command=[str(ping), "127.0.0.1", "-n", "8", "-w", "1000"],
        cwd=cwd,
        reason="WLMCP-R2-001 LocalSystem authority live verification",
        network_required=True,
        risk_summary="Loopback-only timing command for security-boundary verification",
        workspace_write=True,
        max_runtime_seconds=30,
    )
    operation_id = str(staged["approval_id"])
    operation = server.runtime.audit.get_operation(operation_id, include_events=False)
    request = operation["request"]
    if not isinstance(request, dict):
        raise TypeError("live Approved Host request is not an object")
    verify_control_plane_generation(
        server.runtime.settings,
        request.get("control_plane_generation"),
    )
    expected_hash = approved_request_hash(request)
    if expected_hash != operation.get("request_hash"):
        raise RuntimeError("live Approved Host request hash mismatch")
    verify_approval_bundle(
        settings=server.runtime.settings,
        operation_id=operation_id,
        expected_digest=str(request["approval_manifest_digest"]),
    )
    server.runtime.audit.approve_and_claim(
        operation_id,
        approver="approved-host-live-verification",
        note="operator explicitly approved live security-boundary verification",
        expected_request_hash=expected_hash,
    )
    server.runtime.executor.launch(operation_id, 0)
    return server.runtime, operation_id


def _wait_for_child(
    runtime: Any,
    operation_id: str,
    timeout: float = _LIVE_CHILD_START_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    # The verifier process itself is the authority-bound requester. Approved Host preflight can
    # legitimately spend tens of seconds hashing the immutable runtime and control plane before
    # CreateProcessAsUser runs. Exiting this verifier early would make the requester PID disappear
    # and correctly force the SYSTEM worker to fail closed, producing a false verification failure.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        operation = runtime.audit.get_operation(operation_id, include_events=False)
        if operation.get("child_pid"):
            return operation
        if operation["status"] in TERMINAL_STATUSES:
            raise AssertionError(
                f"Approved Host terminated before live boundary checks: {operation}"
            )
        time.sleep(0.05)
    raise TimeoutError("Approved Host child did not start before live verification timeout")


def _wait_terminal(runtime: Any, operation_id: str, timeout: float = 45.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        operation = runtime.audit.get_operation(operation_id, include_events=False)
        if operation["status"] in TERMINAL_STATUSES:
            return operation
        time.sleep(0.1)
    raise TimeoutError("Approved Host operation did not reach a terminal state")


def run_live_verification(cwd: str) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Approved Host live verification requires native Windows")
    requester_sid, requester_elevated = _process_token_details(os.getpid())
    if requester_elevated:
        raise PermissionError(
            "run Approved Host live verification from the normal non-elevated runtime user"
        )
    initial = ApprovedHostAuthorityClient().assert_available()
    _assert_service_mutation_rights_denied()
    service_pid = _service_process_id()
    _assert_sensitive_process_rights_denied(service_pid, "authority service")
    _assert_sensitive_thread_rights_denied(service_pid, "authority service")

    runtime, operation_id = _stage_and_launch_live_operation(cwd)
    operation = _wait_for_child(runtime, operation_id)
    worker_pid = int(operation["worker_pid"])
    child_pid = int(operation["child_pid"])
    if worker_pid == child_pid:
        raise AssertionError("SYSTEM monitor and user child unexpectedly share a PID")

    _assert_sensitive_process_rights_denied(worker_pid, "authority worker")
    _assert_sensitive_thread_rights_denied(worker_pid, "authority worker")
    _assert_child_keeps_requester_authority(child_pid, requester_sid)
    _assert_state_namespace_inaccessible(default_authority_state_root())

    terminal = _wait_terminal(runtime, operation_id)
    if terminal["status"] != "succeeded":
        raise AssertionError(
            "normal Approved Host E2E failed: "
            + json.dumps(terminal, ensure_ascii=False, default=str)
        )

    deadline = time.monotonic() + 10.0
    final_probe: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            final_probe = ApprovedHostAuthorityClient().assert_available()
            break
        except Exception:  # noqa: BLE001 - service watcher may still be consuming proof
            time.sleep(0.1)
    if final_probe is None:
        raise AssertionError("authority latch did not clear after verified normal completion")

    return {
        "status": "passed",
        "operation_id": operation_id,
        "requester_sid": requester_sid,
        "service_pid": service_pid,
        "worker_pid": worker_pid,
        "child_pid": child_pid,
        "initial_service_epoch": initial.get("service_epoch"),
        "final_service_epoch": final_probe.get("service_epoch"),
        "child_authority": "same non-elevated runtime user",
        "monitor_authority": "LocalSystem sensitive rights denied to runtime user",
        "durable_state": "runtime-user enumerate/write denied",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path)
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        raise PermissionError(
            "live verification requires explicit --execute after operator confirmation"
        )
    if args.config is not None:
        os.environ["LOCAL_MCP_CONFIG"] = str(args.config.resolve(strict=True))
    result = run_live_verification(args.cwd)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
