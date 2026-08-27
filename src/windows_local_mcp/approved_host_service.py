from __future__ import annotations

import argparse
import ctypes
import json
import os
import secrets
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from ctypes import wintypes
from pathlib import Path
from typing import Any

import psutil

from .approved_host_authority import (
    APPROVED_HOST_AUTHORITY_PIPE,
    APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION,
    APPROVED_HOST_AUTHORITY_SERVICE_NAME,
    ApprovedHostRecoveryRequired,
    AuthorityStateStore,
    AuthorityWorkerIdentity,
    authority_completion_path,
    default_authority_state_root,
)
from .process_utils import capture_process_identity, creation_flags
from .util import canonical_json

_SYSTEM_SID = "S-1-5-18"
_MAX_PIPE_MESSAGE_BYTES = 1024 * 1024


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _PIPE_ACCESS_DUPLEX = 0x00000003
    _PIPE_TYPE_MESSAGE = 0x00000004
    _PIPE_READMODE_MESSAGE = 0x00000002
    _PIPE_WAIT = 0x00000000
    _PIPE_UNLIMITED_INSTANCES = 255
    _ERROR_PIPE_CONNECTED = 535
    _ERROR_MORE_DATA = 234
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _PROCESS_TERMINATE = 0x0001
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _TOKEN_ELEVATION = 20
    _SDDL_REVISION_1 = 1
    _SERVICE_WIN32_OWN_PROCESS = 0x00000010
    _SERVICE_START_PENDING = 2
    _SERVICE_STOP_PENDING = 3
    _SERVICE_RUNNING = 4
    _SERVICE_STOPPED = 1
    _SERVICE_ACCEPT_STOP = 0x00000001
    _SERVICE_ACCEPT_SHUTDOWN = 0x00000004
    _SERVICE_CONTROL_STOP = 1
    _SERVICE_CONTROL_SHUTDOWN = 5
    _NO_ERROR = 0

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _TOKEN_USER_VALUE(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _TOKEN_ELEVATION_VALUE(ctypes.Structure):
        _fields_ = [("TokenIsElevated", wintypes.DWORD)]

    class _SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    _HANDLER_FUNCTION = ctypes.WINFUNCTYPE(
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    _SERVICE_MAIN_FUNCTION = ctypes.WINFUNCTYPE(
        None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR)
    )

    class _SERVICE_TABLE_ENTRY(ctypes.Structure):
        _fields_ = [
            ("lpServiceName", wintypes.LPWSTR),
            ("lpServiceProc", _SERVICE_MAIN_FUNCTION),
        ]

    _kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
    ]
    _kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    _kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    _kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    _kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    _kernel32.GetNamedPipeClientProcessId.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)
    ]
    _kernel32.GetNamedPipeClientProcessId.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
        wintypes.LPCWSTR,
        _HANDLER_FUNCTION,
        ctypes.c_void_p,
    ]
    _advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    _advapi32.SetServiceStatus.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_SERVICE_STATUS)
    ]
    _advapi32.SetServiceStatus.restype = wintypes.BOOL
    _advapi32.StartServiceCtrlDispatcherW.argtypes = [
        ctypes.POINTER(_SERVICE_TABLE_ENTRY)
    ]
    _advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL


def _winerror(action: str) -> RuntimeError:
    return RuntimeError(f"{action} failed: WinError {ctypes.get_last_error()}")


def _process_token_details(pid: int) -> tuple[str, bool]:
    if os.name != "nt":
        raise RuntimeError("Approved Host authority requires native Windows")
    process = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise _winerror("OpenProcess(requester)")
    token = wintypes.HANDLE()
    try:
        if not _advapi32.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
            raise _winerror("OpenProcessToken(requester)")
        needed = wintypes.DWORD()
        _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise _winerror("GetTokenInformation(TokenUser size)")
        user_buffer = ctypes.create_string_buffer(needed.value)
        if not _advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            user_buffer,
            len(user_buffer),
            ctypes.byref(needed),
        ):
            raise _winerror("GetTokenInformation(TokenUser)")
        token_user = ctypes.cast(
            user_buffer, ctypes.POINTER(_TOKEN_USER_VALUE)
        ).contents
        sid_text = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(
            token_user.Sid, ctypes.byref(sid_text)
        ):
            raise _winerror("ConvertSidToStringSidW")
        try:
            sid = str(sid_text.value)
        finally:
            _kernel32.LocalFree(sid_text)

        elevation = _TOKEN_ELEVATION_VALUE()
        returned = wintypes.DWORD()
        if not _advapi32.GetTokenInformation(
            token,
            _TOKEN_ELEVATION,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(returned),
        ):
            raise _winerror("GetTokenInformation(TokenElevation)")
        return sid, bool(elevation.TokenIsElevated)
    finally:
        if token:
            _kernel32.CloseHandle(token)
        _kernel32.CloseHandle(process)


def _current_process_sid() -> str:
    return _process_token_details(os.getpid())[0]


def _requester_create_time(pid: int) -> float:
    return float(psutil.Process(pid).create_time())


def _worker_bootstrap_argv(
    *,
    operation_id: str,
    context_path: Path,
    context_sha256: str,
    requester_pid: int,
    requester_create_time: float,
    service_epoch: str,
    authority_nonce: str,
    proof_path: Path,
) -> list[str]:
    package = Path(__file__).resolve(strict=True).parent
    source_root = package.parent
    bootstrap = (
        "import runpy,sys;"
        f"sys.path.insert(0,{str(source_root)!r});"
        "runpy.run_module('windows_local_mcp.approved_host_worker',run_name='__main__')"
    )
    return [
        sys.executable,
        "-I",
        "-B",
        "-c",
        bootstrap,
        "--operation-id",
        operation_id,
        "--context",
        str(context_path),
        "--context-sha256",
        context_sha256,
        "--approved-host-requester-pid",
        str(requester_pid),
        "--approved-host-requester-create-time",
        repr(requester_create_time),
        "--authority-service-epoch",
        service_epoch,
        "--authority-nonce",
        authority_nonce,
        "--authority-proof-path",
        str(proof_path),
    ]


class ApprovedHostAuthorityServer:
    def __init__(self, *, runtime_sid: str, state_root: Path) -> None:
        if os.name != "nt":
            raise RuntimeError("Approved Host authority requires native Windows")
        if _current_process_sid() != _SYSTEM_SID:
            raise PermissionError("Approved Host authority must run as LocalSystem")
        self.runtime_sid = runtime_sid
        self.service_epoch = secrets.token_hex(32)
        self.store = AuthorityStateStore(state_root, self.service_epoch)
        self.store.ensure_root()
        if self.store.read_active() is not None:
            self.store.mark_recovery_required(
                "authority service restarted while an operation was active"
            )
        self._stop = threading.Event()
        self._workers_lock = threading.RLock()
        self._workers: dict[str, subprocess.Popen[Any]] = {}
        self._security_descriptor = ctypes.c_void_p()
        self._security_attributes = self._build_pipe_security(runtime_sid)

    def _build_pipe_security(self, runtime_sid: str) -> _SECURITY_ATTRIBUTES:
        descriptor = ctypes.c_void_p()
        descriptor_size = wintypes.DWORD()
        sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{runtime_sid})"
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            ctypes.byref(descriptor_size),
        ):
            raise _winerror("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        self._security_descriptor = descriptor
        return _SECURITY_ATTRIBUTES(
            nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
            lpSecurityDescriptor=descriptor,
            bInheritHandle=False,
        )

    def close(self) -> None:
        self._stop.set()
        self.wake()
        if self._security_descriptor:
            _kernel32.LocalFree(self._security_descriptor)
            self._security_descriptor = ctypes.c_void_p()

    def wake(self) -> None:
        if os.name != "nt":
            return
        handle = _kernel32.CreateFileW(
            APPROVED_HOST_AUTHORITY_PIPE,
            _GENERIC_READ | _GENERIC_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle not in (None, invalid):
            _kernel32.CloseHandle(handle)

    def serve(self) -> None:
        while not self._stop.is_set():
            pipe = _kernel32.CreateNamedPipeW(
                APPROVED_HOST_AUTHORITY_PIPE,
                _PIPE_ACCESS_DUPLEX,
                _PIPE_TYPE_MESSAGE | _PIPE_READMODE_MESSAGE | _PIPE_WAIT,
                _PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                ctypes.byref(self._security_attributes),
            )
            invalid = ctypes.c_void_p(-1).value
            if pipe in (None, invalid):
                raise _winerror("CreateNamedPipeW")
            try:
                connected = bool(_kernel32.ConnectNamedPipe(pipe, None))
                if not connected and ctypes.get_last_error() != _ERROR_PIPE_CONNECTED:
                    if self._stop.is_set():
                        return
                    raise _winerror("ConnectNamedPipe")
                if self._stop.is_set():
                    return
                client_pid = wintypes.DWORD()
                if not _kernel32.GetNamedPipeClientProcessId(
                    pipe, ctypes.byref(client_pid)
                ):
                    raise _winerror("GetNamedPipeClientProcessId")
                try:
                    request = self._read_message(pipe)
                    response = self.handle_request(int(client_pid.value), request)
                except Exception as error:  # noqa: BLE001 - RPC must fail closed
                    response = {
                        "protocol_version": APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION,
                        "ok": False,
                        "error_type": type(error).__name__,
                        "error": str(error)[:4000],
                    }
                self._write_message(pipe, response)
                _kernel32.FlushFileBuffers(pipe)
            finally:
                _kernel32.DisconnectNamedPipe(pipe)
                _kernel32.CloseHandle(pipe)

    def _read_message(self, pipe: wintypes.HANDLE) -> dict[str, Any]:
        chunks: list[bytes] = []
        total = 0
        while True:
            buffer = ctypes.create_string_buffer(64 * 1024)
            read = wintypes.DWORD()
            ctypes.set_last_error(0)
            ok = _kernel32.ReadFile(
                pipe, buffer, len(buffer), ctypes.byref(read), None
            )
            if read.value:
                chunk = bytes(buffer.raw[: read.value])
                chunks.append(chunk)
                total += len(chunk)
                if total > _MAX_PIPE_MESSAGE_BYTES:
                    raise ValueError(
                        "Approved Host authority request exceeds the IPC bound"
                    )
            if ok:
                break
            if ctypes.get_last_error() != _ERROR_MORE_DATA:
                raise _winerror("ReadFile(Approved Host authority server)")
        value = json.loads(b"".join(chunks).decode("utf-8"))
        if not isinstance(value, dict):
            raise TypeError("Approved Host authority request must be a JSON object")
        return value

    def _write_message(
        self, pipe: wintypes.HANDLE, response: Mapping[str, Any]
    ) -> None:
        data = canonical_json(dict(response)).encode("utf-8")
        if len(data) > _MAX_PIPE_MESSAGE_BYTES:
            raise RuntimeError("Approved Host authority response exceeds the IPC bound")
        buffer = ctypes.create_string_buffer(data)
        written = wintypes.DWORD()
        if not _kernel32.WriteFile(
            pipe, buffer, len(data), ctypes.byref(written), None
        ):
            raise _winerror("WriteFile(Approved Host authority server)")
        if int(written.value) != len(data):
            raise RuntimeError("Approved Host authority response write was partial")

    def handle_request(
        self, client_pid: int, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        if request.get("protocol_version") != APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION:
            raise RuntimeError("Approved Host authority protocol version mismatch")
        client_sid, elevated = _process_token_details(client_pid)
        if client_sid.casefold() != self.runtime_sid.casefold():
            raise PermissionError(
                "Approved Host authority client SID is not the configured runtime user"
            )
        if elevated:
            raise PermissionError(
                "Approved Host authority requires a non-elevated requester token"
            )

        action = str(request.get("action") or "")
        if action == "probe":
            active = self.store.read_active()
            return {
                "protocol_version": APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION,
                "ok": True,
                "healthy": active is None,
                "service_epoch": self.service_epoch,
                "active_operation_id": active.get("operation_id") if active else None,
                "recovery_reason": active.get("recovery_reason") if active else None,
            }
        if action == "launch":
            return self._launch(client_pid, request)
        if action == "cancel":
            return self._cancel(request)
        raise ValueError("unknown Approved Host authority action")

    def _launch(
        self, client_pid: int, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        requester_pid = int(request.get("requester_pid") or 0)
        if requester_pid != client_pid:
            raise PermissionError(
                "Approved Host authority requester PID does not match pipe peer"
            )
        requester_create_time = float(request.get("requester_create_time") or 0.0)
        actual_create_time = _requester_create_time(requester_pid)
        if abs(actual_create_time - requester_create_time) > 0.01:
            raise PermissionError(
                "Approved Host authority requester process identity changed"
            )

        operation_id = str(request.get("operation_id") or "")
        context_sha256 = str(request.get("context_sha256") or "")
        process_nonce = str(request.get("process_nonce") or "")
        if not operation_id or not context_sha256 or not process_nonce:
            raise ValueError("Approved Host authority launch request is incomplete")
        context_path = Path(str(request.get("context_path") or "")).resolve(strict=True)
        environment_value = request.get("worker_environment")
        if not isinstance(environment_value, dict):
            raise TypeError(
                "Approved Host authority worker environment must be an object"
            )
        worker_environment = {
            str(key): str(value) for key, value in environment_value.items()
        }
        if worker_environment.get("WINDOWS_LOCAL_MCP_JOB_NONCE") != process_nonce:
            raise PermissionError(
                "Approved Host authority worker nonce binding changed"
            )
        if (
            sum(len(key) + len(value) for key, value in worker_environment.items())
            > 256 * 1024
        ):
            raise ValueError(
                "Approved Host authority worker environment exceeds its bound"
            )

        if self.store.read_active() is not None:
            raise ApprovedHostRecoveryRequired(
                "a previous Approved Host authority state is still active; "
                "explicit recovery is required"
            )

        authority_nonce = secrets.token_hex(32)
        proof_path = authority_completion_path(
            self.store.root, operation_id, authority_nonce
        )
        self.store.arm(
            operation_id=operation_id,
            authority_nonce=authority_nonce,
            requester_pid=requester_pid,
            requester_create_time=requester_create_time,
            requester_sid=self.runtime_sid,
            context_sha256=context_sha256,
            proof_path=proof_path,
        )
        argv = _worker_bootstrap_argv(
            operation_id=operation_id,
            context_path=context_path,
            context_sha256=context_sha256,
            requester_pid=requester_pid,
            requester_create_time=requester_create_time,
            service_epoch=self.service_epoch,
            authority_nonce=authority_nonce,
            proof_path=proof_path,
        )
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creation_flags(),
                env=worker_environment,
            )
            identity = capture_process_identity(process.pid, process_nonce)
            authority_identity = AuthorityWorkerIdentity(
                pid=identity.pid,
                create_time=identity.create_time,
                executable=identity.executable,
            )
            self.store.mark_running(authority_identity)
        except Exception as error:
            self.store.mark_recovery_required(
                f"SYSTEM worker launch failed: {type(error).__name__}: {error}"
            )
            raise

        with self._workers_lock:
            self._workers[operation_id] = process
        watcher = threading.Thread(
            target=self._watch_worker,
            args=(operation_id, process, proof_path),
            name=f"wlmcp-approved-host-{operation_id}",
            daemon=True,
        )
        watcher.start()
        return {
            "protocol_version": APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION,
            "ok": True,
            "service_epoch": self.service_epoch,
            "worker": {
                "pid": authority_identity.pid,
                "create_time": authority_identity.create_time,
                "executable": authority_identity.executable,
            },
        }

    def _watch_worker(
        self,
        operation_id: str,
        process: subprocess.Popen[Any],
        proof_path: Path,
    ) -> None:
        exit_code = process.wait()
        try:
            if proof_path.exists():
                self.store.consume_completion(proof_path)
            else:
                self.store.mark_recovery_required(
                    "SYSTEM worker exited without an authority completion proof",
                    worker_exit_code=exit_code,
                )
        except Exception as error:  # noqa: BLE001 - uncertainty stays latched
            self.store.mark_recovery_required(
                "authority completion verification failed: "
                f"{type(error).__name__}: {error}",
                worker_exit_code=exit_code,
            )
        finally:
            with self._workers_lock:
                self._workers.pop(operation_id, None)

    def _cancel(self, request: Mapping[str, Any]) -> dict[str, Any]:
        operation_id = str(request.get("operation_id") or "")
        active = self.store.read_active()
        if active is None or active.get("operation_id") != operation_id:
            raise RuntimeError(
                "Approved Host authority has no matching active operation"
            )
        with self._workers_lock:
            process = self._workers.get(operation_id)
        if process is None:
            self.store.mark_recovery_required(
                "cancellation requested after worker identity was lost"
            )
            raise ApprovedHostRecoveryRequired(
                "Approved Host worker identity was lost; explicit recovery is required"
            )
        handle = _kernel32.OpenProcess(_PROCESS_TERMINATE, False, process.pid)
        if not handle:
            self.store.mark_recovery_required(
                "cancellation could not open the SYSTEM worker"
            )
            raise _winerror("OpenProcess(PROCESS_TERMINATE SYSTEM worker)")
        try:
            process.terminate()
        finally:
            _kernel32.CloseHandle(handle)
        self.store.mark_recovery_required(
            "operator cancellation terminated the SYSTEM worker; "
            "postflight completion was not proven"
        )
        return {
            "protocol_version": APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION,
            "ok": True,
            "status": "recovery_required",
        }


class _WindowsServiceHost:
    def __init__(
        self, server_factory: Callable[[], ApprovedHostAuthorityServer]
    ) -> None:
        self.server_factory = server_factory
        self.server: ApprovedHostAuthorityServer | None = None
        self.status_handle = wintypes.HANDLE()
        self.stop_event = threading.Event()
        self._handler_callback = _HANDLER_FUNCTION(self._handler)
        self._main_callback = _SERVICE_MAIN_FUNCTION(self._service_main)

    def run(self) -> None:
        table = (_SERVICE_TABLE_ENTRY * 2)()
        table[0].lpServiceName = APPROVED_HOST_AUTHORITY_SERVICE_NAME
        table[0].lpServiceProc = self._main_callback
        table[1].lpServiceName = None
        table[1].lpServiceProc = _SERVICE_MAIN_FUNCTION()
        if not _advapi32.StartServiceCtrlDispatcherW(table):
            raise _winerror("StartServiceCtrlDispatcherW")

    def _set_status(
        self,
        state: int,
        *,
        controls: int = 0,
        win32_exit: int = 0,
        wait_hint: int = 0,
    ) -> None:
        status = _SERVICE_STATUS(
            dwServiceType=_SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState=state,
            dwControlsAccepted=controls,
            dwWin32ExitCode=win32_exit,
            dwServiceSpecificExitCode=0,
            dwCheckPoint=0,
            dwWaitHint=wait_hint,
        )
        if not _advapi32.SetServiceStatus(
            self.status_handle, ctypes.byref(status)
        ):
            raise _winerror("SetServiceStatus")

    def _service_main(
        self,
        _argc: int,
        _argv: ctypes.POINTER(wintypes.LPWSTR),
    ) -> None:
        self.status_handle = _advapi32.RegisterServiceCtrlHandlerExW(
            APPROVED_HOST_AUTHORITY_SERVICE_NAME,
            self._handler_callback,
            None,
        )
        if not self.status_handle:
            return
        try:
            self._set_status(_SERVICE_START_PENDING, wait_hint=10000)
            self.server = self.server_factory()
            thread = threading.Thread(
                target=self.server.serve,
                name="wlmcp-approved-host-pipe",
                daemon=True,
            )
            thread.start()
            self._set_status(
                _SERVICE_RUNNING,
                controls=_SERVICE_ACCEPT_STOP | _SERVICE_ACCEPT_SHUTDOWN,
            )
            self.stop_event.wait()
            self._set_status(_SERVICE_STOP_PENDING, wait_hint=10000)
            self.server.close()
            thread.join(timeout=10)
            self._set_status(_SERVICE_STOPPED)
        except Exception:
            try:
                self._set_status(_SERVICE_STOPPED, win32_exit=1)
            except Exception:
                pass

    def _handler(
        self,
        control: int,
        _event_type: int,
        _event_data: ctypes.c_void_p,
        _context: ctypes.c_void_p,
    ) -> int:
        if control in {_SERVICE_CONTROL_STOP, _SERVICE_CONTROL_SHUTDOWN}:
            self.stop_event.set()
            if self.server is not None:
                self.server.wake()
        return _NO_ERROR


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-sid", required=True)
    parser.add_argument(
        "--state-root", type=Path, default=default_authority_state_root()
    )
    parser.add_argument("--console", action="store_true")
    args = parser.parse_args()

    def factory() -> ApprovedHostAuthorityServer:
        return ApprovedHostAuthorityServer(
            runtime_sid=args.runtime_sid,
            state_root=args.state_root,
        )

    if args.console:
        server = factory()
        try:
            server.serve()
        finally:
            server.close()
        return
    _WindowsServiceHost(factory).run()


if __name__ == "__main__":
    main()
