from __future__ import annotations

import ctypes
import json
import os
import stat
import tempfile
import time
from collections.abc import Mapping
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import canonical_json, utc_now_iso

APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION = 1
APPROVED_HOST_AUTHORITY_SERVICE_NAME = "WindowsLocalMCPApprovedHost"
APPROVED_HOST_AUTHORITY_PIPE = r"\\.\pipe\WindowsLocalMCPApprovedHost-v1"
APPROVED_HOST_AUTHORITY_STATE_VERSION = 1
_MAX_PIPE_MESSAGE_BYTES = 1024 * 1024


class ApprovedHostAuthorityUnavailable(RuntimeError):
    """The independently privileged Approved Host authority is not usable."""


class ApprovedHostRecoveryRequired(RuntimeError):
    """A prior Approved Host operation lost its trusted completion path."""


@dataclass(frozen=True)
class AuthorityWorkerIdentity:
    pid: int
    create_time: float
    executable: str


@dataclass(frozen=True)
class AuthorityLaunchResult:
    worker: AuthorityWorkerIdentity
    service_epoch: str


@dataclass
class AuthorityWorkerLease:
    """Write a SYSTEM-only completion proof after trusted postflight finishes.

    The service arms its durable state before creating the worker. This lease is handed only
    to that SYSTEM worker. A graceful pre-launch rejection may clear the service latch, but
    once an Approved Host child has started only a verified security postflight may do so.
    """

    operation_id: str
    service_epoch: str
    authority_nonce: str
    proof_path: Path
    child_started: bool = False
    postflight_verified: bool = False

    def mark_child_started(self) -> None:
        self.child_started = True

    def mark_postflight_verified(self) -> None:
        self.postflight_verified = True

    def finalize(self, exit_code: int) -> None:
        if self.child_started and not self.postflight_verified:
            return
        payload = {
            "version": APPROVED_HOST_AUTHORITY_STATE_VERSION,
            "operation_id": self.operation_id,
            "service_epoch": self.service_epoch,
            "authority_nonce": self.authority_nonce,
            "child_started": self.child_started,
            "postflight_verified": self.postflight_verified,
            "worker_exit_code": int(exit_code),
            "completed_at": utc_now_iso(),
        }
        _write_json_exclusive(self.proof_path, payload)


class AuthorityStateStore:
    """SYSTEM-owned durable state for the Approved Host security authority."""

    def __init__(self, root: Path, service_epoch: str) -> None:
        self.root = Path(root)
        self.service_epoch = service_epoch
        self.active_path = self.root / "active.json"
        self.completed_root = self.root / "completed"

    def ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.completed_root.mkdir(parents=True, exist_ok=True)
        _reject_unsafe_state_path(self.root, directory=True)
        _reject_unsafe_state_path(self.completed_root, directory=True)

    def read_active(self) -> dict[str, Any] | None:
        self.ensure_root()
        if not self.active_path.exists():
            return None
        _reject_unsafe_state_path(self.active_path, directory=False)
        return _read_json_object(self.active_path)

    def arm(
        self,
        *,
        operation_id: str,
        authority_nonce: str,
        requester_pid: int,
        requester_create_time: float,
        requester_sid: str,
        context_sha256: str,
        proof_path: Path,
    ) -> dict[str, Any]:
        self.ensure_root()
        existing = self.read_active()
        if existing is not None:
            raise ApprovedHostRecoveryRequired(
                "a previous Approved Host authority state is still active; explicit recovery is required"
            )
        payload = {
            "version": APPROVED_HOST_AUTHORITY_STATE_VERSION,
            "state": "armed",
            "operation_id": operation_id,
            "service_epoch": self.service_epoch,
            "authority_nonce": authority_nonce,
            "requester_pid": int(requester_pid),
            "requester_create_time": float(requester_create_time),
            "requester_sid": requester_sid,
            "context_sha256": context_sha256,
            "proof_path": str(proof_path),
            "armed_at": utc_now_iso(),
            "recovery": "manual operator review required after abnormal authority loss",
        }
        _write_json_exclusive(self.active_path, payload)
        return payload

    def mark_running(self, worker: AuthorityWorkerIdentity) -> dict[str, Any]:
        active = self.require_current_active()
        active.update(
            {
                "state": "running",
                "worker_pid": worker.pid,
                "worker_create_time": worker.create_time,
                "worker_executable": worker.executable,
                "worker_started_at": utc_now_iso(),
            }
        )
        _atomic_replace_json(self.active_path, active)
        return active

    def mark_recovery_required(self, reason: str, *, worker_exit_code: int | None = None) -> None:
        active = self.read_active()
        if active is None:
            return
        active["state"] = "recovery_required"
        active["recovery_reason"] = str(reason)[:2000]
        active["recovery_required_at"] = utc_now_iso()
        if worker_exit_code is not None:
            active["worker_exit_code"] = int(worker_exit_code)
        _atomic_replace_json(self.active_path, active)

    def require_current_active(self) -> dict[str, Any]:
        active = self.read_active()
        if active is None:
            raise RuntimeError("Approved Host authority active state disappeared")
        if active.get("version") != APPROVED_HOST_AUTHORITY_STATE_VERSION:
            raise RuntimeError("Approved Host authority active state version changed")
        if active.get("service_epoch") != self.service_epoch:
            raise ApprovedHostRecoveryRequired(
                "Approved Host authority state belongs to an earlier service epoch"
            )
        return active

    def consume_completion(self, proof_path: Path) -> dict[str, Any]:
        active = self.require_current_active()
        _reject_unsafe_state_path(proof_path, directory=False)
        proof = _read_json_object(proof_path)
        for field in ("operation_id", "service_epoch", "authority_nonce"):
            if proof.get(field) != active.get(field):
                raise RuntimeError(f"Approved Host completion proof {field} mismatch")
        if proof.get("version") != APPROVED_HOST_AUTHORITY_STATE_VERSION:
            raise RuntimeError("Approved Host completion proof version mismatch")
        child_started = bool(proof.get("child_started"))
        postflight_verified = bool(proof.get("postflight_verified"))
        if child_started and not postflight_verified:
            raise RuntimeError("Approved Host child completed without verified security postflight")

        archive = self.completed_root / (
            f"{active['operation_id']}-{active['authority_nonce']}.json"
        )
        record = {
            "version": APPROVED_HOST_AUTHORITY_STATE_VERSION,
            "state": "completed",
            "active": active,
            "proof": proof,
            "archived_at": utc_now_iso(),
        }
        _write_json_exclusive(archive, record)
        self.active_path.unlink()
        proof_path.unlink()
        return record


def default_authority_state_root() -> Path:
    program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    return Path(program_data) / "WindowsLocalMCP" / "ApprovedHostAuthority"


def authority_completion_path(root: Path, operation_id: str, authority_nonce: str) -> Path:
    safe_operation = _safe_component(operation_id, "operation id")
    safe_nonce = _safe_component(authority_nonce, "authority nonce")
    return Path(root) / f"completion-{safe_operation}-{safe_nonce}.json"


def _safe_component(value: str, label: str) -> str:
    if not value or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in value):
        raise ValueError(f"invalid {label}")
    return value


def _reject_unsafe_state_path(path: Path, *, directory: bool) -> None:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    if path.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise RuntimeError(f"Approved Host authority state path is a reparse point: {path}")
    if directory:
        if not path.is_dir():
            raise RuntimeError(f"Approved Host authority state path is not a directory: {path}")
        return
    if not path.is_file() or details.st_nlink != 1:
        raise RuntimeError(f"Approved Host authority state file has unsafe identity: {path}")


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Approved Host authority state is not an object: {path}")
    return value


def _write_json_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_json(dict(payload)).encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _atomic_replace_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=path.parent) as output:
            output.write(canonical_json(dict(payload)).encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _OPEN_EXISTING = 3
    _PIPE_READMODE_MESSAGE = 0x00000002
    _ERROR_PIPE_BUSY = 231
    _ERROR_MORE_DATA = 234
    _SC_MANAGER_CONNECT = 0x0001
    _SERVICE_QUERY_STATUS = 0x0004
    _SC_STATUS_PROCESS_INFO = 0
    _SERVICE_RUNNING = 4

    class _SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwServiceFlags", wintypes.DWORD),
        ]

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
    _kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    _kernel32.SetNamedPipeHandleState.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _kernel32.SetNamedPipeHandleState.restype = wintypes.BOOL
    _kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.GetNamedPipeServerProcessId.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _advapi32.OpenSCManagerW.restype = wintypes.HANDLE
    _advapi32.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    _advapi32.OpenServiceW.restype = wintypes.HANDLE
    _advapi32.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
    _advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    _advapi32.CloseServiceHandle.restype = wintypes.BOOL


def _winerror(action: str) -> ApprovedHostAuthorityUnavailable:
    return ApprovedHostAuthorityUnavailable(f"{action} failed: WinError {ctypes.get_last_error()}")


def _service_process_id() -> int:
    if os.name != "nt":
        raise ApprovedHostAuthorityUnavailable("Approved Host authority requires native Windows")
    manager = _advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise _winerror("OpenSCManagerW")
    service = wintypes.HANDLE()
    try:
        service = _advapi32.OpenServiceW(
            manager,
            APPROVED_HOST_AUTHORITY_SERVICE_NAME,
            _SERVICE_QUERY_STATUS,
        )
        if not service:
            raise _winerror("OpenServiceW")
        status = _SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        if not _advapi32.QueryServiceStatusEx(
            service,
            _SC_STATUS_PROCESS_INFO,
            ctypes.byref(status),
            ctypes.sizeof(status),
            ctypes.byref(needed),
        ):
            raise _winerror("QueryServiceStatusEx")
        if status.dwCurrentState != _SERVICE_RUNNING or not status.dwProcessId:
            raise ApprovedHostAuthorityUnavailable("Approved Host authority service is not running")
        return int(status.dwProcessId)
    finally:
        if service:
            _advapi32.CloseServiceHandle(service)
        _advapi32.CloseServiceHandle(manager)


def _open_verified_pipe(timeout_ms: int = 5000) -> wintypes.HANDLE:
    if os.name != "nt":
        raise ApprovedHostAuthorityUnavailable("Approved Host authority requires native Windows")
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
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
            mode = wintypes.DWORD(_PIPE_READMODE_MESSAGE)
            if not _kernel32.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None):
                _kernel32.CloseHandle(handle)
                raise _winerror("SetNamedPipeHandleState")
            server_pid = wintypes.DWORD()
            if not _kernel32.GetNamedPipeServerProcessId(handle, ctypes.byref(server_pid)):
                _kernel32.CloseHandle(handle)
                raise _winerror("GetNamedPipeServerProcessId")
            expected_pid = _service_process_id()
            if int(server_pid.value) != expected_pid:
                _kernel32.CloseHandle(handle)
                raise ApprovedHostAuthorityUnavailable(
                    "Approved Host authority pipe is not owned by the configured SCM service"
                )
            return handle
        error = ctypes.get_last_error()
        if error != _ERROR_PIPE_BUSY or time.monotonic() >= deadline:
            raise _winerror("CreateFileW(Approved Host authority pipe)")
        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
        if (
            not _kernel32.WaitNamedPipeW(APPROVED_HOST_AUTHORITY_PIPE, remaining_ms)
            and time.monotonic() >= deadline
        ):
            raise _winerror("WaitNamedPipeW")


def _write_pipe_message(handle: wintypes.HANDLE, payload: Mapping[str, Any]) -> None:
    data = canonical_json(dict(payload)).encode("utf-8")
    if len(data) > _MAX_PIPE_MESSAGE_BYTES:
        raise ValueError("Approved Host authority request exceeds the IPC bound")
    buffer = ctypes.create_string_buffer(data)
    written = wintypes.DWORD()
    if not _kernel32.WriteFile(
        handle,
        buffer,
        len(data),
        ctypes.byref(written),
        None,
    ):
        raise _winerror("WriteFile(Approved Host authority pipe)")
    if int(written.value) != len(data):
        raise ApprovedHostAuthorityUnavailable("Approved Host authority request write was partial")


def _read_pipe_message(handle: wintypes.HANDLE) -> dict[str, Any]:
    chunks: list[bytes] = []
    total = 0
    while True:
        buffer = ctypes.create_string_buffer(64 * 1024)
        read = wintypes.DWORD()
        ctypes.set_last_error(0)
        ok = _kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None)
        if read.value:
            chunk = bytes(buffer.raw[: read.value])
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_PIPE_MESSAGE_BYTES:
                raise ApprovedHostAuthorityUnavailable(
                    "Approved Host authority response exceeds the IPC bound"
                )
        if ok:
            break
        if ctypes.get_last_error() != _ERROR_MORE_DATA:
            raise _winerror("ReadFile(Approved Host authority pipe)")
    value = json.loads(b"".join(chunks).decode("utf-8"))
    if not isinstance(value, dict):
        raise ApprovedHostAuthorityUnavailable("Approved Host authority response is not an object")
    return value


def _authority_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    handle = _open_verified_pipe()
    try:
        request = dict(payload)
        request["protocol_version"] = APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION
        _write_pipe_message(handle, request)
        response = _read_pipe_message(handle)
    finally:
        _kernel32.CloseHandle(handle)
    if response.get("protocol_version") != APPROVED_HOST_AUTHORITY_PROTOCOL_VERSION:
        raise ApprovedHostAuthorityUnavailable("Approved Host authority protocol version mismatch")
    if not bool(response.get("ok")):
        error_type = str(response.get("error_type") or "RuntimeError")
        message = str(response.get("error") or "Approved Host authority request failed")
        if error_type == "ApprovedHostRecoveryRequired":
            raise ApprovedHostRecoveryRequired(message)
        raise ApprovedHostAuthorityUnavailable(message)
    return response


class ApprovedHostAuthorityClient:
    def probe(self) -> dict[str, Any]:
        return _authority_request({"action": "probe"})

    def assert_available(self) -> dict[str, Any]:
        response = self.probe()
        if not bool(response.get("healthy")):
            raise ApprovedHostRecoveryRequired(
                str(response.get("recovery_reason") or "Approved Host authority requires recovery")
            )
        return response

    def launch(
        self,
        *,
        operation_id: str,
        context_path: Path,
        context_sha256: str,
        process_nonce: str,
        worker_environment: Mapping[str, str],
        requester_pid: int,
        requester_create_time: float,
    ) -> AuthorityLaunchResult:
        response = _authority_request(
            {
                "action": "launch",
                "operation_id": operation_id,
                "context_path": str(context_path),
                "context_sha256": context_sha256,
                "process_nonce": process_nonce,
                "worker_environment": dict(worker_environment),
                "requester_pid": int(requester_pid),
                "requester_create_time": float(requester_create_time),
            }
        )
        worker = response.get("worker")
        if not isinstance(worker, dict):
            raise ApprovedHostAuthorityUnavailable("Approved Host authority returned no worker identity")
        return AuthorityLaunchResult(
            worker=AuthorityWorkerIdentity(
                pid=int(worker["pid"]),
                create_time=float(worker["create_time"]),
                executable=str(worker["executable"]),
            ),
            service_epoch=str(response["service_epoch"]),
        )
