from __future__ import annotations

import ctypes
import os
import stat
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping

from .approved_host_authority import (
    APPROVED_HOST_AUTHORITY_SERVICE_NAME,
    APPROVED_HOST_AUTHORITY_STATE_VERSION,
    ApprovedHostRecoveryRequired,
    AuthorityStateStore,
    AuthorityWorkerIdentity,
    _read_json_object,
    _reject_unsafe_state_path,
    _write_json_exclusive,
)
from .util import canonical_json, utc_now_iso

_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_SE_DACL_PROTECTED = 0x1000
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPE = 1
_INHERITED_ACE = 0x10
_SERVICE_QUERY_STATUS = 0x0004
_READ_CONTROL = 0x00020000


if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SC_MANAGER_CONNECT = 0x0001

    class _ACL(ctypes.Structure):
        _fields_ = [
            ("AclRevision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
        ]

    class _ACCESS_ACE_PREFIX(ctypes.Structure):
        _fields_ = [
            ("Header", _ACE_HEADER),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    _advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_ACL)),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    _advapi32.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    _advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    _advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.POINTER(_ACL)),
        ctypes.POINTER(wintypes.BOOL),
    ]
    _advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    _advapi32.GetAce.argtypes = [
        ctypes.POINTER(_ACL),
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetAce.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
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
    _advapi32.QueryServiceObjectSecurity.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _advapi32.QueryServiceObjectSecurity.restype = wintypes.BOOL
    _advapi32.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    _advapi32.CloseServiceHandle.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p


def _winerror(action: str) -> RuntimeError:
    return RuntimeError(f"{action} failed: WinError {ctypes.get_last_error()}")


def _sid_string(pointer: ctypes.c_void_p) -> str:
    value = wintypes.LPWSTR()
    if not _advapi32.ConvertSidToStringSidW(pointer, ctypes.byref(value)):
        raise _winerror("ConvertSidToStringSidW")
    try:
        return str(value.value)
    finally:
        _kernel32.LocalFree(value)


def _descriptor_acl_records(
    descriptor: ctypes.c_void_p,
    *,
    owner_pointer: ctypes.c_void_p,
    dacl: ctypes.POINTER(_ACL),
) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not _advapi32.GetSecurityDescriptorControl(
        descriptor,
        ctypes.byref(control),
        ctypes.byref(revision),
    ):
        raise _winerror("GetSecurityDescriptorControl")
    if not dacl:
        raise RuntimeError("security descriptor has a null DACL")
    records: list[tuple[int, int, int, str]] = []
    for index in range(int(dacl.contents.AceCount)):
        ace_pointer = ctypes.c_void_p()
        if not _advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
            raise _winerror("GetAce")
        prefix = ctypes.cast(
            ace_pointer,
            ctypes.POINTER(_ACCESS_ACE_PREFIX),
        ).contents
        sid_pointer = ctypes.c_void_p(
            int(ace_pointer.value) + _ACCESS_ACE_PREFIX.SidStart.offset
        )
        records.append(
            (
                int(prefix.Header.AceType),
                int(prefix.Header.AceFlags),
                int(prefix.Mask),
                _sid_string(sid_pointer),
            )
        )
    return (
        _sid_string(owner_pointer),
        bool(int(control.value) & _SE_DACL_PROTECTED),
        records,
    )


def _path_security(path: Path) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    if os.name != "nt":
        raise RuntimeError("Approved Host security descriptors require native Windows")
    owner = ctypes.c_void_p()
    dacl = ctypes.POINTER(_ACL)()
    descriptor = ctypes.c_void_p()
    error = _advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if error != 0 or not descriptor:
        raise RuntimeError(f"GetNamedSecurityInfoW failed for {path}: {error}")
    try:
        return _descriptor_acl_records(
            descriptor,
            owner_pointer=owner,
            dacl=dacl,
        )
    finally:
        _kernel32.LocalFree(descriptor)


def _service_security() -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    if os.name != "nt":
        raise RuntimeError("Approved Host service security requires native Windows")
    manager = _advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not manager:
        raise _winerror("OpenSCManagerW")
    service = wintypes.HANDLE()
    try:
        service = _advapi32.OpenServiceW(
            manager,
            APPROVED_HOST_AUTHORITY_SERVICE_NAME,
            _READ_CONTROL,
        )
        if not service:
            raise _winerror("OpenServiceW(READ_CONTROL)")
        needed = wintypes.DWORD()
        _advapi32.QueryServiceObjectSecurity(
            service,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            None,
            0,
            ctypes.byref(needed),
        )
        if not needed.value:
            raise _winerror("QueryServiceObjectSecurity(size)")
        buffer = ctypes.create_string_buffer(needed.value)
        if not _advapi32.QueryServiceObjectSecurity(
            service,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            buffer,
            len(buffer),
            ctypes.byref(needed),
        ):
            raise _winerror("QueryServiceObjectSecurity")
        descriptor = ctypes.cast(buffer, ctypes.c_void_p)
        owner = ctypes.c_void_p()
        owner_defaulted = wintypes.BOOL()
        if not _advapi32.GetSecurityDescriptorOwner(
            descriptor,
            ctypes.byref(owner),
            ctypes.byref(owner_defaulted),
        ):
            raise _winerror("GetSecurityDescriptorOwner")
        dacl = ctypes.POINTER(_ACL)()
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        if not _advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ) or not present.value:
            raise RuntimeError("Approved Host service has no DACL")
        return _descriptor_acl_records(
            descriptor,
            owner_pointer=owner,
            dacl=dacl,
        )
    finally:
        if service:
            _advapi32.CloseServiceHandle(service)
        _advapi32.CloseServiceHandle(manager)


def _reject_reparse_ancestry(path: Path, *, stop: Path) -> None:
    current = path.absolute()
    stop = stop.absolute()
    while True:
        if current.exists():
            details = current.lstat()
            attributes = int(getattr(details, "st_file_attributes", 0))
            if current.is_symlink() or bool(
                attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise RuntimeError(
                    f"Approved Host authority path ancestry contains a reparse point: {current}"
                )
        if current == stop:
            return
        if current == Path(current.anchor):
            raise RuntimeError("Approved Host authority state escaped ProgramData")
        current = current.parent


def _assert_root_acl(path: Path) -> None:
    owner, protected, records = _path_security(path)
    if owner.casefold() != _SYSTEM_SID.casefold():
        raise PermissionError(
            f"Approved Host authority state owner is not LocalSystem: {path}: {owner}"
        )
    if not protected:
        raise PermissionError(
            f"Approved Host authority state DACL is not protected: {path}"
        )
    allowed = {_SYSTEM_SID.casefold(), _ADMINISTRATORS_SID.casefold()}
    seen: set[str] = set()
    for ace_type, ace_flags, _mask, sid in records:
        if ace_flags & _INHERITED_ACE:
            raise PermissionError(
                f"Approved Host authority root contains inherited ACEs: {path}"
            )
        if ace_type == _ACCESS_DENIED_ACE_TYPE:
            continue
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise PermissionError(
                f"Approved Host authority root contains unsupported ACE type {ace_type}: {path}"
            )
        folded = sid.casefold()
        if folded not in allowed:
            raise PermissionError(
                "Approved Host authority root grants access outside SYSTEM/Administrators: "
                f"{path}: {sid}"
            )
        seen.add(folded)
    if not allowed.issubset(seen):
        raise PermissionError(
            f"Approved Host authority root ACL is missing SYSTEM/Administrators: {path}"
        )


def assert_authority_state_security(root: Path) -> None:
    """Verify the protected ProgramData namespace and state-file identities."""
    if os.name != "nt":
        raise RuntimeError("Approved Host authority state security requires native Windows")
    program_data = Path(os.environ.get("PROGRAMDATA") or r"C:\ProgramData").absolute()
    root = Path(root).absolute()
    try:
        root.relative_to(program_data)
    except ValueError as error:
        raise PermissionError("Approved Host authority state must be below ProgramData") from error
    _reject_reparse_ancestry(root, stop=program_data)
    completed = root / "completed"
    for path in (root, completed):
        if not path.is_dir():
            raise RuntimeError(f"Approved Host authority directory is missing: {path}")
        _reject_unsafe_state_path(path, directory=True)
        _assert_root_acl(path)
    for child in root.iterdir():
        if child == completed:
            continue
        if child.is_dir():
            raise RuntimeError(
                f"Approved Host authority state contains an unexpected directory: {child}"
            )
        _reject_unsafe_state_path(child, directory=False)
    for child in completed.iterdir():
        _reject_unsafe_state_path(child, directory=False)


def assert_authority_service_security(runtime_sid: str) -> None:
    """Verify SCM DACL: runtime user gets query-status only; only SYSTEM/admin may mutate."""
    owner, protected, records = _service_security()
    if owner.casefold() not in {
        _SYSTEM_SID.casefold(),
        _ADMINISTRATORS_SID.casefold(),
    }:
        raise PermissionError(
            f"Approved Host authority service has unexpected owner: {owner}"
        )
    if not protected:
        raise PermissionError("Approved Host authority service DACL is not protected")
    expected_runtime = runtime_sid.casefold()
    privileged = {_SYSTEM_SID.casefold(), _ADMINISTRATORS_SID.casefold()}
    seen_runtime = False
    seen_privileged: set[str] = set()
    for ace_type, ace_flags, mask, sid in records:
        if ace_flags & _INHERITED_ACE:
            raise PermissionError("Approved Host authority service contains inherited ACEs")
        if ace_type == _ACCESS_DENIED_ACE_TYPE:
            continue
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise PermissionError(
                f"Approved Host authority service contains unsupported ACE type {ace_type}"
            )
        folded = sid.casefold()
        if folded in privileged:
            seen_privileged.add(folded)
            continue
        if folded == expected_runtime:
            if mask & ~_SERVICE_QUERY_STATUS:
                raise PermissionError(
                    "Approved Host runtime user has service rights beyond QUERY_STATUS"
                )
            if not (mask & _SERVICE_QUERY_STATUS):
                raise PermissionError(
                    "Approved Host runtime user lacks service QUERY_STATUS"
                )
            seen_runtime = True
            continue
        raise PermissionError(
            f"Approved Host authority service grants access to unexpected SID: {sid}"
        )
    if not privileged.issubset(seen_privileged) or not seen_runtime:
        raise PermissionError(
            "Approved Host authority service ACL is missing required principals"
        )


def _atomic_status_write(path: Path, payload: Mapping[str, Any]) -> None:
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


class HardenedAuthorityStateStore(AuthorityStateStore):
    """Production store with an immutable active latch and diagnostic sidecar status."""

    def __init__(self, root: Path, service_epoch: str) -> None:
        super().__init__(root, service_epoch)
        self.status_path = self.root / "active-status.json"

    def read_active(self) -> dict[str, Any] | None:
        active = super().read_active()
        if active is None:
            if self.status_path.exists():
                raise ApprovedHostRecoveryRequired(
                    "Approved Host authority status exists without its immutable active latch"
                )
            return None
        if self.status_path.exists():
            _reject_unsafe_state_path(self.status_path, directory=False)
            status = _read_json_object(self.status_path)
            for field in ("version", "operation_id", "service_epoch", "authority_nonce"):
                if status.get(field) != active.get(field):
                    raise ApprovedHostRecoveryRequired(
                        f"Approved Host authority status {field} binding mismatch"
                    )
            active = dict(active)
            for field in (
                "state",
                "worker_pid",
                "worker_create_time",
                "worker_executable",
                "worker_started_at",
                "recovery_reason",
                "recovery_required_at",
                "worker_exit_code",
            ):
                if field in status:
                    active[field] = status[field]
        return active

    @staticmethod
    def _status_payload(active: Mapping[str, Any], **fields: Any) -> dict[str, Any]:
        payload = {
            "version": APPROVED_HOST_AUTHORITY_STATE_VERSION,
            "operation_id": active["operation_id"],
            "service_epoch": active["service_epoch"],
            "authority_nonce": active["authority_nonce"],
        }
        payload.update(fields)
        return payload

    def mark_running(self, worker: AuthorityWorkerIdentity) -> dict[str, Any]:
        active = self.require_current_active()
        _atomic_status_write(
            self.status_path,
            self._status_payload(
                active,
                state="running",
                worker_pid=worker.pid,
                worker_create_time=worker.create_time,
                worker_executable=worker.executable,
                worker_started_at=utc_now_iso(),
            ),
        )
        return self.require_current_active()

    def mark_recovery_required(
        self,
        reason: str,
        *,
        worker_exit_code: int | None = None,
    ) -> None:
        active = self.read_active()
        if active is None:
            return
        fields: dict[str, Any] = {
            "state": "recovery_required",
            "recovery_reason": str(reason)[:2000],
            "recovery_required_at": utc_now_iso(),
        }
        if worker_exit_code is not None:
            fields["worker_exit_code"] = int(worker_exit_code)
        _atomic_status_write(
            self.status_path,
            self._status_payload(active, **fields),
        )

    def consume_completion(self, proof_path: Path) -> dict[str, Any]:
        active = self.require_current_active()
        _reject_unsafe_state_path(proof_path, directory=False)
        proof = _read_json_object(proof_path)
        for field in ("operation_id", "service_epoch", "authority_nonce"):
            if proof.get(field) != active.get(field):
                raise RuntimeError(
                    f"Approved Host completion proof {field} mismatch"
                )
        if proof.get("version") != APPROVED_HOST_AUTHORITY_STATE_VERSION:
            raise RuntimeError("Approved Host completion proof version mismatch")
        if not bool(proof.get("worker_returned_normally")):
            raise RuntimeError(
                "Approved Host worker did not prove normal return from the execution pipeline"
            )
        child_started = bool(proof.get("child_started"))
        postflight_verified = bool(proof.get("postflight_verified"))
        if child_started and not postflight_verified:
            raise RuntimeError(
                "Approved Host child completed without verified security postflight"
            )
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
        # Keep the immutable latch until every earlier cleanup step has completed.
        proof_path.unlink()
        self.status_path.unlink(missing_ok=True)
        self.active_path.unlink()
        return record
