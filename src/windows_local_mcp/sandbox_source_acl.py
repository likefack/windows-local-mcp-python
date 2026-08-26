from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path

SOURCE_WORKSPACE_READ_GUARD_VERSION = "wlmcp-source-workspace-read-deny-v1"

_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_DENY_ACCESS = 3
_TRUSTEE_IS_SID = 0
_TRUSTEE_IS_UNKNOWN = 0
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_INHERIT_ONLY_ACE = 0x08
_INHERITED_ACE = 0x10
_ACCESS_DENIED_ACE_TYPE = 0x01
_FILE_GENERIC_READ = 0x00120089
_FILE_GENERIC_WRITE = 0x00120116
_FILE_GENERIC_EXECUTE = 0x001200A0
_FILE_ALL_ACCESS = 0x001F01FF
_GENERIC_READ = 0x80000000
_ERROR_SUCCESS = 0
_ACL_SIZE_INFORMATION = 2


class SourceWorkspaceAclError(RuntimeError):
    """The source-workspace read-deny ACL is absent, inconsistent, or unavailable."""


@dataclass(frozen=True)
class SourceWorkspaceReadGuard:
    version: str
    workspace_root: str
    target_sid: str
    explicit_deny_read: bool
    inheritable_to_files: bool
    inheritable_to_directories: bool
    added: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", wintypes.BYTE),
        ("AceFlags", wintypes.BYTE),
        ("AceSize", wintypes.WORD),
    ]


class _AccessDeniedAce(ctypes.Structure):
    _fields_ = [
        ("Header", _AceHeader),
        ("Mask", wintypes.DWORD),
        ("SidStart", wintypes.DWORD),
    ]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


class _GenericMapping(ctypes.Structure):
    _fields_ = [
        ("GenericRead", wintypes.DWORD),
        ("GenericWrite", wintypes.DWORD),
        ("GenericExecute", wintypes.DWORD),
        ("GenericAll", wintypes.DWORD),
    ]


class _TrusteeW(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", ctypes.c_void_p),
        ("MultipleTrusteeOperation", wintypes.DWORD),
        ("TrusteeForm", wintypes.DWORD),
        ("TrusteeType", wintypes.DWORD),
        ("ptstrName", wintypes.LPWSTR),
    ]


class _ExplicitAccessW(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", wintypes.DWORD),
        ("grfAccessMode", wintypes.DWORD),
        ("grfInheritance", wintypes.DWORD),
        ("Trustee", _TrusteeW),
    ]


def ensure_source_workspace_read_deny(
    workspace_root: Path, target_sid: str
) -> dict[str, object]:
    """Persist an inheritable read-deny for the fixed Codex offline account.

    The deny is intentionally persistent. A worker crash must not reopen the original
    source workspace to a later Sandbox process. The trusted Windows user remains
    unaffected because the ACE targets only the dedicated Sandbox account SID.
    """

    workspace = workspace_root.resolve(strict=True)
    if not workspace.is_dir():
        raise SourceWorkspaceAclError("source workspace root is not a directory")
    if not target_sid.startswith("S-1-"):
        raise SourceWorkspaceAclError("Sandbox account SID is invalid")

    state = _inspect_source_workspace_read_deny(workspace, target_sid)
    added = False
    if not _state_satisfies_guard(state):
        _apply_source_workspace_read_deny(workspace, target_sid)
        added = True
        state = _inspect_source_workspace_read_deny(workspace, target_sid)
    if not _state_satisfies_guard(state):
        raise SourceWorkspaceAclError(
            "source workspace read-deny ACL did not converge after update"
        )
    return SourceWorkspaceReadGuard(
        version=SOURCE_WORKSPACE_READ_GUARD_VERSION,
        workspace_root=str(workspace),
        target_sid=target_sid,
        explicit_deny_read=state.explicit_deny_read,
        inheritable_to_files=state.inheritable_to_files,
        inheritable_to_directories=state.inheritable_to_directories,
        added=added,
    ).as_dict()


@dataclass(frozen=True)
class _ReadDenyState:
    explicit_deny_read: bool
    inheritable_to_files: bool
    inheritable_to_directories: bool


def _state_satisfies_guard(state: _ReadDenyState) -> bool:
    return (
        state.explicit_deny_read
        and state.inheritable_to_files
        and state.inheritable_to_directories
    )


def _windows_apis() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    if os.name != "nt":
        raise SourceWorkspaceAclError("source workspace ACL guard requires native Windows")
    return (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
    )


def _convert_sid(advapi32: ctypes.WinDLL, sid: str) -> ctypes.c_void_p:
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    pointer = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW(sid, ctypes.byref(pointer)) or not pointer:
        raise SourceWorkspaceAclError(
            f"ConvertStringSidToSidW failed: WinError {ctypes.get_last_error()}"
        )
    return pointer


def _read_dacl(
    advapi32: ctypes.WinDLL, path: Path
) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    code = advapi32.GetNamedSecurityInfoW(
        ctypes.c_wchar_p(str(path)),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if code != _ERROR_SUCCESS or not dacl:
        raise SourceWorkspaceAclError(
            f"GetNamedSecurityInfoW failed for source workspace: {int(code)}"
        )
    return dacl, security_descriptor


def _mapped_file_read_mask(advapi32: ctypes.WinDLL, raw_mask: int) -> int:
    advapi32.MapGenericMask.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_GenericMapping),
    ]
    advapi32.MapGenericMask.restype = None
    mask = wintypes.DWORD(raw_mask)
    mapping = _GenericMapping(
        GenericRead=_FILE_GENERIC_READ,
        GenericWrite=_FILE_GENERIC_WRITE,
        GenericExecute=_FILE_GENERIC_EXECUTE,
        GenericAll=_FILE_ALL_ACCESS,
    )
    advapi32.MapGenericMask(ctypes.byref(mask), ctypes.byref(mapping))
    return int(mask.value)


def _inspect_source_workspace_read_deny(
    workspace: Path, target_sid: str
) -> _ReadDenyState:
    advapi32, kernel32 = _windows_apis()
    target = _convert_sid(advapi32, target_sid)
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    try:
        dacl, security_descriptor = _read_dacl(advapi32, workspace)
        advapi32.GetAclInformation.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_int,
        ]
        advapi32.GetAclInformation.restype = wintypes.BOOL
        advapi32.GetAce.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.GetAce.restype = wintypes.BOOL
        advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        advapi32.EqualSid.restype = wintypes.BOOL

        info = _AclSizeInformation()
        if not advapi32.GetAclInformation(
            dacl,
            ctypes.byref(info),
            ctypes.sizeof(info),
            _ACL_SIZE_INFORMATION,
        ):
            raise SourceWorkspaceAclError(
                f"GetAclInformation failed: WinError {ctypes.get_last_error()}"
            )

        for index in range(int(info.AceCount)):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer)):
                continue
            header = ctypes.cast(ace_pointer, ctypes.POINTER(_AceHeader)).contents
            if header.AceType != _ACCESS_DENIED_ACE_TYPE:
                continue
            if header.AceFlags & (_INHERIT_ONLY_ACE | _INHERITED_ACE):
                continue
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessDeniedAce)).contents
            sid_pointer = ctypes.c_void_p(
                int(ace_pointer.value) + _AccessDeniedAce.SidStart.offset
            )
            if not advapi32.EqualSid(sid_pointer, target):
                continue
            mapped_mask = _mapped_file_read_mask(advapi32, int(ace.Mask))
            if (mapped_mask & _FILE_GENERIC_READ) != _FILE_GENERIC_READ:
                continue
            return _ReadDenyState(
                explicit_deny_read=True,
                inheritable_to_files=bool(header.AceFlags & _OBJECT_INHERIT_ACE),
                inheritable_to_directories=bool(
                    header.AceFlags & _CONTAINER_INHERIT_ACE
                ),
            )
        return _ReadDenyState(False, False, False)
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)
        if target:
            kernel32.LocalFree(target)


def _apply_source_workspace_read_deny(workspace: Path, target_sid: str) -> None:
    advapi32, kernel32 = _windows_apis()
    target = _convert_sid(advapi32, target_sid)
    dacl = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    new_dacl = ctypes.c_void_p()
    try:
        dacl, security_descriptor = _read_dacl(advapi32, workspace)
        advapi32.SetEntriesInAclW.argtypes = [
            wintypes.ULONG,
            ctypes.POINTER(_ExplicitAccessW),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.SetEntriesInAclW.restype = wintypes.DWORD
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            ctypes.c_int,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

        explicit = _ExplicitAccessW()
        explicit.grfAccessPermissions = _FILE_GENERIC_READ | _GENERIC_READ
        explicit.grfAccessMode = _DENY_ACCESS
        explicit.grfInheritance = _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE
        explicit.Trustee = _TrusteeW(
            pMultipleTrustee=None,
            MultipleTrusteeOperation=0,
            TrusteeForm=_TRUSTEE_IS_SID,
            TrusteeType=_TRUSTEE_IS_UNKNOWN,
            ptstrName=ctypes.cast(target, wintypes.LPWSTR),
        )
        code = advapi32.SetEntriesInAclW(
            1,
            ctypes.byref(explicit),
            dacl,
            ctypes.byref(new_dacl),
        )
        if code != _ERROR_SUCCESS or not new_dacl:
            raise SourceWorkspaceAclError(
                f"SetEntriesInAclW failed for source workspace: {int(code)}"
            )
        code = advapi32.SetNamedSecurityInfoW(
            ctypes.c_wchar_p(str(workspace)),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            new_dacl,
            None,
        )
        if code != _ERROR_SUCCESS:
            raise SourceWorkspaceAclError(
                f"SetNamedSecurityInfoW failed for source workspace: {int(code)}"
            )
    finally:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if new_dacl:
            kernel32.LocalFree(new_dacl)
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)
        if target:
            kernel32.LocalFree(target)
