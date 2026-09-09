"""固定 WFP object の読み取り権限を管理者が明示的に設定する。"""

from __future__ import annotations

import ctypes
import struct
from collections.abc import Iterator
from contextlib import contextmanager

from .wfp_guard import (
    APP_ISOLATION_SUBLAYER_KEY,
    GUARD_SUBLAYER_KEY,
    GUARD_V4_FILTER_KEY,
    GUARD_V6_FILTER_KEY,
    WfpGuardError,
    ensure_codex_loopback_block,
    verify_codex_loopback_block,
)
from .windows_wfp import WindowsWfpApi, _Guid

# Windows SDK fwpmu.h。0x1 は ADD であり、READ ではない。
_FWPM_ACTRL_READ = 0x80
_DACL_INFORMATION = 4
_OWNER_GROUP_DACL_INFORMATION = 7
_FIXED_OBJECTS = (
    ("SubLayer", APP_ISOLATION_SUBLAYER_KEY),
    ("SubLayer", GUARD_SUBLAYER_KEY),
    ("Filter", GUARD_V4_FILTER_KEY),
    ("Filter", GUARD_V6_FILTER_KEY),
)


def _acl_entries(raw: bytes) -> tuple[int, tuple[bytes, ...]]:
    """ACE の内容・順序を変更せず、ACL の使用部分だけを取り出す。"""
    if len(raw) < 8:
        raise WfpGuardError("Truncated WFP ACL")
    revision, _, size, count, _ = struct.unpack_from("<BBHHH", raw)
    if revision not in (2, 4) or size != len(raw):
        raise WfpGuardError("Invalid WFP ACL header")
    offset = 8
    entries = []
    for _ in range(count):
        if offset + 4 > size:
            raise WfpGuardError("Truncated WFP ACE header")
        ace_size = struct.unpack_from("<H", raw, offset + 2)[0]
        if ace_size < 4 or ace_size % 4 or offset + ace_size > size:
            raise WfpGuardError("Invalid WFP ACE size")
        entries.append(raw[offset:offset + ace_size])
        offset += ace_size
    return revision, tuple(entries)


def _with_read_ace(raw: bytes, sid: bytes) -> bytes:
    revision, entries = _acl_entries(raw)
    if len(sid) < 8 or sid[0] != 1 or len(sid) != 8 + 4 * sid[1]:
        raise WfpGuardError("Invalid operator SID")
    # ACCESS_ALLOWED_ACE、継承なし、FWPM_ACTRL_READ だけを追加する。
    ace = struct.pack("<BBHI", 0, 0, 8 + len(sid), _FWPM_ACTRL_READ) + sid
    if ace in entries:
        return raw
    updated = list(entries)
    index = next((i for i, item in enumerate(updated) if item[1] & 0x10), len(updated))
    updated.insert(index, ace)
    body = b"".join(updated)
    if len(body) + 8 > 65535 or len(updated) > 65535:
        raise WfpGuardError("WFP ACL cannot fit the read-only ACE")
    return struct.pack("<BBHHH", revision, 0, len(body) + 8, len(updated), 0) + body


class _ReadAccessApi:
    def __init__(self, api: WindowsWfpApi) -> None:
        self.api = api
        a = api._advapi32
        a.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        a.ConvertStringSidToSidW.restype = ctypes.c_int
        a.GetLengthSid.argtypes = [ctypes.c_void_p]
        a.GetLengthSid.restype = ctypes.c_uint32
        a.IsValidAcl.argtypes = [ctypes.c_void_p]
        a.IsValidAcl.restype = ctypes.c_int
        for kind in ("SubLayer", "Filter"):
            get = getattr(api._fwpuclnt, f"Fwpm{kind}GetSecurityInfoByKey0")
            get.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Guid), ctypes.c_uint32] + [
                ctypes.POINTER(ctypes.c_void_p)
            ] * 5
            get.restype = ctypes.c_uint32
            set_security = getattr(api._fwpuclnt, f"Fwpm{kind}SetSecurityInfoByKey0")
            set_security.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Guid), ctypes.c_uint32] + [
                ctypes.c_void_p
            ] * 4
            set_security.restype = ctypes.c_uint32

    def sid_bytes(self, sid: str) -> bytes:
        pointer = ctypes.c_void_p()
        if not self.api._advapi32.ConvertStringSidToSidW(sid, ctypes.byref(pointer)):
            raise WfpGuardError("Cannot convert operator SID")
        try:
            return ctypes.string_at(pointer, self.api._advapi32.GetLengthSid(pointer))
        finally:
            self.api._kernel32.LocalFree(pointer)

    @contextmanager
    def security(self, engine: ctypes.c_void_p, kind: str, key: _Guid) -> Iterator[tuple]:
        owner, group, dacl, sacl, descriptor = [ctypes.c_void_p() for _ in range(5)]
        get = getattr(self.api._fwpuclnt, f"Fwpm{kind}GetSecurityInfoByKey0")
        try:
            self.api._check(get(
                engine, ctypes.byref(key), _OWNER_GROUP_DACL_INFORMATION,
                *[ctypes.byref(p) for p in (owner, group, dacl, sacl, descriptor)],
            ), f"Fwpm{kind}GetSecurityInfoByKey0")
            # NULL DACL は全許可を意味するため、権限追加の前提として受け入れない。
            if not dacl or not self.api._advapi32.IsValidAcl(dacl):
                raise WfpGuardError("WFP object has a missing or invalid DACL")
            size = ctypes.c_uint16.from_address(dacl.value + 2).value
            yield (
                self.api._sid_to_string(owner), self.api._sid_to_string(group),
                ctypes.string_at(dacl, size),
            )
        finally:
            if descriptor:
                self.api._free_wfp_memory(descriptor)

    def grant(self, kind: str, key: _Guid, sid: bytes) -> bool:
        with self.api._engine() as engine:
            with self.security(engine, kind, key) as before:
                updated = _with_read_ace(before[2], sid)
            if updated == before[2]:
                return False
            acl = ctypes.create_string_buffer(updated)
            if not self.api._advapi32.IsValidAcl(acl):
                raise WfpGuardError("Constructed read-only WFP ACL is invalid")
            set_security = getattr(self.api._fwpuclnt, f"Fwpm{kind}SetSecurityInfoByKey0")
            # DACL のみを設定する。所有者・group・SACL・継承保護フラグは変更しない。
            self.api._check(set_security(
                engine, ctypes.byref(key), _DACL_INFORMATION, None, None, acl, None,
            ), f"Fwpm{kind}SetSecurityInfoByKey0")
            with self.security(engine, kind, key) as after:
                if after[:2] != before[:2] or _acl_entries(after[2]) != _acl_entries(updated):
                    raise WfpGuardError("WFP read-access DACL read-back mismatch")
            return True


def prepare_current_operator_read_access(api: WindowsWfpApi) -> dict:
    if not ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin():
        raise WfpGuardError("WFP read-access setup requires an administrator")
    operator_sid = api._current_process_sid()
    verification = ensure_codex_loopback_block(api)
    if operator_sid == verification.target_sid:
        raise WfpGuardError("WFP read-access operator must not be the Sandbox account")
    # 完全な policy 検証の後だけ、外部入力を持たない固定4個の DACL を設定する。
    access = _ReadAccessApi(api)
    sid = access.sid_bytes(operator_sid)
    changed = []
    for kind, key in _FIXED_OBJECTS:
        if access.grant(kind, _Guid.from_uuid(key), sid):
            changed.append(str(key))
    return {
        "operator_sid": operator_sid,
        "access_mask": _FWPM_ACTRL_READ,
        "changed_objects": changed,
        "verification": verify_codex_loopback_block(api).as_dict(),
    }
