from __future__ import annotations

import struct
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from windows_local_mcp import wfp_read_access as access
from windows_local_mcp.wfp_guard import WfpGuardError

SID = bytes.fromhex("010100000000000520000000")


def _ace(kind: int, flags: int, mask: int) -> bytes:
    return struct.pack("<BBHI", kind, flags, 8 + len(SID), mask) + SID


def _acl(*entries: bytes) -> bytes:
    body = b"".join(entries)
    return struct.pack("<BBHHH", 2, 0, 8 + len(body), len(entries), 0) + body


def test_read_grant_preserves_denies_and_inheritance_and_is_idempotent() -> None:
    deny = _ace(1, 0, 0x50000)
    inherited = _ace(0, 0x10, 0x100)
    original = _acl(deny, inherited)
    updated = access._with_read_ace(original, SID)
    assert access._acl_entries(updated) == (2, (deny, _ace(0, 0, 0x80), inherited))
    assert access._with_read_ace(updated, SID) == updated
    # SDK の READ は 0x80。ADD や WRITE_DAC、DELETE は追加されない。
    assert access._FWPM_ACTRL_READ == 0x80


@pytest.mark.parametrize("raw", [b"", b"\0" * 8, struct.pack("<BBHHH", 2, 0, 8, 1, 0)])
def test_malformed_acl_is_rejected(raw: bytes) -> None:
    with pytest.raises(WfpGuardError):
        access._with_read_ace(raw, SID)


def test_existing_broader_entry_is_not_rewritten() -> None:
    original = _ace(0, 0, 0x10000)
    assert access._acl_entries(access._with_read_ace(_acl(original), SID))[1] == (
        original, _ace(0, 0, 0x80),
    )


def _install(monkeypatch: pytest.MonkeyPatch, *, admin: bool = True):
    calls = []
    monkeypatch.setattr(access.ctypes, "WinDLL", lambda *a, **k: SimpleNamespace(
        IsUserAnAdmin=lambda: admin,
    ))
    verification = SimpleNamespace(target_sid="sandbox", as_dict=lambda: {"checked": True})

    def ensure(api):
        calls.append("ensure")
        return verification

    def verify(api):
        calls.append("verify")
        return verification

    class FakeAccess:
        def __init__(self, api):
            calls.append("access")

        def sid_bytes(self, sid):
            assert sid == "operator"
            return SID

        def grant(self, kind, key, sid):
            assert sid == SID
            calls.append((kind, key.to_uuid()))
            return True

    monkeypatch.setattr(access, "ensure_codex_loopback_block", ensure)
    monkeypatch.setattr(access, "verify_codex_loopback_block", verify)
    monkeypatch.setattr(access, "_ReadAccessApi", FakeAccess)
    return calls, SimpleNamespace(_current_process_sid=lambda: "operator")


def test_setup_checks_policy_before_only_four_fixed_grants(monkeypatch) -> None:
    calls, api = _install(monkeypatch)
    result = access.prepare_current_operator_read_access(api)
    assert calls == ["ensure", "access", *access._FIXED_OBJECTS, "verify"]
    assert len(result["changed_objects"]) == 4
    assert result["access_mask"] == 0x80


def test_setup_does_not_mutate_when_policy_is_unverified(monkeypatch) -> None:
    calls, api = _install(monkeypatch)

    def fail(api):
        raise WfpGuardError("policy mismatch")

    monkeypatch.setattr(access, "ensure_codex_loopback_block", fail)
    with pytest.raises(WfpGuardError, match="policy mismatch"):
        access.prepare_current_operator_read_access(api)
    assert calls == []


def test_nonadministrator_does_not_even_ensure(monkeypatch) -> None:
    calls, api = _install(monkeypatch, admin=False)
    with pytest.raises(WfpGuardError, match="administrator"):
        access.prepare_current_operator_read_access(api)
    assert calls == []


def test_sandbox_principal_cannot_receive_read_access(monkeypatch) -> None:
    calls, api = _install(monkeypatch)
    api._current_process_sid = lambda: "sandbox"
    with pytest.raises(WfpGuardError, match="Sandbox account"):
        access.prepare_current_operator_read_access(api)
    assert calls == ["ensure"]


@pytest.mark.parametrize("mode", ["success", "write_failure", "readback_mismatch"])
def test_native_grant_uses_only_dacl_and_propagates_failure(mode) -> None:
    original = _acl(_ace(1, 0, 0x50000))
    states = [("owner", "group", original)]
    calls = []

    @contextmanager
    def engine():
        yield 42

    def set_security(handle, key, information, owner, group, dacl, sacl):
        import ctypes

        assert handle == 42
        assert information == 4
        assert owner is None and group is None and sacl is None
        calls.append("write")
        if mode == "write_failure":
            return 5
        updated = bytes(dacl)[:-1]
        assert access._acl_entries(updated)[1] == (_ace(1, 0, 0x50000), _ace(0, 0, 0x80))
        assert ctypes.sizeof(dacl) == len(updated) + 1
        states.append(("wrong" if mode == "readback_mismatch" else "owner", "group", updated))
        return 0

    def check(status, operation):
        if status:
            raise WfpGuardError(f"{operation}: {status}")

    native = access._ReadAccessApi.__new__(access._ReadAccessApi)
    native.api = SimpleNamespace(
        _engine=engine, _check=check,
        _advapi32=SimpleNamespace(IsValidAcl=lambda _: True),
        _fwpuclnt=SimpleNamespace(FwpmSubLayerSetSecurityInfoByKey0=set_security),
    )

    @contextmanager
    def security(handle, kind, key):
        calls.append("read")
        yield states[-1]

    native.security = security
    key = access._Guid.from_uuid(access.GUARD_SUBLAYER_KEY)
    if mode == "success":
        assert native.grant("SubLayer", key, SID)
        assert not native.grant("SubLayer", key, SID)
        assert calls == ["read", "write", "read", "read"]
    else:
        with pytest.raises(WfpGuardError):
            native.grant("SubLayer", key, SID)
        assert calls.count("write") == 1
