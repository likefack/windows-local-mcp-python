from __future__ import annotations

import uuid
from dataclasses import replace

import pytest

from windows_local_mcp.wfp_guard import (
    ALE_AUTH_CONNECT_V4,
    ALE_AUTH_CONNECT_V6,
    APP_ISOLATION_PROVIDER_KEY,
    APP_ISOLATION_SUBLAYER_KEY,
    GUARD_FILTER_NAMES,
    GUARD_SUBLAYER_DESCRIPTION,
    GUARD_SUBLAYER_KEY,
    GUARD_SUBLAYER_NAME,
    GUARD_SUBLAYER_WEIGHT,
    GUARD_V4_FILTER_KEY,
    GUARD_V6_FILTER_KEY,
    FilterConditionSnapshot,
    FilterSnapshot,
    SubLayerSnapshot,
    WfpGuardError,
    ensure_codex_loopback_block,
    maintenance_remove_codex_loopback_block,
)

TARGET_SID = "S-1-5-21-100-200-300-1004"


class FakeWfpApi:
    def __init__(self, *, installed: bool = True) -> None:
        self.sid = TARGET_SID
        self.app = SubLayerSnapshot(
            found=True,
            key=APP_ISOLATION_SUBLAYER_KEY,
            flags=0,
            provider_key=APP_ISOLATION_PROVIDER_KEY,
            weight=7,
        )
        self.sublayer = _guard_sublayer(found=installed)
        self.filters = {
            GUARD_V4_FILTER_KEY: _guard_filter("v4", found=installed),
            GUARD_V6_FILTER_KEY: _guard_filter("v6", found=installed),
        }
        self.add_sublayer_calls = 0
        self.add_filter_calls: list[tuple[bool, bool, str]] = []
        self.fail_add_filters = False
        self.fail_readback = False

    def resolve_account_sid(self, account_name: str) -> str:
        assert account_name == "CodexSandboxOffline"
        return self.sid

    def read_sublayer(self, key: uuid.UUID) -> SubLayerSnapshot:
        if key == APP_ISOLATION_SUBLAYER_KEY:
            return self.app
        assert key == GUARD_SUBLAYER_KEY
        return self.sublayer

    def read_filter(self, key: uuid.UUID) -> FilterSnapshot:
        value = self.filters[key]
        if self.fail_readback and self.add_filter_calls:
            return replace(value, action="permit")
        return value

    def add_sublayer(self) -> None:
        self.add_sublayer_calls += 1
        self.sublayer = _guard_sublayer(found=True)

    def add_filters(self, *, add_v4: bool, add_v6: bool, target_sid: str) -> None:
        self.add_filter_calls.append((add_v4, add_v6, target_sid))
        if self.fail_add_filters:
            raise OSError("simulated transaction failure")
        if add_v4:
            self.filters[GUARD_V4_FILTER_KEY] = _guard_filter("v4", found=True)
        if add_v6:
            self.filters[GUARD_V6_FILTER_KEY] = _guard_filter("v6", found=True)

    def delete_filter(self, key: uuid.UUID) -> None:
        self.filters[key] = replace(self.filters[key], found=False)

    def delete_sublayer(self, key: uuid.UUID) -> None:
        assert key == GUARD_SUBLAYER_KEY
        self.sublayer = replace(self.sublayer, found=False)


def _guard_sublayer(*, found: bool) -> SubLayerSnapshot:
    return SubLayerSnapshot(
        found=found,
        key=GUARD_SUBLAYER_KEY,
        name=GUARD_SUBLAYER_NAME,
        description=GUARD_SUBLAYER_DESCRIPTION,
        flags=0,
        weight=GUARD_SUBLAYER_WEIGHT,
    )


def _guard_filter(family: str, *, found: bool) -> FilterSnapshot:
    return FilterSnapshot(
        found=found,
        key=GUARD_V4_FILTER_KEY if family == "v4" else GUARD_V6_FILTER_KEY,
        runtime_id=501 if family == "v4" else 502,
        name=GUARD_FILTER_NAMES[family],
        flags=0,
        layer_key=ALE_AUTH_CONNECT_V4 if family == "v4" else ALE_AUTH_CONNECT_V6,
        sublayer_key=GUARD_SUBLAYER_KEY,
        action="block",
        weight_type="empty",
        effective_weight=100,
        conditions=(
            FilterConditionSnapshot(
                kind="ale_user_id",
                match_type="equal",
                value_type="security_descriptor",
                sid=TARGET_SID,
                security_descriptor_sddl=f"D:(A;;CC;;;{TARGET_SID})",
            ),
            FilterConditionSnapshot(
                kind="flags",
                match_type="flags_all_set",
                value_type="uint32",
                flags=1,
            ),
        ),
    )


def test_ensure_reuses_normal_guard_state() -> None:
    api = FakeWfpApi()
    result = ensure_codex_loopback_block(api)
    assert result.target_sid == TARGET_SID
    assert result.v4_filter_id == 501
    assert result.v6_filter_id == 502
    assert api.add_sublayer_calls == 0
    assert api.add_filter_calls == []


def test_ensure_creates_all_missing_objects() -> None:
    api = FakeWfpApi(installed=False)
    ensure_codex_loopback_block(api)
    assert api.add_sublayer_calls == 1
    assert api.add_filter_calls == [(True, True, TARGET_SID)]


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_ensure_creates_only_missing_filter(family: str) -> None:
    api = FakeWfpApi()
    key = GUARD_V4_FILTER_KEY if family == "v4" else GUARD_V6_FILTER_KEY
    api.filters[key] = replace(api.filters[key], found=False)
    ensure_codex_loopback_block(api)
    assert api.add_filter_calls == [(family == "v4", family == "v6", TARGET_SID)]


def test_missing_sublayer_with_existing_filter_is_not_guessed_or_overwritten() -> None:
    api = FakeWfpApi()
    api.sublayer = replace(api.sublayer, found=False)
    with pytest.raises(WfpGuardError, match="without the required Guard sublayer"):
        ensure_codex_loopback_block(api)
    assert api.add_sublayer_calls == 0


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda api: setattr(api, "sid", "S-1-5-21-incorrect"), "conditions"),
        (
            lambda api: api.filters.__setitem__(
                GUARD_V4_FILTER_KEY,
                replace(api.filters[GUARD_V4_FILTER_KEY], layer_key=ALE_AUTH_CONNECT_V6),
            ),
            "unexpected content",
        ),
        (
            lambda api: api.filters.__setitem__(
                GUARD_V4_FILTER_KEY,
                replace(api.filters[GUARD_V4_FILTER_KEY], action="permit"),
            ),
            "unexpected content",
        ),
        (
            lambda api: api.filters.__setitem__(
                GUARD_V4_FILTER_KEY,
                replace(api.filters[GUARD_V4_FILTER_KEY], conditions=()),
            ),
            "conditions",
        ),
        (
            lambda api: api.filters.__setitem__(
                GUARD_V4_FILTER_KEY,
                replace(
                    api.filters[GUARD_V4_FILTER_KEY],
                    conditions=(
                        replace(
                            api.filters[GUARD_V4_FILTER_KEY].conditions[0],
                            security_descriptor_sddl=(
                                f"D:(A;;CC;;;{TARGET_SID})(A;;CC;;;S-1-5-32-545)"
                            ),
                        ),
                        api.filters[GUARD_V4_FILTER_KEY].conditions[1],
                    ),
                ),
            ),
            "conditions",
        ),
        (lambda api: setattr(api, "app", replace(api.app, weight=10)), "not above"),
        (
            lambda api: setattr(api, "sublayer", replace(api.sublayer, weight=7)),
            "unexpected content",
        ),
        (
            lambda api: setattr(api, "sublayer", replace(api.sublayer, name="foreign")),
            "unexpected content",
        ),
    ],
)
def test_ensure_rejects_security_mismatch(mutation: object, message: str) -> None:
    api = FakeWfpApi()
    mutation(api)  # type: ignore[operator]
    with pytest.raises(WfpGuardError, match=message):
        ensure_codex_loopback_block(api)
    assert api.add_sublayer_calls == 0
    assert api.add_filter_calls == []


def test_partial_creation_failure_is_visible_and_next_ensure_can_resume() -> None:
    api = FakeWfpApi(installed=False)
    api.fail_add_filters = True
    with pytest.raises(OSError, match="transaction failure"):
        ensure_codex_loopback_block(api)
    assert api.sublayer.found is True
    api.fail_add_filters = False
    ensure_codex_loopback_block(api)
    assert api.add_sublayer_calls == 1
    assert api.add_filter_calls[-1] == (True, True, TARGET_SID)


def test_readback_failure_is_not_reported_as_success() -> None:
    api = FakeWfpApi(installed=False)
    api.fail_readback = True
    with pytest.raises(WfpGuardError, match="unexpected content"):
        ensure_codex_loopback_block(api)


def test_ensure_is_idempotent() -> None:
    api = FakeWfpApi(installed=False)
    first = ensure_codex_loopback_block(api)
    second = ensure_codex_loopback_block(api)
    assert first == second
    assert api.add_sublayer_calls == 1
    assert api.add_filter_calls == [(True, True, TARGET_SID)]


def test_maintenance_cleanup_removes_only_verified_exact_objects() -> None:
    api = FakeWfpApi()
    maintenance_remove_codex_loopback_block(api)
    assert api.sublayer.found is False
    assert api.filters[GUARD_V4_FILTER_KEY].found is False
    assert api.filters[GUARD_V6_FILTER_KEY].found is False


def test_maintenance_cleanup_handles_verified_partial_creation() -> None:
    api = FakeWfpApi(installed=False)
    api.sublayer = _guard_sublayer(found=True)
    maintenance_remove_codex_loopback_block(api)
    assert api.sublayer.found is False


def test_maintenance_cleanup_refuses_mismatched_object() -> None:
    api = FakeWfpApi()
    api.filters[GUARD_V4_FILTER_KEY] = replace(
        api.filters[GUARD_V4_FILTER_KEY], action="permit"
    )
    with pytest.raises(WfpGuardError, match="unexpected content"):
        maintenance_remove_codex_loopback_block(api)
    assert api.sublayer.found is True
    assert api.filters[GUARD_V6_FILTER_KEY].found is True
