from __future__ import annotations

import os
import uuid
from dataclasses import asdict, dataclass
from typing import Protocol

GUARD_POLICY_GENERATION = 1
GUARD_VERSION = "wlmcp-wfp-loopback-guard-v1"
TARGET_ACCOUNT = "CodexSandboxOffline"

APP_ISOLATION_SUBLAYER_KEY = uuid.UUID("ffe221c3-92a8-4564-a59f-dafb70756020")
APP_ISOLATION_PROVIDER_KEY = uuid.UUID("3cc2631f-2d5d-43a0-b174-614837d863a1")
GUARD_SUBLAYER_KEY = uuid.UUID("7019c9c2-acc9-5a02-97cb-d9ccdca1b9ab")
GUARD_V4_FILTER_KEY = uuid.UUID("0acea791-e272-5a9c-ae2f-5bf41970dd41")
GUARD_V6_FILTER_KEY = uuid.UUID("cb98391f-1773-5060-bfb6-3de2306f8baa")
ALE_AUTH_CONNECT_V4 = uuid.UUID("c38d57d1-05a7-4c33-904f-7fbceee60e82")
ALE_AUTH_CONNECT_V6 = uuid.UUID("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")

GUARD_SUBLAYER_WEIGHT = 10
GUARD_SUBLAYER_NAME = "WLMCP Codex Sandbox loopback block"
GUARD_SUBLAYER_DESCRIPTION = "Static non-persistent WLMCP block for CodexSandboxOffline loopback."
GUARD_FILTER_NAMES = {
    "v4": "WLMCP Codex Sandbox loopback block V4",
    "v6": "WLMCP Codex Sandbox loopback block V6",
}


class WfpGuardError(RuntimeError):
    """The required WFP boundary is absent, inconsistent, or unverified."""


@dataclass(frozen=True)
class SubLayerSnapshot:
    found: bool
    key: uuid.UUID
    name: str = ""
    description: str = ""
    flags: int = 0
    provider_key: uuid.UUID | None = None
    provider_data_size: int = 0
    weight: int = 0


@dataclass(frozen=True)
class FilterConditionSnapshot:
    kind: str
    match_type: str
    value_type: str
    sid: str | None = None
    security_descriptor_sddl: str | None = None
    flags: int | None = None


@dataclass(frozen=True)
class FilterSnapshot:
    found: bool
    key: uuid.UUID
    runtime_id: int = 0
    name: str = ""
    description: str = ""
    flags: int = 0
    provider_key: uuid.UUID | None = None
    provider_data_size: int = 0
    layer_key: uuid.UUID | None = None
    sublayer_key: uuid.UUID | None = None
    action: str = ""
    weight_type: str = ""
    effective_weight: int | None = None
    conditions: tuple[FilterConditionSnapshot, ...] = ()


@dataclass(frozen=True)
class GuardVerification:
    guard_version: str
    policy_generation: int
    target_account: str
    target_sid: str
    app_isolation_sublayer_key: str
    app_isolation_weight: int
    guard_sublayer_key: str
    guard_sublayer_weight: int
    v4_filter_key: str
    v4_filter_id: int
    v4_effective_weight: int | None
    v6_filter_key: str
    v6_filter_id: int
    v6_effective_weight: int | None
    static_nonpersistent: bool = True
    dynamic_session: bool = False
    persistent: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class WfpGuardApi(Protocol):
    def resolve_account_sid(self, account_name: str) -> str: ...

    def read_sublayer(self, key: uuid.UUID) -> SubLayerSnapshot: ...

    def read_filter(self, key: uuid.UUID) -> FilterSnapshot: ...

    def add_sublayer(self) -> None: ...

    def add_filters(self, *, add_v4: bool, add_v6: bool, target_sid: str) -> None: ...

    def delete_filter(self, key: uuid.UUID) -> None: ...

    def delete_sublayer(self, key: uuid.UUID) -> None: ...


def ensure_codex_loopback_block(api: WfpGuardApi) -> GuardVerification:
    """Create missing fixed objects and verify the complete boundary by read-back."""

    target_sid = _resolve_target_sid(api)
    app_isolation = _verify_app_isolation_sublayer(api)
    sublayer = api.read_sublayer(GUARD_SUBLAYER_KEY)
    v4 = api.read_filter(GUARD_V4_FILTER_KEY)
    v6 = api.read_filter(GUARD_V6_FILTER_KEY)

    if sublayer.found:
        _verify_guard_sublayer(sublayer, app_isolation)
    else:
        if v4.found or v6.found:
            raise WfpGuardError(
                "Guard filter exists without the required Guard sublayer; refusing repair"
            )
        api.add_sublayer()
        # Read back before creating filters so a wrong or low-weight sublayer never receives them.
        sublayer = api.read_sublayer(GUARD_SUBLAYER_KEY)
        _verify_guard_sublayer(sublayer, app_isolation)

    if v4.found:
        _verify_guard_filter(v4, family="v4", target_sid=target_sid)
    if v6.found:
        _verify_guard_filter(v6, family="v6", target_sid=target_sid)
    if not v4.found or not v6.found:
        api.add_filters(add_v4=not v4.found, add_v6=not v6.found, target_sid=target_sid)

    return verify_codex_loopback_block(api)


def verify_codex_loopback_block(api: WfpGuardApi) -> GuardVerification:
    """Verify every security-relevant field without changing WFP state."""

    target_sid = _resolve_target_sid(api)
    app_isolation = _verify_app_isolation_sublayer(api)
    sublayer = api.read_sublayer(GUARD_SUBLAYER_KEY)
    v4 = api.read_filter(GUARD_V4_FILTER_KEY)
    v6 = api.read_filter(GUARD_V6_FILTER_KEY)
    _verify_guard_sublayer(sublayer, app_isolation)
    _verify_guard_filter(v4, family="v4", target_sid=target_sid)
    _verify_guard_filter(v6, family="v6", target_sid=target_sid)
    return GuardVerification(
        guard_version=GUARD_VERSION,
        policy_generation=GUARD_POLICY_GENERATION,
        target_account=TARGET_ACCOUNT,
        target_sid=target_sid,
        app_isolation_sublayer_key=str(app_isolation.key),
        app_isolation_weight=app_isolation.weight,
        guard_sublayer_key=str(sublayer.key),
        guard_sublayer_weight=sublayer.weight,
        v4_filter_key=str(v4.key),
        v4_filter_id=v4.runtime_id,
        v4_effective_weight=v4.effective_weight,
        v6_filter_key=str(v6.key),
        v6_filter_id=v6.runtime_id,
        v6_effective_weight=v6.effective_weight,
    )


def maintenance_remove_codex_loopback_block(api: WfpGuardApi) -> None:
    """Remove only the exact verified objects; this is not a runtime operation."""

    target_sid = _resolve_target_sid(api)
    app_isolation = _verify_app_isolation_sublayer(api)
    sublayer = api.read_sublayer(GUARD_SUBLAYER_KEY)
    v4 = api.read_filter(GUARD_V4_FILTER_KEY)
    v6 = api.read_filter(GUARD_V6_FILTER_KEY)
    # Maintenance can recover a known partial creation, but never deletes a mismatched key.
    if sublayer.found:
        _verify_guard_sublayer(sublayer, app_isolation)
    if v4.found:
        _verify_guard_filter(v4, family="v4", target_sid=target_sid)
    if v6.found:
        _verify_guard_filter(v6, family="v6", target_sid=target_sid)
    if v4.found:
        api.delete_filter(GUARD_V4_FILTER_KEY)
    if v6.found:
        api.delete_filter(GUARD_V6_FILTER_KEY)
    if sublayer.found:
        api.delete_sublayer(GUARD_SUBLAYER_KEY)
    if (
        api.read_filter(GUARD_V4_FILTER_KEY).found
        or api.read_filter(GUARD_V6_FILTER_KEY).found
        or api.read_sublayer(GUARD_SUBLAYER_KEY).found
    ):
        raise WfpGuardError("Guard maintenance cleanup did not remove every exact object")


def _resolve_target_sid(api: WfpGuardApi) -> str:
    sid = api.resolve_account_sid(TARGET_ACCOUNT)
    if not sid.startswith("S-1-"):
        raise WfpGuardError("Windows returned an invalid CodexSandboxOffline SID")
    return sid


def _verify_app_isolation_sublayer(api: WfpGuardApi) -> SubLayerSnapshot:
    sublayer = api.read_sublayer(APP_ISOLATION_SUBLAYER_KEY)
    if not sublayer.found:
        raise WfpGuardError("The current App Isolation sublayer is unavailable")
    if (
        sublayer.key != APP_ISOLATION_SUBLAYER_KEY
        or sublayer.flags != 0
        or sublayer.provider_key != APP_ISOLATION_PROVIDER_KEY
        or sublayer.provider_data_size != 0
    ):
        raise WfpGuardError("The App Isolation sublayer identity is unexpected")
    if sublayer.weight >= GUARD_SUBLAYER_WEIGHT:
        raise WfpGuardError("Guard sublayer weight is not above App Isolation")
    return sublayer


def _verify_guard_sublayer(sublayer: SubLayerSnapshot, app_isolation: SubLayerSnapshot) -> None:
    if not sublayer.found:
        raise WfpGuardError("Required Guard sublayer is missing")
    if (
        sublayer.key != GUARD_SUBLAYER_KEY
        or sublayer.name != GUARD_SUBLAYER_NAME
        or sublayer.description != GUARD_SUBLAYER_DESCRIPTION
        or sublayer.flags != 0
        or sublayer.provider_key is not None
        or sublayer.provider_data_size != 0
        or sublayer.weight != GUARD_SUBLAYER_WEIGHT
    ):
        raise WfpGuardError("Required Guard sublayer has unexpected content")
    if sublayer.weight <= app_isolation.weight:
        raise WfpGuardError("Guard sublayer weight is not above App Isolation")


def _verify_guard_filter(snapshot: FilterSnapshot, *, family: str, target_sid: str) -> None:
    expected_key = GUARD_V4_FILTER_KEY if family == "v4" else GUARD_V6_FILTER_KEY
    expected_layer = ALE_AUTH_CONNECT_V4 if family == "v4" else ALE_AUTH_CONNECT_V6
    if not snapshot.found:
        raise WfpGuardError(f"Required Guard {family.upper()} filter is missing")
    if (
        snapshot.key != expected_key
        or snapshot.runtime_id <= 0
        or snapshot.name != GUARD_FILTER_NAMES[family]
        or snapshot.flags != 0
        or snapshot.provider_key is not None
        or snapshot.provider_data_size != 0
        or snapshot.layer_key != expected_layer
        or snapshot.sublayer_key != GUARD_SUBLAYER_KEY
        or snapshot.action != "block"
        or snapshot.weight_type != "empty"
        or snapshot.effective_weight is None
    ):
        raise WfpGuardError(f"Required Guard {family.upper()} filter has unexpected content")
    expected_conditions = {
        FilterConditionSnapshot(
            kind="ale_user_id",
            match_type="equal",
            value_type="security_descriptor",
            sid=target_sid,
            security_descriptor_sddl=f"D:(A;;CC;;;{target_sid})",
        ),
        FilterConditionSnapshot(
            kind="flags",
            match_type="flags_all_set",
            value_type="uint32",
            flags=1,
        ),
    }
    if len(snapshot.conditions) != 2 or set(snapshot.conditions) != expected_conditions:
        raise WfpGuardError(f"Required Guard {family.upper()} filter conditions are unexpected")


def new_windows_wfp_api() -> WfpGuardApi:
    if os.name != "nt":
        raise WfpGuardError("The WFP Guard requires native Windows")
    from .windows_wfp import WindowsWfpApi

    return WindowsWfpApi()
