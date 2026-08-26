from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_backend import (
    SANDBOX_LIVE_MARKER_VERSION,
    SANDBOX_SECURITY_PROPERTIES,
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    require_codex_sandbox_live_verification,
    sandbox_isolation_context,
    sandbox_live_verification_route_eligible,
)
from windows_local_mcp.util import canonical_json, sha256_text
from windows_local_mcp.wfp_guard import (
    GUARD_POLICY_GENERATION,
    GUARD_VERSION,
    SandboxAccountIdentity,
)

MANDATORY_DESCENDANT_CHECKS = (
    "child_source_workspace_read_denied",
    "child_source_workspace_write_denied",
    "child_outside_user_read_denied",
    "child_control_plane_read_denied",
    "child_control_plane_write_denied",
    "child_internet_denied",
    "child_loopback_denied",
    "grandchild_source_workspace_read_denied",
    "grandchild_source_workspace_write_denied",
    "grandchild_outside_user_read_denied",
    "grandchild_control_plane_read_denied",
    "grandchild_control_plane_write_denied",
    "grandchild_internet_denied",
    "grandchild_loopback_denied",
)


def _account_identity() -> SandboxAccountIdentity:
    return SandboxAccountIdentity(
        account_name="CodexSandboxOffline",
        computer_name="TESTPC",
        qualified_account_name=r"TESTPC\CodexSandboxOffline",
        sid="S-1-5-21-100-200-300-1004",
        sid_name_use=1,
    )


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def _backend(tmp_path: Path) -> CodexSandboxBackend:
    return CodexSandboxBackend(
        executable=str(tmp_path / "codex.exe"),
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
        version="test-version",
    )


def _accepted_residual_risk_evidence(
    settings: Settings, backend: CodexSandboxBackend
) -> dict[str, object]:
    properties = {
        name: {"status": "verified"} for name in SANDBOX_SECURITY_PROPERTIES
    }
    properties["protected_information_read"] = {"status": "failed"}
    properties["lan"] = {"status": "failed"}
    properties["descendant_containment"] = {"status": "failed"}
    checks = {name: True for name in MANDATORY_DESCENDANT_CHECKS}
    checks.update(
        {
            "child_protected_information_denied": False,
            "child_lan_denied": False,
            "grandchild_protected_information_denied": False,
            "grandchild_lan_denied": False,
            "brokered_process_creation_denied": True,
        }
    )
    context = sandbox_isolation_context(settings, backend)
    guard_implementation = context["wfp_guard_implementation"]
    os_identity = context["windows_os_identity"]
    account_identity = _account_identity().as_dict()
    wfp_binding = {
        "guard_version": GUARD_VERSION,
        "policy_generation": GUARD_POLICY_GENERATION,
        "sandbox_account_identity": account_identity,
        "test_binding": True,
    }
    return {
        "version": SANDBOX_LIVE_MARKER_VERSION,
        "passed": False,
        "backend_digest": sha256_text(canonical_json(backend.as_dict())),
        "backend_version": backend.version,
        "isolation_context_digest": sha256_text(canonical_json(context)),
        "guard_implementation": guard_implementation,
        "guard_implementation_digest": guard_implementation["digest"],
        "windows_os_identity": os_identity,
        "windows_os_identity_digest": sha256_text(canonical_json(os_identity)),
        "sandbox_account_identity": account_identity,
        "wfp_guard_binding": wfp_binding,
        "wfp_guard_binding_digest": sha256_text(canonical_json(wfp_binding)),
        "properties": properties,
        "checks": checks,
    }


def test_accepted_workspace_protected_and_lan_failures_do_not_block_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.resolve_sandbox_account_identity",
        _account_identity,
    )
    backend = _backend(tmp_path)
    evidence = _accepted_residual_risk_evidence(settings, backend)

    assert evidence["passed"] is False
    assert sandbox_live_verification_route_eligible(evidence) is True

    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    marker.write_text(canonical_json(evidence), encoding="utf-8")
    accepted = require_codex_sandbox_live_verification(settings, backend)
    assert accepted["properties"]["protected_information_read"]["status"] == "failed"
    assert accepted["properties"]["lan"]["status"] == "failed"
    assert accepted["checks"]["child_protected_information_denied"] is False
    assert accepted["checks"]["grandchild_protected_information_denied"] is False


def test_mandatory_descendant_failure_still_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.resolve_sandbox_account_identity",
        _account_identity,
    )
    backend = _backend(tmp_path)
    evidence = _accepted_residual_risk_evidence(settings, backend)
    checks = evidence["checks"]
    assert isinstance(checks, dict)
    checks["child_loopback_denied"] = False

    assert sandbox_live_verification_route_eligible(evidence) is False

    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    marker.write_text(canonical_json(evidence), encoding="utf-8")
    with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):
        require_codex_sandbox_live_verification(settings, backend)


@pytest.mark.parametrize("status", ["failed", "unverified"])
def test_workspace_protected_information_is_accepted_residual_risk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.resolve_sandbox_account_identity",
        _account_identity,
    )
    backend = _backend(tmp_path)
    evidence = _accepted_residual_risk_evidence(settings, backend)
    properties = evidence["properties"]
    assert isinstance(properties, dict)
    properties["protected_information_read"] = {"status": status}
    properties["lan"] = {"status": "verified"}

    assert sandbox_live_verification_route_eligible(evidence) is True

    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    marker.write_text(canonical_json(evidence), encoding="utf-8")
    accepted = require_codex_sandbox_live_verification(settings, backend)
    assert accepted["properties"]["protected_information_read"]["status"] == status
