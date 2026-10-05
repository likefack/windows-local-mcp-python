from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from windows_local_mcp import sandbox_backend
from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_backend import (
    SANDBOX_LIVE_MARKER_VERSION,
    SANDBOX_SECURITY_PROPERTIES,
    CodexSandboxBackend,
    codex_sandbox_policy_compatibility,
)
from windows_local_mcp.util import canonical_json, sha256_text
from windows_local_mcp.wfp_guard import (
    GUARD_POLICY_GENERATION,
    GUARD_VERSION,
    GuardVerification,
    SandboxAccountIdentity,
    guard_verification_binding,
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


def _backend(tmp_path: Path, *, version: str = "test-version") -> CodexSandboxBackend:
    executable = tmp_path / "trusted" / "codex.exe"
    return CodexSandboxBackend(
        executable=str(executable),
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject='CN="OpenAI OpCo, LLC"',
        signer_thumbprint="b" * 40,
        helpers=(),
        version=version,
    )


def _identity_context(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    backend: CodexSandboxBackend,
) -> tuple[dict[str, object], SandboxAccountIdentity, dict[str, object]]:
    context: dict[str, object] = {
        "wfp_guard_implementation": {"digest": "guard-implementation"},
        "windows_os_identity": {"platform": "windows", "build": "test"},
    }
    account = SandboxAccountIdentity(
        account_name="CodexSandboxOffline",
        computer_name="TESTPC",
        qualified_account_name=r"TESTPC\CodexSandboxOffline",
        sid="S-1-5-21-100-200-300-1004",
        sid_name_use=1,
    )
    verification = GuardVerification(
        guard_version=GUARD_VERSION,
        policy_generation=GUARD_POLICY_GENERATION,
        target_account=account.account_name,
        target_computer_name=account.computer_name,
        target_qualified_account=account.qualified_account_name,
        target_sid_name_use=account.sid_name_use,
        target_sid=account.sid,
        app_isolation_sublayer_key="app-sublayer",
        app_isolation_weight=7,
        guard_sublayer_key="guard-sublayer",
        guard_sublayer_weight=10,
        v4_filter_key="v4-filter",
        v4_filter_id=1,
        v4_effective_weight=100,
        v6_filter_key="v6-filter",
        v6_filter_id=2,
        v6_effective_weight=100,
    )
    monkeypatch.setattr(
        sandbox_backend,
        "sandbox_isolation_context",
        lambda _settings, _backend: context,
    )
    monkeypatch.setattr(
        sandbox_backend,
        "resolve_sandbox_account_identity",
        lambda: account,
    )
    return context, account, guard_verification_binding(verification)


def _write_marker(
    settings: Settings,
    backend: CodexSandboxBackend,
    context: dict[str, object],
    account: SandboxAccountIdentity,
    binding: dict[str, object],
    *,
    persisted_status: str,
    simple_command: bool | None,
    verified_at: datetime | None = None,
    properties: dict[str, dict[str, object]] | None = None,
    probe_diagnostics: list[dict[str, object]] | None = None,
) -> None:
    os_identity = context["windows_os_identity"]
    guard_implementation = context["wfp_guard_implementation"]
    assert isinstance(os_identity, dict)
    assert isinstance(guard_implementation, dict)
    evidence = {
        "version": SANDBOX_LIVE_MARKER_VERSION,
        "verification_status": persisted_status,
        "verified_at": (verified_at or datetime.now(UTC)).isoformat(),
        "backend_digest": sha256_text(canonical_json(backend.as_dict())),
        "backend_version": backend.version,
        "isolation_context_digest": sha256_text(canonical_json(context)),
        "guard_implementation": guard_implementation,
        "guard_implementation_digest": guard_implementation["digest"],
        "windows_os_identity": os_identity,
        "windows_os_identity_digest": sha256_text(canonical_json(os_identity)),
        "sandbox_account_identity": account.as_dict(),
        "wfp_guard_binding": binding,
        "wfp_guard_binding_digest": sha256_text(canonical_json(binding)),
        "checks": {
            "simple_command": simple_command,
            "brokered_process_creation_denied": True,
        },
        "properties": properties
        or {name: {"status": "unverified"} for name in SANDBOX_SECURITY_PROPERTIES},
        "probe_diagnostics": probe_diagnostics or [],
        "diagnostics": {},
        "passed": False,
    }
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    marker.write_text(canonical_json(evidence), encoding="utf-8")


def test_signature_and_presence_without_policy_evidence_are_unverified(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    result = codex_sandbox_policy_compatibility(settings, _backend(tmp_path))

    assert result["status"] == "unverified"
    assert result["reason"]


def test_simple_success_accepts_managed_policy_without_route_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    backend = _backend(tmp_path)
    context, account, binding = _identity_context(monkeypatch, settings, backend)
    failed_properties = {
        name: {"status": "failed" if name == "filesystem_read" else "verified"}
        for name in SANDBOX_SECURITY_PROPERTIES
    }
    _write_marker(
        settings,
        backend,
        context,
        account,
        binding,
        persisted_status="failed",
        simple_command=True,
        properties=failed_properties,
    )

    result = codex_sandbox_policy_compatibility(settings, backend)

    assert result == {"status": "accepted", "reason": None}
    with pytest.raises(sandbox_backend.ApprovedSandboxUnavailable):
        sandbox_backend.require_codex_sandbox_live_verification(settings, backend)

    drifted_backend = _backend(tmp_path, version="different-version")
    drifted = codex_sandbox_policy_compatibility(settings, drifted_backend)
    assert drifted["status"] == "unverified"


def test_exact_root_read_rejection_is_rejected_only_after_identity_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    backend = _backend(tmp_path)
    context, account, binding = _identity_context(monkeypatch, settings, backend)
    rejection = "elevated Windows sandbox requires effective `:root` read access"
    _write_marker(
        settings,
        backend,
        context,
        account,
        binding,
        persisted_status="unverified",
        simple_command=None,
        probe_diagnostics=[
            {"probe": "simple_command", "stderr": rejection, "stdout": ""}
        ],
    )

    result = codex_sandbox_policy_compatibility(settings, backend)

    assert result == {"status": "rejected", "reason": rejection}

    drifted_backend = _backend(tmp_path, version="different-version")
    drifted = codex_sandbox_policy_compatibility(settings, drifted_backend)
    assert drifted["status"] == "unverified"


@pytest.mark.parametrize("drift", ["wfp", "os", "account", "binding"])
def test_policy_acceptance_requires_current_live_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    settings = _settings(tmp_path)
    backend = _backend(tmp_path)
    context, account, binding = _identity_context(monkeypatch, settings, backend)
    _write_marker(
        settings,
        backend,
        context,
        account,
        binding,
        persisted_status="failed",
        simple_command=True,
        properties={
            name: {"status": "failed" if name == "filesystem_read" else "verified"}
            for name in SANDBOX_SECURITY_PROPERTIES
        },
    )
    if drift == "wfp":
        monkeypatch.setattr(
            sandbox_backend,
            "sandbox_isolation_context",
            lambda _settings, _backend: {
                **context,
                "wfp_guard_implementation": {"digest": "different-guard"},
            },
        )
    elif drift == "os":
        monkeypatch.setattr(
            sandbox_backend,
            "sandbox_isolation_context",
            lambda _settings, _backend: {
                **context,
                "windows_os_identity": {"platform": "windows", "build": "different"},
            },
        )
    elif drift == "account":
        changed_account = SandboxAccountIdentity(
            account_name=account.account_name,
            computer_name=account.computer_name,
            qualified_account_name=account.qualified_account_name,
            sid="S-1-5-21-100-200-300-1005",
            sid_name_use=account.sid_name_use,
        )
        monkeypatch.setattr(
            sandbox_backend,
            "resolve_sandbox_account_identity",
            lambda: changed_account,
        )
    else:
        monkeypatch.setattr(
            sandbox_backend,
            "GUARD_POLICY_GENERATION",
            GUARD_POLICY_GENERATION + 1,
        )

    result = codex_sandbox_policy_compatibility(settings, backend)

    assert result["status"] == "unverified"


@pytest.mark.parametrize("drift", ["policy", "ttl"])
def test_policy_acceptance_is_invalidated_by_context_or_ttl_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    settings = _settings(tmp_path)
    backend = _backend(tmp_path)
    context, account, binding = _identity_context(monkeypatch, settings, backend)
    verified_at = datetime.now(UTC) - timedelta(days=30 if drift == "ttl" else 0)
    _write_marker(
        settings,
        backend,
        context,
        account,
        binding,
        persisted_status="failed",
        simple_command=True,
        verified_at=verified_at,
        properties={
            name: {"status": "failed" if name == "filesystem_read" else "verified"}
            for name in SANDBOX_SECURITY_PROPERTIES
        },
    )
    if drift == "policy":
        monkeypatch.setattr(
            sandbox_backend,
            "sandbox_isolation_context",
            lambda _settings, _backend: {
                **context,
                "policy_generation": "changed",
            },
        )

    result = codex_sandbox_policy_compatibility(settings, backend)

    assert result["status"] == "unverified"
