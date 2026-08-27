from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.git_broker_live_verify import (
    GIT_BROKER_COMMAND_POLICY_VERSION,
    GIT_BROKER_LIVE_MARKER_VERSION,
    git_broker_live_context,
    require_git_broker_live_verification,
    verify_git_broker_live,
)
from windows_local_mcp.git_broker_sandbox import GitBrokerUnavailable
from windows_local_mcp.sandbox_backend import SANDBOX_SECURITY_PROPERTIES


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        git_enabled=True,
        **overrides,
    )
    settings.ensure_directories()
    return settings


def _identity(tmp_path: Path, digest: str = "a" * 64) -> dict[str, object]:
    return {
        "path": str((tmp_path / "git.exe").resolve()),
        "sha256": digest,
        "size": 123,
        "mtime_ns": 456,
        "stable_file_identity": {"platform": "test", "id": 1},
        "provenance": "explicit-local-config",
    }


def _evidence(*, override: tuple[str, str] | None = None) -> dict[str, object]:
    properties = {
        name: {"status": "verified"} for name in SANDBOX_SECURITY_PROPERTIES
    }
    if override is not None:
        name, status = override
        properties[name] = {"status": status}
    return {"version": 5, "properties": properties, "checks": {}}


def _containment(evidence: dict[str, object]) -> SimpleNamespace:
    backend = SimpleNamespace(
        version="test-backend",
        as_dict=lambda: {"version": "test-backend", "identity": "bound"},
    )
    return SimpleNamespace(
        backend=backend,
        live_evidence=evidence,
        policy_digest="containment-policy",
    )


def _probe_results(digest: str = "c" * 64) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            returncode=0,
            stdout=b"true\n",
            stderr=b"",
            snapshot_digest=digest,
        ),
        SimpleNamespace(
            returncode=0,
            stdout=b"",
            stderr=b"",
            snapshot_digest=digest,
        ),
    ]


def test_git_live_context_rejects_generic_sandbox_residual_property(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity = _identity(tmp_path)
    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: _containment(
            _evidence(override=("lan", "unverified"))
        ),
    )

    with pytest.raises(GitBrokerUnavailable, match="every Sandbox security property"):
        git_broker_live_context(settings, identity)


def test_git_live_context_binds_small_scratch_quota_without_artificial_floor(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, max_sandbox_scratch_bytes=1024 * 1024)
    identity = _identity(tmp_path)

    context = git_broker_live_context(
        settings,
        identity,
        containment=_containment(_evidence()),
    )

    assert context["max_sandbox_scratch_bytes"] == 1024 * 1024
    assert context["command_policy_version"] == GIT_BROKER_COMMAND_POLICY_VERSION


def test_git_live_context_binds_scratch_quota(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, max_sandbox_scratch_bytes=16 * 1024 * 1024)
    identity = _identity(tmp_path)

    context = git_broker_live_context(
        settings,
        identity,
        containment=_containment(_evidence()),
    )

    assert context["max_sandbox_scratch_bytes"] == 16 * 1024 * 1024


def test_git_live_verifier_writes_exact_context_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity = _identity(tmp_path)
    containment = _containment(_evidence())
    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify, "configured_git_identity", lambda _settings: identity
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "run_git_broker_batch",
        lambda **_kwargs: _probe_results(),
    )

    marker = verify_git_broker_live(settings)

    assert marker["version"] == GIT_BROKER_LIVE_MARKER_VERSION
    assert marker["context"]["command_policy_version"] == GIT_BROKER_COMMAND_POLICY_VERSION
    assert marker["route_eligible"] is True
    assert marker["checks"]["git_projection_snapshot_bound"] is True
    assert all(marker["checks"].values())
    assert require_git_broker_live_verification(settings, identity) == marker


def test_git_live_verifier_rejects_mismatched_projection_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity = _identity(tmp_path)
    containment = _containment(_evidence())
    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify, "configured_git_identity", lambda _settings: identity
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )
    results = _probe_results()
    results[1].snapshot_digest = "d" * 64
    monkeypatch.setattr(
        git_broker_live_verify,
        "run_git_broker_batch",
        lambda **_kwargs: results,
    )

    with pytest.raises(GitBrokerUnavailable, match="live verification failed"):
        verify_git_broker_live(settings)


def test_git_live_marker_is_stale_when_pinned_git_identity_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity = _identity(tmp_path)
    containment = _containment(_evidence())
    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify, "configured_git_identity", lambda _settings: identity
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "run_git_broker_batch",
        lambda **_kwargs: _probe_results(),
    )
    verify_git_broker_live(settings)

    changed = dict(identity)
    changed["sha256"] = "b" * 64
    with pytest.raises(GitBrokerUnavailable, match="stale"):
        require_git_broker_live_verification(settings, changed)


def test_git_live_marker_is_stale_when_command_policy_generation_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity = _identity(tmp_path)
    containment = _containment(_evidence())
    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify, "configured_git_identity", lambda _settings: identity
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "run_git_broker_batch",
        lambda **_kwargs: _probe_results(),
    )
    verify_git_broker_live(settings)

    monkeypatch.setattr(
        git_broker_live_verify,
        "GIT_BROKER_COMMAND_POLICY_VERSION",
        GIT_BROKER_COMMAND_POLICY_VERSION + 1,
    )
    with pytest.raises(GitBrokerUnavailable, match="stale"):
        require_git_broker_live_verification(settings, identity)


def test_missing_git_live_marker_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    identity = _identity(tmp_path)
    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: _containment(_evidence()),
    )

    with pytest.raises(GitBrokerUnavailable, match="has not completed"):
        require_git_broker_live_verification(settings, identity)
