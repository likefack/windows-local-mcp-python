from __future__ import annotations

import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp import sandbox_live_verify_hardened as hardened
from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_backend import SANDBOX_SECURITY_PROPERTIES
from windows_local_mcp.util import canonical_json, sha256_text


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


def _verified_properties() -> dict[str, dict[str, object]]:
    return {
        name: {
            "status": "verified",
            "checks": [],
            "failed": [],
            "unverified": [],
            "missing_or_failed": [],
            "reasons": {},
        }
        for name in SANDBOX_SECURITY_PROPERTIES
    }


def test_hardened_verifier_provisions_source_acl_before_base_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    sid = "S-1-5-21-100-200-300-1004"
    backend_payload = {"name": "test-backend"}
    backend = SimpleNamespace(
        version="test-version",
        as_dict=lambda: backend_payload,
    )
    calls: list[str] = []

    def ensure_acl(_workspace: Path, target_sid: str) -> dict[str, object]:
        calls.append("source-acl")
        assert target_sid == sid
        return {
            "version": "wlmcp-source-workspace-read-deny-v1",
            "workspace_root": str(settings.workspace_root.resolve()),
            "target_sid": sid,
            "explicit_deny_read": True,
            "inheritable_to_files": True,
            "inheritable_to_directories": True,
            "added": len(calls) == 1,
        }

    def base(_settings: Settings, *, persist_evidence: bool = True) -> dict[str, object]:
        assert persist_evidence is False
        calls.append("base-live-probes")
        return {
            "backend_digest": sha256_text(canonical_json(backend_payload)),
            "backend_version": backend.version,
            "sandbox_account_identity": {"sid": sid},
            "checks": {"simple_command": True},
            "properties": _verified_properties(),
            "diagnostics": {},
            "probe_diagnostics": [],
            "passed": True,
        }

    def wrapped_placeholder(_settings: Settings) -> dict[str, object]:
        raise AssertionError("decorated base wrapper must not be called")

    wrapped_placeholder.__wrapped__ = base  # type: ignore[attr-defined]

    monkeypatch.setattr(hardened, "_base_verify_codex_sandbox_live", wrapped_placeholder)
    monkeypatch.setattr(
        hardened,
        "resolve_sandbox_account_identity",
        lambda: SimpleNamespace(sid=sid),
    )
    monkeypatch.setattr(hardened, "ensure_source_workspace_read_deny", ensure_acl)
    monkeypatch.setattr(hardened, "resolve_codex_sandbox_backend", lambda _settings: backend)
    monkeypatch.setattr(
        hardened,
        "hold_codex_sandbox_backend",
        lambda _backend: nullcontext(_backend),
    )
    monkeypatch.setattr(
        hardened,
        "brokered_process_probe_command",
        lambda _token: ["probe"],
    )
    monkeypatch.setattr(
        hardened,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["probe"],
            0,
            b"WLMCP_BROKERED_PROCESS=DENIED\r\n",
            b"",
        ),
    )
    monkeypatch.setattr(hardened, "_write_evidence", lambda *_args: None)

    result = hardened.verify_codex_sandbox_live.__wrapped__(settings)

    assert calls == ["source-acl", "base-live-probes", "source-acl"]
    guard = result["source_workspace_read_acl_guard"]
    assert isinstance(guard, dict)
    assert guard["explicit_deny_read"] is True
    assert guard["added_before_verification"] is True
    checks = result["checks"]
    assert isinstance(checks, dict)
    assert checks["brokered_process_creation_denied"] is True


def test_hardened_verifier_rejects_account_change_after_acl_provision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    sid = "S-1-5-21-100-200-300-1004"

    def base(_settings: Settings, *, persist_evidence: bool = True) -> dict[str, object]:
        assert persist_evidence is False
        return {"sandbox_account_identity": {"sid": "S-1-5-21-OTHER"}}

    def wrapped_placeholder(_settings: Settings) -> dict[str, object]:
        raise AssertionError("decorated base wrapper must not be called")

    wrapped_placeholder.__wrapped__ = base  # type: ignore[attr-defined]
    monkeypatch.setattr(hardened, "_base_verify_codex_sandbox_live", wrapped_placeholder)
    monkeypatch.setattr(
        hardened,
        "resolve_sandbox_account_identity",
        lambda: SimpleNamespace(sid=sid),
    )
    monkeypatch.setattr(
        hardened,
        "ensure_source_workspace_read_deny",
        lambda *_args: {"added": True},
    )

    with pytest.raises(RuntimeError, match="account changed"):
        hardened.verify_codex_sandbox_live.__wrapped__(settings)


def test_hardened_verifier_preserves_unverified_result_when_identity_was_not_measured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    sid = "S-1-5-21-100-200-300-1004"
    writes: list[dict[str, object]] = []

    def base(_settings: Settings, *, persist_evidence: bool = True) -> dict[str, object]:
        assert persist_evidence is False
        return {
            "sandbox_account_identity": None,
            "checks": {"simple_command": None},
            "properties": _verified_properties(),
            "diagnostics": {"verification_error": "WFP read-back unavailable"},
            "probe_diagnostics": [],
            "passed": False,
        }

    def wrapped_placeholder(_settings: Settings) -> dict[str, object]:
        raise AssertionError("decorated base wrapper must not be called")

    wrapped_placeholder.__wrapped__ = base  # type: ignore[attr-defined]
    monkeypatch.setattr(hardened, "_base_verify_codex_sandbox_live", wrapped_placeholder)
    monkeypatch.setattr(
        hardened,
        "resolve_sandbox_account_identity",
        lambda: SimpleNamespace(sid=sid),
    )
    monkeypatch.setattr(
        hardened,
        "ensure_source_workspace_read_deny",
        lambda *_args: {"added": False},
    )
    monkeypatch.setattr(hardened, "_write_evidence", lambda _path, value: writes.append(value))

    result = hardened.verify_codex_sandbox_live.__wrapped__(settings)

    assert result["verification_status"] == "unverified"
    assert result["verification_failure_reason"] == "WFP read-back unavailable"
    assert len(writes) == 2


def test_hardened_verifier_skips_followup_after_foundational_setup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    sid = "S-1-5-21-100-200-300-1004"
    writes: list[dict[str, object]] = []

    def base(_settings: Settings, *, persist_evidence: bool = True) -> dict[str, object]:
        assert persist_evidence is False
        return {
            "sandbox_account_identity": {"sid": sid},
            "checks": {"simple_command": None},
            "properties": _verified_properties(),
            "diagnostics": {"verification_error": "setup failed"},
            "probe_diagnostics": [],
            "passed": False,
        }

    def wrapped_placeholder(_settings: Settings) -> dict[str, object]:
        raise AssertionError("decorated base wrapper must not be called")

    wrapped_placeholder.__wrapped__ = base  # type: ignore[attr-defined]
    monkeypatch.setattr(hardened, "_base_verify_codex_sandbox_live", wrapped_placeholder)
    monkeypatch.setattr(
        hardened,
        "resolve_sandbox_account_identity",
        lambda: SimpleNamespace(sid=sid),
    )
    monkeypatch.setattr(
        hardened,
        "ensure_source_workspace_read_deny",
        lambda *_args: {"added": False},
    )
    monkeypatch.setattr(
        hardened,
        "resolve_codex_sandbox_backend",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("follow-up backend must not be resolved")
        ),
    )
    monkeypatch.setattr(
        hardened,
        "_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("follow-up Sandbox must not launch")
        ),
    )
    monkeypatch.setattr(hardened, "_write_evidence", lambda _path, result: writes.append(result))

    result = hardened.verify_codex_sandbox_live.__wrapped__(settings)

    assert result["checks"]["brokered_process_creation_denied"] is None
    assert result["passed"] is False
    assert writes[0]["verification_status"] == "verifying"
    assert writes[0]["passed"] is False
    assert writes[1] == result
    assert result["verification_status"] == "unverified"
