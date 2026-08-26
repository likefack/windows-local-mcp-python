from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_backend import (
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    guard_and_launch_codex_sandbox,
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


def _backend() -> CodexSandboxBackend:
    return CodexSandboxBackend(
        executable=sys.executable,
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
        version="test",
    )


def test_runtime_brokered_preflight_failure_blocks_payload_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    backend = _backend()
    evidence: dict[str, object] = {
        "sandbox_account_identity": {},
        "wfp_guard_binding": {"bound": True},
        "wfp_guard_binding_digest": "guard-digest",
    }
    calls: list[str] = []

    class Identity:
        def as_dict(self) -> dict[str, object]:
            return {}

    class Verification:
        def as_dict(self) -> dict[str, object]:
            return {"verified": True}

    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.require_codex_sandbox_live_verification",
        lambda *_args, **_kwargs: evidence,
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.resolve_sandbox_account_identity",
        lambda: Identity(),
    )
    monkeypatch.setattr(
        "windows_local_mcp.wfp_guard_runtime.ensure_runtime_codex_loopback_guard",
        lambda: Verification(),
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.guard_verification_binding",
        lambda _verification: {"bound": True},
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.guard_verification_binding_digest",
        lambda _verification: "guard-digest",
    )

    def reject_brokered(*_args: object, **_kwargs: object) -> None:
        calls.append("brokered-preflight")
        raise ApprovedSandboxUnavailable("brokered process boundary changed")

    def forbidden_launch(*_args: object, **_kwargs: object) -> object:
        calls.append("payload-launch")
        raise AssertionError("payload must not launch after brokered preflight failure")

    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend._require_brokered_process_creation_denied",
        reject_brokered,
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.launch_codex_sandbox",
        forbidden_launch,
    )

    with pytest.raises(ApprovedSandboxUnavailable, match="brokered process boundary changed"):
        guard_and_launch_codex_sandbox(
            backend,
            settings=settings,
            command=[sys.executable, "-c", "pass"],
            cwd=settings.workspace_root,
            writable_roots=(),
            environment={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            expected_live_evidence=evidence,
        )

    assert calls == ["brokered-preflight"]
