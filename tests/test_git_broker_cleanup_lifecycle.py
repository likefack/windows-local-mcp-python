from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_backend import SANDBOX_SECURITY_PROPERTIES


_BUILTINS = b"status diff log show rev-parse ls-files\n"


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        git_enabled=True,
    )
    settings.ensure_directories()
    return settings


def _containment() -> SimpleNamespace:
    evidence = {
        "version": 5,
        "properties": {
            name: {"status": "verified"} for name in SANDBOX_SECURITY_PROPERTIES
        },
        "checks": {},
    }
    backend = SimpleNamespace(
        version="test-backend",
        as_dict=lambda: {"version": "test-backend", "identity": "bound"},
    )
    return SimpleNamespace(
        backend=backend,
        live_evidence=evidence,
        policy_digest="containment-policy",
    )


def _probe_results() -> list[SimpleNamespace]:
    digest = "c" * 64
    return [
        SimpleNamespace(returncode=0, stdout=b"true\n", stderr=b"", snapshot_digest=digest),
        SimpleNamespace(returncode=0, stdout=b"", stderr=b"", snapshot_digest=digest),
        SimpleNamespace(returncode=0, stdout=_BUILTINS, stderr=b"", snapshot_digest=digest),
    ]


def test_live_verifier_cleans_its_exact_readonly_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    assert settings.sandbox_scratch_dir is not None
    from windows_local_mcp import git_broker_live_verify

    identity = {
        "path": str(tmp_path / "git.exe"),
        "sha256": "a" * 64,
        "size": 1,
        "mtime_ns": 1,
        "stable_file_identity": {"platform": "test", "id": 1},
        "provenance": "explicit-local-config",
    }
    containment = _containment()
    observed: dict[str, Path] = {}

    monkeypatch.setattr(
        git_broker_live_verify, "configured_git_identity", lambda _settings: identity
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )

    def fake_batch(**kwargs: object) -> list[SimpleNamespace]:
        token = str(kwargs["token"])
        root = settings.sandbox_scratch_dir / "git-broker" / token
        object_file = root / "repository" / ".git" / "objects" / "00" / "object"
        object_file.parent.mkdir(parents=True)
        object_file.write_bytes(b"object")
        object_file.chmod(stat.S_IREAD)
        observed["root"] = root
        return _probe_results()

    monkeypatch.setattr(git_broker_live_verify, "run_git_broker_batch", fake_batch)

    marker = git_broker_live_verify.verify_git_broker_live(settings)

    assert marker["route_eligible"] is True
    assert "root" in observed
    assert not observed["root"].exists()


def test_live_verifier_cleanup_is_scoped_to_its_operation_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    assert settings.sandbox_scratch_dir is not None
    from windows_local_mcp import git_broker_live_verify

    identity = {
        "path": str(tmp_path / "git.exe"),
        "sha256": "a" * 64,
        "size": 1,
        "mtime_ns": 1,
        "stable_file_identity": {"platform": "test", "id": 1},
        "provenance": "explicit-local-config",
    }
    containment = _containment()
    unrelated = settings.sandbox_scratch_dir / "git-broker" / "other-operation"
    unrelated.mkdir(parents=True)
    (unrelated / "keep.bin").write_bytes(b"keep")

    monkeypatch.setattr(
        git_broker_live_verify, "configured_git_identity", lambda _settings: identity
    )
    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_containment",
        lambda _settings, _identity: containment,
    )

    def fake_batch(**kwargs: object) -> list[SimpleNamespace]:
        token = str(kwargs["token"])
        root = settings.sandbox_scratch_dir / "git-broker" / token
        root.mkdir(parents=True)
        (root / "artifact.bin").write_bytes(os.urandom(8))
        return _probe_results()

    monkeypatch.setattr(git_broker_live_verify, "run_git_broker_batch", fake_batch)

    marker = git_broker_live_verify.verify_git_broker_live(settings)

    assert marker["route_eligible"] is True
    assert unrelated.is_dir()
    assert (unrelated / "keep.bin").read_bytes() == b"keep"
