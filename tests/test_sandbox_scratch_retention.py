from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.resources import prune_artifacts


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        retention_days=1,
    )
    settings.ensure_directories()
    return settings


def _make_stale(path: Path) -> None:
    old = time.time() - 3 * 24 * 60 * 60
    os.utime(path, (old, old))


def test_prune_removes_readonly_git_projection_artifact(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    assert settings.sandbox_scratch_dir is not None
    stale = settings.sandbox_scratch_dir / "git-broker" / "stale"
    object_file = stale / "repository" / ".git" / "objects" / "00" / "object"
    object_file.parent.mkdir(parents=True)
    object_file.write_bytes(b"git-object")
    object_file.chmod(stat.S_IREAD)
    _make_stale(stale)

    removed = prune_artifacts(settings)

    assert removed >= 1
    assert not stale.exists()


def test_sandbox_scratch_delete_failure_does_not_break_audit_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    assert settings.sandbox_scratch_dir is not None
    stale = settings.sandbox_scratch_dir / "git-broker" / "undeletable"
    stale.mkdir(parents=True)
    (stale / "artifact.bin").write_bytes(b"x")
    _make_stale(stale)

    from windows_local_mcp import resources

    original = resources._remove_artifact

    def deny_only_sandbox_candidate(path: Path) -> None:
        if path == stale:
            raise PermissionError("simulated sandbox-owned artifact")
        original(path)

    monkeypatch.setattr(resources, "_remove_artifact", deny_only_sandbox_candidate)

    store = AuditStore(settings)

    assert store.db_path.is_file()
    assert stale.exists()


def test_trusted_data_dir_retention_failure_remains_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    stale = settings.data_dir / "outputs" / "trusted-artifact.bin"
    stale.write_bytes(b"x")
    _make_stale(stale)

    from windows_local_mcp import resources

    original = resources._remove_artifact

    def deny_trusted_candidate(path: Path) -> None:
        if path == stale:
            raise PermissionError("simulated trusted-store cleanup failure")
        original(path)

    monkeypatch.setattr(resources, "_remove_artifact", deny_trusted_candidate)

    with pytest.raises(PermissionError, match="trusted-store"):
        prune_artifacts(settings)
