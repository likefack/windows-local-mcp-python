from pathlib import Path

import pytest

from windows_local_mcp import git_snapshot
from windows_local_mcp.config import Settings


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=True,
    )
    settings.ensure_directories()
    return settings


def _install_snapshot_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, message: str
) -> None:
    monkeypatch.setattr(
        git_snapshot,
        "trusted_helper_identity",
        lambda _settings, _program: {"path": str(tmp_path / "git.exe")},
    )
    monkeypatch.setattr(
        git_snapshot,
        "hold_verified_path",
        lambda path, **_kwargs: Path(path),
    )
    monkeypatch.setattr(git_snapshot, "release_verified_hold", lambda _path: None)

    def fail_batch(**_kwargs: object) -> list[object]:
        raise RuntimeError(message)

    monkeypatch.setattr(git_snapshot, "run_git_broker_batch", fail_batch)


def test_required_git_snapshot_preserves_broker_root_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    _install_snapshot_failure(monkeypatch, tmp_path, "projection path overflow")

    with pytest.raises(RuntimeError, match="projection path overflow"):
        git_snapshot.capture_git_snapshot(
            settings=settings,
            operation_id="operation",
            stage="requested",
        )


def test_optional_git_snapshot_remains_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    _install_snapshot_failure(monkeypatch, tmp_path, "optional snapshot failed")

    assert (
        git_snapshot.capture_git_snapshot(
            settings=settings,
            operation_id="operation",
            stage="telemetry",
            required=False,
        )
        is None
    )
