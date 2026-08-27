from datetime import UTC, datetime, timedelta
from pathlib import Path

from windows_local_mcp.config import Settings
from windows_local_mcp.resources import prune_artifacts


def test_prune_artifacts_removes_stale_git_broker_scratch(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        retention_days=1,
    )
    settings.ensure_directories()

    stale = settings.sandbox_scratch_dir / "git-broker" / "stale-operation"
    stale.mkdir(parents=True)
    (stale / "repository.bin").write_bytes(b"stale")
    old = (datetime.now(UTC) - timedelta(days=2)).timestamp()
    for path in (stale / "repository.bin", stale):
        path.touch()
        import os

        os.utime(path, (old, old))

    removed = prune_artifacts(settings)

    assert removed >= 1
    assert not stale.exists()
