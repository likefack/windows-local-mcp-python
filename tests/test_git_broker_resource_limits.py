from pathlib import Path

from windows_local_mcp.config import Settings
from windows_local_mcp.git_broker_sandbox import _repo_limits


def _settings(tmp_path: Path, scratch_bytes: int) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        max_sandbox_scratch_bytes=scratch_bytes,
    )
    settings.ensure_directories()
    return settings


def test_git_repository_projection_never_exceeds_half_scratch_quota(tmp_path: Path) -> None:
    for scratch_bytes in (1024 * 1024, 16 * 1024 * 1024, 512 * 1024 * 1024):
        byte_limit, _entry_limit = _repo_limits(
            _settings(tmp_path / str(scratch_bytes), scratch_bytes)
        )
        assert byte_limit <= scratch_bytes // 2


def test_git_repository_projection_has_no_legacy_16_mib_floor(tmp_path: Path) -> None:
    settings = _settings(tmp_path, 1024 * 1024)

    byte_limit, _entry_limit = _repo_limits(settings)

    assert byte_limit == 512 * 1024
