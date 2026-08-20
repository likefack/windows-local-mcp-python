from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.config_binding import export_config_binding
from windows_local_mcp.control_plane import create_worker_context, load_worker_context


def _settings_with_config(tmp_path: Path, config: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings._config_selection_source = "LOCAL_MCP_CONFIG"
    settings._config_path = str(config.resolve(strict=True))
    settings._workspace_selection_source = "explicit_config"
    settings._ambient_root_present = False
    settings.ensure_directories()
    return settings


def test_config_binding_preserves_selector_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.toml"
    config.write_text("git_enabled = false\n", encoding="utf-8")
    selector = tmp_path / "selected.toml"
    try:
        selector.symlink_to(config)
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or elevation")
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(selector))
    settings = _settings_with_config(tmp_path, config)

    binding = export_config_binding(settings)

    assert binding["config_selector_path"] == str(selector.absolute())
    assert binding["config_path"] == str(config.resolve(strict=True))


def test_worker_context_rejects_retargeted_config_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config.toml"
    config.write_text("git_enabled = false\n", encoding="utf-8")
    replacement = tmp_path / "replacement.toml"
    replacement.write_text("git_enabled = true\n", encoding="utf-8")
    selector = tmp_path / "selected.toml"
    try:
        selector.symlink_to(config)
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or elevation")
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(selector))
    settings = _settings_with_config(tmp_path, config)
    context, digest = create_worker_context(settings, "selector-retarget")

    selector.unlink()
    selector.symlink_to(replacement)

    with pytest.raises(RuntimeError, match="selector was retargeted"):
        load_worker_context(str(context), digest, "selector-retarget")


def test_direct_active_config_falls_back_to_resolved_path_selector(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("git_enabled = false\n", encoding="utf-8")
    settings = _settings_with_config(tmp_path, config)

    binding = export_config_binding(settings)

    assert binding["config_selector_path"] == str(config.resolve(strict=True))
