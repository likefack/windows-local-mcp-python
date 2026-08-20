import os
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings, load_settings
from windows_local_mcp.config_binding import export_config_binding
from windows_local_mcp.control_plane import create_worker_context, load_worker_context


def _write_config(tmp_path: Path) -> tuple[Path, Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "selected.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{workspace.as_posix()}"',
                f'data_dir = "{data.as_posix()}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
            ]
        ),
        encoding="utf-8",
    )
    return workspace, data, config


def _load_file_backed_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Settings, Path]:
    workspace, data, config = _write_config(tmp_path)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    settings = load_settings()
    assert settings.workspace_root == workspace.resolve()
    assert settings.data_dir == data.resolve()
    return settings, config


def test_real_config_selection_survives_worker_context_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, config = _load_file_backed_settings(tmp_path, monkeypatch)
    expected = export_config_binding(settings)

    context_path, context_digest = create_worker_context(
        settings, "real-config-worker-round-trip"
    )
    loaded = load_worker_context(
        str(context_path), context_digest, "real-config-worker-round-trip"
    )

    assert export_config_binding(loaded) == expected
    assert loaded.selection_info()["config_source"] == "LOCAL_MCP_CONFIG"
    assert loaded.selection_info()["config_path"] == str(config.resolve(strict=True))


def test_real_config_content_tamper_invalidates_worker_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, config = _load_file_backed_settings(tmp_path, monkeypatch)
    context_path, context_digest = create_worker_context(
        settings, "real-config-content-tamper"
    )

    config.write_text(
        config.read_text(encoding="utf-8") + "\nfilesystem_enabled = false\n",
        encoding="utf-8",
    )

    with pytest.raises((PermissionError, RuntimeError)):
        load_worker_context(
            str(context_path), context_digest, "real-config-content-tamper"
        )


def test_real_config_same_content_replacement_invalidates_worker_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, config = _load_file_backed_settings(tmp_path, monkeypatch)
    context_path, context_digest = create_worker_context(
        settings, "real-config-replacement"
    )

    replacement = tmp_path / "replacement.toml"
    replacement.write_bytes(config.read_bytes())
    os.replace(replacement, config)

    with pytest.raises(RuntimeError, match="file identity changed before use"):
        load_worker_context(
            str(context_path), context_digest, "real-config-replacement"
        )
