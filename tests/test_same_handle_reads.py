from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest
from PIL import Image as PILImage

from windows_local_mcp import approval
from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace, read_verified_bytes
from windows_local_mcp.workspace_history import capture_workspace_state


def _workspace(tmp_path: Path) -> Workspace:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings.ensure_directories()
    return Workspace(settings)


def _load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "server-workspace"
    root.mkdir()
    data = tmp_path / "server-data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(root).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    return importlib.import_module("windows_local_mcp.server"), root


@pytest.mark.skipif(os.name != "nt", reason="same-HANDLE read is the Windows security boundary")
def test_verified_read_consumes_the_validation_handle_without_path_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path)
    target = workspace.root / "safe.txt"
    target.write_bytes(b"safe")
    verified = workspace.resolve_existing("safe.txt", allow_directory=False)
    real_open = Path.open

    def guarded_open(self: Path, *args, **kwargs):
        if Path(self).resolve(strict=False) == target.resolve(strict=False):
            raise AssertionError("verified workspace file was reopened by pathname")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    assert read_verified_bytes(verified, 1024) == b"safe"


@pytest.mark.skipif(os.name != "nt", reason="same-HANDLE read is the Windows security boundary")
def test_broker_workspace_read_sinks_do_not_reopen_verified_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = _load_server(tmp_path, monkeypatch)
    text = root / "note.txt"
    text.write_bytes(b"hello\n")
    csv = root / "table.csv"
    csv.write_bytes(b"a,b\n1,2\n")
    artifact = root / "artifact.bin"
    artifact.write_bytes(b"artifact")
    image = root / "pixel.png"
    PILImage.new("RGB", (2, 2), "white").save(image)
    guarded = {item.resolve(strict=False) for item in (text, csv, artifact, image)}
    real_open = Path.open

    def guarded_open(self: Path, *args, **kwargs):
        if Path(self).resolve(strict=False) in guarded:
            raise AssertionError(f"workspace source was reopened by pathname: {self}")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    assert server.read_file("note.txt")["content"] == "hello"
    server.get_image("pixel.png")
    assert server.structured_file_inspect("table.csv")["format"] == "csv"
    server.artifact_download_begin("artifact.bin")
    capture_workspace_state(
        server.runtime.settings, "same-handle-checkpoint", "before", paths={"note.txt"}
    )
    staged = tmp_path / "approval-stage"
    staged.mkdir()
    records = approval._copy_tree_bounded(
        source=root,
        destination=staged,
        settings=server.runtime.settings,
        workspace=server.runtime.workspace,
    )
    assert records

    dart_tool = root / ".dart_tool"
    dart_tool.mkdir()
    package_config = dart_tool / "package_config.json"
    package_config.write_text('{"packages": []}', encoding="utf-8")
    guarded.add(package_config.resolve(strict=False))
    staged_cwd = tmp_path / "dart-staged-cwd"
    (staged_cwd / ".dart_tool").mkdir(parents=True)
    staged_config = staged_cwd / ".dart_tool" / "package_config.json"
    staged_config.write_text('{"packages": []}', encoding="utf-8")
    dependency_stage = tmp_path / "dart-dependency-stage"
    dependency_stage.mkdir()
    dart_records = [approval._file_record(staged_config)]
    dart_records[0].update(
        {"source_path": str(package_config), "staged_path": str(staged_config)}
    )
    assert approval._stage_dart_package_dependencies(
        source_cwd=root,
        staged_cwd=staged_cwd,
        stage_root=dependency_stage,
        settings=server.runtime.settings,
        workspace=server.runtime.workspace,
        records=dart_records,
        entry_budget=approval._EntryBudget(server.runtime.settings),
    ) == []


def test_session_info_names_actual_read_and_commit_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _root = _load_server(tmp_path, monkeypatch)
    properties = server.session_info()["capabilities"]["status"]["broker"]["properties"]
    assert "filesystem_identity_lock_replace" not in properties
    assert "same_handle_workspace_read" in properties
    assert "transactional_workspace_commit" in properties
    if os.name == "nt":
        assert properties["same_handle_workspace_read"]["status"] == "verified"
        assert properties["transactional_workspace_commit"]["status"] == "verified"
    else:
        assert properties["same_handle_workspace_read"]["status"] == "unsupported"
        assert properties["transactional_workspace_commit"]["status"] == "unsupported"
        assert properties["same_handle_workspace_read"]["production_supported"] is False
        assert properties["transactional_workspace_commit"]["production_supported"] is False
