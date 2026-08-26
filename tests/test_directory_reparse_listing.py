import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from windows_local_mcp.paths import release_verified_hold

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows reparse semantics are the directory-listing security boundary",
)


def load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
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
    server = importlib.import_module("windows_local_mcp.server")
    return server, root


def create_junction(link: Path, target: Path) -> None:
    subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
    )


def entry_types(result: dict[str, object]) -> dict[str, str]:
    entries = result["entries"]
    assert isinstance(entries, list)
    return {
        str(entry["name"]): str(entry["type"])
        for entry in entries
        if isinstance(entry, dict)
    }


def test_list_directory_does_not_follow_external_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    create_junction(root / "external-junction", outside)
    (root / "normal-dir").mkdir()
    (root / "normal.txt").write_text("inside", encoding="utf-8")

    types = entry_types(server.list_directory("."))

    assert types["normal-dir"] == "directory"
    assert types["normal.txt"] == "file"
    # Reparse entries remain opaque: the distinct type prevents callers from treating the
    # target as either an ordinary file or a safe-to-traverse workspace directory.
    assert types["external-junction"] == "reparse"


def test_list_directory_does_not_follow_external_directory_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "external-symlink"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink creation is unavailable: {error}")

    types = entry_types(server.list_directory("."))

    assert types["external-symlink"] == "reparse"


def test_listed_reparse_child_is_dir_uses_parent_enumeration_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    create_junction(root / "external-junction", outside)

    directory = server.runtime.workspace.resolve_directory(".")
    try:
        child = next(entry for entry in directory.iterdir() if entry.name == "external-junction")

        def forbidden_child_stat(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("listed child type must not stat the child target")

        monkeypatch.setattr(type(child), "stat", forbidden_child_stat)
        assert child.is_dir() is False
    finally:
        release_verified_hold(directory)
