import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from windows_local_mcp.config import Settings, load_settings


def test_rejects_data_dir_inside_workspace(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    with pytest.raises(ValidationError, match="overlap"):
        Settings(workspace_root=root, data_dir=root / ".audit")


def test_rejects_workspace_inside_data_dir(tmp_path: Path) -> None:
    data = tmp_path / "data"
    root = data / "workspace"
    root.mkdir(parents=True)
    with pytest.raises(ValidationError, match="overlap"):
        Settings(workspace_root=root, data_dir=data)


def test_rejects_non_loopback_http(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    with pytest.raises(ValidationError, match="loopback"):
        Settings(
            workspace_root=root,
            data_dir=tmp_path / "data",
            http_enabled=True,
            http_host="0.0.0.0",
        )


def test_rejects_multi_principal_http_without_principal_ownership(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    with pytest.raises(ValidationError, match="multi-principal"):
        Settings(
            workspace_root=root,
            data_dir=tmp_path / "data",
            http_enabled=True,
            http_multi_principal_enabled=True,
        )


def test_rejects_lexical_workspace_overlap_through_symlink(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "audit-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or elevation")
    with pytest.raises(ValidationError, match="lexically overlap"):
        Settings(workspace_root=root, data_dir=link)


def test_load_requires_explicit_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    monkeypatch.delenv("LOCAL_MCP_CONFIG", raising=False)
    with pytest.raises(ValueError, match="explicitly set"):
        load_settings()


def test_disabled_optional_capabilities_do_not_resolve_tools(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    assert not settings.flutter_enabled
    assert not settings.dart_enabled
    assert not settings.adb_enabled
    assert not settings.powershell_enabled


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL integration")
def test_data_dir_acl_grants_current_principal_and_system(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "protected-data"
    settings = Settings(workspace_root=root, data_dir=data, protect_data_dir_acl=True)
    try:
        settings.ensure_directories()
        acl = subprocess.run(
            ["icacls.exe", str(data)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=True,
            shell=False,
        ).stdout
        assert "SYSTEM" in acl
        assert "(F)" in acl
    finally:
        subprocess.run(
            ["icacls.exe", str(data), "/inheritance:e", "/T", "/C"],
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
