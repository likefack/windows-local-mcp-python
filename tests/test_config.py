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


def test_explicit_config_workspace_is_not_overridden_by_ambient_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = tmp_path / "configured"
    ambient = tmp_path / "ambient"
    configured.mkdir()
    ambient.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "selected.toml"
    config.write_text(
        f'workspace_root = "{configured.as_posix()}"\n'
        f'data_dir = "{data.as_posix()}"\n'
        "protect_data_dir_acl = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.setenv("LOCAL_MCP_ROOT", str(ambient))
    with pytest.raises(ValueError, match="conflicts"):
        load_settings()


def test_session_selection_metadata_reports_explicit_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = tmp_path / "selected.toml"
    config.write_text(
        f'workspace_root = "{workspace.as_posix()}"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        "protect_data_dir_acl = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    settings = load_settings()
    assert settings.selection_info()["workspace_source"] == "explicit_config"
    assert settings.selection_info()["ambient_root_overrode_config"] is False


def test_active_config_must_be_outside_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = workspace / "config.local.toml"
    config.write_text(
        f'workspace_root = "{workspace.as_posix()}"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        "protect_data_dir_acl = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    with pytest.raises(ValueError, match="outside workspace_root"):
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


def test_helper_path_and_hash_must_be_configured_together(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"git")
    with pytest.raises(ValueError, match="must be configured together"):
        Settings(
            workspace_root=root,
            data_dir=tmp_path / "data",
            protect_data_dir_acl=False,
            git_executable_path=executable,
        )


def test_enabled_sandbox_cannot_disable_live_verification(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    with pytest.raises(ValueError, match="cannot be disabled"):
        Settings(
            workspace_root=root,
            data_dir=tmp_path / "data",
            protect_data_dir_acl=False,
            approved_sandbox_enabled=True,
            approved_sandbox_require_live_verification=False,
        )


def test_physical_alias_overlap_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
    )

    def aliased(path: Path) -> str:
        if path.name in {"data", "scratch"}:
            return r"\\?\Volume{test}\shared"
        return r"\\?\Volume{test}\workspace"

    monkeypatch.setattr("windows_local_mcp.config.physical_filesystem_path", aliased)
    with pytest.raises(ValueError, match="physically overlap"):
        settings.ensure_directories()


def test_obsolete_appcontainer_configuration_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = tmp_path / "obsolete.toml"
    config.write_text(
        f'workspace_root = "{workspace.as_posix()}"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        "protect_data_dir_acl = false\n"
        'safe_network_isolation_mode = "appcontainer"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)

    with pytest.raises(ValueError, match="obsolete Safe Tier/AppContainer"):
        load_settings()


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
        namespace = data / "control-plane" / "namespace.json"
        assert namespace.read_bytes()
        nested = data / "control-plane" / "acl-roundtrip.bin"
        nested.write_bytes(b"roundtrip")
        assert nested.read_bytes() == b"roundtrip"
        # The marker path avoids a recursive ACL reset on ordinary startup while still
        # checking that the protected namespace remains usable by the bound principal.
        settings.ensure_directories()
    finally:
        subprocess.run(
            ["icacls.exe", str(data), "/inheritance:e", "/T", "/C"],
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
