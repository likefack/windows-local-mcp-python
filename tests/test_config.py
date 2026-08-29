import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from windows_local_mcp.config import (
    Settings,
    _legacy_acl_digest_candidates_from_raw,
    load_settings,
    validate_configuration_candidate,
)


def test_configuration_candidate_uses_final_path_defaults_without_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "日本語 workspace"
    workspace.mkdir()
    local_app_data = tmp_path / "local app data"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    candidate = tmp_path / "config.toml.tmp-candidate"
    final_config = tmp_path / "settings" / "config.toml"
    candidate.write_text(
        f'workspace_root = "{workspace.as_posix()}"\n',
        encoding="utf-8",
    )

    settings = validate_configuration_candidate(
        candidate, final_config_path=final_config
    )

    assert str(settings.data_dir).startswith(str(local_app_data))
    assert settings.sandbox_scratch_dir is not None
    assert not settings.data_dir.exists()
    assert not settings.sandbox_scratch_dir.exists()
    assert not list(tmp_path.rglob("namespace.json"))
    assert not list(tmp_path.rglob(".acl-policy.json"))


def test_configuration_candidate_rejects_roots_and_invalid_existing_paths(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    final_config = tmp_path / "settings" / "config.toml"
    root_candidate = tmp_path / "root.toml"
    root_candidate.write_text(
        f'workspace_root = "{Path(tmp_path.anchor).as_posix()}"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        "protect_data_dir_acl = false\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="drive root"):
        validate_configuration_candidate(root_candidate, final_config_path=final_config)

    invalid_data = tmp_path / "not-a-directory"
    invalid_data.write_text("file", encoding="utf-8")
    invalid_candidate = tmp_path / "invalid.toml"
    invalid_candidate.write_text(
        f'workspace_root = "{workspace.as_posix()}"\n'
        f'data_dir = "{invalid_data.as_posix()}"\n'
        "protect_data_dir_acl = false\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must be a directory"):
        validate_configuration_candidate(invalid_candidate, final_config_path=final_config)


def test_configuration_candidate_rejects_reparse_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    workspace_link = tmp_path / "workspace-link"
    try:
        workspace_link.symlink_to(workspace, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlink is unavailable: {error}")
    candidate = tmp_path / "reparse.toml"
    candidate.write_text(
        f'workspace_root = "{workspace_link.as_posix()}"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        "protect_data_dir_acl = false\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reparse point"):
        validate_configuration_candidate(
            candidate, final_config_path=tmp_path / "settings" / "config.toml"
        )


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


def test_legacy_acl_digest_candidates_bridge_windows_console_encodings() -> None:
    logical = (
        "C:\\日本語\\data USER:(F)\r\n"
        "1 個のファイルを正常に処理しました。0 個のファイルを処理できませんでした\r\n"
    )
    legacy_raw = logical.encode("cp932")
    legacy_text = legacy_raw.decode("utf-8", errors="replace")
    legacy_digest = hashlib.sha256(legacy_text.encode("utf-8")).hexdigest()

    current_raw = logical.encode("utf-8")
    candidates = _legacy_acl_digest_candidates_from_raw(current_raw)

    assert legacy_digest in candidates


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
        acl_marker = data / ".acl-policy.json"
        marker_payload = json.loads(acl_marker.read_text(encoding="utf-8"))
        assert marker_payload["version"] == 2
        assert isinstance(marker_payload["root_dacl_sddl_sha256"], str)
        legacy_acl = subprocess.run(
            ["icacls.exe", str(data)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=True,
            shell=False,
        ).stdout
        legacy_digest = hashlib.sha256(legacy_acl.encode("utf-8")).hexdigest()
        acl_marker.write_text(
            json.dumps(
                {
                    "version": 1,
                    "sid": marker_payload["sid"],
                    "root_acl_sha256": legacy_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        settings.ensure_directories()
        migrated_payload = json.loads(acl_marker.read_text(encoding="utf-8"))
        assert migrated_payload["version"] == 2
        marker_bytes = acl_marker.read_bytes()
        acl_marker.unlink()
        with pytest.raises(PermissionError, match="marker is missing"):
            settings.ensure_directories()
        acl_marker.write_bytes(marker_bytes)

        tamper = subprocess.run(
            ["icacls.exe", str(data), "/grant", "*S-1-1-0:(RX)"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            shell=False,
        )
        assert tamper.returncode == 0, tamper.stderr or tamper.stdout
        with pytest.raises(PermissionError, match="ACL changed after provisioning"):
            settings.ensure_directories()
    finally:
        subprocess.run(
            ["icacls.exe", str(data), "/remove:g", "*S-1-1-0", "/C"],
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
        subprocess.run(
            ["icacls.exe", str(data), "/inheritance:e", "/T", "/C"],
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
