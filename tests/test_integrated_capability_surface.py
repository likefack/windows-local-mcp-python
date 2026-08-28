from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


def _load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(workspace).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data_dir).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "adb_enabled = false",
                "approved_sandbox_enabled = false",
                "approved_host_enabled = false",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    return importlib.import_module("windows_local_mcp.server")


def test_session_info_keeps_git_live_marker_and_host_authority_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = _load_server(tmp_path, monkeypatch)
    settings = server.runtime.settings
    settings.git_enabled = True
    settings.git_executable_path = str(tmp_path / "trusted" / "git.exe")
    settings.git_executable_sha256 = "a" * 64
    settings.approved_host_enabled = True

    monkeypatch.setattr(
        server,
        "trusted_helper_identity",
        lambda _settings, program_key: {
            "provenance": "operator-pinned",
            "sha256": "a" * 64,
            "program_key": program_key,
        },
    )
    monkeypatch.setattr(
        server,
        "_codex_sandbox_capability",
        lambda: {
            "configured": False,
            "enabled": False,
            "available": False,
            "execution_route_available": False,
            "live_verified": False,
            "windows_live_verified": False,
        },
    )
    monkeypatch.setattr(
        server,
        "assert_approved_host_runtime_immutable",
        lambda: {
            "version": 1,
            "scope": "complete-runtime",
            "path_count": 12,
            "file_count": 5,
            "directory_count": 4,
            "ancestor_directory_count": 3,
            "digest": "b" * 64,
        },
    )
    monkeypatch.setattr(
        server,
        "assert_approved_host_authority_available",
        lambda: {
            "healthy": True,
            "service_epoch": "integration-epoch",
            "active_operation_id": None,
        },
    )

    result = server.session_info()
    status = result["capabilities"]["status"]

    git = status["git_broker_helper"]
    assert git["configured"] is True
    assert git["enabled"] is True
    assert git["available"] is True
    assert git["live_verified"] is True
    assert git["windows_live_verified"] is True
    assert git["verification_scope"] == "git-specific-live-marker"

    host = status["approved_host"]
    assert host["enabled"] is True
    assert host["available"] is True
    assert host["execution_route_available"] is True
    assert host["live_verified"] is False
    assert host["windows_live_verified"] is False
    assert host["verification_scope"] == "runtime_and_authority_preflight_only"
    assert host["runtime_preflight"]["status"] == "passed"
    assert host["authority_preflight"] == {
        "status": "passed",
        "healthy": True,
        "service_epoch": "integration-epoch",
        "active_operation_id": None,
    }
