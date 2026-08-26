from __future__ import annotations

import importlib
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from windows_local_mcp.approved_host_policy import require_approved_host_target
from windows_local_mcp.config import Settings
from windows_local_mcp.policy import NormalizedCommand
from windows_local_mcp.tool_safety import capture_executable_identity


def _settings(tmp_path: Path, *, trusted_adb: Path | None = None) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    values: dict[str, object] = {
        "workspace_root": workspace,
        "data_dir": tmp_path / "data",
        "sandbox_scratch_dir": tmp_path / "scratch",
        "protect_data_dir_acl": False,
    }
    if trusted_adb is not None:
        values.update(
            adb_enabled=True,
            adb_executable_path=trusted_adb,
            adb_executable_sha256=sha256(trusted_adb.read_bytes()).hexdigest(),
        )
    settings = Settings(**values)
    settings.ensure_directories()
    return settings


def _normalized(executable: Path, program_key: str) -> NormalizedCommand:
    identity = capture_executable_identity(executable, provenance="approval-request")
    return NormalizedCommand(
        executable=str(executable.resolve()),
        args=["--version"],
        cwd=str(executable.parent),
        display_command=[str(executable.resolve()), "--version"],
        program_key=program_key,
        executable_identity=identity,
    )


@pytest.mark.parametrize(
    "program_key",
    ["dotnet", "java", "ruby", "perl", "msbuild", "gradle", "mvn", "cmake"],
)
def test_unclassified_runtime_cannot_enter_approved_host(
    tmp_path: Path, program_key: str
) -> None:
    settings = _settings(tmp_path)
    executable = tmp_path / "installed" / f"{program_key}.exe"
    executable.parent.mkdir(exist_ok=True)
    executable.write_bytes(b"installed runtime")

    with pytest.raises(PermissionError, match="request_sandbox_command"):
        require_approved_host_target(settings, _normalized(executable, program_key))


def test_same_name_adb_alias_does_not_gain_approved_host_eligibility(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted" / "adb.exe"
    trusted.parent.mkdir()
    trusted.write_bytes(b"trusted adb")
    alias = tmp_path / "other" / "adb.exe"
    alias.parent.mkdir()
    alias.write_bytes(b"different adb")
    settings = _settings(tmp_path, trusted_adb=trusted)

    with pytest.raises(PermissionError, match="configured trusted identity"):
        require_approved_host_target(settings, _normalized(alias, "adb"))


def test_configured_identity_pinned_adb_is_eligible_for_approved_host(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted" / "adb.exe"
    trusted.parent.mkdir()
    trusted.write_bytes(b"trusted adb")
    settings = _settings(tmp_path, trusted_adb=trusted)

    require_approved_host_target(settings, _normalized(trusted, "adb"))


def _load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "server-workspace"
    root.mkdir()
    data = tmp_path / "server-data"
    config = tmp_path / "server-config.toml"
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


def test_server_host_gate_rejects_runtime_outside_legacy_loader_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = _load_server(tmp_path, monkeypatch)
    executable = tmp_path / "installed" / "dotnet.exe"
    executable.parent.mkdir(exist_ok=True)
    executable.write_bytes(b"installed dotnet")
    normalized = NormalizedCommand(
        executable=str(executable.resolve()),
        args=["run"],
        cwd=str(root),
        display_command=[str(executable.resolve()), "run"],
        program_key="dotnet",
        executable_identity=capture_executable_identity(
            executable, provenance="approval-request"
        ),
    )
    monkeypatch.setattr(
        server.runtime.policy,
        "normalize_host",
        lambda **_kwargs: normalized,
    )

    with pytest.raises(PermissionError, match="request_sandbox_command"):
        server.request_host_command(
            [str(executable), "run"],
            reason="adversarial runtime must remain in Sandbox",
            workspace_write=True,
        )

    records = server.runtime.audit.list_operations(limit=10)
    assert any(
        record["tool_name"] == "request_host_command"
        and record["status"] == "rejected"
        for record in records
    )
