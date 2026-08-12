import os
from pathlib import Path

import pytest

from windows_local_mcp.child_env import (
    build_allowlisted_environment,
    build_command_environment,
    build_worker_environment,
    sanitize_executable_search_path,
    sanitize_process_environment,
)
from windows_local_mcp.config import Settings


def test_child_environment_does_not_inherit_unlisted_values() -> None:
    source = {
        "PATH": r"C:\Windows\System32",
        "SYSTEMROOT": r"C:\Windows",
        "UNRELATED_SECRET": "must-not-leak",
        "PYTHONPATH": r"C:\hostile",
        "GIT_DIR": r"C:\outside\.git",
    }

    child = build_allowlisted_environment(source)

    assert child["PATH"] == source["PATH"]
    assert child["SYSTEMROOT"] == source["SYSTEMROOT"]
    assert "UNRELATED_SECRET" not in child
    assert "PYTHONPATH" not in child
    assert "GIT_DIR" not in child


def test_explicit_safe_environment_name_can_be_added() -> None:
    source = {"PATH": "base", "MY_BUILD_FLAG": "enabled", "OTHER": "hidden"}

    child = build_command_environment(
        source,
        extra_names=["MY_BUILD_FLAG"],
        nonce="nonce-1",
    )

    assert child["MY_BUILD_FLAG"] == "enabled"
    assert "OTHER" not in child
    assert child["WINDOWS_LOCAL_MCP_JOB_NONCE"] == "nonce-1"


@pytest.mark.parametrize(
    "name",
    [
        "PYTHONPATH",
        "NODE_OPTIONS",
        "JAVA_TOOL_OPTIONS",
        "GIT_DIR",
        "GIT_CONFIG_COUNT",
        "LOCAL_MCP_CONFIG",
        "WINDOWS_LOCAL_MCP_JOB_NONCE",
    ],
)
def test_unsafe_environment_names_cannot_be_allowlisted(tmp_path: Path, name: str) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(ValueError):
        Settings(
            workspace_root=workspace,
            data_dir=tmp_path / "data",
            protect_data_dir_acl=False,
            child_environment_allowlist=[name],
        )


def test_worker_environment_keeps_only_required_internal_values() -> None:
    source = {
        "PATH": "base",
        "LOCAL_MCP_CONFIG": r"C:\config.toml",
        "LOCAL_MCP_ROOT": r"C:\workspace",
        "LOCAL_MCP_TRANSPORT": "streamable-http",
        "LOCAL_MCP_HOST": "127.0.0.1",
        "PRIVATE_TOKEN": "secret",
    }

    worker = build_worker_environment(source, nonce="nonce-2")

    assert worker["LOCAL_MCP_CONFIG"] == source["LOCAL_MCP_CONFIG"]
    assert worker["LOCAL_MCP_ROOT"] == source["LOCAL_MCP_ROOT"]
    assert worker["LOCAL_MCP_TRANSPORT"] == source["LOCAL_MCP_TRANSPORT"]
    assert "LOCAL_MCP_HOST" not in worker
    assert "PRIVATE_TOKEN" not in worker
    assert worker["WINDOWS_LOCAL_MCP_JOB_NONCE"] == "nonce-2"


def test_process_environment_is_reduced_in_place() -> None:
    environment = {
        "PATH": "base",
        "SYSTEMROOT": r"C:\Windows",
        "MY_BUILD_FLAG": "enabled",
        "PRIVATE_TOKEN": "secret",
        "LOCAL_MCP_CONFIG": r"C:\config.toml",
        "LOCAL_MCP_TRANSPORT": "stdio",
        "GIT_DIR": r"C:\outside\.git",
    }

    sanitize_process_environment(
        environment,
        extra_names=["MY_BUILD_FLAG"],
    )

    assert environment["PATH"] == "base"
    assert environment["MY_BUILD_FLAG"] == "enabled"
    assert environment["LOCAL_MCP_CONFIG"] == r"C:\config.toml"
    assert environment["LOCAL_MCP_TRANSPORT"] == "stdio"
    assert "PRIVATE_TOKEN" not in environment
    assert "GIT_DIR" not in environment


def test_search_path_skips_inaccessible_ambient_entry_without_weakening_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = tmp_path / "workspace"
    prepend = tmp_path / "trusted-launcher"
    allowed = tmp_path / "allowed-tools"
    inaccessible = tmp_path / "inaccessible-alias"
    for directory in (forbidden, prepend, allowed, inaccessible):
        directory.mkdir()
    original_resolve = Path.resolve

    def resolve_with_inaccessible_alias(self: Path, strict: bool = False) -> Path:
        if self == inaccessible:
            raise PermissionError("simulated inaccessible App Execution Alias")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolve_with_inaccessible_alias)
    environment = {"PATH": os.pathsep.join((str(inaccessible), str(allowed)))}

    sanitize_executable_search_path(
        environment,
        forbidden_roots=(forbidden,),
        prepend=(prepend,),
    )

    assert environment["PATH"].split(os.pathsep) == [str(prepend), str(allowed)]
