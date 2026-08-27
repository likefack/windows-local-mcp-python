from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="WLMCP stdio production route is Windows-only")


def _literal_toml_path(path: Path) -> str:
    return str(path.resolve()).replace("'", "''")


def test_cli_stdio_negotiates_and_serves_a_tool() -> None:
    """Pin the real Windows subprocess/wire path that production MCP hosts use."""

    root = Path(tempfile.mkdtemp(prefix="wlmcp-stdio-e2e-"))
    try:
        workspace = root / "workspace"
        data_dir = root / "data"
        scratch = root / "scratch"
        workspace.mkdir()
        config = root / "config.toml"
        config.write_text(
            "\n".join(
                (
                    f"workspace_root = '{_literal_toml_path(workspace)}'",
                    f"data_dir = '{_literal_toml_path(data_dir)}'",
                    f"sandbox_scratch_dir = '{_literal_toml_path(scratch)}'",
                    "filesystem_enabled = false",
                    "git_enabled = false",
                    "approved_sandbox_enabled = false",
                    "approved_host_enabled = false",
                    "protect_data_dir_acl = false",
                    "",
                )
            ),
            encoding="utf-8",
        )

        repository = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["LOCAL_MCP_CONFIG"] = str(config)
        environment["LOCAL_MCP_TRANSPORT"] = "stdio"
        environment["PYTHONPATH"] = str(repository / "src")
        environment.pop("LOCAL_MCP_ROOT", None)

        async def exercise() -> None:
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "windows_local_mcp.cli", "server"],
                env=environment,
                cwd=str(repository),
            )
            async with Client(stdio_client(server)) as client:
                result = await client.call_tool("session_info", {})
                assert result.is_error is False
                assert isinstance(result.structured_content, dict)
                assert result.structured_content.get("workspace_root") == str(workspace.resolve())

        anyio.run(exercise)
    finally:
        shutil.rmtree(root, ignore_errors=True)
