import os
import shutil
import subprocess
import sys
from pathlib import Path

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def test_real_stdio_tools_list_and_file_round_trip(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    git = shutil.which("git.exe") or shutil.which("git")
    assert git is not None
    subprocess.run(
        [git, "init", str(workspace)],
        capture_output=True,
        check=True,
        shell=False,
    )
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    root_text = str(workspace).replace("\\", "\\\\")
    data_text = str(data).replace("\\", "\\\\")
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{root_text}"',
                f'data_dir = "{data_text}"',
                "protect_data_dir_acl = false",
                "git_enabled = true",
            ]
        ),
        encoding="utf-8",
    )

    async def exercise() -> None:
        environment = os.environ.copy()
        environment["LOCAL_MCP_CONFIG"] = str(config)
        environment.pop("LOCAL_MCP_ROOT", None)
        server = StdioServerParameters(
            command=sys.executable,
            args=["-m", "windows_local_mcp.cli", "server"],
            env=environment,
            cwd=str(Path(__file__).parents[1]),
        )
        async with (
            stdio_client(server) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()
            listed = await session.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            assert {"session_info", "write_file", "read_file", "git_info"} <= tools.keys()
            assert tools["read_file"].annotations.read_only_hint is True
            assert tools["write_file"].annotations.destructive_hint is True

            write = await session.call_tool(
                "write_file", {"path": "hello.txt", "content": "hello stdio"}
            )
            assert not write.is_error
            read = await session.call_tool("read_file", {"path": "hello.txt"})
            assert not read.is_error
            assert read.structured_content is not None
            assert read.structured_content["content"] == "hello stdio"

            git_info = await session.call_tool("git_info", {})
            assert not git_info.is_error
            assert git_info.structured_content is not None
            assert "===== status" in git_info.structured_content["content"]
            git_status = await session.call_tool(
                "execute", {"program": "git", "args": ["status", "--short"]}
            )
            assert not git_status.is_error
            assert git_status.structured_content is not None
            assert git_status.structured_content["status"] == "succeeded"

    anyio.run(exercise)
