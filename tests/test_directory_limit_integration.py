import os
import sys
from pathlib import Path

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def test_list_directory_accepts_limit_and_rejects_limit_plus_one(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    small = workspace / "small"
    small.mkdir()
    large = workspace / "large"
    large.mkdir()

    for index in range(3):
        (small / f"file-{index}.txt").write_text("ok", encoding="utf-8")
    for index in range(4):
        (large / f"file-{index}.txt").write_text("too many", encoding="utf-8")

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
                "git_enabled = false",
                "max_directory_entries = 3",
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

            within_limit = await session.call_tool("list_directory", {"path": "small"})
            assert not within_limit.is_error
            assert within_limit.structured_content is not None
            assert len(within_limit.structured_content["entries"]) == 3

            over_limit = await session.call_tool("list_directory", {"path": "large"})
            assert over_limit.is_error

    anyio.run(exercise)
