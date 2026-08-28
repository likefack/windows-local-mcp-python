from pathlib import Path

import anyio
import pytest
from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from windows_local_mcp.config import Settings
from windows_local_mcp.paths import Workspace
from windows_local_mcp.policy import CommandPolicy, SandboxRouteRequiredError


def _result_text(result: object) -> str:
    content = getattr(result, "content", [])
    return "\n".join(
        str(getattr(item, "text", ""))
        for item in content
        if getattr(item, "text", None) is not None
    )


def test_content_bearing_git_uses_explicit_model_visible_route_error(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=True,
    )
    settings.ensure_directories()
    policy = CommandPolicy(settings, Workspace(settings))

    with pytest.raises(SandboxRouteRequiredError, match="request_sandbox_command") as raised:
        policy.normalize_safe(program="git", args=["show", "--patch"], cwd=".")

    assert isinstance(raised.value, PermissionError)
    assert isinstance(raised.value, ToolError)


def test_mcp_surfaces_only_explicit_route_guidance() -> None:
    server = MCPServer("policy-error-visibility-test")

    @server.tool()
    def route_to_sandbox() -> None:
        raise SandboxRouteRequiredError(
            "content-bearing Git output is not eligible for Automatic Git; "
            "use request_sandbox_command"
        )

    @server.tool()
    def internal_failure() -> None:
        raise PermissionError("sensitive-internal-path-must-stay-masked")

    async def exercise() -> None:
        async with Client(server) as client:
            routed = await client.call_tool("route_to_sandbox", {})
            assert routed.is_error
            routed_text = _result_text(routed)
            assert "request_sandbox_command" in routed_text
            assert "content-bearing Git" in routed_text

            internal = await client.call_tool("internal_failure", {})
            assert internal.is_error
            internal_text = _result_text(internal)
            assert "sensitive-internal-path-must-stay-masked" not in internal_text
            assert "Error executing tool internal_failure" in internal_text

    anyio.run(exercise)
