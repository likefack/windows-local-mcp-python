import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def _tool_result_text(result: object) -> str:
    content = getattr(result, "content", [])
    return "\n".join(
        str(getattr(item, "text", ""))
        for item in content
        if getattr(item, "text", None) is not None
    )


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _ensure_launcher_runtime(repository_root: Path) -> bool:
    development_python = repository_root / ".venv" / "Scripts" / "python.exe"
    if development_python.is_file():
        return False
    development_root = repository_root / ".venv"
    if development_root.exists():
        pytest.skip("repository .venv exists but has no launcher Python; test will not modify it")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "venv",
            "--system-site-packages",
            "--without-pip",
            str(development_root),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert development_python.is_file()
    return True


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher and ACL integration")
def test_saved_acl_config_starts_through_normal_launcher(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell is unavailable")

    workspace = tmp_path / "日本語 workspace"
    data = tmp_path / "日本語 data"
    scratch = tmp_path / "scratch with spaces"
    local_app_data = tmp_path / "local app data"
    config = local_app_data / "WindowsLocalMCP" / "config.toml"
    candidate = tmp_path / "candidate.toml"
    workspace.mkdir()

    def toml_path(value: Path) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    candidate.write_text(
        "\n".join(
            [
                f'workspace_root = "{toml_path(workspace)}"',
                f'data_dir = "{toml_path(data)}"',
                f'sandbox_scratch_dir = "{toml_path(scratch)}"',
                "filesystem_enabled = false",
                "git_enabled = false",
                "approved_sandbox_enabled = false",
                "protect_data_dir_acl = true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_app_data)
    environment.pop("LOCAL_MCP_CONFIG", None)
    environment.pop("LOCAL_MCP_ROOT", None)
    environment["PYTHONIOENCODING"] = "utf-8"

    setup_command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(repository_root / 'setup-localmcp.ps1')} -FunctionsOnly
$content = [IO.File]::ReadAllText({_ps_literal(candidate)}, [Text.Encoding]::UTF8)
Save-Config -Content $content -Path {_ps_literal(config)} -PythonPath {_ps_literal(sys.executable)}
Set-ActiveConfig -ConfigPath {_ps_literal(config)}
"""
    created_development_runtime = False
    try:
        configured = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", setup_command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
            shell=False,
            env=environment,
        )
        assert configured.returncode == 0, configured.stdout + configured.stderr
        marker = data / ".acl-policy.json"
        assert marker.is_file()

        created_development_runtime = _ensure_launcher_runtime(repository_root)

        async def exercise_launcher() -> None:
            server = StdioServerParameters(
                command=shell,
                args=[
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(repository_root / "run-localmcp.ps1"),
                ],
                env=environment,
                cwd=str(repository_root),
            )
            async with (
                stdio_client(server) as (read_stream, write_stream),
                ClientSession(read_stream, write_stream) as session,
            ):
                await session.initialize()
                listed = await session.list_tools()
                assert "session_info" in {tool.name for tool in listed.tools}

        anyio.run(exercise_launcher)
    finally:
        subprocess.run(
            ["icacls.exe", str(data), "/inheritance:e", "/T", "/C"],
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
        if created_development_runtime:
            shutil.rmtree(repository_root / ".venv", ignore_errors=True)


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
    git_text = str(Path(git).resolve()).replace("\\", "\\\\")
    git_sha256 = hashlib.sha256(Path(git).read_bytes()).hexdigest()
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{root_text}"',
                f'data_dir = "{data_text}"',
                "protect_data_dir_acl = false",
                "git_enabled = true",
                f'git_executable_path = "{git_text}"',
                f'git_executable_sha256 = "{git_sha256}"',
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
            assert {
                "session_info",
                "write_file",
                "read_file",
                "git_info",
                "execute_readonly",
                "execute_workspace_write",
                "adb_read",
                "request_host_command",
                "poll_approval",
                "audit_get",
                "activity_timeline",
                "activity_get",
                "request_workspace_rollback",
                "request_selective_undo",
            } <= tools.keys()
            assert {"execute", "start_command", "execute_approved"}.isdisjoint(tools.keys())

            assert tools["read_file"].annotations.read_only_hint is True
            assert tools["write_file"].annotations.destructive_hint is True

            readonly = tools["execute_readonly"].annotations
            assert readonly.read_only_hint is True
            assert readonly.destructive_hint is False
            assert readonly.open_world_hint is False

            workspace_write = tools["execute_workspace_write"].annotations
            assert workspace_write.read_only_hint is False
            assert workspace_write.destructive_hint is True
            assert workspace_write.open_world_hint is False

            adb_read = tools["adb_read"].annotations
            assert adb_read.read_only_hint is True
            assert adb_read.destructive_hint is False
            assert adb_read.open_world_hint is False

            approval_request = tools["request_host_command"].annotations
            assert approval_request.read_only_hint is False
            assert approval_request.destructive_hint is False
            assert approval_request.open_world_hint is False

            write = await session.call_tool(
                "write_file", {"path": "hello.txt", "content": "hello stdio"}
            )
            assert not write.is_error
            read = await session.call_tool("read_file", {"path": "hello.txt"})
            assert not read.is_error
            assert read.structured_content is not None
            assert read.structured_content["content"] == "hello stdio"

            git_info = await session.call_tool("git_info", {})
            assert git_info.is_error
            git_status = await session.call_tool(
                "execute_readonly", {"program": "git", "args": ["status", "--short"]}
            )
            assert git_status.is_error

            for rejected_args in (
                ["show", "--patch"],
                ["diff", "--patch"],
                ["diff", "--check"],
            ):
                rejected = await session.call_tool(
                    "execute_readonly",
                    {"program": "git", "args": rejected_args},
                )
                assert rejected.is_error
                assert "request_sandbox_command" in _tool_result_text(rejected)

            wrong_surface = await session.call_tool(
                "execute_workspace_write",
                {"program": "git", "args": ["status", "--short"]},
            )
            assert wrong_surface.is_error

            rejected_project_host = await session.call_tool(
                "request_host_command",
                {
                    "command": [sys.executable, "-c", "print('must stay sandboxed')"],
                    "reason": "verify project-controlled code is rejected from Approved Host",
                    "risk_summary": "test request must fail before approval creation",
                },
            )
            assert rejected_project_host.is_error

            approval = await session.call_tool(
                "request_host_command",
                {
                    "command": [git, "status", "--short"],
                    "reason": "verify explicit approved Git request-only MCP behavior",
                    "risk_summary": "test request must not launch a child process",
                },
            )
            assert not approval.is_error
            assert approval.structured_content is not None
            assert approval.structured_content["status"] == "pending"
            approval_id = approval.structured_content["approval_id"]

            approval_record = await session.call_tool("audit_get", {"operation_id": approval_id})
            assert not approval_record.is_error
            assert approval_record.structured_content is not None
            assert approval_record.structured_content["status"] == "pending_approval"
            assert approval_record.structured_content["approval_status"] == "pending"
            facts = approval_record.structured_content["request"]["objective_risk"]
            assert "network_requested" not in facts["detected_requested_effects"]
            assert (
                facts["effective_host_capabilities"]["direct_socket_api_os_possible"]
                is True
            )
            assert approval_record.structured_content["worker_pid"] is None
            assert approval_record.structured_content["child_pid"] is None

    anyio.run(exercise)
