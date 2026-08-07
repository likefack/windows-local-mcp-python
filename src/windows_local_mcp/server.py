from __future__ import annotations

import difflib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Image

from .audit import AuditStore
from .config import Settings, load_settings
from .executor import Executor
from .paths import Workspace
from .policy import CommandPolicy, NormalizedCommand, approval_hash
from .util import canonical_json, read_text_limited, sha256_bytes, sha256_text, utc_now_iso


class Runtime:
    def __init__(self) -> None:
        self.settings: Settings = load_settings()
        self.workspace = Workspace(self.settings)
        self.audit = AuditStore(self.settings)
        self.policy = CommandPolicy(self.settings, self.workspace)
        self.executor = Executor(self.settings, self.audit)


runtime = Runtime()

mcp = MCPServer(
    "Windows Local MCP",
    version="0.2.0",
    instructions=(
        "Operate only inside the configured workspace. "
        "Use execute for allowlisted low-risk commands. "
        "Use request_host_command for arbitrary PowerShell, network, deletion, "
        "process control, or any command rejected by execute. "
        "Never claim a command succeeded without checking its returned status."
    ),
    log_level="INFO",
)


def _log_simple(
    *,
    tool_name: str,
    request: dict[str, Any],
    result: dict[str, Any],
    status: str = "succeeded",
) -> str:
    operation_id = runtime.audit.create_operation(
        tool_name=tool_name,
        tier="read",
        status=status,
        cwd=str(runtime.settings.workspace_root),
        request=request,
    )
    runtime.audit.update_operation(
        operation_id,
        result_json=canonical_json(result),
        finished_at=utc_now_iso(),
    )
    runtime.audit.add_event(operation_id, status, result)
    return operation_id


@mcp.tool()
def session_info() -> dict[str, Any]:
    """Show the allowed workspace, audit location, and permission model."""
    result = {
        "workspace_root": str(runtime.settings.workspace_root),
        "data_dir": str(runtime.settings.data_dir),
        "audit_db": str(runtime.audit.db_path),
        "safe_programs": ["git", "flutter", "dart", "adb", "configured PowerShell scripts"],
        "arbitrary_host_commands": "require request_host_command and human approval",
        "network_isolation": (
            "Not guaranteed at the Windows OS level. "
            "Safe-command policy excludes known network commands by default."
        ),
    }
    operation_id = _log_simple(tool_name="session_info", request={}, result=result)
    result["operation_id"] = operation_id
    return result


@mcp.tool()
def list_directory(path: str = ".") -> dict[str, Any]:
    """List entries in a directory inside the configured workspace."""
    directory = runtime.workspace.resolve_directory(path)
    entries = list(directory.iterdir())
    if len(entries) > runtime.settings.max_directory_entries:
        raise ValueError(
            f"項目数が多すぎます: {len(entries)} > {runtime.settings.max_directory_entries}"
        )

    result_entries = [
        {
            "name": entry.name,
            "type": "directory" if entry.is_dir() else "file",
        }
        for entry in sorted(entries, key=lambda item: item.name.casefold())
        if not runtime.workspace.is_excluded(entry)
    ]
    result = {
        "path": runtime.workspace.relative(directory),
        "entries": result_entries,
    }
    operation_id = _log_simple(
        tool_name="list_directory",
        request={"path": path},
        result=result,
    )
    result["operation_id"] = operation_id
    return result


@mcp.tool()
def read_file(
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> dict[str, Any]:
    """Read a UTF-8 text file inside the workspace, optionally by line range."""
    file_path = runtime.workspace.resolve_existing(path, allow_directory=False)
    text = read_text_limited(file_path, runtime.settings.max_text_file_bytes)
    lines = text.splitlines()

    start = 1 if start_line is None else max(1, start_line)
    end = len(lines) if end_line is None else min(len(lines), max(start, end_line))
    selected = "\n".join(lines[start - 1 : end])

    result = {
        "path": runtime.workspace.relative(file_path),
        "sha256": sha256_text(text),
        "start_line": start,
        "end_line": end,
        "total_lines": len(lines),
        "content": selected,
    }
    operation_id = _log_simple(
        tool_name="read_file",
        request={"path": path, "start_line": start_line, "end_line": end_line},
        result={key: value for key, value in result.items() if key != "content"},
    )
    result["operation_id"] = operation_id
    return result


@mcp.tool()
def get_image(path: str) -> Image:
    """Return an image file from inside the workspace as native MCP image content."""
    image_path = runtime.workspace.resolve_existing(path, allow_directory=False)
    size = image_path.stat().st_size
    if size > runtime.settings.max_image_bytes:
        raise ValueError(
            f"画像が大きすぎます: {size} > {runtime.settings.max_image_bytes} bytes"
        )
    _log_simple(
        tool_name="get_image",
        request={"path": path},
        result={"path": runtime.workspace.relative(image_path), "bytes": size},
    )
    return Image(path=image_path)


@mcp.tool()
def write_file(
    path: str,
    content: str,
    expected_sha256: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Atomically create or replace a UTF-8 file and persist an exact diff and backup."""
    target = runtime.workspace.resolve_for_write(path)
    previous_bytes = target.read_bytes() if target.exists() else b""
    try:
        previous_text = previous_bytes.decode("utf-8") if previous_bytes else ""
    except UnicodeDecodeError as error:
        raise ValueError("既存ファイルはUTF-8テキストではありません") from error

    before_sha = sha256_bytes(previous_bytes)
    if expected_sha256 is not None and expected_sha256 != before_sha:
        raise RuntimeError(
            "ファイルが読み取り後に変更されています。expected_sha256が一致しません"
        )

    request = {
        "path": runtime.workspace.relative(target),
        "reason": reason,
        "expected_sha256": expected_sha256,
        "content_characters": len(content),
    }
    operation_id = runtime.audit.create_operation(
        tool_name="write_file",
        tier="workspace_write",
        status="running",
        cwd=str(runtime.settings.workspace_root),
        request=request,
    )

    backup_path: str | None = None
    diff_path = runtime.settings.data_dir / "diffs" / f"{operation_id}.diff"
    try:
        if target.exists():
            backup_dir = runtime.settings.data_dir / "backups" / operation_id
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_file = backup_dir / target.name
            shutil.copy2(target, backup_file)
            backup_path = str(backup_file)

        diff = "".join(
            difflib.unified_diff(
                previous_text.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"a/{runtime.workspace.relative(target)}",
                tofile=f"b/{runtime.workspace.relative(target)}",
            )
        )
        diff_path.write_text(diff, encoding="utf-8")

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            delete=False,
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        ) as temp:
            temp.write(content)
            temp_path = Path(temp.name)
        os.replace(temp_path, target)

        after_bytes = target.read_bytes()
        after_sha = sha256_bytes(after_bytes)
        result = {
            "operation_id": operation_id,
            "status": "succeeded",
            "path": runtime.workspace.relative(target),
            "before_sha256": before_sha,
            "after_sha256": after_sha,
            "diff_path": str(diff_path),
            "backup_path": backup_path,
            "added_lines": sum(
                1 for line in diff.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            ),
            "removed_lines": sum(
                1 for line in diff.splitlines()
                if line.startswith("-") and not line.startswith("---")
            ),
        }
        runtime.audit.update_operation(
            operation_id,
            status="succeeded",
            finished_at=utc_now_iso(),
            diff_path=str(diff_path),
            backup_path=backup_path,
            result_json=canonical_json(result),
        )
        runtime.audit.add_event(operation_id, "file_written", result)
        return result
    except Exception as error:
        runtime.audit.update_operation(
            operation_id,
            status="failed",
            finished_at=utc_now_iso(),
            diff_path=str(diff_path) if diff_path.exists() else None,
            backup_path=backup_path,
            error=f"{type(error).__name__}: {error}",
        )
        runtime.audit.add_event(operation_id, "failed", {"error": str(error)})
        raise


def _queue_command(
    *,
    tool_name: str,
    tier: str,
    normalized_command: dict[str, Any],
    foreground_timeout_seconds: int,
    max_runtime_seconds: int,
) -> dict[str, Any]:
    max_runtime = max(10, min(max_runtime_seconds, 86400))
    timeout = max(0, min(foreground_timeout_seconds, 600))
    request = {
        "normalized_command": normalized_command,
        "max_runtime_seconds": max_runtime,
    }
    operation_id = runtime.audit.create_operation(
        tool_name=tool_name,
        tier=tier,
        status="queued",
        cwd=normalized_command["cwd"],
        request=request,
    )
    return runtime.executor.launch(operation_id, timeout)


@mcp.tool()
def execute(
    program: str,
    args: list[str],
    cwd: str = ".",
    foreground_timeout_seconds: int | None = None,
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Execute an allowlisted low-risk command. Long commands become background jobs."""
    normalized = runtime.policy.normalize_safe(program=program, args=args, cwd=cwd)
    return _queue_command(
        tool_name="execute",
        tier="safe_command",
        normalized_command=normalized.model_dump(),
        foreground_timeout_seconds=(
            runtime.settings.default_foreground_timeout_seconds
            if foreground_timeout_seconds is None
            else foreground_timeout_seconds
        ),
        max_runtime_seconds=(
            runtime.settings.default_max_runtime_seconds
            if max_runtime_seconds is None
            else max_runtime_seconds
        ),
    )


@mcp.tool()
def start_command(
    program: str,
    args: list[str],
    cwd: str = ".",
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Start an allowlisted command immediately as a background job."""
    normalized = runtime.policy.normalize_safe(program=program, args=args, cwd=cwd)
    return _queue_command(
        tool_name="start_command",
        tier="safe_command",
        normalized_command=normalized.model_dump(),
        foreground_timeout_seconds=0,
        max_runtime_seconds=(
            runtime.settings.default_max_runtime_seconds
            if max_runtime_seconds is None
            else max_runtime_seconds
        ),
    )


@mcp.tool()
def poll_job(job_id: str) -> dict[str, Any]:
    """Return the durable status and result of a command job."""
    return runtime.executor.poll(job_id)


@mcp.tool()
def stop_job(job_id: str) -> dict[str, Any]:
    """Stop a running command and record cancellation in the audit log."""
    return runtime.executor.stop(job_id)


@mcp.tool()
def request_host_command(
    command: list[str],
    cwd: str = ".",
    reason: str = "",
    network_required: bool = False,
    risk_summary: str = "",
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Create a human approval request for arbitrary host command execution."""
    normalized = runtime.policy.normalize_host(
        command=command,
        cwd=cwd,
        network_expected=network_required,
    )
    request_hash = approval_hash(
        normalized=normalized,
        reason=reason,
        risk_summary=risk_summary,
    )
    request = {
        "normalized_command": normalized.model_dump(),
        "reason": reason,
        "risk_summary": risk_summary,
        "network_required": network_required,
        "max_runtime_seconds": (
            runtime.settings.default_max_runtime_seconds
            if max_runtime_seconds is None
            else max(10, min(max_runtime_seconds, 86400))
        ),
    }
    operation_id = runtime.audit.create_operation(
        tool_name="request_host_command",
        tier="host_approval",
        status="pending_approval",
        cwd=normalized.cwd,
        request=request,
        request_hash=request_hash,
        approval_status="pending",
    )
    return {
        "approval_id": operation_id,
        "status": "pending",
        "request_hash": request_hash,
        "message": (
            "別ターミナルの承認UIでユーザーが承認または拒否します。"
            "poll_approvalで状態を確認してください。"
        ),
    }


@mcp.tool()
def poll_approval(approval_id: str) -> dict[str, Any]:
    """Check whether a host command request is pending, approved, rejected, or expired."""
    operation = runtime.audit.get_operation(approval_id, include_events=False)
    return {
        "approval_id": approval_id,
        "status": operation["approval_status"],
        "operation_status": operation["status"],
        "approval_by": operation.get("approval_by"),
        "approval_note": operation.get("approval_note"),
        "approved_at": operation.get("approved_at"),
        "request_hash": operation.get("request_hash"),
    }


@mcp.tool()
def execute_approved(
    approval_id: str,
    foreground_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Execute exactly the host command that the user approved."""
    operation = runtime.audit.get_operation(approval_id, include_events=False)
    request = operation["request"]
    normalized = NormalizedCommand.model_validate(request["normalized_command"])

    expected_hash = approval_hash(
        normalized=normalized,
        reason=request.get("reason", ""),
        risk_summary=request.get("risk_summary", ""),
    )
    if expected_hash != operation.get("request_hash"):
        raise RuntimeError("承認後に要求内容が変化しています。再承認が必要です")

    runtime.audit.claim_approved(approval_id)
    return runtime.executor.launch(
        approval_id,
        (
            runtime.settings.default_foreground_timeout_seconds
            if foreground_timeout_seconds is None
            else foreground_timeout_seconds
        ),
    )


@mcp.tool()
def audit_list(
    limit: int = 50,
    status: str | None = None,
    approval_status: str | None = None,
) -> list[dict[str, Any]]:
    """List durable audit records without returning full stdout or file contents."""
    return runtime.audit.list_operations(
        limit=limit,
        status=status,
        approval_status=approval_status,
    )


@mcp.tool()
def audit_get(operation_id: str) -> dict[str, Any]:
    """Return one full audit record and its state-transition events."""
    return runtime.audit.get_operation(operation_id, include_events=True)


def main() -> None:
    transport = os.environ.get("LOCAL_MCP_TRANSPORT", "stdio").strip().casefold()
    if transport == "streamable-http":
        host = os.environ.get("LOCAL_MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("LOCAL_MCP_PORT", "8000"))
        mcp.run(transport="streamable-http", host=host, port=port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
