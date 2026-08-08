from __future__ import annotations

import difflib
import os
import shutil
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Image
from mcp.types import ToolAnnotations

from .approval import prepare_approval_bundle
from .audit import AuditStore
from .command_traits import (
    SafeExecutionKind,
    classify_safe_execution,
    dart_format_writes,
    recommended_tool,
)
from .config import Settings, load_settings
from .executor import Executor
from .git_snapshot import capture_git_snapshot
from .paths import Workspace
from .policy import CommandPolicy, NormalizedCommand, approval_hash
from .resources import WorkspaceExecutionLock, enforce_data_quota
from .util import canonical_json, read_text_limited, sha256_bytes, sha256_text, utc_now_iso

READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)
LOCAL_WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
)
APPROVAL_REQUEST = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)
CONTROL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)


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
    version="0.3.0",
    instructions=(
        "Operate inside the configured workspace. Use execute_readonly for safe Git/analyze "
        "operations, execute_workspace_write for constrained automatic source formatting, and "
        "adb_read for fixed read-only emulator operations. Test/build/general shell/destructive "
        "ADB require request_host_command and local approval. request_host_command only stages "
        "the request; local approval performs the dangerous execution once. Poll the result."
    ),
    log_level="INFO",
)


def _safe_request(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return "<depth-limited>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            folded = str(key).casefold()
            if any(secret in folded for secret in ("token", "password", "secret", "api_key")):
                result[str(key)] = "<redacted>"
            elif folded == "content":
                encoded = str(item).encode("utf-8", errors="replace")
                result[str(key)] = {"bytes": len(encoded), "sha256": sha256_bytes(encoded)}
            else:
                result[str(key)] = _safe_request(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_safe_request(item, depth=depth + 1) for item in value[:200]]
    if isinstance(value, str) and len(value) > 4000:
        return {"characters": len(value), "sha256": sha256_text(value)}
    return value


def _log_simple(
    *,
    tool_name: str,
    request: dict[str, Any],
    result: Any,
    status: str = "succeeded",
    tier: str = "read",
) -> str:
    operation_id = runtime.audit.create_operation(
        tool_name=tool_name,
        tier=tier,
        status=status,
        cwd=str(runtime.settings.workspace_root),
        request=_safe_request(request),
    )
    summary = _safe_request(result)
    runtime.audit.update_operation(
        operation_id,
        result_json=canonical_json(summary),
        finished_at=utc_now_iso(),
    )
    runtime.audit.add_event(operation_id, status, summary if isinstance(summary, dict) else {})
    return operation_id


def _audit_rejection(tool_name: str, request: dict[str, Any], error: Exception) -> None:
    operation_id = runtime.audit.create_operation(
        tool_name=tool_name,
        tier="denied",
        status="rejected",
        cwd=str(runtime.settings.workspace_root),
        request=_safe_request(request),
    )
    message = f"{type(error).__name__}: {error}"
    runtime.audit.update_operation(operation_id, finished_at=utc_now_iso(), error=message)
    runtime.audit.add_event(operation_id, "rejected", {"error": message[:1000]})


def _require_filesystem() -> None:
    if not runtime.settings.filesystem_enabled:
        raise PermissionError("filesystem capability is disabled")


@mcp.tool(annotations=READ_ONLY)
def session_info() -> dict[str, Any]:
    """Show workspace, capability switches, limits, and approval model."""
    result = {
        "workspace_root": str(runtime.settings.workspace_root),
        "data_dir": str(runtime.settings.data_dir),
        "capabilities": {
            "filesystem": runtime.settings.filesystem_enabled,
            "git": runtime.settings.git_enabled,
            "flutter": runtime.settings.flutter_enabled,
            "dart": runtime.settings.dart_enabled,
            "adb": runtime.settings.adb_enabled,
            "powershell": runtime.settings.powershell_enabled,
        },
        "adb_emulator_only": runtime.settings.adb_emulator_only,
        "approval_flow": "request -> local approve-and-run -> poll",
        "automatic_tools": {
            "read_only": "execute_readonly",
            "workspace_write": "execute_workspace_write",
            "adb_read": "adb_read",
        },
        "transport": "stdio by default; optional loopback-only streamable-http",
    }
    result["operation_id"] = _log_simple(tool_name="session_info", request={}, result=result)
    return result


@mcp.tool(annotations=READ_ONLY)
def list_directory(path: str = ".") -> dict[str, Any]:
    """List non-hidden entries in a workspace directory."""
    request = {"path": path}
    try:
        _require_filesystem()
        directory = runtime.workspace.resolve_directory(path)
        limit = runtime.settings.max_directory_entries
        entries = list(islice(directory.iterdir(), limit + 1))
        if len(entries) > limit:
            raise ValueError("directory entry limit exceeded")
        result = {
            "path": runtime.workspace.relative(directory),
            "entries": [
                {"name": entry.name, "type": "directory" if entry.is_dir() else "file"}
                for entry in sorted(entries, key=lambda item: item.name.casefold())
                if not runtime.workspace.is_hidden(entry)
            ],
        }
        result["operation_id"] = _log_simple(
            tool_name="list_directory", request=request, result=result
        )
        return result
    except Exception as error:
        _audit_rejection("list_directory", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def read_file(
    path: str, start_line: int | None = None, end_line: int | None = None
) -> dict[str, Any]:
    """Read a bounded UTF-8 text file inside the workspace."""
    request = {"path": path, "start_line": start_line, "end_line": end_line}
    try:
        _require_filesystem()
        file_path = runtime.workspace.resolve_existing(path, allow_directory=False)
        text = read_text_limited(file_path, runtime.settings.max_text_file_bytes)
        lines = text.splitlines()
        start = 1 if start_line is None else max(1, start_line)
        end = len(lines) if end_line is None else min(len(lines), max(start, end_line))
        result = {
            "path": runtime.workspace.relative(file_path),
            "sha256": sha256_text(text),
            "start_line": start,
            "end_line": end,
            "total_lines": len(lines),
            "content": "\n".join(lines[start - 1 : end]),
        }
        result["operation_id"] = _log_simple(
            tool_name="read_file",
            request=request,
            result={key: value for key, value in result.items() if key != "content"},
        )
        return result
    except Exception as error:
        _audit_rejection("read_file", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def get_image(path: str) -> Image:
    """Return one bounded image from the workspace."""
    request = {"path": path}
    try:
        _require_filesystem()
        image_path = runtime.workspace.resolve_existing(path, allow_directory=False)
        size = image_path.stat().st_size
        if size > runtime.settings.max_image_bytes:
            raise ValueError("image byte limit exceeded")
        _log_simple(
            tool_name="get_image",
            request=request,
            result={"path": runtime.workspace.relative(image_path), "bytes": size},
        )
        return Image(path=image_path)
    except Exception as error:
        _audit_rejection("get_image", request, error)
        raise


@mcp.tool(annotations=LOCAL_WRITE)
def write_file(
    path: str,
    content: str,
    expected_sha256: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Atomically write a bounded UTF-8 file with optimistic concurrency and audit artifacts."""
    request_input = {
        "path": path,
        "content": content,
        "expected_sha256": expected_sha256,
        "reason": reason,
    }
    operation_id: str | None = None
    try:
        _require_filesystem()
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > runtime.settings.max_write_bytes:
            raise ValueError("write exceeds max_write_bytes")
        target = runtime.workspace.resolve_for_write(path)
        with WorkspaceExecutionLock(
            runtime.settings, target=target
        ), runtime.workspace.lock_target(target):
            target = runtime.workspace.resolve_for_write(path)
            parent_identity = runtime.workspace.identity(target.parent)
            if parent_identity is None:
                raise RuntimeError("write parent disappeared")
            target_identity = runtime.workspace.identity(target)
            previous_bytes = target.read_bytes() if target.exists() else b""
            if len(previous_bytes) > runtime.settings.max_text_file_bytes:
                raise ValueError("existing file exceeds max_text_file_bytes")
            if len(previous_bytes) > runtime.settings.max_backup_bytes:
                raise ValueError("existing file exceeds max_backup_bytes")
            try:
                previous_text = previous_bytes.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("existing file is not UTF-8 text") from error
            before_sha = sha256_bytes(previous_bytes)
            if expected_sha256 is not None and expected_sha256 != before_sha:
                raise RuntimeError("expected_sha256 mismatch")

            request = {
                "path": runtime.workspace.relative(target),
                "reason": reason,
                "expected_sha256": expected_sha256,
                "content_bytes": len(content_bytes),
                "content_sha256": sha256_bytes(content_bytes),
            }
            operation_id = runtime.audit.create_operation(
                tool_name="write_file",
                tier="workspace_write",
                status="running",
                cwd=str(runtime.settings.workspace_root),
                request=request,
            )
            diff_path = runtime.settings.data_dir / "diffs" / f"{operation_id}.diff"
            added, removed, diff_bytes = _write_bounded_diff(
                previous_text=previous_text,
                content=content,
                relative=runtime.workspace.relative(target),
                destination=diff_path,
            )
            enforce_data_quota(runtime.settings, incoming_bytes=diff_bytes + len(previous_bytes))
            backup_path: str | None = None
            if target.exists():
                backup_dir = runtime.settings.data_dir / "backups" / operation_id
                backup_dir.mkdir(parents=True)
                backup_file = backup_dir / target.name
                shutil.copy2(target, backup_file)
                backup_path = str(backup_file)

            temp_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    delete=False,
                    dir=target.parent,
                    prefix=f".{target.name}.",
                    suffix=".tmp",
                ) as temp:
                    temp.write(content_bytes)
                    temp.flush()
                    os.fsync(temp.fileno())
                    temp_path = Path(temp.name)
                runtime.workspace.revalidate_for_replace(
                    target,
                    parent_identity=parent_identity,
                    target_identity=target_identity,
                )
                os.replace(temp_path, target)
                temp_path = None
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)

            after_bytes = target.read_bytes()
            after_sha = sha256_bytes(after_bytes)
            if after_sha != sha256_bytes(content_bytes):
                raise RuntimeError("post-write content verification failed")
            result = {
                "operation_id": operation_id,
                "status": "succeeded",
                "path": runtime.workspace.relative(target),
                "before_sha256": before_sha,
                "after_sha256": after_sha,
                "diff_path": str(diff_path),
                "backup_path": backup_path,
                "added_lines": added,
                "removed_lines": removed,
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
        if operation_id is None:
            _audit_rejection("write_file", request_input, error)
        else:
            runtime.audit.update_operation(
                operation_id,
                status="failed",
                finished_at=utc_now_iso(),
                error=f"{type(error).__name__}: {error}",
            )
            runtime.audit.add_event(operation_id, "failed", {"error": str(error)[:1000]})
        raise


def _write_bounded_diff(
    *, previous_text: str, content: str, relative: str, destination: Path
) -> tuple[int, int, int]:
    added = 0
    removed = 0
    total = 0
    try:
        with destination.open("wb") as output:
            for line in difflib.unified_diff(
                previous_text.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            ):
                encoded = line.encode("utf-8")
                total += len(encoded)
                if total > runtime.settings.max_diff_bytes:
                    raise ValueError("generated diff exceeds max_diff_bytes")
                output.write(encoded)
                if line.startswith("+") and not line.startswith("+++"):
                    added += 1
                elif line.startswith("-") and not line.startswith("---"):
                    removed += 1
        return added, removed, total
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _queue_command(
    *,
    tool_name: str,
    tier: str,
    normalized_command: dict[str, Any],
    foreground_timeout_seconds: int,
    max_runtime_seconds: int,
    safe_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    max_runtime = max(10, min(max_runtime_seconds, runtime.settings.default_max_runtime_seconds))
    timeout = max(0, min(foreground_timeout_seconds, 600))
    operation_id = str(uuid.uuid4())
    normalized_model = NormalizedCommand.model_validate(normalized_command)
    execution_manifest_digest: str | None = None
    if normalized_model.program_key in {"flutter", "dart"}:
        dart_writes = normalized_model.program_key == "dart" and dart_format_writes(
            normalized_model.args
        )
        with WorkspaceExecutionLock(runtime.settings):
            _, _, execution_manifest_digest = prepare_approval_bundle(
                settings=runtime.settings,
                workspace=runtime.workspace,
                operation_id=operation_id,
                normalized=normalized_model,
                workspace_write=dart_writes,
            )
    request = {
        "normalized_command": normalized_command,
        "safe_request": safe_request,
        "execution_manifest_digest": execution_manifest_digest,
        "max_runtime_seconds": max_runtime,
    }
    runtime.audit.create_operation(
        operation_id=operation_id,
        tool_name=tool_name,
        tier=tier,
        status="queued",
        cwd=normalized_command["cwd"],
        request=request,
    )
    return runtime.executor.launch(operation_id, timeout)


def _run_automatic_tool(
    *,
    tool_name: str,
    expected_kind: SafeExecutionKind,
    program: str,
    args: list[str],
    cwd: str,
    foreground_timeout_seconds: int | None,
    max_runtime_seconds: int | None,
) -> dict[str, Any]:
    request = {"program": program, "args": args, "cwd": cwd}
    try:
        normalized = runtime.policy.normalize_safe(program=program, args=args, cwd=cwd)
        actual_kind = classify_safe_execution(normalized)
        if actual_kind != expected_kind:
            raise PermissionError(
                f"command belongs to {recommended_tool(actual_kind)}, not {tool_name}"
            )
        return _queue_command(
            tool_name=tool_name,
            tier="safe_command",
            normalized_command=normalized.model_dump(),
            safe_request=request,
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
    except Exception as error:
        _audit_rejection(tool_name, request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def execute_readonly(
    program: str,
    args: list[str],
    cwd: str = ".",
    foreground_timeout_seconds: int | None = None,
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Run validated read-only Git/Flutter/Dart commands; use timeout 0 for a background job."""
    return _run_automatic_tool(
        tool_name="execute_readonly",
        expected_kind=SafeExecutionKind.READ_ONLY,
        program=program,
        args=args,
        cwd=cwd,
        foreground_timeout_seconds=foreground_timeout_seconds,
        max_runtime_seconds=max_runtime_seconds,
    )


@mcp.tool(annotations=LOCAL_WRITE)
def execute_workspace_write(
    program: str,
    args: list[str],
    cwd: str = ".",
    foreground_timeout_seconds: int | None = None,
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Run only validated automatic commands that intentionally modify workspace source files."""
    return _run_automatic_tool(
        tool_name="execute_workspace_write",
        expected_kind=SafeExecutionKind.WORKSPACE_WRITE,
        program=program,
        args=args,
        cwd=cwd,
        foreground_timeout_seconds=foreground_timeout_seconds,
        max_runtime_seconds=max_runtime_seconds,
    )


@mcp.tool(annotations=READ_ONLY)
def adb_read(
    args: list[str],
    cwd: str = ".",
    foreground_timeout_seconds: int | None = None,
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Run only the fixed read-only ADB grammar against an allowed emulator target."""
    return _run_automatic_tool(
        tool_name="adb_read",
        expected_kind=SafeExecutionKind.ADB_READ,
        program="adb",
        args=args,
        cwd=cwd,
        foreground_timeout_seconds=foreground_timeout_seconds,
        max_runtime_seconds=max_runtime_seconds,
    )


@mcp.tool(annotations=READ_ONLY)
def git_info() -> dict[str, Any]:
    """Return a bounded Git branch/HEAD/status/diff/staged/log/changed-files snapshot."""
    request: dict[str, Any] = {}
    try:
        if not runtime.settings.git_enabled:
            raise PermissionError("git capability is disabled")
        operation_id = runtime.audit.create_operation(
            tool_name="git_info",
            tier="read",
            status="running",
            cwd=str(runtime.settings.workspace_root),
            request=request,
        )
        snapshot = capture_git_snapshot(
            settings=runtime.settings, operation_id=operation_id, stage="requested"
        )
        if snapshot is None:
            raise RuntimeError("workspace is not a Git worktree or Git is unavailable")
        content = read_text_limited(Path(snapshot), runtime.settings.max_diff_bytes)
        result = {"operation_id": operation_id, "snapshot_path": snapshot, "content": content}
        runtime.audit.update_operation(
            operation_id,
            status="succeeded",
            finished_at=utc_now_iso(),
            result_json=canonical_json({"snapshot_path": snapshot, "bytes": len(content.encode())}),
        )
        runtime.audit.add_event(operation_id, "git_snapshot_read", {})
        return result
    except Exception as error:
        _audit_rejection("git_info", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def poll_job(job_id: str) -> dict[str, Any]:
    """Return durable job status and bounded result previews."""
    try:
        result = runtime.executor.poll(job_id)
        _log_simple(tool_name="poll_job", request={"job_id": job_id}, result=result)
        return result
    except Exception as error:
        _audit_rejection("poll_job", {"job_id": job_id}, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def get_adb_screenshot(job_id: str) -> Image:
    """Return the bounded PNG produced by a successful safe emulator screenshot job."""
    request = {"job_id": job_id}
    try:
        operation = runtime.audit.get_operation(job_id, include_events=False)
        normalized = operation["request"].get("normalized_command", {})
        args = normalized.get("args", []) if isinstance(normalized, dict) else []
        if (
            operation["status"] != "succeeded"
            or normalized.get("program_key") != "adb"
            or list(args[-3:]) != ["exec-out", "screencap", "-p"]
            or bool(operation.get("result", {}).get("stdout_truncated"))
        ):
            raise PermissionError("job is not a successful safe ADB screenshot")
        output = Path(str(operation["stdout_path"])).resolve(strict=True)
        output.relative_to((runtime.settings.data_dir / "outputs").resolve(strict=True))
        if output.is_symlink() or output.stat().st_size > runtime.settings.max_image_bytes:
            raise ValueError("ADB screenshot artifact is unsafe or too large")
        _log_simple(
            tool_name="get_adb_screenshot",
            request=request,
            result={"bytes": output.stat().st_size},
        )
        return Image(path=output)
    except Exception as error:
        _audit_rejection("get_adb_screenshot", request, error)
        raise


@mcp.tool(annotations=LOCAL_WRITE)
def stop_job(job_id: str) -> dict[str, Any]:
    """Stop a job only after durable process identity verification."""
    try:
        result = runtime.executor.stop(job_id)
        _log_simple(tool_name="stop_job", request={"job_id": job_id}, result=result, tier="control")
        return result
    except Exception as error:
        _audit_rejection("stop_job", {"job_id": job_id}, error)
        raise


@mcp.tool(annotations=APPROVAL_REQUEST)
def request_host_command(
    command: list[str],
    cwd: str = ".",
    reason: str = "",
    network_required: bool = False,
    risk_summary: str = "",
    workspace_write: bool = False,
    max_runtime_seconds: int | None = None,
) -> dict[str, Any]:
    """Stage an immutable approval request; this tool never launches the requested host command."""
    request_input = {
        "command": command,
        "cwd": cwd,
        "reason": reason,
        "network_required": network_required,
        "workspace_write": workspace_write,
    }
    operation_id = str(uuid.uuid4())
    try:
        if len(reason) > runtime.settings.max_reason_characters or len(
            risk_summary
        ) > runtime.settings.max_reason_characters:
            raise ValueError("reason or risk_summary exceeds max_reason_characters")
        normalized = runtime.policy.normalize_host(
            command=command, cwd=cwd, network_expected=network_required
        )
        with WorkspaceExecutionLock(runtime.settings):
            _, manifest, manifest_digest = prepare_approval_bundle(
                settings=runtime.settings,
                workspace=runtime.workspace,
                operation_id=operation_id,
                normalized=normalized,
                workspace_write=workspace_write,
            )
        request_hash = approval_hash(
            normalized=normalized,
            reason=reason,
            risk_summary=risk_summary,
            manifest_digest=manifest_digest,
        )
        now = datetime.now(UTC)
        request_expires_at = (
            now + timedelta(seconds=runtime.settings.approval_request_ttl_seconds)
        ).isoformat()
        request = {
            "normalized_command": normalized.model_dump(),
            "reason": reason,
            "risk_summary": risk_summary,
            "network_required": network_required,
            "workspace_write": workspace_write,
            "approval_manifest_digest": manifest_digest,
            "approval_manifest_summary": {
                "mode": manifest["mode"],
                "files": len(manifest.get("inputs", [])),
                "bytes": sum(item["size"] for item in manifest.get("inputs", [])),
                "executable_sha256": manifest["executable"]["sha256"],
            },
            "max_runtime_seconds": (
                runtime.settings.default_max_runtime_seconds
                if max_runtime_seconds is None
                else max(10, min(max_runtime_seconds, runtime.settings.default_max_runtime_seconds))
            ),
        }
        runtime.audit.create_operation(
            operation_id=operation_id,
            tool_name="request_host_command",
            tier="host_approval",
            status="pending_approval",
            cwd=normalized.cwd,
            request=request,
            request_hash=request_hash,
            approval_status="pending",
            request_expires_at=request_expires_at,
        )
        return {
            "approval_id": operation_id,
            "status": "pending",
            "request_hash": request_hash,
            "expires_at": request_expires_at,
            "message": "Local approval may execute it once; poll_approval for status/result.",
        }
    except Exception as error:
        _audit_rejection("request_host_command", request_input, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def poll_approval(approval_id: str) -> dict[str, Any]:
    """Poll approval and, after local approve-and-run, its execution result."""
    try:
        runtime.audit.expire_pending()
        operation = runtime.audit.get_operation(approval_id, include_events=False)
        result = {
            "approval_id": approval_id,
            "status": operation["approval_status"],
            "operation_status": operation["status"],
            "approval_by": operation.get("approval_by"),
            "approval_note": operation.get("approval_note"),
            "approved_at": operation.get("approved_at"),
            "request_expires_at": operation.get("request_expires_at"),
            "request_hash": operation.get("request_hash"),
            "result": operation.get("result"),
            "error": operation.get("error"),
        }
        _log_simple(
            tool_name="poll_approval", request={"approval_id": approval_id}, result=result
        )
        return result
    except Exception as error:
        _audit_rejection("poll_approval", {"approval_id": approval_id}, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def audit_list(
    limit: int = 50,
    status: str | None = None,
    approval_status: str | None = None,
) -> list[dict[str, Any]]:
    """List bounded audit metadata; access to the audit log is itself audited."""
    request = {"limit": limit, "status": status, "approval_status": approval_status}
    try:
        result = runtime.audit.list_operations(
            limit=limit, status=status, approval_status=approval_status
        )
        _log_simple(tool_name="audit_list", request=request, result={"returned": len(result)})
        return result
    except Exception as error:
        _audit_rejection("audit_list", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def audit_get(operation_id: str) -> dict[str, Any]:
    """Return one audit record; the access is recorded separately."""
    request = {"operation_id": operation_id}
    try:
        result = runtime.audit.get_operation(operation_id, include_events=True)
        _log_simple(tool_name="audit_get", request=request, result={"accessed": operation_id})
        return result
    except Exception as error:
        _audit_rejection("audit_get", request, error)
        raise


def main() -> None:
    transport = os.environ.get("LOCAL_MCP_TRANSPORT", "stdio").strip().casefold()
    if transport == "stdio":
        mcp.run()
        return
    if transport == "streamable-http":
        if not runtime.settings.http_enabled:
            raise RuntimeError("streamable HTTP is disabled by configuration")
        mcp.run(
            transport="streamable-http",
            host=runtime.settings.http_host,
            port=runtime.settings.http_port,
        )
        return
    raise ValueError(f"unsupported transport: {transport}")


if __name__ == "__main__":
    main()
