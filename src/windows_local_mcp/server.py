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

from .approval import prepare_approval_bundle, settings_digest
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
from .policy import CommandPolicy, NormalizedCommand, approved_request_hash
from .resources import WorkspaceExecutionLock, enforce_data_quota
from .risk import command_risk_facts
from .sandbox_backend import (
    codex_sandbox_effective_policy,
    resolve_codex_sandbox_backend,
)
from .timeline import timeline_entry, timeline_list
from .util import canonical_json, read_text_limited, sha256_bytes, sha256_text, utc_now_iso
from .workspace_history import (
    WorkspaceMutationError,
    begin_single_file_write_transaction,
    capture_workspace_state,
    checkpoint_manifest_digest,
    compare_workspace_states,
    describe_workspace_restore,
    finalize_workspace_transaction,
    prepare_selective_undo,
    update_single_file_write_transaction,
    verify_checkpoint_integrity,
    workspace_recovery_required,
)

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
    version="0.6.0",
    instructions=(
        "Operate inside the configured workspace. Use execute_readonly for safe Git/analyze "
        "operations, execute_workspace_write for constrained automatic source formatting, and "
        "adb_read for fixed read-only emulator operations. Test/build/general shell/destructive "
        "ADB use request_sandbox_command and local approval by default; request_host_command "
        "is the explicit last-resort host tier. Activity tools expose bounded "
        "operation details; workspace rollback is always a locally approved operation. "
        "request_host_command only stages "
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


def _require_workspace_mutation_ready() -> None:
    if workspace_recovery_required(runtime.settings):
        raise RuntimeError(
            "workspace mutation is blocked because an interrupted restore requires recovery"
        )


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
        "safe_network_isolation": {
            "mode": runtime.settings.safe_network_isolation_mode,
            "git_dart_flutter": "AppContainer without network capabilities",
            "adb": "separate AppContainer profile with explicit loopback exemption",
            "os_enforced": runtime.settings.safe_network_isolation_mode == "appcontainer",
        },
        "configuration_selection": runtime.settings.selection_info(),
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
        _require_workspace_mutation_ready()
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > runtime.settings.max_write_bytes:
            raise ValueError("write exceeds max_write_bytes")
        target = runtime.workspace.resolve_for_write(path)
        with WorkspaceExecutionLock(runtime.settings), runtime.workspace.lock_target(target):
            _require_workspace_mutation_ready()
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
            pre_workspace = capture_workspace_state(runtime.settings, operation_id, "before")
            runtime.audit.update_operation(
                operation_id, pre_workspace_path=pre_workspace.manifest_path
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
            workspace_changed = False
            begin_single_file_write_transaction(
                runtime.settings,
                operation_id,
                pre_workspace.manifest_path,
                runtime.workspace.relative(target),
                before_sha if target_identity is not None else None,
                sha256_bytes(content_bytes),
            )
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
                workspace_changed = True
            except Exception as write_error:
                if not workspace_changed:
                    update_single_file_write_transaction(
                        runtime.settings,
                        operation_id,
                        state="failed_recovered",
                        error=write_error,
                    )
                raise
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)

            try:
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
                post_workspace = capture_workspace_state(runtime.settings, operation_id, "after")
                workspace_change = compare_workspace_states(
                    runtime.settings,
                    pre_workspace.manifest_path,
                    post_workspace.manifest_path,
                    operation_id,
                )
                result.update(workspace_change)
                result["rollback_state"] = "complete"
                update_single_file_write_transaction(
                    runtime.settings,
                    operation_id,
                    state="applied_verified",
                    target_manifest=post_workspace.manifest_path,
                )
                runtime.audit.update_operation(
                    operation_id,
                    status="succeeded",
                    finished_at=utc_now_iso(),
                    diff_path=str(workspace_change["diff_path"]),
                    backup_path=backup_path,
                    pre_workspace_path=pre_workspace.manifest_path,
                    post_workspace_path=post_workspace.manifest_path,
                    rollback_state="complete",
                    result_json=canonical_json(result),
                )
                finalize_workspace_transaction(runtime.settings, operation_id)
                runtime.audit.add_event(operation_id, "file_written", result)
                return result
            except Exception as post_error:
                if not workspace_changed:
                    raise
                try:
                    if target_identity is None:
                        target.unlink(missing_ok=True)
                    else:
                        recovery_temp: Path | None = None
                        try:
                            with tempfile.NamedTemporaryFile(
                                mode="wb", delete=False, dir=target.parent
                            ) as recovery:
                                recovery.write(previous_bytes)
                                recovery.flush()
                                os.fsync(recovery.fileno())
                                recovery_temp = Path(recovery.name)
                            os.replace(recovery_temp, target)
                            recovery_temp = None
                        finally:
                            if recovery_temp is not None:
                                recovery_temp.unlink(missing_ok=True)
                    recovered = target.read_bytes() if target.exists() else b""
                    existed_before = target_identity is not None
                    if recovered != previous_bytes or target.exists() != existed_before:
                        raise RuntimeError("write recovery verification failed")
                except Exception as recovery_error:
                    recovery_journal = update_single_file_write_transaction(
                        runtime.settings,
                        operation_id,
                        state="recovery_required",
                        error=recovery_error,
                    )
                    runtime.audit.update_operation(
                        operation_id,
                        rollback_state="recovery_required",
                        pre_workspace_path=pre_workspace.manifest_path,
                    )
                    raise WorkspaceMutationError(
                        "write_file failed after replacement and automatic recovery failed",
                        recovery_state="recovery_required",
                        journal_path=recovery_journal,
                    ) from recovery_error
                recovery_journal = update_single_file_write_transaction(
                    runtime.settings,
                    operation_id,
                    state="failed_recovered",
                    error=post_error,
                )
                runtime.audit.update_operation(
                    operation_id,
                    rollback_state="failed_recovered",
                    pre_workspace_path=pre_workspace.manifest_path,
                )
                raise WorkspaceMutationError(
                    f"write_file failed after replacement; starting state recovered: {post_error}",
                    recovery_state="failed_recovered",
                    journal_path=recovery_journal,
                ) from post_error
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
        if dart_writes:
            _require_workspace_mutation_ready()
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
        "settings_digest": settings_digest(runtime.settings),
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
            tier="safe_sandbox",
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
            tier="safe_sandbox",
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


def _request_approved_command(
    *,
    tool_name: str,
    execution_tier: str,
    command: list[str],
    cwd: str,
    reason: str,
    network_required: bool,
    risk_summary: str,
    workspace_write: bool,
    max_runtime_seconds: int | None,
    escalation_source_operation_id: str | None = None,
    escalation_reason: str = "",
) -> dict[str, Any]:
    request_input = {
        "command": command,
        "cwd": cwd,
        "reason": reason,
        "network_required": network_required,
        "workspace_write": workspace_write,
        "execution_tier": execution_tier,
        "escalation_source_operation_id": escalation_source_operation_id,
    }
    operation_id = str(uuid.uuid4())
    try:
        if (
            len(reason) > runtime.settings.max_reason_characters
            or len(risk_summary) > runtime.settings.max_reason_characters
        ):
            raise ValueError("reason or risk_summary exceeds max_reason_characters")
        normalized = runtime.policy.normalize_host(
            command=command, cwd=cwd, network_expected=network_required
        )
        backend: dict[str, Any] | None = None
        sandbox_policy: dict[str, Any] | None = None
        backend_digest: str | None = None
        if execution_tier == "approved_sandbox":
            if network_required:
                raise PermissionError(
                    "Approved Sandbox is offline; request Approved Host separately only if "
                    "network access is genuinely required"
                )
            backend = resolve_codex_sandbox_backend(runtime.settings).as_dict()
            sandbox_policy = codex_sandbox_effective_policy(workspace_write=workspace_write)
            backend_digest = sha256_text(canonical_json(backend))
        if escalation_source_operation_id:
            source = runtime.audit.get_operation(
                escalation_source_operation_id, include_events=False
            )
            source_result = source.get("result") or {}
            if (
                source.get("tier") != "safe_sandbox"
                or not isinstance(source_result, dict)
                or source_result.get("failure_class") != "sandbox_compatibility"
            ):
                raise PermissionError(
                    "Safe Sandbox escalation requires a recorded compatibility failure"
                )
        with WorkspaceExecutionLock(runtime.settings):
            _, manifest, manifest_digest = prepare_approval_bundle(
                settings=runtime.settings,
                workspace=runtime.workspace,
                operation_id=operation_id,
                normalized=normalized,
                workspace_write=workspace_write,
            )
        now = datetime.now(UTC)
        request_expires_at = (
            now + timedelta(seconds=runtime.settings.approval_request_ttl_seconds)
        ).isoformat()
        request = {
            "approval_binding_version": 2,
            "normalized_command": normalized.model_dump(),
            "reason": reason,
            "risk_summary": risk_summary,
            "network_required": network_required,
            "workspace_write": workspace_write,
            "execution_tier": execution_tier,
            "sandbox_backend": backend,
            "sandbox_backend_digest": backend_digest,
            "effective_sandbox_policy": sandbox_policy,
            "escalation_source_tier": (
                "safe_sandbox" if escalation_source_operation_id else None
            ),
            "escalation_source_operation_id": escalation_source_operation_id,
            "escalation_reason": escalation_reason,
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
        request["objective_risk"] = command_risk_facts(
            normalized,
            workspace_write=workspace_write,
            manifest=manifest,
            execution_tier=execution_tier,
            sandbox_policy=sandbox_policy,
        )
        request_hash = approved_request_hash(request)
        runtime.audit.create_operation(
            operation_id=operation_id,
            tool_name=tool_name,
            tier=execution_tier,
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
            "execution_tier": execution_tier,
            "message": (
                "Local approval may execute it once in the selected boundary; "
                "poll_approval for status/result. No fallback to another tier occurs."
            ),
        }
    except Exception as error:
        _audit_rejection(tool_name, request_input, error)
        raise


@mcp.tool(annotations=APPROVAL_REQUEST)
def request_sandbox_command(
    command: list[str],
    cwd: str = ".",
    reason: str = "",
    network_required: bool = False,
    risk_summary: str = "",
    workspace_write: bool = False,
    max_runtime_seconds: int | None = None,
    escalation_source_operation_id: str | None = None,
    escalation_reason: str = "",
) -> dict[str, Any]:
    """Stage a one-shot Approved Sandbox request; this call never executes the command."""
    return _request_approved_command(
        tool_name="request_sandbox_command",
        execution_tier="approved_sandbox",
        command=command,
        cwd=cwd,
        reason=reason,
        network_required=network_required,
        risk_summary=risk_summary,
        workspace_write=workspace_write,
        max_runtime_seconds=max_runtime_seconds,
        escalation_source_operation_id=escalation_source_operation_id,
        escalation_reason=escalation_reason,
    )


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
    """Stage a separate one-shot Approved Host request; never a sandbox fallback."""
    return _request_approved_command(
        tool_name="request_host_command",
        execution_tier="approved_host",
        command=command,
        cwd=cwd,
        reason=reason,
        network_required=network_required,
        risk_summary=risk_summary,
        workspace_write=workspace_write,
        max_runtime_seconds=max_runtime_seconds,
    )


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
        _log_simple(tool_name="poll_approval", request={"approval_id": approval_id}, result=result)
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


@mcp.tool(annotations=READ_ONLY)
def activity_timeline(limit: int = 50) -> list[dict[str, Any]]:
    """List human-readable, bounded operation history including changes and network policy."""
    request = {"limit": limit}
    try:
        result = timeline_list(runtime.settings, runtime.audit, limit)
        _log_simple(
            tool_name="activity_timeline", request=request, result={"returned": len(result)}
        )
        return result
    except Exception as error:
        _audit_rejection("activity_timeline", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def activity_get(operation_id: str) -> dict[str, Any]:
    """Return one detailed Timeline entry with bounded previews and unified diff."""
    request = {"operation_id": operation_id}
    try:
        result = timeline_entry(runtime.settings, runtime.audit, operation_id)
        _log_simple(tool_name="activity_get", request=request, result={"accessed": operation_id})
        return result
    except Exception as error:
        _audit_rejection("activity_get", request, error)
        raise


@mcp.tool(annotations=APPROVAL_REQUEST)
def request_workspace_rollback(operation_id: str, reason: str = "") -> dict[str, Any]:
    """Request local human approval to restore the workspace to an operation completion point."""
    request_input = {"operation_id": operation_id, "reason": reason}
    try:
        _require_workspace_mutation_ready()
        target = runtime.audit.get_operation(operation_id, include_events=False)
        if not target.get("post_workspace_path"):
            raise ValueError("target operation has no workspace completion checkpoint")
        rollback_id = str(uuid.uuid4())
        with WorkspaceExecutionLock(runtime.settings):
            verify_checkpoint_integrity(
                runtime.settings, str(target["post_workspace_path"])
            )
            current = capture_workspace_state(
                runtime.settings, rollback_id, "rollback-preview-current"
            )
            preview = describe_workspace_restore(
                runtime.settings,
                current.manifest_path,
                str(target["post_workspace_path"]),
            )
        now = datetime.now(UTC)
        expires = (
            now + timedelta(seconds=runtime.settings.approval_request_ttl_seconds)
        ).isoformat()
        request = {
            "target_operation_id": operation_id,
            "target_checkpoint": target["post_workspace_path"],
            "expected_current_checkpoint": current.manifest_path,
            "expected_current_manifest_sha256": checkpoint_manifest_digest(
                runtime.settings, current.manifest_path
            ),
            "target_manifest_sha256": checkpoint_manifest_digest(
                runtime.settings, str(target["post_workspace_path"])
            ),
            "operation_type": "point_in_time_rollback",
            "undo_preview": preview,
            "reason": reason,
            "objective_risk": _workspace_mutation_risk(
                "point_in_time_rollback", operation_id, preview
            ),
        }
        request_hash = sha256_text(canonical_json(request))
        runtime.audit.create_operation(
            operation_id=rollback_id,
            tool_name="request_workspace_rollback",
            tier="approved_host",
            status="pending_approval",
            cwd=str(runtime.settings.workspace_root),
            request=request,
            request_hash=request_hash,
            approval_status="pending",
            request_expires_at=expires,
        )
        return {
            "approval_id": rollback_id,
            "status": "pending",
            "request_hash": request_hash,
            "expires_at": expires,
            "operation_type": "point_in_time_rollback",
            "preview": preview,
        }
    except Exception as error:
        _audit_rejection("request_workspace_rollback", request_input, error)
        raise


@mcp.tool(annotations=APPROVAL_REQUEST)
def request_selective_undo(operation_id: str, reason: str = "") -> dict[str, Any]:
    """Request approval to remove only one operation's changes using a three-state merge."""
    request_input = {"operation_id": operation_id, "reason": reason}
    undo_id = str(uuid.uuid4())
    try:
        _require_workspace_mutation_ready()
        target = runtime.audit.get_operation(operation_id, include_events=False)
        before_path = target.get("pre_workspace_path")
        after_path = target.get("post_workspace_path")
        if not before_path or not after_path:
            raise ValueError("target operation has no before/after workspace delta")
        with WorkspaceExecutionLock(runtime.settings):
            preview = prepare_selective_undo(
                runtime.settings,
                undo_id,
                str(before_path),
                str(after_path),
            )
        target_rollback_state = str(target.get("rollback_state") or "not_applicable")
        preview["target_rollback_state"] = target_rollback_state
        if target_rollback_state in {"partial", "unavailable"}:
            preview["fully_reversible"] = False
            preview["reversibility_limitation"] = (
                "Only MCP-writable workspace files are covered; protected or external effects "
                "of the target operation are not reversible."
            )
        request = {
            "target_operation_id": operation_id,
            "operation_type": "selective_undo",
            "target_before_checkpoint": before_path,
            "target_after_checkpoint": after_path,
            "expected_current_checkpoint": preview["expected_current_checkpoint"],
            "target_checkpoint": preview["target_checkpoint"],
            "expected_current_manifest_sha256": checkpoint_manifest_digest(
                runtime.settings, str(preview["expected_current_checkpoint"])
            ),
            "target_manifest_sha256": checkpoint_manifest_digest(
                runtime.settings, str(preview["target_checkpoint"])
            ),
            "undo_preview": preview,
            "reason": reason,
            "objective_risk": _workspace_mutation_risk(
                "selective_undo", operation_id, preview
            ),
        }
        if preview["conflict_count"]:
            runtime.audit.create_operation(
                operation_id=undo_id,
                tool_name="request_selective_undo",
                tier="workspace_control",
                status="conflict",
                cwd=str(runtime.settings.workspace_root),
                request=request,
            )
            runtime.audit.update_operation(
                undo_id,
                finished_at=utc_now_iso(),
                rollback_state="conflict",
                result_json=canonical_json(preview),
                error="selective undo requires human conflict resolution",
            )
            runtime.audit.add_event(undo_id, "selective_undo_conflict", preview)
            return {
                "operation_id": undo_id,
                "status": "conflict",
                "operation_type": "selective_undo",
                "preview": preview,
            }
        now = datetime.now(UTC)
        expires = (
            now + timedelta(seconds=runtime.settings.approval_request_ttl_seconds)
        ).isoformat()
        request_hash = sha256_text(canonical_json(request))
        runtime.audit.create_operation(
            operation_id=undo_id,
            tool_name="request_selective_undo",
            tier="approved_host",
            status="pending_approval",
            cwd=str(runtime.settings.workspace_root),
            request=request,
            request_hash=request_hash,
            approval_status="pending",
            request_expires_at=expires,
        )
        return {
            "approval_id": undo_id,
            "status": "pending",
            "request_hash": request_hash,
            "expires_at": expires,
            "operation_type": "selective_undo",
            "preview": preview,
        }
    except Exception as error:
        _audit_rejection("request_selective_undo", request_input, error)
        raise


def _workspace_mutation_risk(
    operation_type: str, target_operation_id: str, preview: dict[str, Any]
) -> dict[str, Any]:
    return {
        "risk_level": "high" if preview.get("deletes_files") else "medium",
        "detected_requested_effects": {
            "workspace_mutation": True,
            "operation_type": operation_type,
            "target_operation_id": target_operation_id,
            "changed_file_count": preview.get("changed_file_count", 0),
            "creates_files": bool(preview.get("creates_files")),
            "restores_files": bool(preview.get("restores_files")),
            "deletes_files": bool(preview.get("deletes_files")),
            "conflict_count": preview.get("conflict_count", 0),
            "automatic_merge": bool(preview.get("automatic_merge")),
            "fully_reversible": bool(preview.get("fully_reversible")),
            "undo_can_be_undone": True,
        },
        "effective_host_capabilities": {
            "filesystem_scope": "MCP-writable workspace paths through the path broker",
            "network": "not used",
            "child_process": "not used",
        },
    }


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
