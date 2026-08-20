from __future__ import annotations

import base64
import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path, PureWindowsPath
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Image
from mcp.types import ToolAnnotations

from .approval import prepare_approval_bundle, settings_digest
from .audit import AuditStore
from .command_traits import (
    SafeExecutionKind,
    classify_safe_execution,
    recommended_tool,
)
from .config import Settings, load_settings
from .control_plane import (
    assert_trusted_runtime,
    control_plane_generation,
)
from .control_plane_guard import assert_control_plane_healthy
from .executor import Executor
from .git_snapshot import capture_git_snapshot
from .paths import Workspace
from .policy import CommandPolicy, NormalizedCommand, approved_request_hash
from .redaction import redact_command_args, redact_text
from .resources import NamedControlPlaneLock, WorkspaceExecutionLock, enforce_data_quota
from .risk import command_risk_facts
from .sandbox_backend import (
    SANDBOX_LIVE_MARKER_VERSION,
    SANDBOX_SECURITY_PROPERTIES,
    codex_sandbox_effective_policy,
    isolation_context_digest,
    require_codex_sandbox_live_verification,
    resolve_codex_sandbox_backend,
)
from .structured_files import infer_format, read_zip_entries, read_zip_entry
from .structured_files import inspect as inspect_structured
from .structured_files import transform as transform_structured
from .timeline import timeline_entry, timeline_list
from .tool_safety import trusted_helper_identity
from .util import (
    canonical_json,
    read_text_limited,
    sha256_bytes,
    sha256_file,
    sha256_text,
    utc_now_iso,
)
from .workspace_history import (
    WorkspaceMutationError,
    begin_single_file_write_transaction,
    build_workspace_target_from_bytes,
    capture_workspace_state,
    checkpoint_manifest_digest,
    checkpoint_scope,
    compare_workspace_states,
    describe_workspace_restore,
    finalize_workspace_transaction,
    mark_workspace_transaction_audit_reconciled,
    prepare_selective_undo,
    restore_workspace_state,
    rollback_applied_workspace_transaction,
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
        assert_trusted_runtime(self.settings)
        self.workspace = Workspace(self.settings)
        self.audit = AuditStore(self.settings)
        self.policy = CommandPolicy(self.settings, self.workspace)
        self.executor = Executor(self.settings, self.audit)


runtime = Runtime()

mcp = MCPServer(
    "Windows Local MCP",
    version="0.6.0",
    instructions=(
        "Operate inside the configured workspace. Use broker primitives for bounded file, "
        "artifact, Git-read, and fixed ADB-read operations. DOCX/XLSX/CSV/TSV/ZIP/image work "
        "uses bounded structured processing or hash-bound container artifacts. Project code, "
        "plugins, Flutter/Dart processing, test/build, and general commands use "
        "request_sandbox_command; request_host_command "
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
    if isinstance(value, str):
        if len(value) > 4000:
            return {"characters": len(value), "sha256": sha256_text(value)}
        return redact_text(value)
    return value


def _redacted_normalized(normalized: NormalizedCommand) -> dict[str, Any]:
    payload = normalized.model_dump()
    payload["args"] = redact_command_args(normalized.args)
    payload["display_command"] = redact_command_args(normalized.display_command)
    return payload


def _log_simple(
    *,
    tool_name: str,
    request: dict[str, Any],
    result: Any,
    status: str = "succeeded",
    tier: str = "broker",
    operation_id: str | None = None,
) -> str:
    operation_id = runtime.audit.create_operation(
        tool_name=tool_name,
        tier=tier,
        status=status,
        cwd=str(runtime.settings.workspace_root),
        request=_safe_request(request),
        operation_id=operation_id,
    )
    summary = _safe_request(result)
    runtime.audit.update_operation(
        operation_id,
        result_json=canonical_json(summary),
        finished_at=utc_now_iso(),
    )
    runtime.audit.add_event(operation_id, status, summary if isinstance(summary, dict) else {})
    return operation_id


def _log_transfer_event(
    *,
    manifest: dict[str, Any],
    tool_name: str,
    request: dict[str, Any],
    result: dict[str, Any],
) -> None:
    operation_id = manifest.get("operation_id")
    if isinstance(operation_id, str):
        runtime.audit.add_event(
            operation_id,
            tool_name,
            {"request": _safe_request(request), "result": _safe_request(result)},
        )
        return
    _log_simple(tool_name=tool_name, request=request, result=result)


def _audit_rejection(tool_name: str, request: dict[str, Any], error: Exception) -> None:
    operation_id = runtime.audit.create_operation(
        tool_name=tool_name,
        tier="broker",
        status="rejected",
        cwd=str(runtime.settings.workspace_root),
        request=_safe_request(request),
    )
    message = f"{type(error).__name__}: {error}"
    runtime.audit.update_operation(operation_id, finished_at=utc_now_iso(), error=message)
    runtime.audit.add_event(operation_id, "rejected", {"error": message[:1000]})


def _require_filesystem() -> None:
    assert_control_plane_healthy(runtime.settings)
    if not runtime.settings.filesystem_enabled:
        raise PermissionError("filesystem capability is disabled")


def _require_workspace_mutation_ready() -> None:
    if workspace_recovery_required(runtime.settings):
        raise RuntimeError(
            "workspace mutation is blocked because an interrupted restore requires recovery"
        )


def _codex_sandbox_capability() -> dict[str, Any]:
    status: dict[str, Any] = {
        "configured": True,
        "enabled": runtime.settings.approved_sandbox_enabled,
        "available": False,
        "execution_route_available": False,
        "dependency_available": False,
        "live_verified": False,
        "windows_live_verified": False,
        "properties": {
            name: {"status": "unverified"} for name in SANDBOX_SECURITY_PROPERTIES
        },
    }
    if not runtime.settings.approved_sandbox_enabled:
        status["unavailable_reason"] = "disabled by configuration"
        return status
    try:
        resolved = resolve_codex_sandbox_backend(runtime.settings)
        backend = resolved.as_dict()
        status["dependency_available"] = True
        status["available"] = True
        status["backend"] = {
            key: backend[key]
            for key in ("name", "provenance", "signature_status", "signer_subject")
        }
        marker = runtime.settings.data_dir / "control-plane" / "sandbox-live-verification.json"
        if marker.is_file():
            evidence = json.loads(marker.read_text(encoding="utf-8"))
            if (
                evidence.get("version") == SANDBOX_LIVE_MARKER_VERSION
                and evidence.get("backend_digest") == sha256_text(canonical_json(backend))
                and evidence.get("isolation_context_digest")
                == isolation_context_digest(runtime.settings, resolved)
                and evidence.get("backend_version") == resolved.version
                and isinstance(evidence.get("guard_implementation"), dict)
                and isinstance(evidence.get("sandbox_account_identity"), dict)
                and isinstance(evidence.get("wfp_guard_binding"), dict)
                and isinstance(evidence.get("windows_os_identity"), dict)
                and isinstance(evidence.get("properties"), dict)
            ):
                status["properties"] = evidence["properties"]
                status["live_verified_at"] = evidence.get("verified_at")
            else:
                status["live_verification_stale"] = True
    except Exception as error:  # noqa: BLE001 - availability must never break session_info
        status["unavailable_reason"] = redact_text(f"{type(error).__name__}: {error}")
        return status
    try:
        require_codex_sandbox_live_verification(runtime.settings, resolved)
        status["execution_route_available"] = True
        status["live_verified"] = True
        status["windows_live_verified"] = True
    except Exception as error:  # noqa: BLE001 - route status must remain independently visible
        status["execution_unavailable_reason"] = redact_text(
            f"{type(error).__name__}: {error}"
        )
    return status


def _broker_helper_capability(program_key: str, enabled: bool) -> dict[str, Any]:
    configured = bool(
        getattr(runtime.settings, f"{program_key}_executable_path")
        and getattr(runtime.settings, f"{program_key}_executable_sha256")
    )
    result: dict[str, Any] = {
        "configured": configured,
        "enabled": enabled,
        "available": False,
        "windows_live_verified": False,
    }
    if not enabled:
        result["unavailable_reason"] = "disabled by configuration"
        return result
    try:
        identity = trusted_helper_identity(runtime.settings, program_key)
        result.update(
            available=True,
            provenance=identity["provenance"],
            executable_sha256=identity["sha256"],
        )
    except Exception as error:  # noqa: BLE001 - capability display must remain available
        result["unavailable_reason"] = redact_text(f"{type(error).__name__}: {error}")
    return result


@mcp.tool(annotations=READ_ONLY)
def session_info() -> dict[str, Any]:
    """Show workspace, capability switches, limits, and approval model."""
    codex_sandbox = _codex_sandbox_capability()
    git_helper = _broker_helper_capability("git", runtime.settings.git_enabled)
    adb_helper = _broker_helper_capability("adb", runtime.settings.adb_enabled)
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
            "structured_files": runtime.settings.filesystem_enabled,
            "codex_sandbox_configured": runtime.settings.approved_sandbox_enabled,
            "approved_host_configured": runtime.settings.approved_host_enabled,
            "status": {
                "broker": {
                    "configured": True,
                    "enabled": runtime.settings.filesystem_enabled,
                    "available": True,
                    "live_verified": False,
                    "windows_live_verified": False,
                    "properties": {
                        "filesystem_identity_lock_replace": {
                            "status": "verified",
                            "evidence": "startup filesystem identity/lock/replace probe",
                        },
                        "complete_broker_boundary": {"status": "unverified"},
                    },
                },
                "structured_processing": {
                    "configured": True,
                    "enabled": runtime.settings.filesystem_enabled,
                    "available": runtime.settings.filesystem_enabled,
                    "live_verified": False,
                },
                "chatgpt_container": {
                    "configured": "client-dependent",
                    "enabled": "client-dependent",
                    "available": "unknown-to-WLMCP",
                    "live_verified": False,
                },
                "codex_sandbox": codex_sandbox,
                "git_broker_helper": git_helper,
                "adb_broker_helper": adb_helper,
                "approved_host": {
                    "configured": runtime.settings.approved_host_enabled,
                    "enabled": runtime.settings.approved_host_enabled,
                    "available": runtime.settings.approved_host_enabled and os.name == "nt",
                    "live_verified": False,
                },
            },
        },
        "architecture": {
            "version": "broker-centered-sandboxed-processing-v1",
            "layers": {
                "broker": "closed-world file, artifact, Git-read, fixed ADB-read, checkpoint, transaction, rollback, and audit primitives",
                "structured_processing": "bounded declarative WLMCP processing or hash-bound ChatGPT container artifacts",
                "codex_sandbox": "open-ended execution, project-controlled code/plugins, Flutter/Dart processing, test/build, and general commands",
                "approved_host": "separately approved operations requiring real Windows user authority",
            },
            "legacy_safe_tier": "obsolete; fixed operations are broker primitives",
        },
        "adb_emulator_only": runtime.settings.adb_emulator_only,
        "approval_flow": "request -> local approve-and-run -> poll",
        "automatic_tools": {
            "read_only": "execute_readonly",
            "workspace_write": "execute_workspace_write",
            "adb_read": "adb_read",
        },
        "execution_boundaries": {
            "broker": "closed-world validation; no general command surface",
            "codex_sandbox": "configured independently; live verification reported separately",
            "approved_host": "separate approval; never an automatic fallback",
        },
        "configuration_selection": runtime.settings.selection_info(),
        "transport": {
            "stdio": {
                "configured": True,
                "enabled": True,
                "available": True,
                "principal_model": "single local user",
                "startup_validation": "accepted",
            },
            "http": {
                "configured": runtime.settings.http_enabled,
                "enabled": False,
                "available": False,
                "principal_model": "unsupported without authenticated ownership",
                "startup_validation": "rejected when configured",
            },
        },
        "structured_file_processing": {
            "chatgpt_container": (
                "a first-class path via hash-bound transfer when container capabilities, format "
                "preservation, transfer cost, and latency make it the better choice"
            ),
            "broker_direct": (
                "a first-class path when WLMCP can deterministically validate inputs, outputs, "
                "resource bounds, mutation targets, and side effects; the current built-in "
                "declarative transforms use this route"
            ),
            "transfer": "hash-bound, chunked byte-exact download/upload staging",
            "external_processing_policy": (
                "external-process use alone does not require Codex Sandbox. Use Sandbox when "
                "WLMCP cannot close and verify the effective side effects (for example arbitrary "
                "code or project-controlled helpers). A bounded helper may run broker-directed but "
                "must return its result for broker validation and transactional commit; never "
                "fall back automatically to Approved Host"
            ),
            "route_selection": [
                "available capabilities",
                "closed-world verifiability",
                "format preservation",
                "file and resource limits",
                "transfer cost and latency",
            ],
        },
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
        raw = text.encode("utf-8")
        lines = text.splitlines()
        start = 1 if start_line is None else max(1, start_line)
        end = len(lines) if end_line is None else min(len(lines), max(start, end_line))
        result = {
            "path": runtime.workspace.relative(file_path),
            "sha256": sha256_bytes(raw),
            "raw_bytes": len(raw),
            "newline": (
                "mixed"
                if "\r\n" in text and "\n" in text.replace("\r\n", "")
                else "crlf"
                if "\r\n" in text
                else "lf"
            ),
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
        image_format = {
            ".png": "png",
            ".jpg": "jpeg",
            ".jpeg": "jpeg",
            ".gif": "gif",
            ".webp": "webp",
        }.get(image_path.suffix.casefold())
        if image_format is None:
            raise ValueError("unsupported image format")
        data = image_path.read_bytes()
        if len(data) != size:
            raise RuntimeError("image changed while reading")
        _log_simple(
            tool_name="get_image",
            request=request,
            result={"path": runtime.workspace.relative(image_path), "bytes": len(data)},
        )
        return Image(data=data, format=image_format)
    except Exception as error:
        _audit_rejection("get_image", request, error)
        raise


def _atomic_binary_mutation(
    *,
    tool_name: str,
    path: str,
    expected_sha256: str | None,
    reason: str,
    request_summary: dict[str, Any],
    transform: Any,
    allow_create: bool = False,
    require_expected_for_existing: bool = False,
    source_bindings: tuple[tuple[str, str], ...] = (),
) -> dict[str, Any]:
    """Apply one verified binary replacement through the normal workspace journal.

    The transform passed here must be a completed, bounded artifact operation. Expensive parsing
    and transformation happens before this commit boundary. Source bindings are checked again
    while the workspace mutation lock is held.
    """
    _require_filesystem()
    _require_workspace_mutation_ready()
    operation_id: str | None = None
    target = runtime.workspace.resolve_for_write(path)
    bound_sources: list[Path] = []
    for source_path, _expected_sha256 in source_bindings:
        source = runtime.workspace.resolve_existing(
            source_path,
            allow_directory=False,
            hold_identity=False,
        )
        if source != target:
            source = runtime.workspace.resolve_existing(source_path, allow_directory=False)
        bound_sources.append(source)
    independent_source_bindings = tuple(
        binding
        for binding, source in zip(source_bindings, bound_sources, strict=True)
        if source != target
    )
    with WorkspaceExecutionLock(runtime.settings, targets=(target, *bound_sources)):
        target = runtime.workspace.resolve_for_write(path)
        if not target.exists() and not allow_create:
            raise FileNotFoundError("structured editing requires an existing file")
        with runtime.workspace.lock_target(target):
            _require_workspace_mutation_ready()
            target = runtime.workspace.resolve_for_write(path)
            if not target.exists() and not allow_create:
                raise FileNotFoundError("structured editing requires an existing file")
            parent_identity = runtime.workspace.identity(target.parent)
            if parent_identity is None:
                raise RuntimeError("write parent disappeared")
            target_identity = runtime.workspace.identity(target)
            if target.exists():
                source_size = target.stat().st_size
                if source_size > runtime.settings.max_structured_file_bytes:
                    raise ValueError("structured file exceeds max_structured_file_bytes")
                before = target.read_bytes()
            else:
                before = b""
            before_sha = sha256_bytes(before)
            if target.exists() and require_expected_for_existing and expected_sha256 is None:
                raise ValueError("expected_sha256 is required when replacing an existing file")
            if expected_sha256 is not None and expected_sha256 != before_sha:
                raise RuntimeError("expected_sha256 mismatch; source is stale or concurrently modified")

            _verify_binary_source_bindings(source_bindings)

            after, semantic = transform(before)
            if not isinstance(after, bytes):
                raise TypeError("binary mutation transform must return bytes")
            if len(after) > runtime.settings.max_structured_file_bytes:
                raise ValueError("result exceeds max_structured_file_bytes")
            current_exists = target.exists()
            if current_exists != (target_identity is not None):
                raise RuntimeError("structured file changed concurrently before commit")
            if current_exists:
                current_size = target.stat().st_size
                if current_size > runtime.settings.max_structured_file_bytes:
                    raise RuntimeError("structured file changed beyond the configured size limit")
                if sha256_bytes(target.read_bytes()) != before_sha:
                    raise RuntimeError("source is stale or concurrently modified")
            after_sha = sha256_bytes(after)
            request = {
                "path": runtime.workspace.relative(target),
                "expected_sha256": expected_sha256,
                "reason": reason,
                "before_sha256": before_sha,
                "before_bytes": len(before),
                **request_summary,
            }
            operation_id = runtime.audit.create_operation(
                tool_name=tool_name,
                tier="structured_processing",
                status="running",
                cwd=str(runtime.settings.workspace_root),
                request=_safe_request(request),
            )
            checkpoint_paths = {runtime.workspace.relative(target)}
            pre_workspace = capture_workspace_state(
                runtime.settings,
                operation_id,
                "before",
                paths=checkpoint_paths,
            )
            runtime.audit.update_operation(operation_id, pre_workspace_path=pre_workspace.manifest_path)
            begin_single_file_write_transaction(
                runtime.settings,
                operation_id,
                pre_workspace.manifest_path,
                runtime.workspace.relative(target),
                before_sha if target_identity is not None else None,
                after_sha,
            )
            temp_path: Path | None = None
            workspace_changed = False
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb", delete=False, dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
                ) as temp:
                    temp.write(after)
                    temp.flush()
                    os.fsync(temp.fileno())
                    temp_path = Path(temp.name)
                runtime.workspace.revalidate_for_replace(
                    target, parent_identity=parent_identity, target_identity=target_identity
                )
                current_exists = target.exists()
                if current_exists != (target_identity is not None):
                    raise RuntimeError("structured file changed concurrently before replacement")
                if current_exists and sha256_bytes(target.read_bytes()) != before_sha:
                    raise RuntimeError("source is stale or concurrently modified")
                _verify_binary_source_bindings(source_bindings)
                os.replace(temp_path, target)
                temp_path = None
                workspace_changed = True
                if target.read_bytes() != after:
                    raise RuntimeError("post-write content verification failed")
                _verify_binary_source_bindings(independent_source_bindings)
                post_workspace = capture_workspace_state(
                    runtime.settings,
                    operation_id,
                    "after",
                    paths=checkpoint_paths,
                )
                workspace_change = compare_workspace_states(
                    runtime.settings, pre_workspace.manifest_path, post_workspace.manifest_path, operation_id
                )
                result = {
                    "operation_id": operation_id,
                    "status": "succeeded",
                    "execution_path": "broker_direct",
                    "path": runtime.workspace.relative(target),
                    "before_sha256": before_sha,
                    "after_sha256": after_sha,
                    "before_bytes": len(before),
                    "after_bytes": len(after),
                    "rollback_state": "complete",
                    **semantic,
                    **workspace_change,
                }
                update_single_file_write_transaction(
                    runtime.settings, operation_id, state="applied_verified", target_manifest=post_workspace.manifest_path
                )
                runtime.audit.transition_operation(
                    operation_id,
                    from_statuses={"running"},
                    status="succeeded",
                    finished_at=utc_now_iso(),
                    diff_path=str(workspace_change["diff_path"]),
                    pre_workspace_path=pre_workspace.manifest_path,
                    post_workspace_path=post_workspace.manifest_path,
                    rollback_state="complete",
                    result_json=canonical_json(_safe_request(result)),
                )
                finalize_workspace_transaction(runtime.settings, operation_id)
                runtime.audit.add_event(operation_id, "structured_file_written", _safe_request(result))
                return result
            except Exception as error:
                if workspace_changed:
                    try:
                        live_exists = target.exists()
                        live_bytes = target.read_bytes() if live_exists else b""
                        if not live_exists or live_bytes != after:
                            raise RuntimeError(
                                "automatic recovery refused to overwrite a concurrent target change"
                            )
                        if target_identity is None:
                            target.unlink(missing_ok=True)
                        else:
                            with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=target.parent) as recovery:
                                recovery.write(before)
                                recovery.flush()
                                os.fsync(recovery.fileno())
                                recovery_path = Path(recovery.name)
                            os.replace(recovery_path, target)
                        restored = target.read_bytes() if target.exists() else b""
                        if restored != before or target.exists() != (target_identity is not None):
                            raise RuntimeError("binary mutation recovery verification failed")
                    except Exception as recovery_error:
                        journal = update_single_file_write_transaction(
                            runtime.settings, operation_id, state="recovery_required", error=recovery_error
                        )
                        runtime.audit.transition_operation(
                            operation_id,
                            from_statuses={"running"},
                            status="failed",
                            finished_at=utc_now_iso(),
                            rollback_state="recovery_required",
                            error=f"{type(recovery_error).__name__}: {recovery_error}",
                        )
                        raise WorkspaceMutationError(
                            "structured file mutation failed and automatic recovery failed",
                            recovery_state="recovery_required", journal_path=journal,
                        ) from recovery_error
                    update_single_file_write_transaction(
                        runtime.settings, operation_id, state="failed_recovered", error=error
                    )
                    raise WorkspaceMutationError(
                        f"structured file mutation failed; starting state recovered: {error}",
                        recovery_state="failed_recovered",
                        journal_path=str(runtime.settings.data_dir / "workspace-history" / "transactions" / operation_id / "journal.json"),
                    ) from error
                update_single_file_write_transaction(
                    runtime.settings, operation_id, state="failed_recovered", error=error
                )
                raise
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
                if operation_id is not None:
                    transitioned = runtime.audit.transition_operation(
                        operation_id,
                        from_statuses={"running"},
                        status="failed",
                        finished_at=utc_now_iso(),
                        error="structured mutation failed before replacement",
                    )
                    if transitioned:
                        runtime.audit.add_event(operation_id, "failed", {"path": path})


def _read_bounded_binary(
    path: str, *, allow_missing: bool = False
) -> tuple[Path, bytes, bool]:
    """Read one stable workspace file under its target lock for off-lock processing."""
    target = runtime.workspace.resolve_for_write(path) if allow_missing else runtime.workspace.resolve_existing(
        path, allow_directory=False
    )
    with WorkspaceExecutionLock(runtime.settings, target=target), runtime.workspace.lock_target(target):
        target = runtime.workspace.resolve_for_write(path)
        if not target.exists():
            if allow_missing:
                return target, b"", False
            raise FileNotFoundError(path)
        identity = runtime.workspace.identity(target)
        parent_identity = runtime.workspace.identity(target.parent)
        if parent_identity is None:
            raise RuntimeError("source parent disappeared")
        size = target.stat().st_size
        if size > runtime.settings.max_structured_file_bytes:
            raise ValueError("structured file exceeds max_structured_file_bytes")
        data = target.read_bytes()
        runtime.workspace.revalidate_for_replace(
            target,
            parent_identity=parent_identity,
            target_identity=identity,
        )
        if target.read_bytes() != data:
            raise RuntimeError("source changed while preparing the processing artifact")
        return target, data, True


def _verify_binary_source_bindings(bindings: tuple[tuple[str, str], ...]) -> None:
    for path, expected in bindings:
        source = runtime.workspace.resolve_existing(path, allow_directory=False)
        if source.stat().st_size > runtime.settings.max_structured_file_bytes:
            raise RuntimeError("bound source exceeds max_structured_file_bytes")
        if sha256_bytes(source.read_bytes()) != expected:
            raise RuntimeError(f"bound source changed before commit: {path}")


@mcp.tool(annotations=READ_ONLY)
def structured_file_inspect(
    path: str, format: str | None = None, range_ref: str | None = None
) -> dict[str, Any]:
    """Inspect a bounded DOCX, XLSX, CSV/TSV, ZIP, or image without mutating it."""
    request = {"path": path, "format": format, "range_ref": range_ref}
    try:
        _require_filesystem()
        source = runtime.workspace.resolve_existing(path, allow_directory=False)
        if source.stat().st_size > runtime.settings.max_structured_file_bytes:
            raise ValueError("structured file exceeds max_structured_file_bytes")
        data = source.read_bytes()
        result = inspect_structured(data, runtime.workspace.relative(source), runtime.settings, format=format, range_ref=range_ref)
        result["path"] = runtime.workspace.relative(source)
        result["execution_paths"] = ["broker_direct", "transfer"]
        result["operation_id"] = _log_simple(tool_name="structured_file_inspect", request=request, result=result)
        return result
    except Exception as error:
        _audit_rejection("structured_file_inspect", request, error)
        raise


@mcp.tool(annotations=LOCAL_WRITE)
def structured_file_apply(
    path: str,
    operations: list[dict[str, Any]],
    expected_sha256: str | None = None,
    reason: str = "",
    format: str | None = None,
    output_path: str | None = None,
    expected_output_sha256: str | None = None,
) -> dict[str, Any]:
    """Apply a declarative transform with separately bound source and destination identities."""
    request = {
        "path": path,
        "operations": operations,
        "expected_sha256": expected_sha256,
        "reason": reason,
        "format": format,
        "output_path": output_path,
        "expected_output_sha256": expected_output_sha256,
    }
    try:
        kind = infer_format(path, format)
        target_path = output_path or path
        distinct_output = PureWindowsPath(target_path).as_posix().casefold() != PureWindowsPath(
            path
        ).as_posix().casefold()
        if distinct_output and kind != "image":
            raise ValueError("output_path is currently supported only for image transformations")
        if not distinct_output and expected_output_sha256 is not None:
            raise ValueError("expected_output_sha256 is only valid for a distinct output_path")
        allow_create = kind in {"csv", "tsv", "zip"} and not distinct_output
        _target, prepared_source, source_exists = _read_bounded_binary(
            path, allow_missing=allow_create
        )
        prepared_sha = sha256_bytes(prepared_source)
        if source_exists and expected_sha256 is None:
            raise ValueError("expected_sha256 is required when replacing an existing file")
        if expected_sha256 is not None and expected_sha256 != prepared_sha:
            raise RuntimeError("expected_sha256 mismatch; source is stale or concurrently modified")
        if distinct_output:
            _output_target, prepared_output, output_exists = _read_bounded_binary(
                target_path, allow_missing=True
            )
            if output_exists and expected_output_sha256 is None:
                raise ValueError(
                    "expected_output_sha256 is required when replacing an existing output file"
                )
            if (
                expected_output_sha256 is not None
                and expected_output_sha256 != sha256_bytes(prepared_output)
            ):
                raise RuntimeError(
                    "expected_output_sha256 mismatch; output is stale or concurrently modified"
                )
        output, semantic = transform_structured(
            prepared_source,
            path,
            operations,
            runtime.settings,
            format=format,
            output_path=target_path,
        )

        def apply(target_before: bytes) -> tuple[bytes, dict[str, Any]]:
            if not distinct_output and target_before != prepared_source:
                raise RuntimeError("source changed while the structured artifact was processed")
            return output, semantic

        return _atomic_binary_mutation(
            tool_name="structured_file_apply",
            path=target_path,
            expected_sha256=(expected_output_sha256 if distinct_output else expected_sha256),
            reason=reason,
            request_summary={
                "format": kind,
                "source_path": path,
                "output_path": target_path,
                "operations": [item.get("op") for item in operations],
            },
            transform=apply,
            allow_create=allow_create or distinct_output,
            require_expected_for_existing=True,
            source_bindings=(
                ((path, prepared_sha),) if distinct_output else ()
            ),
        )
    except Exception as error:
        _audit_rejection("structured_file_apply", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def zip_entry_read(path: str, entry: str) -> dict[str, Any]:
    """Return one validated ZIP entry as a bounded base64 artifact payload."""
    request = {"path": path, "entry": entry}
    try:
        _require_filesystem()
        archive = runtime.workspace.resolve_existing(path, allow_directory=False)
        if infer_format(runtime.workspace.relative(archive)) != "zip":
            raise ValueError("path must be a ZIP file")
        if archive.stat().st_size > runtime.settings.max_structured_file_bytes:
            raise ValueError("structured file exceeds max_structured_file_bytes")
        payload = read_zip_entry(archive.read_bytes(), entry, runtime.settings)
        if len(payload) > runtime.settings.max_transfer_chunk_bytes:
            raise ValueError(
                "ZIP entry exceeds max_transfer_chunk_bytes; use zip_entry_extract for local extraction"
            )
        result = {
            "path": runtime.workspace.relative(archive),
            "entry": entry,
            "bytes": len(payload),
            "sha256": sha256_bytes(payload),
            "base64": base64.b64encode(payload).decode("ascii"),
        }
        result["operation_id"] = _log_simple(
            tool_name="zip_entry_read",
            request=request,
            result={key: value for key, value in result.items() if key != "base64"},
        )
        return result
    except Exception as error:
        _audit_rejection("zip_entry_read", request, error)
        raise


@mcp.tool(annotations=LOCAL_WRITE)
def zip_entry_extract(
    path: str,
    entry: str,
    output_path: str,
    expected_archive_sha256: str,
    expected_output_sha256: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Atomically extract one safe ZIP entry to the workspace with source and output bindings."""
    request = {
        "path": path,
        "entry": entry,
        "output_path": output_path,
        "expected_archive_sha256": expected_archive_sha256,
        "expected_output_sha256": expected_output_sha256,
        "reason": reason,
    }
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256):
            raise ValueError("expected_archive_sha256 must be a lowercase SHA-256 digest")
        archive, archive_data, _archive_exists = _read_bounded_binary(path)
        archive_relative = runtime.workspace.relative(archive)
        if infer_format(archive_relative) != "zip":
            raise ValueError("path must be a ZIP file")
        if sha256_bytes(archive_data) != expected_archive_sha256:
            raise RuntimeError("expected_archive_sha256 mismatch; archive is stale or concurrently modified")
        payload = read_zip_entry(archive_data, entry, runtime.settings)

        def extract(_: bytes) -> tuple[bytes, dict[str, Any]]:
            return payload, {
                "format": "zip",
                "operation": "entry_extract",
                "archive_path": archive_relative,
                "archive_sha256": expected_archive_sha256,
                "entry": entry,
            }

        return _atomic_binary_mutation(
            tool_name="zip_entry_extract",
            path=output_path,
            expected_sha256=expected_output_sha256,
            reason=reason,
            request_summary={"archive_path": path, "entry": entry, "expected_archive_sha256": expected_archive_sha256},
            transform=extract,
            allow_create=True,
            require_expected_for_existing=True,
            source_bindings=((archive_relative, expected_archive_sha256),),
        )
    except Exception as error:
        _audit_rejection("zip_entry_extract", request, error)
        raise


@mcp.tool(annotations=LOCAL_WRITE)
def zip_extract_many(
    path: str,
    output_directory: str,
    expected_archive_sha256: str,
    entries: list[str] | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Extract selected or all ZIP files as one recoverable workspace transaction."""
    request = {
        "path": path,
        "output_directory": output_directory,
        "expected_archive_sha256": expected_archive_sha256,
        "entries": entries,
        "reason": reason,
    }
    operation_id: str | None = None
    try:
        _require_filesystem()
        _require_workspace_mutation_ready()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256):
            raise ValueError("expected_archive_sha256 must be a lowercase SHA-256 digest")
        archive, archive_data, _exists = _read_bounded_binary(path)
        archive_relative = runtime.workspace.relative(archive)
        if infer_format(archive_relative) != "zip":
            raise ValueError("path must be a ZIP file")
        if sha256_bytes(archive_data) != expected_archive_sha256:
            raise RuntimeError("expected_archive_sha256 mismatch; archive is stale or concurrently modified")
        extracted = read_zip_entries(archive_data, entries, runtime.settings)
        changes: dict[str, bytes] = {}
        mutation_targets = [archive]
        base = PureWindowsPath(output_directory)
        for entry, payload in extracted.items():
            relative = str(base / PureWindowsPath(entry.replace("/", "\\")))
            target = runtime.workspace.resolve_planned_write(relative)
            normalized = PureWindowsPath(runtime.workspace.relative(target)).as_posix()
            if normalized.casefold() == archive_relative.casefold():
                raise ValueError("ZIP extraction cannot overwrite its source archive")
            changes[normalized] = payload
            mutation_targets.append(target)
        operation_id = runtime.audit.create_operation(
            tool_name="zip_extract_many",
            tier="structured_processing",
            status="running",
            cwd=str(runtime.settings.workspace_root),
            request=_safe_request(request),
        )
        with WorkspaceExecutionLock(runtime.settings, targets=mutation_targets):
            _require_workspace_mutation_ready()
            _verify_binary_source_bindings(((archive_relative, expected_archive_sha256),))
            checkpoint_paths = set(changes)
            before = capture_workspace_state(
                runtime.settings,
                operation_id,
                "before",
                paths=checkpoint_paths,
            )
            target_manifest = build_workspace_target_from_bytes(
                runtime.settings,
                operation_id,
                before.manifest_path,
                changes,
            )
            runtime.audit.update_operation(operation_id, pre_workspace_path=before.manifest_path)
            applied = False
            try:
                restore_workspace_state(
                    runtime.settings,
                    before.manifest_path,
                    target_manifest,
                    operation_id=operation_id,
                )
                applied = True
                _verify_binary_source_bindings(
                    ((archive_relative, expected_archive_sha256),)
                )
            except Exception as operation_error:
                if applied:
                    recovered = rollback_applied_workspace_transaction(
                        runtime.settings, operation_id
                    )
                    raise WorkspaceMutationError(
                        f"ZIP extraction was rolled back after source verification failed: {operation_error}",
                        recovery_state=str(recovered["rollback_state"]),
                        journal_path=str(recovered["transaction_journal"]),
                    ) from operation_error
                raise
            after = capture_workspace_state(
                runtime.settings,
                operation_id,
                "after",
                paths=checkpoint_paths,
            )
            workspace_change = compare_workspace_states(
                runtime.settings, before.manifest_path, after.manifest_path, operation_id
            )
            result = {
                "operation_id": operation_id,
                "status": "succeeded",
                "execution_path": "broker_direct",
                "archive_path": archive_relative,
                "archive_sha256": expected_archive_sha256,
                "extracted_files": sorted(changes),
                "extracted_file_count": len(changes),
                "rollback_state": "complete",
                **workspace_change,
            }
            runtime.audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="succeeded",
                finished_at=utc_now_iso(),
                pre_workspace_path=before.manifest_path,
                post_workspace_path=after.manifest_path,
                diff_path=str(workspace_change["diff_path"]),
                rollback_state="complete",
                result_json=canonical_json(result),
            )
            finalize_workspace_transaction(runtime.settings, operation_id)
            runtime.audit.add_event(operation_id, "zip_extracted", result)
            return result
    except Exception as error:
        if operation_id is not None:
            transitioned = runtime.audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="failed",
                finished_at=utc_now_iso(),
                rollback_state=getattr(error, "recovery_state", "not_applied"),
                error=f"{type(error).__name__}: {error}",
            )
            if transitioned:
                if getattr(error, "recovery_state", None) == "failed_recovered":
                    mark_workspace_transaction_audit_reconciled(
                        runtime.settings, operation_id
                    )
                runtime.audit.add_event(
                    operation_id, "failed", {"error": f"{type(error).__name__}: {error}"}
                )
        else:
            _audit_rejection("zip_extract_many", request, error)
        raise


def _transfer_root(transfer_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f-]{36}", transfer_id):
        raise ValueError("invalid transfer id")
    return runtime.settings.data_dir / "binary-transfers" / transfer_id


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _transfer_file_identity(path: Path) -> dict[str, int]:
    details = path.stat()
    return {
        "device": details.st_dev,
        "inode": details.st_ino,
        "size": details.st_size,
        "modified_ns": details.st_mtime_ns,
    }


def _validated_transfer_payload(
    root: Path,
    manifest: dict[str, Any],
    *,
    immutable: bool,
) -> Path:
    payload = root / "payload.bin"
    if not payload.exists() or _is_reparse(payload) or not payload.is_file():
        raise RuntimeError("transfer payload has an unsafe file identity")
    details = payload.stat()
    if details.st_nlink > 1 or details.st_size != int(manifest["bytes"]):
        raise RuntimeError("transfer payload does not match its declared byte identity")
    if immutable and _transfer_file_identity(payload) != manifest.get("payload_identity"):
        raise RuntimeError("download snapshot changed after transfer begin")
    return payload


def _copy_source_to_reserved_snapshot(source: Path, destination: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    limit = runtime.settings.max_structured_file_bytes
    with source.open("rb") as input_file, destination.open("r+b") as output_file:
        output_file.seek(0)
        while chunk := input_file.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("structured file exceeds max_structured_file_bytes")
            output_file.write(chunk)
            digest.update(chunk)
        output_file.truncate(total)
        output_file.flush()
        os.fsync(output_file.fileno())
    return digest.hexdigest(), total


def _admit_transfer() -> None:
    root = runtime.settings.data_dir / "binary-transfers"
    open_count = 0
    if root.is_dir() and not root.is_symlink():
        for manifest_path in root.glob("*/manifest.json"):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if manifest.get("state") in {"preparing", "open"}:
                try:
                    created = datetime.fromisoformat(str(manifest["created_at"]))
                except (KeyError, TypeError, ValueError):
                    raise RuntimeError("binary transfer manifest has invalid lifetime binding")
                if datetime.now(UTC) - created > timedelta(
                    seconds=runtime.settings.approval_request_ttl_seconds
                ):
                    with NamedControlPlaneLock(
                        runtime.settings, f"transfer-{manifest_path.parent.name}"
                    ):
                        current = json.loads(manifest_path.read_text(encoding="utf-8"))
                        if current.get("state") not in {"preparing", "open"}:
                            continue
                        current_created = datetime.fromisoformat(str(current["created_at"]))
                        if datetime.now(UTC) - current_created <= timedelta(
                            seconds=runtime.settings.approval_request_ttl_seconds
                        ):
                            open_count += 1
                            continue
                        current["state"] = "expired"
                        _write_transfer_manifest(manifest_path.parent, current)
                    continue
                open_count += 1
                if open_count >= runtime.settings.max_open_transfers:
                    raise RuntimeError("open binary transfer admission limit reached")


def _write_transfer_manifest(root: Path, manifest: dict[str, Any]) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=root) as output:
            output.write(canonical_json(manifest).encode("utf-8"))
            output.flush()
            temporary = Path(output.name)
        os.replace(temporary, root / "manifest.json")
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _load_transfer(transfer_id: str, expected_direction: str) -> tuple[Path, dict[str, Any]]:
    root = _transfer_root(transfer_id)
    transfer_root = runtime.settings.data_dir / "binary-transfers"
    if _is_reparse(transfer_root) or not transfer_root.is_dir():
        raise RuntimeError("binary transfer root has an unsafe directory identity")
    transfers = transfer_root.resolve(strict=True)
    if not root.exists() or _is_reparse(root) or not root.is_dir():
        raise FileNotFoundError("transfer session was not found")
    root.resolve(strict=True).relative_to(transfers)
    manifest_path = root / "manifest.json"
    if (
        not manifest_path.exists()
        or _is_reparse(manifest_path)
        or not manifest_path.is_file()
        or manifest_path.stat().st_nlink > 1
    ):
        raise FileNotFoundError("transfer session was not found")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("version") not in {1, 2, 3, 4}:
        raise RuntimeError("transfer session version is unsupported")
    if manifest.get("direction") != expected_direction or manifest.get("state") != "open":
        raise RuntimeError("transfer session is not open for this operation")
    created = datetime.fromisoformat(str(manifest["created_at"]))
    if datetime.now(UTC) - created > timedelta(seconds=runtime.settings.approval_request_ttl_seconds):
        manifest["state"] = "expired"
        _write_transfer_manifest(root, manifest)
        raise RuntimeError("transfer session expired")
    return root, manifest


def _write_upload_chunk_locked(
    root: Path,
    manifest: dict[str, Any],
    *,
    offset: int,
    payload: bytes,
) -> dict[str, Any]:
    if offset != int(manifest["received"]):
        raise RuntimeError("upload chunk offset is not the next expected offset")
    if offset + len(payload) > int(manifest["bytes"]):
        raise ValueError("upload exceeds declared total_bytes")
    if manifest["version"] >= 4:
        payload_path = _validated_transfer_payload(root, manifest, immutable=False)
        with payload_path.open("r+b") as output:
            output.seek(offset)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        _validated_transfer_payload(root, manifest, immutable=False)
    else:
        enforce_data_quota(runtime.settings, incoming_bytes=len(payload))
        with (root / "payload.bin").open("ab") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    manifest["received"] = offset + len(payload)
    _write_transfer_manifest(root, manifest)
    return manifest


@mcp.tool(annotations=READ_ONLY)
def artifact_download_begin(path: str, chunk_bytes: int | None = None) -> dict[str, Any]:
    """Begin a hash-bound, byte-exact download of any bounded regular file."""
    request = {"path": path, "chunk_bytes": chunk_bytes}
    try:
        _require_filesystem()
        source = runtime.workspace.resolve_existing(path, allow_directory=False)
        source_identity = runtime.workspace.identity(source)
        if source_identity is None:
            raise FileNotFoundError(path)
        size = source_identity.size
        if size > runtime.settings.max_structured_file_bytes:
            raise ValueError("structured file exceeds max_structured_file_bytes")
        chunk = runtime.settings.max_transfer_chunk_bytes if chunk_bytes is None else chunk_bytes
        if not isinstance(chunk, int) or chunk < 4096 or chunk > runtime.settings.max_transfer_chunk_bytes:
            raise ValueError("chunk_bytes is outside the configured bound")
        transfer_id: str | None = None
        root: Path | None = None
        transfer_operation_id = str(uuid.uuid4())
        with NamedControlPlaneLock(runtime.settings, "binary-transfer"):
            _admit_transfer()
            enforce_data_quota(runtime.settings, incoming_bytes=size + 4096)
            transfer_id = str(uuid.uuid4())
            root = _transfer_root(transfer_id)
            try:
                root.mkdir(parents=True, exist_ok=False)
                with (root / "payload.bin").open("xb") as payload:
                    payload.truncate(size)
                    payload.flush()
                    os.fsync(payload.fileno())
                manifest = {
                    "version": 3,
                    "direction": "download",
                    "state": "preparing",
                    "created_at": utc_now_iso(),
                    "path": runtime.workspace.relative(source),
                    "bytes": size,
                    "chunk_bytes": chunk,
                    "operation_id": transfer_operation_id,
                }
                _write_transfer_manifest(root, manifest)
            except Exception:
                if root.exists():
                    shutil.rmtree(root)
                raise
        try:
            snapshot = root / "payload.bin"
            snapshot_sha, snapshot_bytes = _copy_source_to_reserved_snapshot(source, snapshot)
            current = runtime.workspace.resolve_existing(path, allow_directory=False)
            if current != source or runtime.workspace.identity(current) != source_identity:
                raise RuntimeError("source changed while preparing download snapshot")
            current_sha, current_bytes = sha256_file(
                current, max_bytes=runtime.settings.max_structured_file_bytes
            )
            if (
                runtime.workspace.identity(current) != source_identity
                or current_bytes != snapshot_bytes
                or current_sha != snapshot_sha
            ):
                raise RuntimeError("source changed while preparing download snapshot")
            persisted_sha, persisted_bytes = sha256_file(
                snapshot, max_bytes=runtime.settings.max_structured_file_bytes
            )
            if persisted_bytes != snapshot_bytes or persisted_sha != snapshot_sha:
                raise RuntimeError("download snapshot verification failed")
            manifest.update(
                {
                    "state": "open",
                    "bytes": snapshot_bytes,
                    "sha256": snapshot_sha,
                    "payload_identity": _transfer_file_identity(snapshot),
                }
            )
            with NamedControlPlaneLock(runtime.settings, f"transfer-{transfer_id}"):
                current_manifest = json.loads(
                    (root / "manifest.json").read_text(encoding="utf-8")
                )
                if current_manifest.get("state") != "preparing":
                    raise RuntimeError("download transfer expired while preparing snapshot")
                _write_transfer_manifest(root, manifest)
        except Exception:
            with NamedControlPlaneLock(runtime.settings, "binary-transfer"):
                if root.exists():
                    shutil.rmtree(root)
            raise
        result = {"transfer_id": transfer_id, "path": manifest["path"], "bytes": snapshot_bytes, "sha256": manifest["sha256"], "chunk_bytes": chunk, "chunk_count": (snapshot_bytes + chunk - 1) // chunk, "execution_path": "transfer"}
        try:
            result["operation_id"] = _log_simple(
                tool_name="artifact_download_begin",
                request=request,
                result=result,
                operation_id=transfer_operation_id,
            )
        except Exception:
            with NamedControlPlaneLock(runtime.settings, "binary-transfer"):
                if root.exists():
                    shutil.rmtree(root)
            raise
        return result
    except Exception as error:
        _audit_rejection("artifact_download_begin", request, error)
        raise


@mcp.tool(annotations=READ_ONLY)
def artifact_download_chunk(transfer_id: str, offset: int) -> dict[str, Any]:
    """Read one base64 chunk from the immutable, hash-bound download snapshot."""
    request = {"transfer_id": transfer_id, "offset": offset}
    try:
        root, manifest = _load_transfer(transfer_id, "download")
        if not isinstance(offset, int) or offset < 0 or offset % int(manifest["chunk_bytes"]) != 0:
            raise ValueError("offset must be a non-negative chunk boundary")
        size = int(manifest["bytes"])
        if offset >= size:
            raise ValueError("offset is outside the source file")
        if manifest["version"] >= 3:
            snapshot = _validated_transfer_payload(root, manifest, immutable=True)
            with snapshot.open("rb") as input_file:
                input_file.seek(offset)
                payload = input_file.read(int(manifest["chunk_bytes"]))
            expected_bytes = min(int(manifest["chunk_bytes"]), size - offset)
            if len(payload) != expected_bytes:
                raise RuntimeError("download snapshot changed during chunk read")
        else:
            source = runtime.workspace.resolve_existing(
                str(manifest["path"]), allow_directory=False
            )
            if source.stat().st_size != size or size > runtime.settings.max_structured_file_bytes:
                raise RuntimeError("source changed during transfer; begin a new download")
            data = source.read_bytes()
            if len(data) != size or sha256_bytes(data) != manifest["sha256"]:
                raise RuntimeError("source changed during transfer; begin a new download")
            payload = data[offset : offset + int(manifest["chunk_bytes"])]
        result = {"transfer_id": transfer_id, "offset": offset, "bytes": len(payload), "base64": base64.b64encode(payload).decode("ascii"), "next_offset": offset + len(payload), "complete": offset + len(payload) == size, "sha256": sha256_bytes(payload)}
        _log_transfer_event(
            manifest=manifest,
            tool_name="artifact_download_chunk",
            request=request,
            result={key: value for key, value in result.items() if key != "base64"},
        )
        return result
    except Exception as error:
        _audit_rejection("artifact_download_chunk", request, error)
        raise


@mcp.tool(annotations=CONTROL)
def artifact_upload_begin(
    path: str,
    total_bytes: int,
    sha256: str,
    expected_sha256: str | None = None,
    source_transfer_id: str | None = None,
) -> dict[str, Any]:
    """Stage any bounded binary artifact without changing the workspace."""
    request = {"path": path, "total_bytes": total_bytes, "sha256": sha256, "expected_sha256": expected_sha256, "source_transfer_id": source_transfer_id}
    try:
        _require_filesystem()
        if not isinstance(total_bytes, int) or total_bytes < 0 or total_bytes > runtime.settings.max_structured_file_bytes:
            raise ValueError("total_bytes is outside the configured bound")
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        target = runtime.workspace.resolve_for_write(path)
        if target.exists() and expected_sha256 is None:
            raise ValueError("expected_sha256 is required when replacing an existing file")
        if target.exists():
            if target.stat().st_size > runtime.settings.max_structured_file_bytes:
                raise ValueError("structured file exceeds max_structured_file_bytes")
            if sha256_bytes(target.read_bytes()) != expected_sha256:
                raise RuntimeError("expected_sha256 mismatch; target is stale or concurrently modified")
        source_binding = None
        if source_transfer_id is not None:
            _source_root, source_manifest = _load_transfer(source_transfer_id, "download")
            source_binding = {
                "path": source_manifest["path"],
                "sha256": source_manifest["sha256"],
                "bytes": source_manifest["bytes"],
            }
        transfer_operation_id = str(uuid.uuid4())
        with NamedControlPlaneLock(runtime.settings, "binary-transfer"):
            _admit_transfer()
            enforce_data_quota(runtime.settings, incoming_bytes=total_bytes + 4096)
            transfer_id = str(uuid.uuid4())
            root = _transfer_root(transfer_id)
            try:
                root.mkdir(parents=True, exist_ok=False)
                with (root / "payload.bin").open("xb") as payload:
                    payload.truncate(total_bytes)
                    payload.flush()
                    os.fsync(payload.fileno())
                manifest = {"version": 4, "direction": "upload", "state": "open", "created_at": utc_now_iso(), "path": runtime.workspace.relative(target), "bytes": total_bytes, "sha256": sha256, "expected_sha256": expected_sha256, "received": 0, "source_binding": source_binding, "operation_id": transfer_operation_id}
                _write_transfer_manifest(root, manifest)
            except Exception:
                if root.exists():
                    shutil.rmtree(root)
                raise
        result = {"transfer_id": transfer_id, "path": manifest["path"], "total_bytes": total_bytes, "chunk_bytes_max": runtime.settings.max_transfer_chunk_bytes, "execution_path": "transfer"}
        try:
            result["operation_id"] = _log_simple(
                tool_name="artifact_upload_begin",
                request=request,
                result=result,
                tier="broker",
                operation_id=transfer_operation_id,
            )
        except Exception:
            with NamedControlPlaneLock(runtime.settings, "binary-transfer"):
                if root.exists():
                    shutil.rmtree(root)
            raise
        return result
    except Exception as error:
        _audit_rejection("artifact_upload_begin", request, error)
        raise


@mcp.tool(annotations=CONTROL)
def artifact_upload_chunk(transfer_id: str, offset: int, base64_chunk: str) -> dict[str, Any]:
    """Append one exact, bounded base64 upload chunk at the next expected offset."""
    try:
        root = _transfer_root(transfer_id)
        try:
            payload = base64.b64decode(base64_chunk, validate=True)
        except ValueError as error:
            raise ValueError("base64_chunk must be valid base64") from error
        if not payload or len(payload) > runtime.settings.max_transfer_chunk_bytes:
            raise ValueError("upload chunk is outside the configured bound")
        root, initial_manifest = _load_transfer(transfer_id, "upload")
        if initial_manifest["version"] >= 4:
            with NamedControlPlaneLock(runtime.settings, f"transfer-{transfer_id}"):
                root, manifest = _load_transfer(transfer_id, "upload")
                manifest = _write_upload_chunk_locked(
                    root, manifest, offset=offset, payload=payload
                )
        else:
            with (
                NamedControlPlaneLock(runtime.settings, "binary-transfer"),
                NamedControlPlaneLock(runtime.settings, f"transfer-{transfer_id}"),
            ):
                root, manifest = _load_transfer(transfer_id, "upload")
                manifest = _write_upload_chunk_locked(
                    root, manifest, offset=offset, payload=payload
                )
        result = {"transfer_id": transfer_id, "received": manifest["received"], "complete": manifest["received"] == manifest["bytes"], "chunk_sha256": sha256_bytes(payload)}
        _log_transfer_event(
            manifest=manifest,
            tool_name="artifact_upload_chunk",
            request={
                "transfer_id": transfer_id,
                "offset": offset,
                "chunk_bytes": len(payload),
                "chunk_sha256": result["chunk_sha256"],
            },
            result=result,
        )
        return result
    except Exception as error:
        _audit_rejection("artifact_upload_chunk", {"transfer_id": transfer_id, "offset": offset}, error)
        raise


@mcp.tool(annotations=LOCAL_WRITE)
def artifact_upload_commit(transfer_id: str, reason: str = "") -> dict[str, Any]:
    """Verify a complete staged upload and atomically commit it with checkpoint and rollback."""
    request = {"transfer_id": transfer_id, "reason": reason}
    try:
        with NamedControlPlaneLock(runtime.settings, f"transfer-{transfer_id}"):
            root, manifest = _load_transfer(transfer_id, "upload")
            if int(manifest["received"]) != int(manifest["bytes"]):
                raise RuntimeError("upload is incomplete and cannot be committed")
            payload_path = _validated_transfer_payload(root, manifest, immutable=False)
            payload = payload_path.read_bytes()
            if len(payload) != int(manifest["bytes"]) or sha256_bytes(payload) != manifest["sha256"]:
                raise RuntimeError("staged upload does not match declared byte identity")

            def apply(_: bytes) -> tuple[bytes, dict[str, Any]]:
                return payload, {
                    "execution_path": "transfer",
                    "transfer_id": transfer_id,
                    "artifact_kind": "opaque_binary",
                    "embedded_code_executed": False,
                }

            source_binding = manifest.get("source_binding")
            source_bindings: tuple[tuple[str, str], ...] = ()
            if source_binding is not None:
                source_bindings = ((str(source_binding["path"]), str(source_binding["sha256"])),)
            result = _atomic_binary_mutation(
                tool_name="artifact_upload_commit",
                path=str(manifest["path"]),
                expected_sha256=manifest.get("expected_sha256"),
                reason=reason,
                request_summary={"transfer_id": transfer_id, "declared_bytes": manifest["bytes"], "declared_sha256": manifest["sha256"]},
                transform=apply,
                allow_create=True,
                require_expected_for_existing=True,
                source_bindings=source_bindings,
            )
            manifest["state"] = "committed"
            _write_transfer_manifest(root, manifest)
            return result
    except Exception as error:
        _audit_rejection("artifact_upload_commit", request, error)
        raise


# Compatibility names remain thin aliases; the security boundary and audit identity are the
# format-independent artifact broker above.
@mcp.tool(annotations=READ_ONLY)
def structured_file_download_begin(path: str, chunk_bytes: int | None = None) -> dict[str, Any]:
    return artifact_download_begin(path, chunk_bytes)


@mcp.tool(annotations=READ_ONLY)
def structured_file_download_chunk(transfer_id: str, offset: int) -> dict[str, Any]:
    return artifact_download_chunk(transfer_id, offset)


@mcp.tool(annotations=CONTROL)
def structured_file_upload_begin(
    path: str,
    total_bytes: int,
    sha256: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    return artifact_upload_begin(path, total_bytes, sha256, expected_sha256)


@mcp.tool(annotations=CONTROL)
def structured_file_upload_chunk(
    transfer_id: str, offset: int, base64_chunk: str
) -> dict[str, Any]:
    return artifact_upload_chunk(transfer_id, offset, base64_chunk)


@mcp.tool(annotations=LOCAL_WRITE)
def structured_file_upload_commit(transfer_id: str, reason: str = "") -> dict[str, Any]:
    return artifact_upload_commit(transfer_id, reason)


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
        with WorkspaceExecutionLock(
            runtime.settings, target=target
        ), runtime.workspace.lock_target(target):
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
            if target.exists() and expected_sha256 is None:
                raise ValueError("expected_sha256 is required when replacing an existing file")
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
                tier="broker",
                status="running",
                cwd=str(runtime.settings.workspace_root),
                request=request,
            )
            checkpoint_paths = {runtime.workspace.relative(target)}
            pre_workspace = capture_workspace_state(
                runtime.settings,
                operation_id,
                "before",
                paths=checkpoint_paths,
            )
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
                post_workspace = capture_workspace_state(
                    runtime.settings,
                    operation_id,
                    "after",
                    paths=checkpoint_paths,
                )
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
                runtime.audit.transition_operation(
                    operation_id,
                    from_statuses={"running"},
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
                    live_exists = target.exists()
                    live_bytes = target.read_bytes() if live_exists else b""
                    if not live_exists or live_bytes != content_bytes:
                        raise RuntimeError(
                            "automatic recovery refused to overwrite a concurrent target change"
                        )
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
            runtime.audit.transition_operation(
                operation_id,
                from_statuses={"running"},
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
    if len(runtime.audit.list_active_operations()) >= runtime.settings.max_concurrent_jobs:
        raise RuntimeError("concurrent job admission limit exceeded")
    max_runtime = max(10, min(max_runtime_seconds, runtime.settings.default_max_runtime_seconds))
    timeout = max(0, min(foreground_timeout_seconds, 600))
    operation_id = str(uuid.uuid4())
    execution_manifest_digest: str | None = None
    request = {
        "normalized_command": normalized_command,
        "safe_request": safe_request,
        "execution_manifest_digest": execution_manifest_digest,
        "settings_digest": settings_digest(runtime.settings),
        "control_plane_generation": control_plane_generation(runtime.settings),
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
            tier="broker",
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
    """Run a fixed-grammar Git read as a broker primitive; open-ended tools use Sandbox."""
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
    """Legacy surface; project-controlled formatting now belongs in Codex Sandbox."""
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
    operation_id: str | None = None
    try:
        if not runtime.settings.git_enabled:
            raise PermissionError("git capability is disabled")
        operation_id = runtime.audit.create_operation(
            tool_name="git_info",
            tier="broker",
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
        runtime.audit.transition_operation(
            operation_id,
            from_statuses={"running"},
            status="succeeded",
            finished_at=utc_now_iso(),
            result_json=canonical_json({"snapshot_path": snapshot, "bytes": len(content.encode())}),
        )
        runtime.audit.add_event(operation_id, "git_snapshot_read", {})
        return result
    except Exception as error:
        if operation_id is None:
            _audit_rejection("git_info", request, error)
        else:
            message = f"{type(error).__name__}: {error}"
            if runtime.audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="failed",
                finished_at=utc_now_iso(),
                error=message,
            ):
                runtime.audit.add_event(operation_id, "failed", {"error": message[:1000]})
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
        _log_simple(tool_name="stop_job", request={"job_id": job_id}, result=result, tier="broker")
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
) -> dict[str, Any]:
    request_input = {
        "command": command,
        "cwd": cwd,
        "reason": reason,
        "network_required": network_required,
        "workspace_write": workspace_write,
        "execution_tier": execution_tier,
    }
    operation_id = str(uuid.uuid4())
    try:
        reason = redact_text(reason)
        risk_summary = redact_text(risk_summary)
        if len(runtime.audit.list_pending_approvals()) >= runtime.settings.max_pending_approvals:
            raise RuntimeError("pending approval admission limit exceeded")
        if execution_tier == "approved_host" and not runtime.settings.approved_host_enabled:
            raise PermissionError("Approved Host is disabled by configuration")
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
        if execution_tier == "codex_sandbox":
            if network_required:
                raise PermissionError(
                    "Approved Sandbox is offline; request Approved Host separately only if "
                    "network access is genuinely required"
                )
            resolved_backend = resolve_codex_sandbox_backend(runtime.settings)
            require_codex_sandbox_live_verification(runtime.settings, resolved_backend)
            backend = resolved_backend.as_dict()
            sandbox_policy = codex_sandbox_effective_policy(workspace_write=workspace_write)
            backend_digest = sha256_text(canonical_json(backend))
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
            "approval_binding_version": 3,
            "control_plane_generation": control_plane_generation(runtime.settings),
            "normalized_command": _redacted_normalized(normalized),
            "reason": redact_text(reason),
            "risk_summary": risk_summary,
            "network_required": network_required,
            "workspace_write": workspace_write,
            "execution_tier": execution_tier,
            "sandbox_backend": backend,
            "sandbox_backend_digest": backend_digest,
            "effective_sandbox_policy": sandbox_policy,
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
) -> dict[str, Any]:
    """Stage a one-shot Approved Sandbox request; this call never executes the command."""
    return _request_approved_command(
        tool_name="request_sandbox_command",
        execution_tier="codex_sandbox",
        command=command,
        cwd=cwd,
        reason=reason,
        network_required=network_required,
        risk_summary=risk_summary,
        workspace_write=workspace_write,
        max_runtime_seconds=max_runtime_seconds,
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
            rollback_scope = checkpoint_scope(
                runtime.settings, str(target["post_workspace_path"])
            )
            current = capture_workspace_state(
                runtime.settings,
                rollback_id,
                "rollback-preview-current",
                paths=(
                    None
                    if rollback_scope["kind"] == "workspace"
                    else set(rollback_scope["paths"])
                ),
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
            "reason": redact_text(reason),
            "objective_risk": _workspace_mutation_risk(
                "point_in_time_rollback", operation_id, preview
            ),
            "control_plane_generation": control_plane_generation(runtime.settings),
        }
        request_hash = sha256_text(canonical_json(request))
        runtime.audit.create_operation(
            operation_id=rollback_id,
            tool_name="request_workspace_rollback",
            tier="broker",
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
            "reason": redact_text(reason),
            "objective_risk": _workspace_mutation_risk(
                "selective_undo", operation_id, preview
            ),
            "control_plane_generation": control_plane_generation(runtime.settings),
        }
        if preview["conflict_count"]:
            runtime.audit.create_operation(
                operation_id=undo_id,
                tool_name="request_selective_undo",
                tier="broker",
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
            tier="broker",
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
