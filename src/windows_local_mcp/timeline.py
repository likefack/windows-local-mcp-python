from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import AuditStore
from .config import Settings
from .util import read_text_limited
from .workspace_history import describe_workspace_restore, verify_checkpoint_integrity


def timeline_entry(settings: Settings, audit: AuditStore, operation_id: str) -> dict[str, Any]:
    """Detailed activity view. Large artifacts are expanded only here."""
    operation = audit.get_operation(operation_id, include_events=True)
    request = operation.get("request") or {}
    normalized = request.get("normalized_command") if isinstance(request, dict) else None
    result = operation.get("result") or {}
    command = normalized.get("display_command") if isinstance(normalized, dict) else None
    changed = result.get("changed_files", []) if isinstance(result, dict) else []
    post_available = _checkpoint_available(settings, operation.get("post_workspace_path"))
    pre_available = _checkpoint_available(settings, operation.get("pre_workspace_path"))
    entry = {
        "operation_id": operation["id"],
        "created_at": operation["created_at"],
        "finished_at": operation.get("finished_at"),
        "tool": operation["tool_name"],
        "tier": operation["tier"],
        "execution_tier": operation["tier"],
        "status": operation["status"],
        "cwd": operation.get("cwd"),
        "request": request,
        "target": request.get("path") if isinstance(request, dict) else None,
        "command": command,
        "exit_code": operation.get("exit_code"),
        "duration_ms": operation.get("duration_ms"),
        "stdout_preview": result.get("stdout_preview", "") if isinstance(result, dict) else "",
        "stderr_preview": result.get("stderr_preview", "") if isinstance(result, dict) else "",
        "changed_files": changed,
        "changed_file_count": len(changed),
        "added_lines": result.get("added_lines", 0) if isinstance(result, dict) else 0,
        "removed_lines": result.get("removed_lines", 0) if isinstance(result, dict) else 0,
        "unified_diff": _artifact_preview(settings, operation.get("diff_path")),
        "error": operation.get("error"),
        "rollback_state": operation.get("rollback_state") or "not_applicable",
        "point_in_time_rollback_available": post_available,
        "selective_undo_available": pre_available and post_available,
        "checkpoint_integrity": {
            "before": "verified" if pre_available else "missing_or_invalid",
            "after": "verified" if post_available else "missing_or_invalid",
        },
        "network_policy": operation.get("network_policy"),
        "sandbox_backend": request.get("sandbox_backend")
        if isinstance(request, dict)
        else None,
        "sandbox_detail": request.get("effective_sandbox_policy")
        if isinstance(request, dict)
        else None,
        "escalation_source_tier": request.get("escalation_source_tier")
        if isinstance(request, dict)
        else None,
        "escalation_reason": request.get("escalation_reason")
        if isinstance(request, dict)
        else None,
        "events": operation.get("events", []),
        "result": result,
    }
    if post_available:
        latest = audit.latest_workspace_checkpoint()
        if latest and latest.get("post_workspace_path"):
            entry["point_in_time_rollback_preview"] = {
                "target_operation_id": operation_id,
                "current_checkpoint_operation_id": latest["id"],
                **describe_workspace_restore(
                    settings,
                    str(latest["post_workspace_path"]),
                    str(operation["post_workspace_path"]),
                ),
            }
    return entry


def timeline_list(settings: Settings, audit: AuditStore, limit: int = 50) -> list[dict[str, Any]]:
    """Lightweight summaries only; no diff, events, output, or path-list expansion."""
    result: list[dict[str, Any]] = []
    for item in audit.list_operations(limit=max(1, min(limit, 200))):
        operation = audit.get_operation(str(item["id"]), include_events=False)
        request = operation.get("request") or {}
        payload = operation.get("result") or {}
        normalized = request.get("normalized_command") if isinstance(request, dict) else None
        display = normalized.get("display_command") if isinstance(normalized, dict) else None
        changed = payload.get("changed_files", []) if isinstance(payload, dict) else []
        conflicts = (
            request.get("undo_preview", {}).get("conflict_count", 0)
            if isinstance(request, dict) and isinstance(request.get("undo_preview"), dict)
            else 0
        )
        network = operation.get("network_policy") or {}
        post_available = _checkpoint_available(settings, operation.get("post_workspace_path"))
        pre_available = _checkpoint_available(settings, operation.get("pre_workspace_path"))
        objective = request.get("objective_risk", {}) if isinstance(request, dict) else {}
        result.append(
            {
                "operation_id": operation["id"],
                "time": operation.get("finished_at") or operation["created_at"],
                "tool": operation["tool_name"],
                "operation_type": _operation_type(operation["tool_name"]),
                "status": operation["status"],
                "summary": _summary(request, display),
                "changed_file_count": len(changed),
                "added_lines": payload.get("added_lines", 0)
                if isinstance(payload, dict)
                else 0,
                "removed_lines": payload.get("removed_lines", 0)
                if isinstance(payload, dict)
                else 0,
                "execution_tier": operation["tier"],
                "point_in_time_rollback_available": post_available,
                "selective_undo_available": pre_available and post_available,
                "selective_undo_scope": "workspace_files_partial"
                if operation.get("rollback_state") in {"partial", "unavailable"}
                else "workspace_files_complete",
                "conflict_state": "conflict" if conflicts else "none",
                "network_enforcement": network.get("enforcement", "not_applicable"),
                "network_enforcement_status": network.get(
                    "enforcement_status", "not_applicable"
                ),
                "risk": objective.get("risk_level", "none")
                if isinstance(objective, dict)
                else "none",
            }
        )
    return result


def _summary(request: dict[str, Any], display: object) -> str:
    if isinstance(display, list):
        value = " ".join(str(part) for part in display)
    else:
        value = str(
            request.get("path")
            or request.get("target_operation_id")
            or request.get("operation_id")
            or ""
        )
    return value if len(value) <= 200 else value[:197] + "..."


def _operation_type(tool_name: str) -> str:
    if tool_name == "request_workspace_rollback":
        return "point_in_time_rollback"
    if tool_name == "request_selective_undo":
        return "selective_undo"
    return "operation"


def _artifact_preview(settings: Settings, value: object) -> str:
    if not value:
        return ""
    try:
        path = Path(str(value)).resolve(strict=True)
        path.relative_to((settings.data_dir / "diffs").resolve(strict=True))
        return read_text_limited(path, settings.max_diff_bytes)
    except (FileNotFoundError, OSError, PermissionError, ValueError):
        return "<diff unavailable>"


def _checkpoint_available(settings: Settings, value: object) -> bool:
    if not value:
        return False
    try:
        verify_checkpoint_integrity(settings, str(value))
        return True
    except (FileNotFoundError, OSError, PermissionError, RuntimeError, TypeError, ValueError):
        return False
