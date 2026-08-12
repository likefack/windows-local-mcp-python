from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import TERMINAL_STATUSES, AuditStore
from .config import Settings
from .util import read_text_limited
from .workspace_history import (
    describe_current_workspace_restore,
    verify_checkpoint_integrity,
)

_TRANSFER_CHUNK_EVENTS = {
    "artifact_download_begin": "artifact_download_chunk",
    "artifact_upload_begin": "artifact_upload_chunk",
}


def _transfer_display_state(operation: dict[str, Any]) -> tuple[str, str | None, str]:
    """Derive the user-visible transfer lifecycle from durable chunk events.

    Transfer begin operations are recorded as successful API calls, while chunk activity is
    appended to the same audit operation. Timeline must therefore distinguish "begin returned"
    from "the transfer itself finished" instead of showing a Finished timestamp before later
    chunk events.
    """
    raw_status = str(operation.get("status") or "")
    raw_finished = operation.get("finished_at")
    created_at = str(operation.get("created_at") or "")
    updated_at = str(operation.get("updated_at") or created_at)
    tool = str(operation.get("tool_name") or "")
    expected_event = _TRANSFER_CHUNK_EVENTS.get(tool)
    if expected_event is None:
        return raw_status, str(raw_finished) if raw_finished else None, str(raw_finished or updated_at)

    # Preserve explicit failure/expiry states if the audit layer starts terminalizing transfers.
    if raw_status in TERMINAL_STATUSES and raw_status != "succeeded":
        return raw_status, str(raw_finished) if raw_finished else None, str(raw_finished or updated_at)

    result = operation.get("result") or {}
    total_value = (
        result.get("bytes")
        if tool == "artifact_download_begin" and isinstance(result, dict)
        else result.get("total_bytes")
        if isinstance(result, dict)
        else None
    )
    total_bytes = total_value if isinstance(total_value, int) and total_value >= 0 else None

    # Empty artifacts need no chunk calls, so the successful begin is the complete transfer.
    if total_bytes == 0:
        return "succeeded", str(raw_finished) if raw_finished else None, str(raw_finished or updated_at)

    events = operation.get("events")
    chunk_events = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event_type") == expected_event
    ] if isinstance(events, list) else []
    if not chunk_events:
        return "transferring", None, created_at

    last_activity = str(chunk_events[-1].get("occurred_at") or updated_at)
    complete = False
    if tool == "artifact_upload_begin":
        complete = any(
            isinstance(event.get("payload"), dict)
            and isinstance(event["payload"].get("result"), dict)
            and event["payload"]["result"].get("complete") is True
            for event in chunk_events
        )
    elif total_bytes is not None:
        # Downloads permit random-access chunks. Do not call the transfer complete merely because
        # the final chunk was requested; require durable events to cover the whole byte range.
        ranges: list[tuple[int, int]] = []
        for event in chunk_events:
            payload = event.get("payload")
            outcome = payload.get("result") if isinstance(payload, dict) else None
            if not isinstance(outcome, dict):
                continue
            offset = outcome.get("offset")
            byte_count = outcome.get("bytes")
            if (
                isinstance(offset, int)
                and isinstance(byte_count, int)
                and offset >= 0
                and byte_count > 0
            ):
                ranges.append((offset, offset + byte_count))
        covered_until = 0
        for start, end in sorted(ranges):
            if start > covered_until:
                break
            covered_until = max(covered_until, end)
        complete = covered_until >= total_bytes

    if complete:
        return "succeeded", last_activity, last_activity
    return "transferring", None, last_activity


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
    display_status, display_finished_at, _display_time = _transfer_display_state(operation)
    entry = {
        "operation_id": operation["id"],
        "created_at": operation["created_at"],
        "finished_at": display_finished_at,
        "tool": operation["tool_name"],
        "tier": operation["tier"],
        "execution_tier": operation["tier"],
        "status": display_status,
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
        try:
            entry["point_in_time_rollback_preview"] = {
                "target_operation_id": operation_id,
                **describe_current_workspace_restore(
                    settings, str(operation["post_workspace_path"])
                ),
            }
        except Exception:  # noqa: BLE001 - Timeline detail must survive preview-only failures
            entry["point_in_time_rollback_preview"] = {
                "target_operation_id": operation_id,
                "available": False,
                "reason": "current_scope_preview_unavailable",
            }
    return entry


def timeline_list(settings: Settings, audit: AuditStore, limit: int = 50) -> list[dict[str, Any]]:
    """Lightweight summaries; transfer events are loaded only to derive truthful lifecycle state."""
    result: list[dict[str, Any]] = []
    for item in audit.list_operations(limit=max(1, min(limit, 200))):
        include_events = str(item.get("tool_name") or "") in _TRANSFER_CHUNK_EVENTS
        operation = audit.get_operation(str(item["id"]), include_events=include_events)
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
        display_status, _display_finished_at, display_time = _transfer_display_state(operation)
        result.append(
            {
                "operation_id": operation["id"],
                "time": display_time,
                "tool": operation["tool_name"],
                "operation_type": _operation_type(operation["tool_name"]),
                "status": display_status,
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
