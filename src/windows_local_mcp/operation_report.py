from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .audit import AuditStore
from .config import Settings
from .timeline import timeline_entry

_NOISY_TRANSFER_EVENTS = {"artifact_download_chunk", "artifact_upload_chunk"}
_MAX_EVENT_PAYLOAD_BYTES = 4096


def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return {
        "id": event.get("id"),
        "occurred_at": event.get("occurred_at"),
        "event_type": event.get("event_type"),
        "payload": payload
        if len(encoded) <= _MAX_EVENT_PAYLOAD_BYTES
        else {"truncated": True, "original_bytes": len(encoded)},
    }


def build_operation_report(
    settings: Settings,
    audit: AuditStore,
    operation_id: str,
    *,
    max_events: int = 100,
) -> dict[str, Any]:
    """Aggregate the usual audit and activity views without calling public MCP tools."""

    if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= 200:
        raise ValueError("max_events must be between 1 and 200")
    operation = audit.get_operation(operation_id, include_events=True)
    activity = timeline_entry(settings, audit, operation_id)
    request = operation.get("request") if isinstance(operation.get("request"), dict) else {}
    result = operation.get("result") if isinstance(operation.get("result"), dict) else {}
    events = operation.get("events") if isinstance(operation.get("events"), list) else []
    counts = Counter(str(event.get("event_type") or "unknown") for event in events)
    major = [
        _event_summary(event)
        for event in events
        if isinstance(event, dict)
        and str(event.get("event_type") or "") not in _NOISY_TRANSFER_EVENTS
    ][-max_events:]

    execution_route = (
        result.get("execution_route")
        or result.get("execution_path")
        or request.get("execution_route")
        or request.get("execution_tier")
        or operation.get("tier")
    )
    return {
        "operation_id": operation_id,
        "status": activity.get("status", operation.get("status")),
        "tool": operation.get("tool_name"),
        "high_level_operation": request.get("high_level_operation")
        or result.get("high_level_operation")
        or operation.get("tool_name"),
        "execution_route": execution_route,
        "request_summary": request,
        "result_summary": result,
        "workspace_changes": {
            "changed_files": activity.get("changed_files", []),
            "changed_directories": activity.get("changed_directories", []),
            "added_lines": activity.get("added_lines", 0),
            "removed_lines": activity.get("removed_lines", 0),
            "checkpoint_integrity": activity.get("checkpoint_integrity"),
        },
        "approval": {
            "status": operation.get("approval_status"),
            "by": operation.get("approval_by"),
            "note": operation.get("approval_note"),
            "approved_at": operation.get("approved_at"),
            "request_expires_at": operation.get("request_expires_at"),
        },
        "rollback": {
            "state": activity.get("rollback_state"),
            "point_in_time_available": activity.get("point_in_time_rollback_available"),
            "selective_undo_available": activity.get("selective_undo_available"),
            "preview": activity.get("point_in_time_rollback_preview"),
        },
        "audit_activity": {
            "created_at": operation.get("created_at"),
            "finished_at": activity.get("finished_at"),
            "duration_ms": operation.get("duration_ms"),
            "error": operation.get("error"),
            "event_count": len(events),
            "event_counts": dict(sorted(counts.items())),
            "major_events": major,
            "events_truncated": len(major) < len(events) - sum(
                counts.get(name, 0) for name in _NOISY_TRANSFER_EVENTS
            ),
        },
    }
