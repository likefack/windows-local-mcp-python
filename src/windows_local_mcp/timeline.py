from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import AuditStore
from .config import Settings
from .util import read_text_limited
from .workspace_history import describe_workspace_restore


def timeline_entry(settings: Settings, audit: AuditStore, operation_id: str) -> dict[str, Any]:
    operation = audit.get_operation(operation_id, include_events=True)
    request = operation.get("request") or {}
    normalized = request.get("normalized_command") if isinstance(request, dict) else None
    result = operation.get("result") or {}
    command = normalized.get("display_command") if isinstance(normalized, dict) else None
    changed = result.get("changed_files", []) if isinstance(result, dict) else []
    entry = {
        "operation_id": operation["id"],
        "created_at": operation["created_at"],
        "finished_at": operation.get("finished_at"),
        "tool": operation["tool_name"],
        "tier": operation["tier"],
        "status": operation["status"],
        "cwd": operation.get("cwd"),
        "target": request.get("path") if isinstance(request, dict) else None,
        "command": command,
        "exit_code": operation.get("exit_code"),
        "duration_ms": operation.get("duration_ms"),
        "stdout_preview": result.get("stdout_preview", "") if isinstance(result, dict) else "",
        "stderr_preview": result.get("stderr_preview", "") if isinstance(result, dict) else "",
        "changed_files": changed,
        "added_lines": result.get("added_lines", 0) if isinstance(result, dict) else 0,
        "removed_lines": result.get("removed_lines", 0) if isinstance(result, dict) else 0,
        "unified_diff": _artifact_preview(settings, operation.get("diff_path")),
        "error": operation.get("error"),
        "rollback_state": operation.get("rollback_state") or "not_applicable",
        "network_policy": operation.get("network_policy"),
        "events": operation.get("events", []),
    }
    if operation.get("post_workspace_path"):
        latest = audit.latest_workspace_checkpoint()
        if latest and latest.get("post_workspace_path"):
            entry["rollback_preview"] = {
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
    return [
        timeline_entry(settings, audit, str(item["id"]))
        for item in audit.list_operations(limit=max(1, min(limit, 200)))
    ]


def _artifact_preview(settings: Settings, value: object) -> str:
    if not value:
        return ""
    try:
        path = Path(str(value)).resolve(strict=True)
        path.relative_to((settings.data_dir / "diffs").resolve(strict=True))
        return read_text_limited(path, settings.max_diff_bytes)
    except (FileNotFoundError, OSError, PermissionError, ValueError):
        return "<diff unavailable>"
