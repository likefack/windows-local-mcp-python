"""Approval UI 用の人間向け Live Activity 投影。

監査 DB は完全な技術記録を保持する一方、このモジュールは利用者が現在の処理を
理解するための短い表示だけを作ります。ここで作る文字列はセキュリティ判断には
使わず、監査・承認・checkpoint・transaction の意味論にも触れません。
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .audit import TERMINAL_STATUSES, AuditStore
from .redaction import redact_command_args, redact_text

MAX_ACTIVITY_SUMMARY = 200

_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_CONTROL_RANGES = ((0x00, 0x1F), (0x7F, 0x9F))

# 監査に登場する操作を、表示の責務ごとに宣言する。新しい MCP tool を追加する場合は
# ここへ意味を追加し、監査・承認・実行の実装とは独立に表示を拡張できる。
READ_TOOLS = frozenset(
    {
        "list_directory",
        "read_file",
        "get_image",
        "git_info",
        "structured_file_inspect",
        "zip_entry_read",
        "context_read",
        "context_search",
        "get_adb_screenshot",
    }
)
STRUCTURED_READ_TOOLS = frozenset({"structured_file_inspect"})
STRUCTURED_EDIT_TOOLS = frozenset(
    {
        "structured_file_apply",
        "zip_entry_extract",
        "zip_extract_many",
    }
)
MUTATION_TOOLS = frozenset(
    {"write_file", "move_file", "copy_file", "delete_file", "make_directory"}
)
COMMAND_TOOLS = frozenset(
    {
        "execute_readonly",
        "execute_workspace_write",
        "adb_read",
        "request_host_command",
        "request_sandbox_command",
    }
)
TRANSFER_BEGIN_TO_CHUNK = {
    "artifact_download_begin": "artifact_download_chunk",
    "artifact_upload_begin": "artifact_upload_chunk",
    # 旧 API 名も、監査上の operation 名が旧版に残る場合に対応する。
    "structured_file_download_begin": "structured_file_download_chunk",
    "structured_file_upload_begin": "structured_file_upload_chunk",
}
TRANSFER_CHUNK_TO_BEGIN = {
    chunk: begin for begin, chunk in TRANSFER_BEGIN_TO_CHUNK.items()
}
TRANSFER_COMMIT_TOOLS = frozenset(
    {"artifact_upload_commit", "structured_file_upload_commit"}
)
TRANSFER_TOOLS = frozenset(
    {
        *TRANSFER_BEGIN_TO_CHUNK,
        *TRANSFER_CHUNK_TO_BEGIN,
        *TRANSFER_COMMIT_TOOLS,
    }
)
UNDO_TOOLS = frozenset({"request_selective_undo", "request_workspace_rollback"})
STOP_TOOLS = frozenset({"stop_job"})

# Audit/timeline の閲覧、状態 polling、capability の説明は履歴・診断であり、通常の
# Live Activity に出さない。prefix も併用し、後から追加された audit_* などが表示を
# 埋め尽くさないようにする。
META_TOOLS = frozenset(
    {
        "session_info",
        "poll_job",
        "poll_approval",
        "audit_list",
        "audit_get",
        "activity_timeline",
        "activity_get",
        "timeline_cli",
        "context_read_info",
        "context_export_info",
    }
)
META_PREFIXES = ("audit_", "activity_", "session_", "poll_")

FORMAT_LABELS = {
    "xlsx": "Excel",
    "docx": "Word",
    "csv": "CSV",
    "tsv": "TSV",
    "zip": "ZIP",
    "image": "画像",
}

STATUS_LABELS = {
    "failed": "Failed",
    "rejected": "Rejected",
    "interrupted": "Interrupted",
    "cancelled": "Cancelled",
    "timed_out": "Timed out",
    "expired": "Expired",
    "conflict": "Conflict",
}
ACTIVE_STATUSES = frozenset({"pending", "pending_approval", "approved", "queued", "running", "committing"})


def _is_terminal_control(character: str) -> bool:
    codepoint = ord(character)
    return (
        any(start <= codepoint <= end for start, end in _CONTROL_RANGES)
        or character in _BIDI_CONTROLS
        or 0xD800 <= codepoint <= 0xDFFF
    )


def terminal_safe(value: object) -> str:
    """端末制御・双方向制御・サロゲートを無害な可視表現へ変換する。"""

    raw = str(value)
    # 監査時の伏せ字を補完するため、変換前後の両方で redaction を行う。表示対象は
    # 下記の allowlist metadata に限定し、request/result 本文そのものは受け取らない。
    redacted = redact_text(raw)
    normalized = "".join(
        f"\\u{ord(character):04x}" if _is_terminal_control(character) else character
        for character in redacted
    )
    return redact_text(normalized)


def _truncate(value: str, limit: int = MAX_ACTIVITY_SUMMARY) -> str:
    if len(value) <= limit:
        return value
    if limit <= 1:
        return value[:limit]
    return value[: limit - 1] + "…"


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _request(operation: Mapping[str, object]) -> Mapping[str, object]:
    request = operation.get("request")
    if isinstance(request, Mapping):
        return request
    raw = operation.get("request_json")
    if not isinstance(raw, str):
        return {}
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError, UnicodeError):
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


def _result(operation: Mapping[str, object]) -> Mapping[str, object]:
    result = operation.get("result")
    if isinstance(result, Mapping):
        return result
    raw = operation.get("result_json")
    if not isinstance(raw, str):
        return {}
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError, UnicodeError):
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


def _safe_text(value: object, *, limit: int = MAX_ACTIVITY_SUMMARY) -> str:
    if not isinstance(value, str) or not value:
        return ""
    return _truncate(terminal_safe(value), limit)


def _safe_path(operation: Mapping[str, object], *sources: Mapping[str, object]) -> str:
    """監査 metadata に明示された相対対象だけを表示する。"""

    keys = (
        "path",
        "output_path",
        "target_path",
        "source_path",
        "archive_path",
    )
    for source in (operation, *sources):
        for key in keys:
            path = _safe_text(source.get(key))
            if path:
                return path
    return ""


def _safe_format(operation: Mapping[str, object]) -> str:
    request = _request(operation)
    result = _result(operation)
    # 形式名は audit request/result に明示された既知の値だけを利用する。拡張子からの
    # 推測はしないため、誤って Excel/Word と表示することがない。
    for source in (request, result):
        value = source.get("format")
        if isinstance(value, str):
            normalized = value.casefold()
            if normalized in FORMAT_LABELS:
                return FORMAT_LABELS[normalized]
    return ""


def _command_detail(operation: Mapping[str, object]) -> str:
    request = _request(operation)
    normalized = _mapping(request.get("normalized_command"))
    display = normalized.get("display_command")
    if isinstance(display, str):
        command = _safe_text(display)
    elif isinstance(display, Sequence) and not isinstance(display, (bytes, bytearray)):
        parts = [item for item in display if isinstance(item, str)]
        command = _truncate(
            terminal_safe(" ".join(redact_command_args(parts))), MAX_ACTIVITY_SUMMARY
        )
    else:
        safe_request = _mapping(request.get("safe_request"))
        program = safe_request.get("program")
        args = safe_request.get("args")
        if not isinstance(program, str):
            return "コマンドを実行"
        parts = [program]
        if isinstance(args, Sequence) and not isinstance(args, (bytes, bytearray)):
            parts.extend(item for item in args[:8] if isinstance(item, str))
        command = _truncate(
            terminal_safe(" ".join(redact_command_args(parts))), MAX_ACTIVITY_SUMMARY
        )
    return f"コマンドを実行 {command}" if command else "コマンドを実行"


def _preview(operation: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping(_request(operation).get("undo_preview"))


def _preview_count(preview: Mapping[str, object]) -> int | None:
    count = preview.get("changed_file_count")
    if isinstance(count, int) and count >= 0:
        return count
    files = preview.get("files_that_would_change")
    if isinstance(files, Sequence) and not isinstance(files, (str, bytes, bytearray)):
        return len(files)
    return None


def _preview_target(preview: Mapping[str, object]) -> str:
    files = preview.get("files_that_would_change")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes, bytearray)):
        return ""
    safe_files = [
        _safe_text(item, limit=120) for item in files if isinstance(item, str) and item
    ]
    safe_files = [item for item in safe_files if item]
    return safe_files[0] if len(safe_files) == 1 else ""


def _count_suffix(count: int | None) -> str:
    if count is None:
        return ""
    return f"{count}ファイル"


def _undo_detail(
    operation: Mapping[str, object],
    target: Mapping[str, object] | None = None,
) -> str:
    request = _request(operation)
    preview = _preview(operation)
    operation_type = str(request.get("operation_type") or "").casefold()
    is_rollback = (
        str(operation.get("tool_name") or "") == "request_workspace_rollback"
        or operation_type == "point_in_time_rollback"
    )
    count = _preview_count(preview)
    target_name = _preview_target(preview)
    if not target_name and target is not None:
        target_name = _safe_path(target, _request(target), _result(target))
        target_preview = _preview(target)
        if count is None:
            count = _preview_count(target_preview)
    if is_rollback:
        prefix = "以前の状態へ復元"
    else:
        target_tool = str((target or {}).get("tool_name") or "")
        target_type = str(_request(target or {}).get("operation_type") or "").casefold()
        if target_tool == "request_selective_undo" or target_type == "selective_undo":
            prefix = "Undoした変更を元に戻す"
        else:
            prefix = "変更を元に戻す"
    suffix = target_name or _count_suffix(count)
    return f"{prefix} {suffix}".strip()


def _detail(
    operation: Mapping[str, object],
    *,
    target: Mapping[str, object] | None = None,
    transfer_path: str = "",
) -> str:
    tool = str(operation.get("tool_name") or "")
    request = _request(operation)
    result = _result(operation)
    path = transfer_path or _safe_path(operation, request, result)
    format_name = _safe_format(operation)

    # Mutation tools may carry both a source archive and the destination. Prefer the artifact
    # that the user will see changed, while keeping the source available in Audit details.
    if tool in {"structured_file_apply", "zip_entry_extract"}:
        path = _safe_text(request.get("output_path")) or path
    elif tool == "zip_extract_many":
        path = _safe_text(request.get("output_directory")) or path

    if tool in UNDO_TOOLS:
        return _undo_detail(operation, target)
    if tool in TRANSFER_BEGIN_TO_CHUNK or tool in TRANSFER_CHUNK_TO_BEGIN:
        if path:
            if "upload" in tool:
                return f"PCへ転送 {path}"
            return f"ChatGPTへ取得 {path}"
        return "PCへ転送" if "upload" in tool else "ChatGPTへ取得"
    if tool in TRANSFER_COMMIT_TOOLS:
        return f"PCへ転送 {path}" if path else "PCへ転送"
    if tool in STRUCTURED_EDIT_TOOLS:
        if tool == "zip_extract_many":
            return f"ZIPを展開 {path}".strip()
        if tool == "zip_entry_extract":
            entry = _safe_text(request.get("entry"), limit=100)
            suffix = f" {path}" if path else ""
            return f"ZIP内部を展開{suffix}{f' ({entry})' if entry else ''}".strip()
        action = f"{format_name}を編集" if format_name else "構造化ファイルを編集"
        return f"{action} {path}".strip()
    if tool in MUTATION_TOOLS:
        if tool == "move_file":
            source = _safe_text(request.get("source_path"))
            destination = _safe_text(request.get("destination_path"))
            return f"ファイルを移動 {source} -> {destination}".strip()
        if tool == "copy_file":
            source = _safe_text(request.get("source_path"))
            destination = _safe_text(request.get("destination_path"))
            return f"ファイルをコピー {source} -> {destination}".strip()
        if tool == "delete_file":
            return f"ファイルを削除 {path}".strip()
        if tool == "make_directory":
            return f"フォルダーを作成 {path}".strip()
        return f"ファイルを編集 {path}".strip()
    if tool in STRUCTURED_READ_TOOLS:
        action = f"{format_name}を読み取り" if format_name else "構造化ファイルを読み取り"
        return f"{action} {path}".strip()
    if tool == "zip_entry_read":
        entry = _safe_text(request.get("entry"), limit=100)
        suffix = f" ({entry})" if entry else ""
        return f"ZIP内部を読み取り {path}{suffix}".strip()
    if tool == "list_directory":
        return f"フォルダーを読み取り {path}".strip()
    if tool == "read_file":
        return f"ファイルを読み取り {path}".strip()
    if tool == "get_image":
        return f"画像を読み取り {path}".strip()
    if tool == "git_info":
        return "Gitの状態を読み取り"
    if tool == "context_read":
        return "Contextを読み取り"
    if tool == "context_search":
        return "Contextを検索"
    if tool == "get_adb_screenshot":
        return "エミュレーター画面を読み取り"
    if tool in COMMAND_TOOLS or _mapping(request.get("normalized_command")):
        return _command_detail(operation)
    if tool in STOP_TOOLS:
        return "実行中の処理を停止"
    if tool == "export_context":
        return "Contextを送信"
    if path:
        # 未知の tool でも、監査に明示された対象 path だけを bounded に表示する。
        return f"処理 {path}"
    return "処理"


def _status(operation: Mapping[str, object]) -> str:
    return str(operation.get("status") or "").casefold()


def _approval_pending(operation: Mapping[str, object]) -> bool:
    return _status(operation) in {"pending", "pending_approval"} or str(
        operation.get("approval_status") or ""
    ).casefold() == "pending"


def _event_result(event: Mapping[str, object]) -> Mapping[str, object]:
    payload = _mapping(event.get("payload"))
    return _mapping(payload.get("result"))


def _transfer_info(operation: Mapping[str, object]) -> tuple[str, int | None, list[Mapping[str, object]]]:
    request = _request(operation)
    result = _result(operation)
    transfer_id = ""
    for source in (result, request):
        value = source.get("transfer_id")
        if isinstance(value, str) and value:
            transfer_id = value
            break
    bytes_value = result.get("total_bytes")
    if "download" in str(operation.get("tool_name") or ""):
        bytes_value = result.get("bytes")
    total_bytes = bytes_value if isinstance(bytes_value, int) and bytes_value >= 0 else None
    chunk_name = TRANSFER_BEGIN_TO_CHUNK.get(str(operation.get("tool_name") or ""))
    events = operation.get("events")
    chunks: list[Mapping[str, object]] = []
    if isinstance(events, Sequence) and not isinstance(events, (str, bytes, bytearray)):
        for event in events:
            if not isinstance(event, Mapping):
                continue
            if chunk_name is None or event.get("event_type") == chunk_name:
                chunks.append(event)
    return transfer_id, total_bytes, chunks


def transfer_complete(operation: Mapping[str, object]) -> bool:
    """Audit event の chunk 範囲から transfer の完了を判定する。"""

    tool = str(operation.get("tool_name") or "")
    if tool not in TRANSFER_BEGIN_TO_CHUNK:
        return False
    if _status(operation) in TERMINAL_STATUSES and _status(operation) != "succeeded":
        return False
    _transfer_id, total_bytes, chunks = _transfer_info(operation)
    if _result(operation).get("complete") is True:
        return True
    if total_bytes == 0:
        return True
    if not chunks:
        return False
    if "upload" in tool:
        return any(_event_result(event).get("complete") is True for event in chunks)
    if total_bytes is None:
        return any(_event_result(event).get("complete") is True for event in chunks)
    ranges: list[tuple[int, int]] = []
    for event in chunks:
        outcome = _event_result(event)
        offset = outcome.get("offset")
        count = outcome.get("bytes")
        if isinstance(offset, int) and isinstance(count, int) and offset >= 0 and count > 0:
            ranges.append((offset, offset + count))
    covered_until = 0
    for start, end in sorted(ranges):
        if start > covered_until:
            break
        covered_until = max(covered_until, end)
    return covered_until >= total_bytes


def _transfer_timestamp(operation: Mapping[str, object]) -> object:
    events = operation.get("events")
    if isinstance(events, Sequence) and not isinstance(events, (str, bytes, bytearray)):
        chunk_name = TRANSFER_BEGIN_TO_CHUNK.get(str(operation.get("tool_name") or ""))
        for event in reversed(events):
            if isinstance(event, Mapping) and (
                chunk_name is None or event.get("event_type") == chunk_name
            ):
                occurred_at = event.get("occurred_at")
                if occurred_at:
                    return occurred_at
    return operation.get("updated_at") or operation.get("created_at") or ""


@dataclass(frozen=True)
class ActivityProjection:
    """一つの監査 operation を Live Activity に投影した結果。"""

    label: str
    detail: str
    operation_id: str
    status: str
    timestamp: object
    logical_id: str
    active: bool
    terminal: bool


def _operation_kind(operation: Mapping[str, object]) -> str:
    tool = str(operation.get("tool_name") or "")
    if tool in META_TOOLS or tool.startswith(META_PREFIXES):
        return "meta"
    if tool in TRANSFER_TOOLS:
        return "transfer"
    if tool in UNDO_TOOLS:
        return "undo"
    if tool in READ_TOOLS:
        return "read"
    if tool in STRUCTURED_EDIT_TOOLS:
        return "edit"
    if tool in MUTATION_TOOLS:
        return "edit"
    if tool in COMMAND_TOOLS:
        return "command"
    if tool in STOP_TOOLS:
        return "stop"
    if tool == "export_context":
        return "export"
    # Prefix rules cover compatibility/future structured surfaces without treating audit
    # accessors as user activity.
    if tool.startswith("structured_file_"):
        if "inspect" in tool or "read" in tool:
            return "read"
        if any(word in tool for word in ("apply", "extract", "write", "commit")):
            return "edit"
    if tool.startswith("artifact_"):
        return "transfer"
    if _mapping(_request(operation).get("normalized_command")):
        return "command"
    if _safe_path(operation, _request(operation), _result(operation)):
        # A future data operation with an explicit, allowlisted target remains visible even before
        # a dedicated wording policy is added. Pure metadata families were removed above.
        return "generic"
    return "unknown"


def project_operation(
    operation: Mapping[str, object],
    *,
    transfer_paths: Mapping[str, str] | None = None,
    transfer_states: Mapping[str, str] | None = None,
    target: Mapping[str, object] | None = None,
) -> ActivityProjection | None:
    """監査 operation を表示用状態へ変換する。"""

    kind = _operation_kind(operation)
    if kind == "meta":
        return None
    tool = str(operation.get("tool_name") or "")
    raw_status = _status(operation)
    operation_id = str(operation.get("id") or "")
    # Future tools are projected only when Audit supplies a bounded, allowlisted identity for
    # the user-visible work.  Terminal failures remain visible for diagnosis, while a nonterminal
    # opaque payload without a path/normalized command is intentionally suppressed.
    if kind == "unknown" and raw_status not in TERMINAL_STATUSES and not (
        _safe_path(operation, _request(operation), _result(operation))
        or _mapping(_request(operation).get("normalized_command"))
    ):
        return None
    transfer_id, _total_bytes, _chunks = _transfer_info(operation)
    transfer_path = (transfer_paths or {}).get(transfer_id, "")
    detail = _detail(operation, target=target, transfer_path=transfer_path)
    active = False
    terminal = False

    if _approval_pending(operation):
        label = "Approval"
        active = True
    elif raw_status in ACTIVE_STATUSES or (
        raw_status not in TERMINAL_STATUSES
        and str(operation.get("approval_status") or "").casefold() == "approved"
    ):
        label = "Running"
        active = True
    elif raw_status in TERMINAL_STATUSES:
        terminal = True
        if raw_status == "succeeded":
            if kind == "read":
                label = "Read"
            elif kind == "edit":
                label = {
                    "move_file": "Moved",
                    "copy_file": "Copied",
                    "delete_file": "Deleted",
                    "make_directory": "Created directory",
                }.get(tool, "Edited")
            elif kind == "transfer":
                transfer_state = (transfer_states or {}).get(transfer_id, "")
                if (
                    tool in TRANSFER_BEGIN_TO_CHUNK
                    and "upload" in tool
                    and transfer_state == "terminal_failure"
                ):
                    return None
                if tool in TRANSFER_BEGIN_TO_CHUNK and "upload" in tool and transfer_state == "succeeded":
                    label = "Uploaded"
                elif tool in TRANSFER_BEGIN_TO_CHUNK and not transfer_complete(operation):
                    label = "Running"
                    active = True
                    terminal = False
                elif tool in TRANSFER_BEGIN_TO_CHUNK and "upload" in tool:
                    # Upload chunks only stage the payload. The user-visible transfer is complete
                    # after the separate commit operation verifies and writes it.
                    label = "Running"
                    active = True
                    terminal = False
                elif "download" in tool:
                    label = "Downloaded"
                else:
                    label = "Uploaded"
            elif kind == "stop":
                label = "Cancelled"
            elif kind == "export":
                label = "Exported"
            elif kind == "undo":
                label = "Rolled back" if tool == "request_workspace_rollback" else "Undone"
            else:
                label = "Finished"
        else:
            label = STATUS_LABELS.get(raw_status, "Failed")
    elif raw_status.startswith("failed") or raw_status in {"recovery_required", "error"}:
        terminal = True
        label = "Failed"
    else:
        # Unknown nonterminal values are not silently presented as success. If the operation has
        # a meaningful known kind, Running is the safest human interpretation.  Future tools are
        # also eligible when Audit explicitly supplies an allowlisted target path or normalized
        # command; this keeps the projection extensible without exposing arbitrary request data.
        if kind == "unknown" and not (
            _safe_path(operation, _request(operation), _result(operation))
            or _mapping(_request(operation).get("normalized_command"))
        ):
            return None
        label = "Running"
        active = True

    # Transfer chunk success is an implementation detail. A failed/rejected chunk still matters,
    # so it is projected using the transfer begin's logical identity.
    if tool in TRANSFER_CHUNK_TO_BEGIN and raw_status == "succeeded":
        return None
    if kind == "transfer" and transfer_id:
        logical_id = f"transfer:{transfer_id}"
    else:
        logical_id = f"operation:{operation_id}"
    if raw_status in {"failed", "rejected", "interrupted", "timed_out", "expired", "conflict"}:
        tier = _safe_text(operation.get("tier"), limit=40)
        if tier in {"structured_processing", "transfer", "approved_host", "codex_sandbox"}:
            detail = f"{detail} [{tier}]"
    if kind == "transfer" and tool in TRANSFER_BEGIN_TO_CHUNK and transfer_complete(operation):
        timestamp = _transfer_timestamp(operation)
    else:
        timestamp = operation.get("updated_at") or operation.get("created_at") or ""
    return ActivityProjection(
        label=label,
        detail=_truncate(detail, MAX_ACTIVITY_SUMMARY),
        operation_id=operation_id,
        status=raw_status,
        timestamp=timestamp,
        logical_id=logical_id,
        active=active,
        terminal=terminal,
    )


def _timestamp(value: object) -> str:
    raw = terminal_safe(value)
    try:
        return datetime.fromisoformat(raw).astimezone().strftime("%H:%M:%S")
    except (TypeError, ValueError, OverflowError):
        return "--:--:--"


def format_projection(projection: ActivityProjection) -> str:
    """operation ID は表示し、request hash は出さずに一行へ安全に整形する。"""

    suffix = " [succeeded]" if projection.label == "Finished" and projection.status == "succeeded" else ""
    operation_tag = f"[op:{projection.operation_id}] " if projection.operation_id else ""
    return terminal_safe(
        f"[{_timestamp(projection.timestamp)}] {projection.label:<10} "
        f"{operation_tag}{projection.detail}{suffix}"
    )


def format_activity(
    operation: Mapping[str, object],
    *,
    transfer_paths: Mapping[str, str] | None = None,
    transfer_states: Mapping[str, str] | None = None,
    target: Mapping[str, object] | None = None,
) -> str | None:
    projection = project_operation(
        operation,
        transfer_paths=transfer_paths,
        transfer_states=transfer_states,
        target=target,
    )
    return format_projection(projection) if projection is not None else None


def activity_detail(operation: Mapping[str, object]) -> str:
    """既存 `_activity_detail` 呼び出しとの互換ヘルパー。"""

    return _detail(operation)


def _raw_signature(operation: Mapping[str, object]) -> tuple[object, ...]:
    return (
        operation.get("status"),
        operation.get("approval_status"),
        operation.get("updated_at"),
    )


def _projection_signature(projection: ActivityProjection) -> tuple[object, ...]:
    return (projection.logical_id, projection.label, projection.detail, projection.terminal)


class LiveActivityTracker:
    """Approval UI 向けに監査 lifecycle を差分投影する tracker。"""

    def __init__(self, audit: AuditStore, *, limit: int = 200) -> None:
        self.audit = audit
        self.limit = max(1, min(limit, 500))
        self._baseline_ready = False
        self._known_raw: dict[str, tuple[object, ...]] = {}
        self._known_projection: dict[str, tuple[object, ...]] = {}
        self._transfer_paths: dict[str, str] = {}
        self._transfer_states: dict[str, str] = {}
        self._cached: dict[str, Mapping[str, object]] = {}

    @staticmethod
    def _requires_full(row: Mapping[str, object], previous: tuple[object, ...] | None) -> bool:
        tool = str(row.get("tool_name") or "")
        if tool in META_TOOLS or tool.startswith(META_PREFIXES):
            return False
        # Transfer begin の events は operation.updated_at を変えないため、転送中は毎回
        # 再取得して完了範囲を見直す。
        if tool in TRANSFER_BEGIN_TO_CHUNK:
            return True
        return previous is None or _raw_signature(row) != previous

    def _load_full(self, row: Mapping[str, object]) -> Mapping[str, object] | None:
        operation_id = str(row.get("id") or "")
        tool = str(row.get("tool_name") or "")
        include_events = tool in TRANSFER_BEGIN_TO_CHUNK
        try:
            full = self.audit.get_operation(operation_id, include_events=include_events)
        except Exception:  # noqa: BLE001 - UI polling must survive a concurrent DB transaction
            return None
        self._cached[operation_id] = full
        return full

    def _refresh_transfer_paths(self, operations: Sequence[Mapping[str, object]]) -> None:
        for operation in operations:
            tool = str(operation.get("tool_name") or "")
            if tool not in TRANSFER_TOOLS:
                continue
            transfer_id, _total, _events = _transfer_info(operation)
            if not transfer_id:
                transfer_id = str(_result(operation).get("transfer_id") or "")
            path = _safe_path(operation, _request(operation), _result(operation))
            if transfer_id and path:
                self._transfer_paths[transfer_id] = path
            if tool in TRANSFER_COMMIT_TOOLS and transfer_id:
                status = _status(operation)
                if status == "succeeded":
                    self._transfer_states[transfer_id] = "succeeded"
                elif status in TERMINAL_STATUSES:
                    self._transfer_states[transfer_id] = "terminal_failure"

    def poll_once(self, *, emit: bool = True) -> list[str]:
        try:
            rows = self.audit.list_operations(limit=self.limit)
            # ``limit`` is primarily a history bound. Query each active status separately so a
            # long-lived operation is not hidden behind a burst of newer terminal audit rows.
            active_rows: dict[str, Mapping[str, object]] = {
                str(row.get("id") or ""): row for row in rows
            }
            for active_status in (*ACTIVE_STATUSES, "pending_approval"):
                try:
                    queried_rows = self.audit.list_operations(limit=500, status=active_status)
                except Exception:  # noqa: BLE001 - one optional status query must not stop UI
                    queried_rows = []
                for row in queried_rows:
                    operation_id = str(row.get("id") or "")
                    if operation_id:
                        active_rows[operation_id] = row
            rows = sorted(
                active_rows.values(),
                key=lambda row: (
                    str(row.get("created_at") or ""),
                    str(row.get("id") or ""),
                ),
                reverse=True,
            )
        except Exception:  # noqa: BLE001 - the DB may be unavailable during startup/rotation
            return []
        current_ids = {str(row.get("id") or "") for row in rows}
        loaded: list[Mapping[str, object]] = []
        for row in rows:
            operation_id = str(row.get("id") or "")
            previous_raw = self._known_raw.get(operation_id)
            if emit:
                self._known_raw[operation_id] = _raw_signature(row)
            if self._requires_full(row, previous_raw):
                full = self._load_full(row)
                if full is not None:
                    loaded.append(full)
            elif operation_id in self._cached:
                loaded.append(self._cached[operation_id])
        self._refresh_transfer_paths(loaded)

        # Transfer rows may be omitted from ``loaded`` after completion, but cached data keeps the
        # path association for a later chunk failure/commit row.
        for row in rows:
            operation_id = str(row.get("id") or "")
            if operation_id not in {str(item.get("id") or "") for item in loaded}:
                cached = self._cached.get(operation_id)
                if cached is not None:
                    loaded.append(cached)
        by_id = {str(item.get("id") or ""): item for item in loaded}

        lines: list[str] = []
        logically_active_before_poll = {
            str(signature[0])
            for signature in self._known_projection.values()
            if len(signature) > 1 and signature[1] in {"Approval", "Running"}
        }
        # list_operations is newest-first; reverse it so terminal transitions read naturally.
        for row in reversed(rows):
            operation_id = str(row.get("id") or "")
            operation = by_id.get(operation_id, row)
            tool = str(operation.get("tool_name") or row.get("tool_name") or "")
            target: Mapping[str, object] | None = None
            if tool in UNDO_TOOLS:
                target_id = _request(operation).get("target_operation_id")
                if isinstance(target_id, str) and target_id:
                    target = self._cached.get(target_id)
                    if target is None:
                        try:
                            target = self.audit.get_operation(target_id, include_events=False)
                        except Exception:  # noqa: BLE001 - target may have been pruned
                            target = None
                        if target is not None:
                            self._cached[target_id] = target
            projection = project_operation(
                operation,
                transfer_paths=self._transfer_paths,
                transfer_states=self._transfer_states,
                target=target,
            )
            if projection is None:
                self._known_projection.pop(operation_id, None)
                continue
            signature = _projection_signature(projection)
            previous_signature = self._known_projection.get(operation_id)
            was_new = previous_signature is None
            # Multiple operations in one logical transfer share a logical ID. Keep one line for
            # begin/chunk/commit instead of exposing protocol chatter.
            logical_previous = any(
                value == signature for key, value in self._known_projection.items() if key != operation_id
            )
            changed = previous_signature != signature and not logical_previous
            if not self._baseline_ready:
                self._known_projection[operation_id] = signature
                if projection.active:
                    line = format_projection(projection)
                    if emit:
                        lines.append(line)
                    # Keep the baseline projection even when a caller explicitly suppresses
                    # output; the initial Approval UI poll always emits active work.
                continue
            if changed:
                # Approval UI may pause polling while a user answers. If a fast operation jumps
                # from pending to terminal, preserve a visible Running transition for Undo/
                # rollback and transfer lifecycles.
                previous_label = (
                    previous_signature[1]
                    if previous_signature is not None and len(previous_signature) > 1
                    else None
                )
                synthesize_running = tool in UNDO_TOOLS or (
                    tool in TRANSFER_TOOLS
                    and projection.logical_id not in logically_active_before_poll
                )
                if projection.terminal and (
                    was_new or previous_label == "Approval"
                ) and synthesize_running:
                    synthetic = ActivityProjection(
                        label="Running",
                        detail=projection.detail,
                        operation_id=projection.operation_id,
                        status="running",
                        timestamp=projection.timestamp,
                        logical_id=projection.logical_id,
                        active=True,
                        terminal=False,
                    )
                    if emit:
                        lines.append(format_projection(synthetic))
                line = format_projection(projection)
                if emit:
                    lines.append(line)
            # While the approval prompt is paused, leave the previous projection in place. The
            # first resumed poll then emits the missed transition instead of silently consuming it.
            if emit:
                self._known_projection[operation_id] = signature

        self._baseline_ready = True
        self._known_raw = {
            key: value for key, value in self._known_raw.items() if key in current_ids
        }
        self._known_projection = {
            key: value for key, value in self._known_projection.items() if key in current_ids
        }
        return lines

    def run(
        self,
        stop: threading.Event,
        paused: threading.Event | None = None,
        *,
        interval_seconds: float = 0.5,
        output: Callable[[str], Any] = print,
    ) -> None:
        while not stop.wait(interval_seconds):
            if paused is not None and paused.is_set():
                self.poll_once(emit=False)
                continue
            for line in self.poll_once(emit=True):
                output(line, flush=True)
