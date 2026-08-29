"""安全な一行形式で監査DBの活動を起動端末へ表示する監視CLI。

このモジュールは監査DBを読み取り専用で参照するだけで、監査記録の作成・更新や
``AuditStore`` の初期化を行いません。したがって、LocalMCPの起動と独立して先に
起動した場合でも、DBが作られるまで待機できます。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sqlite3
import sys
import threading
from collections.abc import Mapping, Sequence
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Self, TextIO

from .config import Settings, load_settings
from .redaction import redact_text, redact_value

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 10
DEFAULT_POLL_INTERVAL_SECONDS = 0.5
MAX_SUMMARY_CHARACTERS = 200

_CONTROL_RANGES = ((0x00, 0x1F), (0x7F, 0x9F))
_BIDI_CONTROLS = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)

def _is_terminal_control(character: str) -> bool:
    codepoint = ord(character)
    return (
        any(start <= codepoint <= end for start, end in _CONTROL_RANGES)
        or character in _BIDI_CONTROLS
        or 0xD800 <= codepoint <= 0xDFFF
    )


def sanitize_display_text(value: object) -> str:
    """監査由来の文字列を端末・ログに安全に表示できる形へ整える。

    改行、ANSIエスケープの起点になる制御文字、C1制御文字、双方向制御文字、
    UTF-8へ変換できないサロゲートは除去します。伏せ字は呼び出し側で行うため、
    この関数は文字の形だけを扱います。
    """

    return "".join(character for character in str(value) if not _is_terminal_control(character))


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    if limit <= 1:
        return value[:limit]
    return value[: limit - 1] + "…"


def _safe_redacted_text(value: object) -> str:
    # 伏せ字の前にも制御文字を除去する。``pass<escape>word=...`` のようにキーへ
    # 制御文字を差し込まれると、伏せ字処理が代入形式を検出できなくなるため。
    normalized = sanitize_display_text(value)
    return sanitize_display_text(redact_text(normalized))


def _display_command_summary(display_command: object) -> str:
    """Return a bounded, redacted command display without expanding arbitrary request data."""

    redacted = redact_value(display_command)
    if isinstance(redacted, (list, tuple)):
        parts = [_safe_redacted_text(item) for item in redacted]
        return _truncate(" ".join(part for part in parts if part), MAX_SUMMARY_CHARACTERS)
    return _truncate(_safe_redacted_text(redacted), MAX_SUMMARY_CHARACTERS)


def _request_from_operation(operation: Mapping[str, object]) -> Mapping[str, object]:
    request = operation.get("request")
    if isinstance(request, Mapping):
        return request
    request_json = operation.get("request_json")
    if not isinstance(request_json, str):
        return {}
    try:
        decoded = json.loads(request_json)
    except (TypeError, ValueError, UnicodeError):
        return {}
    return decoded if isinstance(decoded, Mapping) else {}


def summarize_operation(operation: Mapping[str, object]) -> str:
    """Extract only a short command/path/target summary from an operation.

    ``result_json`` is deliberately never read here. In particular, stdout/stderr previews,
    file contents, diffs, and arbitrary request fields are not included in the summary.
    """

    request = _request_from_operation(operation)
    normalized = request.get("normalized_command")
    if isinstance(normalized, Mapping):
        display_command = normalized.get("display_command")
        if isinstance(display_command, (str, Sequence)) and not isinstance(
            display_command, (bytes, bytearray)
        ):
            summary = _display_command_summary(display_command)
            if summary:
                return summary

    path = request.get("path")
    if isinstance(path, str) and path:
        return _truncate(_safe_redacted_text(path), MAX_SUMMARY_CHARACTERS)

    target_operation_id = request.get("target_operation_id")
    if isinstance(target_operation_id, str) and target_operation_id:
        return _truncate(
            "target=" + _safe_redacted_text(target_operation_id), MAX_SUMMARY_CHARACTERS
        )

    return ""


def _timestamp(operation: Mapping[str, object]) -> str:
    raw = operation.get("updated_at") or operation.get("created_at") or ""
    raw_text = sanitize_display_text(raw)
    try:
        return datetime.fromisoformat(raw_text).astimezone().strftime("%H:%M:%S")
    except (TypeError, ValueError, OverflowError):
        return "--:--:--"


def _safe_field(operation: Mapping[str, object], name: str, default: str) -> str:
    value = operation.get(name)
    if value is None or value == "":
        return default
    return _truncate(_safe_redacted_text(value), 120)


def format_activity_line(
    operation: Mapping[str, object], *, event_kind: str = "updated"
) -> str:
    """Format one operation transition without including raw request/result content."""

    normalized_event = event_kind.casefold()
    if normalized_event in {"new", "created"}:
        event = "NEW"
    elif normalized_event == "current":
        event = "CURRENT"
    else:
        event = "UPDATE"
    operation_id = _safe_field(operation, "id", "unknown")
    tool_name = _safe_field(operation, "tool_name", "operation")
    status = _safe_field(operation, "status", "unknown")
    approval_status = _safe_field(operation, "approval_status", "-")
    raw_status = str(operation.get("status") or "").casefold()
    raw_approval_status = str(operation.get("approval_status") or "").casefold()
    pending = raw_status == "pending_approval" or raw_approval_status == "pending"

    fields = [
        f"[{_timestamp(operation)}]",
        event,
        f"operation={operation_id}",
        f"tool={tool_name}",
        f"route={_safe_field(operation, 'tier', '-')}",
        f"status={status}",
        f"approval_status={approval_status}",
    ]
    if pending:
        # 機械可読な状態名と人間向けの目印を併記し、端末を少し離れて見ても承認要求を
        # 見落とさないようにする。
        fields.extend(("PENDING_APPROVAL", "要承認"))
    summary = summarize_operation(operation)
    if summary:
        fields.append(f"summary={summary}")
    return sanitize_display_text(" ".join(fields))


class ActivitySink:
    """Write identical safe lines to stdout and the bounded persistent activity log."""

    def __init__(self, data_dir: str | Path, *, stdout: TextIO | None = None) -> None:
        self.data_dir = Path(data_dir)
        self.log_path = self.data_dir / "logs" / "localmcp-activity.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.stdout = stdout if stdout is not None else sys.stdout
        self._logger = logging.getLogger(f"windows-local-mcp.activity-monitor.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler = RotatingFileHandler(
            self.log_path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
            delay=True,
        )
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(self._handler)
        self._closed = False

    def write_line(self, line: str) -> str:
        if self._closed:
            raise RuntimeError("activity sink is closed")
        safe_line = sanitize_display_text(line)
        print(safe_line, file=self.stdout, flush=True)
        self._logger.info(safe_line)
        self._handler.flush()
        return safe_line

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._logger.removeHandler(self._handler)
        self._handler.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _connect_read_only(db_path: Path) -> sqlite3.Connection:
    """既存の監査DBを、この監視プロセスから書き込めない形で開く。"""

    database_uri = db_path.resolve().as_uri() + "?mode=ro"
    database = sqlite3.connect(database_uri, uri=True, timeout=0.5)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA query_only = ON")
    return database


def _read_operation_metadata(db_path: Path) -> dict[str, dict[str, object]] | None:
    """Read operation state, returning None while the DB/schema is unavailable."""

    if not db_path.is_file():
        return None
    try:
        with _connect_read_only(db_path) as database:
            rows = database.execute(
                "SELECT id, created_at, updated_at, tool_name, tier, status, approval_status "
                "FROM operations ORDER BY created_at ASC, id ASC"
            ).fetchall()
    except (OSError, sqlite3.Error):
        return None
    return {str(row["id"]): dict(row) for row in rows}


def _read_operation(db_path: Path, operation_id: str) -> dict[str, object] | None:
    """Load only the changed row; request JSON is parsed transiently for its safe summary."""

    if not db_path.is_file():
        return None
    try:
        with _connect_read_only(db_path) as database:
            row = database.execute(
                "SELECT id, created_at, updated_at, tool_name, tier, status, approval_status, "
                "request_json FROM operations WHERE id = ?",
                (operation_id,),
            ).fetchone()
    except (OSError, sqlite3.Error):
        return None
    return dict(row) if row is not None else None


def _operation_signature(operation: Mapping[str, object]) -> tuple[object, object]:
    # ライフサイクルの状態だけで行を発生させる。両方の状態を変えない結果・エラーの
    # 書き込みは活動表示のノイズになるため再表示しない。
    return operation.get("status"), operation.get("approval_status")


class ActivityMonitor:
    """Poll ``data_dir/audit.db`` and emit only post-baseline lifecycle changes."""

    def __init__(
        self,
        data_dir: str | Path,
        *,
        sink: ActivitySink | None = None,
        interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "audit.db"
        self.interval_seconds = interval_seconds
        self.sink = sink if sink is not None else ActivitySink(self.data_dir)
        self._owns_sink = sink is None
        self._known: dict[str, tuple[object, object]] = {}
        self._baseline_ready = False

    def poll_once(self) -> list[str]:
        metadata = _read_operation_metadata(self.db_path)
        if metadata is None:
            # Do not establish a baseline until the DB and its operations table can be read.
            return []

        if not self._baseline_ready:
            self._known = {
                operation_id: _operation_signature(operation)
                for operation_id, operation in metadata.items()
            }
            self._baseline_ready = True
            # 起動前から残っている承認待ちだけは見落とさないよう一度表示する。
            # 完了済みの履歴全体は流さず、activity_timeline／audit_list で参照する。
            pending_lines: list[str] = []
            for operation_id, operation in metadata.items():
                raw_status = str(operation.get("status") or "").casefold()
                raw_approval = str(operation.get("approval_status") or "").casefold()
                if raw_status != "pending_approval" and raw_approval != "pending":
                    continue
                full_operation = _read_operation(self.db_path, operation_id)
                if full_operation is None:
                    continue
                line = format_activity_line(full_operation, event_kind="current")
                self.sink.write_line(line)
                pending_lines.append(line)
            return pending_lines

        current_ids = set(metadata)
        lines: list[str] = []
        for operation_id, operation in metadata.items():
            signature = _operation_signature(operation)
            previous = self._known.get(operation_id)
            if previous == signature:
                continue
            full_operation = _read_operation(self.db_path, operation_id)
            if full_operation is None:
                # The row may have been deleted or be mid-transaction. Retry next poll.
                continue
            line = format_activity_line(
                full_operation,
                event_kind="new" if previous is None else "updated",
            )
            self.sink.write_line(line)
            lines.append(line)
            self._known[operation_id] = _operation_signature(full_operation)

        # A deleted ID must not suppress a later operation that legitimately reuses that ID.
        self._known = {
            operation_id: signature
            for operation_id, signature in self._known.items()
            if operation_id in current_ids
        }
        return lines

    def run(self, stop_event: threading.Event | None = None) -> None:
        stop = stop_event if stop_event is not None else threading.Event()
        self.poll_once()
        while not stop.wait(self.interval_seconds):
            self.poll_once()

    def close(self) -> None:
        if self._owns_sink:
            self.sink.close()


def run_activity_monitor(
    settings: Settings | None = None,
    *,
    interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    stop_event: threading.Event | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Run the monitor from an already resolved Settings object or ``load_settings``."""

    resolved = settings if settings is not None else load_settings()
    sink = ActivitySink(resolved.data_dir, stdout=stdout)
    monitor = ActivityMonitor(
        resolved.data_dir,
        sink=sink,
        interval_seconds=interval_seconds,
    )
    try:
        sink.write_line(f"[Activity] 監視開始 log={sink.log_path}")
        monitor.run(stop_event)
    finally:
        sink.close()


def _positive_interval(value: str) -> float:
    interval = float(value)
    if interval <= 0:
        raise argparse.ArgumentTypeError("interval must be greater than zero")
    return interval


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="windows-local-mcp-activity-monitor",
        description="監査DBの新規操作・状態変化を起動端末へ表示します。",
    )
    parser.add_argument(
        "--config",
        "-Config",
        "-c",
        dest="config",
        type=Path,
        help="LocalMCP設定ファイル（省略時はLOCAL_MCP_CONFIGを使用）",
    )
    parser.add_argument(
        "--interval",
        type=_positive_interval,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help="監査DBを確認する間隔（秒）",
    )
    return parser


def _settings_from_config(config_path: Path | None) -> Settings:
    if config_path is not None:
        os.environ["LOCAL_MCP_CONFIG"] = str(config_path.expanduser().resolve())
    return load_settings()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        settings = _settings_from_config(args.config)
    except Exception as error:  # noqa: BLE001 - CLI reports a bounded diagnostic only
        detail = sanitize_display_text(f"{type(error).__name__}: {error}")
        print(f"活動監視を開始できません: {_truncate(detail, 300)}", file=sys.stderr)
        return 2

    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    previous_handlers: dict[int, Any] = {}
    for signal_number in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
        if signal_number is None:
            continue
        previous_handlers[signal_number] = signal.signal(signal_number, request_stop)

    try:
        run_activity_monitor(
            settings,
            interval_seconds=args.interval,
            stop_event=stop,
        )
    except KeyboardInterrupt:
        stop.set()
    finally:
        for signal_number, previous in previous_handlers.items():
            signal.signal(signal_number, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
