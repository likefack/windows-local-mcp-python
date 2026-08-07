from __future__ import annotations

import json
import threading
import time
from datetime import datetime

from .approval import verify_approval_bundle
from .audit import TERMINAL_STATUSES, AuditStore
from .config import Settings, load_settings
from .executor import Executor
from .policy import NormalizedCommand, approval_hash
from .util import utc_now_iso

_READ_ACTIVITY_TOOLS = {"list_directory", "read_file", "get_image", "git_info"}
_COMMAND_ACTIVITY_TOOLS = {"execute_readonly", "execute_workspace_write", "adb_read", "request_host_command"}


def _show(item: dict[str, object]) -> None:
    print("\n" + "=" * 80)
    print(f"Approval ID : {item['id']}")
    print(f"Created     : {item['created_at']}")
    print(f"Expires     : {item['request_expires_at']}")
    print(f"Tool        : {item['tool_name']}")
    print(f"CWD         : {item['cwd']}")
    print(f"Hash        : {item['request_hash']}")
    print("-" * 80)
    print(json.dumps(item["request"], ensure_ascii=False, indent=2))
    print("=" * 80)


def _activity_detail(operation: dict[str, object]) -> str:
    tool = str(operation.get("tool_name") or "operation")
    request = operation.get("request")
    if isinstance(request, dict):
        path = request.get("path")
        if isinstance(path, str) and path:
            return f"{tool} {path}"
        safe_request = request.get("safe_request")
        if isinstance(safe_request, dict):
            program = safe_request.get("program")
            args = safe_request.get("args")
            if isinstance(program, str):
                short_args = ""
                if isinstance(args, list):
                    short_args = " ".join(str(value) for value in args[:3])
                return f"{program} {short_args}".strip()
    return tool


def _format_activity(operation: dict[str, object]) -> str | None:
    tool = str(operation.get("tool_name") or "")
    status = str(operation.get("status") or "")

    if status == "pending_approval" and tool == "request_host_command":
        label = "Approval"
    elif status in {"queued", "running", "approved"} and tool in _COMMAND_ACTIVITY_TOOLS:
        label = "Running"
    elif status == "succeeded" and tool == "write_file":
        label = "Edited"
    elif status == "succeeded" and tool in _READ_ACTIVITY_TOOLS:
        label = "Read"
    elif status in TERMINAL_STATUSES and tool in _COMMAND_ACTIVITY_TOOLS:
        label = "Finished"
    else:
        return None

    timestamp = str(operation.get("updated_at") or operation.get("created_at") or "")
    try:
        when = datetime.fromisoformat(timestamp).astimezone().strftime("%H:%M:%S")
    except (TypeError, ValueError):
        when = "--:--:--"
    detail = _activity_detail(operation)
    suffix = ""
    if label == "Finished":
        suffix = f" [{status}]"
    return f"[{when}] {label:<8} {detail}{suffix}"


def _activity_loop(audit: AuditStore, stop: threading.Event, paused: threading.Event) -> None:
    # Establish a baseline so old successful operations are not replayed on every UI start.
    baseline = audit.list_operations(limit=200)
    seen: dict[str, tuple[str, str]] = {
        str(item["id"]): (str(item.get("status") or ""), str(item.get("updated_at") or ""))
        for item in baseline
    }
    for item in reversed(baseline):
        if item.get("status") in {"queued", "running"}:
            full = audit.get_operation(str(item["id"]), include_events=False)
            line = _format_activity(full)
            if line:
                print(line, flush=True)

    while not stop.wait(0.5):
        if paused.is_set():
            continue
        for item in reversed(audit.list_operations(limit=200)):
            operation_id = str(item["id"])
            signature = (str(item.get("status") or ""), str(item.get("updated_at") or ""))
            if seen.get(operation_id) == signature:
                continue
            seen[operation_id] = signature
            full = audit.get_operation(operation_id, include_events=False)
            line = _format_activity(full)
            if line:
                print(line, flush=True)


def run_approval_ui(settings: Settings | None = None) -> None:
    settings = settings or load_settings()
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    print(f"Audit DB: {audit.db_path}")
    print("Live activity: Read / Edited / Running / Finished")
    print("Pending approvals: y=approve and run once, n=reject, s=skip, q=quit")

    stop_activity = threading.Event()
    pause_activity = threading.Event()
    activity_thread = threading.Thread(
        target=_activity_loop,
        args=(audit, stop_activity, pause_activity),
        daemon=True,
        name="windows-local-mcp-live-activity",
    )
    activity_thread.start()

    try:
        while True:
            pending = audit.list_pending_approvals()
            if not pending:
                time.sleep(0.5)
                continue

            for item in pending:
                pause_activity.set()
                _show(item)
                decision = input("Decision [y/N/s/q]: ").strip().casefold()
                if decision == "q":
                    return
                if decision == "s":
                    pause_activity.clear()
                    continue
                note = input("Note (optional): ").strip()
                operation_id = str(item["id"])
                if decision not in {"y", "yes"}:
                    audit.decide_approval(
                        operation_id,
                        approved=False,
                        approver=settings.default_approver,
                        note=note,
                    )
                    print("Rejected.")
                    pause_activity.clear()
                    continue

                try:
                    request = item["request"]
                    if not isinstance(request, dict):
                        raise TypeError("invalid approval request")
                    normalized = NormalizedCommand.model_validate(request["normalized_command"])
                    manifest_digest = str(request["approval_manifest_digest"])
                    expected_hash = approval_hash(
                        normalized=normalized,
                        reason=str(request.get("reason", "")),
                        risk_summary=str(request.get("risk_summary", "")),
                        manifest_digest=manifest_digest,
                    )
                    if expected_hash != item.get("request_hash"):
                        raise RuntimeError("approval request hash mismatch")
                    verify_approval_bundle(
                        settings=settings,
                        operation_id=operation_id,
                        expected_digest=manifest_digest,
                    )
                    audit.approve_and_claim(
                        operation_id,
                        approver=settings.default_approver,
                        note=note,
                    )
                    executor.launch(operation_id, 0)
                    print("Approved and launched once. The MCP client can poll the result.")
                except Exception as error:  # noqa: BLE001 - fail closed and persist any launch error
                    audit.update_operation(
                        operation_id,
                        status="failed",
                        approval_status="rejected",
                        finished_at=utc_now_iso(),
                        error=f"approval validation or launch failed: {type(error).__name__}: {error}",
                    )
                    audit.add_event(
                        operation_id,
                        "approval_launch_failed",
                        {"error": f"{type(error).__name__}: {error}"[:1000]},
                    )
                    print(f"Not executed: {error}")
                finally:
                    pause_activity.clear()
    except KeyboardInterrupt:
        return
    finally:
        stop_activity.set()
        pause_activity.clear()
        activity_thread.join(timeout=2.0)
