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
from .resources import WorkspaceExecutionLock
from .risk import command_risk_facts
from .util import canonical_json, sha256_text, utc_now_iso
from .workspace_history import (
    WorkspaceMutationError,
    capture_workspace_state,
    checkpoint_manifest_digest,
    compare_workspace_states,
    describe_workspace_restore,
    finalize_workspace_transaction,
    restore_workspace_state,
    workspace_recovery_required,
)

_BIDI_CONTROLS = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _terminal_safe(value: object) -> str:
    """Make request-controlled text inert in a terminal approval boundary."""
    text = str(value)
    return "".join(
        f"\\u{ord(character):04x}"
        if ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or character in _BIDI_CONTROLS
        else character
        for character in text
    )

_READ_ACTIVITY_TOOLS = {"list_directory", "read_file", "get_image", "git_info"}
_COMMAND_ACTIVITY_TOOLS = {
    "execute_readonly",
    "execute_workspace_write",
    "adb_read",
    "request_host_command",
    "request_workspace_rollback",
    "request_selective_undo",
}


def _show(item: dict[str, object]) -> None:
    print("\n" + "=" * 80)
    print(f"Approval ID : {_terminal_safe(item['id'])}")
    print(f"Created     : {_terminal_safe(item['created_at'])}")
    print(f"Expires     : {_terminal_safe(item['request_expires_at'])}")
    print(f"Tool        : {_terminal_safe(item['tool_name'])}")
    print(f"CWD         : {_terminal_safe(item['cwd'])}")
    print(f"Hash        : {_terminal_safe(item['request_hash'])}")
    request = item["request"]
    if isinstance(request, dict):
        normalized_summary = request.get("normalized_command")
        if isinstance(normalized_summary, dict):
            display = normalized_summary.get("display_command")
            if isinstance(display, list):
                print("Command argv: " + json.dumps(display, ensure_ascii=True))
        operation_type = request.get("operation_type")
        if operation_type:
            print(f"Operation   : {_terminal_safe(operation_type)}")
            print(f"Target op   : {_terminal_safe(request.get('target_operation_id', ''))}")
            preview = request.get("undo_preview")
            if isinstance(preview, dict):
                print(
                    "Files       : "
                    f"{preview.get('changed_file_count', 0)} changed; "
                    f"create={bool(preview.get('creates_files'))}, "
                    f"restore={bool(preview.get('restores_files'))}, "
                    f"delete={bool(preview.get('deletes_files'))}"
                )
        facts = request.get("objective_risk")
        normalized_payload = request.get("normalized_command")
        summary = request.get("approval_manifest_summary")
        if isinstance(normalized_payload, dict) and isinstance(summary, dict):
            facts = command_risk_facts(
                NormalizedCommand.model_validate(normalized_payload),
                workspace_write=bool(request.get("workspace_write")),
                manifest=summary,
            )
        if isinstance(facts, dict):
            print(f"Risk level   : {facts.get('risk_level', 'unknown')}")
            detected = facts.get("detected_requested_effects")
            if isinstance(detected, dict) and detected:
                print("Detected / requested effects (verified by MCP):")
                for key, value in detected.items():
                    if value not in {False, None, ""}:
                        print(f"  {_terminal_safe(key)}: {_terminal_safe(value)}")
            capabilities = facts.get("effective_host_capabilities")
            if isinstance(capabilities, dict) and capabilities:
                print("Effective host capabilities:")
                for key, value in capabilities.items():
                    if value not in {False, None, ""}:
                        print(f"  {_terminal_safe(key)}: {_terminal_safe(value)}")
        print("Model-provided context (not independently verified):")
        print(f"  reason: {_terminal_safe(request.get('reason', ''))}")
        print(f"  risk_summary: {_terminal_safe(request.get('risk_summary', ''))}")
        print("-" * 80)
        technical_keys = sorted(
            key
            for key in request
            if key not in {"reason", "risk_summary", "objective_risk"}
        )
        print("Technical details are available through activity_get/audit_get.")
        print(f"  fields: {', '.join(technical_keys)}")
    else:
        print(json.dumps(request, ensure_ascii=False, indent=2))
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
        target_operation = request.get("target_operation_id")
        if isinstance(target_operation, str):
            return f"{tool} target={target_operation}"
    return tool


def _format_activity(operation: dict[str, object]) -> str | None:
    tool = str(operation.get("tool_name") or "")
    status = str(operation.get("status") or "")

    if status == "pending_approval" and tool in {
        "request_host_command",
        "request_workspace_rollback",
        "request_selective_undo",
    }:
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
    return _terminal_safe(f"[{when}] {label:<8} {detail}{suffix}")


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
                    if item.get("tool_name") in {
                        "request_workspace_rollback",
                        "request_selective_undo",
                    }:
                        expected_hash = sha256_text(canonical_json(request))
                        if expected_hash != item.get("request_hash"):
                            raise RuntimeError("workspace control approval request hash mismatch")
                        before = None
                        try:
                            with WorkspaceExecutionLock(settings):
                                if workspace_recovery_required(settings):
                                    raise RuntimeError(
                                        "workspace mutation is blocked pending recovery"
                                    )
                                expected_checkpoint = str(
                                    request["expected_current_checkpoint"]
                                )
                                target_checkpoint = str(request["target_checkpoint"])
                                if checkpoint_manifest_digest(
                                    settings, expected_checkpoint
                                ) != request.get("expected_current_manifest_sha256"):
                                    raise RuntimeError(
                                        "approved current-checkpoint manifest changed"
                                    )
                                if checkpoint_manifest_digest(
                                    settings, target_checkpoint
                                ) != request.get("target_manifest_sha256"):
                                    raise RuntimeError("approved target manifest changed")
                                fresh_preview = describe_workspace_restore(
                                    settings, expected_checkpoint, target_checkpoint
                                )
                                approved_preview = request.get("undo_preview")
                                if not isinstance(approved_preview, dict):
                                    raise TypeError("approved workspace preview is missing")
                                for key in (
                                    "files_that_would_change",
                                    "changed_file_count",
                                    "created_files",
                                    "restored_files",
                                    "deleted_files",
                                ):
                                    if fresh_preview.get(key) != approved_preview.get(key):
                                        raise RuntimeError(
                                            "approved workspace preview no longer matches manifests"
                                        )
                                audit.approve_and_claim(
                                    operation_id,
                                    approver=settings.default_approver,
                                    note=note,
                                    expected_request_hash=expected_hash,
                                )
                                before = capture_workspace_state(settings, operation_id, "before")
                                audit.update_operation(
                                    operation_id,
                                    pre_workspace_path=before.manifest_path,
                                    rollback_state="applying",
                                )
                                restored = restore_workspace_state(
                                    settings,
                                    str(request["expected_current_checkpoint"]),
                                    str(request["target_checkpoint"]),
                                    operation_id=operation_id,
                                )
                                change = compare_workspace_states(
                                    settings,
                                    before.manifest_path,
                                    str(request["target_checkpoint"]),
                                    operation_id,
                                )
                            result = {
                                "operation_id": operation_id,
                                "status": "succeeded",
                                "operation_type": request["operation_type"],
                                "target_operation_id": request["target_operation_id"],
                                **restored,
                                **change,
                                "rollback_state": "complete",
                                "undo_can_be_undone": True,
                            }
                            audit.update_operation(
                                operation_id,
                                status="succeeded",
                                finished_at=utc_now_iso(),
                                pre_workspace_path=before.manifest_path,
                                post_workspace_path=str(request["target_checkpoint"]),
                                diff_path=change["diff_path"],
                                rollback_state="complete",
                                result_json=canonical_json(result),
                            )
                            audit.add_event(operation_id, "workspace_control_complete", result)
                            try:
                                finalize_workspace_transaction(settings, operation_id)
                            except Exception as finalize_error:  # noqa: BLE001 - journal retained
                                result["status"] = "interrupted"
                                result["rollback_state"] = "applied_audit_incomplete"
                                audit.update_operation(
                                    operation_id,
                                    status="interrupted",
                                    rollback_state="applied_audit_incomplete",
                                    result_json=canonical_json(result),
                                    error=(
                                        "workspace reached the approved target, but journal "
                                        f"finalization failed: {finalize_error}"
                                    ),
                                )
                                audit.add_event(
                                    operation_id,
                                    "workspace_control_applied_audit_incomplete",
                                    result,
                                )
                                print(
                                    "Applied, but audit finalization was interrupted; "
                                    "startup reconciliation will finish the journal."
                                )
                            else:
                                print(
                                    "Approved and completed. This operation can itself be undone."
                                )
                        except WorkspaceMutationError as mutation_error:
                            result = {
                                "operation_id": operation_id,
                                "status": "failed",
                                "operation_type": request["operation_type"],
                                "target_operation_id": request["target_operation_id"],
                                "rollback_state": mutation_error.recovery_state,
                                "transaction_journal": mutation_error.journal_path,
                            }
                            audit.update_operation(
                                operation_id,
                                status="failed",
                                finished_at=utc_now_iso(),
                                pre_workspace_path=(
                                    before.manifest_path if before is not None else None
                                ),
                                rollback_state=mutation_error.recovery_state,
                                result_json=canonical_json(result),
                                error=str(mutation_error),
                            )
                            audit.add_event(operation_id, "workspace_control_failed", result)
                            print(f"Failed: {mutation_error}")
                        except Exception as control_error:  # noqa: BLE001 - persist preflight stop
                            result = {
                                "operation_id": operation_id,
                                "status": "failed",
                                "operation_type": request["operation_type"],
                                "target_operation_id": request["target_operation_id"],
                                "rollback_state": "failed_preflight",
                            }
                            audit.update_operation(
                                operation_id,
                                status="failed",
                                finished_at=utc_now_iso(),
                                rollback_state="failed_preflight",
                                result_json=canonical_json(result),
                                error=f"{type(control_error).__name__}: {control_error}",
                            )
                            audit.add_event(
                                operation_id,
                                "workspace_control_preflight_failed",
                                {"error": str(control_error)[:1000]},
                            )
                            print(f"Not applied: {control_error}")
                        pause_activity.clear()
                        continue
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
                        expected_request_hash=expected_hash,
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
