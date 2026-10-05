"""Execute bounded plans through the existing checkpoint, journal and recovery boundary."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import ExitStack, nullcontext
from typing import Any

from .paths import release_verified_hold
from .performance_trace import phase
from .resources import WorkspaceExecutionLock
from .util import canonical_json, sha256_bytes, utc_now_iso
from .workspace_history import (
    WorkspaceMutationError,
    build_workspace_target,
    capture_workspace_state,
    checkpoint_state,
    compare_workspace_states,
    finalize_workspace_transaction,
    incomplete_workspace_transactions,
    mark_workspace_transaction_audit_reconciled,
    restore_workspace_state,
    rollback_applied_workspace_transaction,
)
from .workspace_plan import WorkspacePlan, bind_plan_parents, validate_plan


def run_workspace_plan(
    runtime: Any,
    tool_name: str,
    planner: Callable[[], WorkspacePlan],
    *,
    preview: bool,
    reason: str,
    require_ready: Callable[[], None],
    safe: Callable[[Any], Any],
    prepared: bool = False,
) -> dict[str, Any]:
    """One audit operation per call; never fall back to individual mutation tools."""
    audit, settings, workspace = runtime.audit, runtime.settings, runtime.workspace
    operation_id = audit.create_operation(
        tool_name=tool_name,
        tier="broker",
        status="running",
        cwd=str(settings.workspace_root),
        request={"high_level_operation": tool_name, "preview": preview},
    )
    try:
        with phase("request_validation"):
            require_ready()
            if not isinstance(preview, bool):
                raise TypeError("preview must be boolean")
            if not isinstance(reason, str) or len(reason) > settings.max_reason_characters:
                raise ValueError("reason exceeds max_reason_characters")
        audit.add_event(operation_id, "high_level_preflight_started", {})
        with phase("transform"):
            plan = planner()
            if not prepared:
                bind_plan_parents(workspace, plan)
            if len(plan.scope) > settings.max_high_level_files:
                raise ValueError("workspace plan scope exceeds max_high_level_files")
            if len(plan.scope) > settings.approval_manifest_max_files:
                raise ValueError("workspace plan scope exceeds approval_manifest_max_files")
            if plan.retained_bytes > settings.max_high_level_total_bytes:
                raise ValueError("workspace plan exceeds max_high_level_total_bytes")
        # All bytes stay server-side. Previews report only selected paths and counts.
        audit.add_event(operation_id, "high_level_preflight_completed", safe(plan.summary))
        if preview:
            with phase("cas_recheck"):
                validate_plan(workspace, plan)
            plan_id = runtime.workspace_plans.put(plan)
            result = {
                "operation_id": operation_id,
                "status": "preview",
                "high_level_operation": plan.tool_name,
                "plan_id": plan_id,
                "expires_in_seconds": runtime.workspace_plans.ttl_seconds,
                **plan.summary,
            }
            # The opaque reference is deliberately absent from durable audit records.
            audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="succeeded",
                finished_at=utc_now_iso(),
                result_json=canonical_json(
                    safe({k: v for k, v in result.items() if k != "plan_id"})
                ),
            )
            return result

        targets = tuple(workspace.root / relative for relative in sorted(plan.scope))
        audit.add_event(operation_id, "high_level_lock_wait", {"targets": len(targets)})
        lock = WorkspaceExecutionLock(settings, targets=targets) if targets else nullcontext()
        with lock, ExitStack() as holds:
            for target in sorted(targets, key=lambda item: os.path.normcase(str(item))):
                holds.enter_context(workspace.lock_target(target))
            require_ready()
            # Preserve ancestor and read-only source identity throughout the transaction.
            for relative in plan.parents:
                held = workspace.resolve_directory(relative, access="write")
                holds.callback(release_verified_hold, held)
            for relative in set(plan.snapshots) - set(plan.changes) - plan.deletions:
                held = workspace.resolve_existing(relative, allow_directory=False, access="read")
                holds.callback(release_verified_hold, held)
            with phase("cas_recheck"):
                validate_plan(workspace, plan)
            audit.add_event(operation_id, "high_level_lock_acquired", {"targets": len(targets)})
            if not plan.changes and not plan.deletions and not plan.directories:
                result = {
                    "operation_id": operation_id,
                    "status": "succeeded",
                    "high_level_operation": plan.tool_name,
                    "changed_file_count": 0,
                    "execution_route": "broker_direct",
                    **plan.summary,
                }
                audit.transition_operation(
                    operation_id,
                    from_statuses={"running"},
                    status="succeeded",
                    finished_at=utc_now_iso(),
                    result_json=canonical_json(safe(result)),
                )
                return result
            with phase("checkpoint_before"):
                before = capture_workspace_state(settings, operation_id, "before", paths=plan.scope)
            expected = {
                key: "file:" + sha256_bytes(item.data) for key, item in plan.snapshots.items()
            }
            if checkpoint_state(settings, before.manifest_path) != expected:
                raise RuntimeError(
                    "workspace plan is stale; checkpoint no longer matches preflight"
                )
            validate_plan(workspace, plan)
            audit.update_operation(operation_id, pre_workspace_path=before.manifest_path)
            target_manifest = build_workspace_target(
                settings,
                operation_id,
                before.manifest_path,
                changes=plan.changes,
                deletions=plan.deletions,
                directory_additions=plan.directories,
            )
            identities = {key: item.identity for key, item in plan.snapshots.items()}
            identities.update({key: None for key in plan.absent - plan.directories})
            audit.add_event(
                operation_id, "high_level_transaction_staged", {"paths": len(plan.scope)}
            )
            restore_workspace_state(
                settings,
                before.manifest_path,
                target_manifest,
                operation_id=operation_id,
                expected_identities=identities,
            )
            try:
                with phase("checkpoint_after"):
                    after = capture_workspace_state(
                        settings, operation_id, "after", paths=plan.scope
                    )
                if checkpoint_state(settings, after.manifest_path) != checkpoint_state(
                    settings, target_manifest
                ):
                    raise RuntimeError("workspace plan post-write verification failed")
                changes = compare_workspace_states(
                    settings, before.manifest_path, after.manifest_path, operation_id
                )
                result = {
                    "operation_id": operation_id,
                    "status": "succeeded",
                    "high_level_operation": plan.tool_name,
                    "execution_route": "broker_direct",
                    "transaction": "workspace_restore",
                    "failure_atomicity": "best_effort_with_automatic_recovery",
                    "rollback_state": "complete",
                    **plan.summary,
                    **changes,
                }
                # Persist the result before clearing the interruption journal.
                transitioned = audit.transition_operation(
                    operation_id,
                    from_statuses={"running"},
                    status="succeeded",
                    finished_at=utc_now_iso(),
                    pre_workspace_path=before.manifest_path,
                    post_workspace_path=after.manifest_path,
                    diff_path=str(changes["diff_path"]),
                    rollback_state="complete",
                    result_json=canonical_json(safe(result)),
                )
                if not transitioned:
                    raise RuntimeError("workspace operation audit completion was not accepted")
                audit.add_event(
                    operation_id, "high_level_operation_committed", {"paths": len(plan.scope)}
                )
                finalize_workspace_transaction(settings, operation_id)
            except Exception as error:
                rollback_applied_workspace_transaction(settings, operation_id)
                raise WorkspaceMutationError(
                    "workspace plan failed after mutation; starting state recovered",
                    recovery_state="failed_recovered",
                    journal_path=str(
                        settings.data_dir
                        / "workspace-history"
                        / "transactions"
                        / operation_id
                        / "journal.json"
                    ),
                ) from error
            return result
    except Exception as error:
        recovery = error.recovery_state if isinstance(error, WorkspaceMutationError) else None
        failed_recorded = audit.transition_operation(
            operation_id,
            from_statuses={"running", "succeeded"},
            status="failed",
            finished_at=utc_now_iso(),
            error=safe(f"{type(error).__name__}: {error}"),
            result_json=canonical_json(
                {
                    "operation_id": operation_id,
                    "status": "failed",
                    "high_level_operation": tool_name,
                    "rollback_state": recovery,
                }
            ),
            **({"rollback_state": recovery} if recovery else {}),
        )
        if failed_recorded and recovery == "failed_recovered":
            mark_workspace_transaction_audit_reconciled(settings, operation_id)
        elif failed_recorded and any(
            item.get("operation_id") == operation_id and item.get("state") == "failed_preflight"
            for item in incomplete_workspace_transactions(settings)
        ):
            # A journal can exist even when staging rejects before the first workspace write.
            # Reconcile only that proven terminal state after the audit row is terminal too.
            mark_workspace_transaction_audit_reconciled(settings, operation_id)
        audit.add_event(
            operation_id,
            "high_level_operation_failed",
            {
                "error_type": type(error).__name__,
                "fallback_attempted": False,
                "rollback_state": recovery,
            },
        )
        raise
