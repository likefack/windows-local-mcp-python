from __future__ import annotations

import argparse
import os
import subprocess
import time
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .approval import (
    collect_staged_workspace_changes,
    materialize_execution_copy,
    settings_digest,
    verify_approval_bundle,
)
from .audit import AuditStore
from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .control_plane import load_worker_context, verify_control_plane_generation
from .control_plane_guard import (
    capture_critical_state,
    expected_critical_state,
    mark_control_plane_tamper,
)
from .git_snapshot import capture_git_snapshot
from .network_isolation import apply_safe_network_environment, safe_network_policy
from .paths import Workspace
from .policy import CommandPolicy, NormalizedCommand, approved_request_hash
from .process_utils import (
    ProcessIdentity,
    build_process_argv,
    capture_current_user_processes,
    capture_process_identity,
    creation_flags,
    process_tree_write_bytes,
    terminate_process_tree,
    wait_for_untracked_current_user_processes,
)
from .redaction import redact_text, redact_value
from .resources import (
    BoundedStreamCapture,
    NamedControlPlaneLock,
    WorkspaceExecutionLock,
    enforce_data_quota,
    scan_directory_bounded,
)
from .safe_process import run_safe_process
from .sandbox_backend import (
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    codex_sandbox_effective_policy,
    guard_and_launch_codex_sandbox,
    hold_codex_sandbox_backend,
    probe_codex_version,
    require_codex_sandbox_live_verification,
    verify_codex_sandbox_backend,
)
from .tool_safety import hold_executable_identity
from .util import canonical_json, utc_now_iso
from .wfp_guard_identity import hold_wfp_guard_implementation
from .windows_job import WindowsSandboxJob
from .workspace_history import (
    build_workspace_target_from_bytes,
    capture_workspace_state,
    compare_workspace_states,
    finalize_workspace_transaction,
    restore_workspace_state,
    workspace_recovery_required,
)


class ApprovalExecutionExpired(RuntimeError):
    pass


class OperationDeadlineExceeded(RuntimeError):
    pass


class RuntimeStoragePolicyError(RuntimeError):
    pass


def run_operation(operation_id: str, settings: Settings) -> int:
    operation_started = time.monotonic()
    audit = AuditStore(settings)
    operation = audit.get_operation(operation_id, include_events=False)
    operation["tier"] = {
        "safe_command": "broker",
        "safe_sandbox": "broker",
        "approved_sandbox": "codex_sandbox",
        "host_approval": "approved_host",
    }.get(str(operation.get("tier")), operation.get("tier"))
    request = operation["request"]
    verify_control_plane_generation(settings, request.get("control_plane_generation"))
    normalized = request["normalized_command"]
    approved_tier = operation["tier"] in {"codex_sandbox", "approved_host"}
    sandbox_backend: CodexSandboxBackend | None = None
    sandbox_backend_version: str | None = None
    sandbox_live_evidence: dict[str, Any] | None = None
    workspace_lock: WorkspaceExecutionLock | None = None
    tracks_workspace = _requires_workspace_execution_lock(operation, request, normalized)
    if tracks_workspace:
        workspace_lock = WorkspaceExecutionLock(settings)
        try:
            workspace_lock.__enter__()
        except TimeoutError as lock_error:
            audit.transition_operation(
                operation_id,
                from_statuses={"queued", "running", "committing"},
                status="failed",
                finished_at=utc_now_iso(),
                error=str(lock_error),
            )
            audit.add_event(
                operation_id, "workspace_lock_timeout", {"error": str(lock_error)[:1000]}
            )
            return 1
        if workspace_recovery_required(settings):
            workspace_lock.__exit__(None, None, None)
            audit.transition_operation(
                operation_id,
                from_statuses={"queued", "running", "committing"},
                status="failed",
                finished_at=utc_now_iso(),
                error="workspace mutation is blocked pending recovery",
            )
            audit.add_event(operation_id, "workspace_recovery_required", {})
            return 1
    try:
        if operation["tier"] == "broker" and request.get(
            "settings_digest"
        ) != settings_digest(settings):
            raise RuntimeError("effective MCP settings changed before safe execution")
        if approved_tier:
            if approved_request_hash(request) != operation.get("request_hash"):
                raise RuntimeError("approved request changed after local approval")
            verified = verify_approval_bundle(
                settings=settings,
                operation_id=operation_id,
                expected_digest=request["approval_manifest_digest"],
            )
            if operation["tier"] == "codex_sandbox" or not bool(
                request.get("workspace_write")
            ):
                verified = materialize_execution_copy(
                    settings=settings, operation_id=operation_id, normalized=verified
                )
            normalized = verified.model_dump()
            if operation["tier"] == "codex_sandbox":
                expected_backend = request.get("sandbox_backend")
                if not isinstance(expected_backend, dict):
                    raise ApprovedSandboxUnavailable(
                        "Approved Sandbox request has no immutable backend binding"
                    )
                sandbox_backend = verify_codex_sandbox_backend(settings, expected_backend)
                sandbox_live_evidence = require_codex_sandbox_live_verification(
                    settings, sandbox_backend
                )
            audit.add_event(operation_id, "approval_bundle_verified", {})
        elif operation["tier"] == "broker":
            safe_request = request.get("safe_request")
            if not isinstance(safe_request, dict):
                raise RuntimeError("safe command is missing its original validated request")
            policy = CommandPolicy(settings, Workspace(settings))
            fresh = policy.normalize_safe(
                program=str(safe_request["program"]),
                args=list(safe_request["args"]),
                cwd=str(safe_request["cwd"]),
            )
            if fresh.model_dump() != normalized:
                raise RuntimeError("safe command changed between validation and execution")
            execution_manifest_digest = request.get("execution_manifest_digest")
            if execution_manifest_digest:
                verified = verify_approval_bundle(
                    settings=settings,
                    operation_id=operation_id,
                    expected_digest=str(execution_manifest_digest),
                )
                verified = materialize_execution_copy(
                    settings=settings, operation_id=operation_id, normalized=verified
                )
                normalized = verified.model_dump()
                audit.add_event(operation_id, "safe_execution_bundle_verified", {})
            else:
                normalized = fresh.model_dump()
            audit.add_event(operation_id, "safe_command_revalidated", {})
    except Exception as error:  # noqa: BLE001 - every verification failure must be persisted
        if workspace_lock is not None:
            workspace_lock.__exit__(None, None, None)
        audit.transition_operation(
            operation_id,
            from_statuses={"queued", "running", "committing"},
            status="failed",
            finished_at=utc_now_iso(),
            error=f"pre-execution verification failed: {type(error).__name__}: {error}",
        )
        audit.add_event(
            operation_id,
            "pre_execution_verification_failed",
            {"error": f"{type(error).__name__}: {error}"[:1000]},
        )
        return 1

    executable = normalized["executable"]
    args = list(normalized["args"])
    cwd = normalized["cwd"]
    max_runtime = int(request["max_runtime_seconds"])
    deadline: float | None = None
    nonce = str(operation.get("process_nonce") or os.environ.get("WINDOWS_LOCAL_MCP_JOB_NONCE", ""))
    if not nonce:
        raise RuntimeError("worker process nonce is missing")

    try:
        # Windows venv launchers may hand execution to the base interpreter while retaining
        # the PID. Bind the durable audit identity only after this worker is fully running.
        worker_identity = capture_process_identity(os.getpid(), nonce)
    except Exception as error:  # noqa: BLE001 - uncertain worker identity must fail closed
        if workspace_lock is not None:
            workspace_lock.__exit__(None, None, None)
        audit.transition_operation(
            operation_id,
            from_statuses={"queued", "running"},
            status="failed",
            finished_at=utc_now_iso(),
            error=f"worker identity verification failed: {type(error).__name__}: {error}",
        )
        audit.add_event(
            operation_id,
            "worker_identity_verification_failed",
            {"error": f"{type(error).__name__}: {error}"[:1000]},
        )
        return 1

    stdout_path = settings.data_dir / "outputs" / f"{operation_id}.stdout.log"
    stderr_path = settings.data_dir / "outputs" / f"{operation_id}.stderr.log"
    enforce_data_quota(settings, incoming_bytes=2 * settings.max_output_bytes_per_stream)

    if not audit.transition_operation(
        operation_id,
        from_statuses={"queued"},
        status="running",
        started_at=utc_now_iso(),
        worker_pid=worker_identity.pid,
        worker_create_time=worker_identity.create_time,
        worker_executable=worker_identity.executable,
        process_nonce=nonce,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    ):
        audit.add_event(operation_id, "worker_start_suppressed", {"reason": "operation_already_terminal"})
        if workspace_lock is not None:
            workspace_lock.__exit__(None, None, None)
        return 1
    audit.add_event(
        operation_id,
        "worker_started",
        {
            "worker_pid": worker_identity.pid,
            "worker_create_time": worker_identity.create_time,
            "worker_executable": worker_identity.executable,
            "identity_role": "stable_worker",
            "identity_verified": True,
        },
    )

    staged_sandbox_commit = bool(
        operation["tier"] == "codex_sandbox"
        and request.get("workspace_write")
        and isinstance(request.get("approval_manifest_summary"), dict)
        and request["approval_manifest_summary"].get("mode") == "staged-workspace-write"
    )
    # Approved Sandbox runs from its immutable projection and retains a complete workspace
    # checkpoint for boundary detection and rollback. A second Git Broker snapshot is only
    # optional telemetry, but each fixed Git query launches another sandbox and can consume the
    # complete one-shot execution TTL before the approved child starts. Keep that telemetry for
    # Approved Host, where it describes host-authority effects, but never place it on the
    # Approved Sandbox child-launch path.
    capture_live_git_telemetry = tracks_workspace and operation["tier"] != "codex_sandbox"
    pre_git = (
        capture_git_snapshot(
            settings=settings,
            operation_id=operation_id,
            stage="before",
            required=False,
        )
        if capture_live_git_telemetry
        else None
    )
    if pre_git:
        audit.update_operation(operation_id, pre_git_path=pre_git)
    pre_workspace = None
    if tracks_workspace:
        try:
            checkpoint_started = time.monotonic()
            audit.add_event(operation_id, "workspace_checkpoint_started", {"stage": "before"})
            pre_workspace = capture_workspace_state(settings, operation_id, "before")
            audit.update_operation(operation_id, pre_workspace_path=pre_workspace.manifest_path)
            audit.add_event(
                operation_id,
                "workspace_checkpoint_completed",
                {
                    "stage": "before",
                    "duration_ms": int((time.monotonic() - checkpoint_started) * 1000),
                    "file_count": pre_workspace.file_count,
                    "total_bytes": pre_workspace.total_bytes,
                },
            )
        except Exception as snapshot_error:  # noqa: BLE001 - persist checkpoint failures
            audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="failed",
                finished_at=utc_now_iso(),
                error=f"workspace checkpoint failed: {type(snapshot_error).__name__}: {snapshot_error}",
            )
            audit.add_event(
                operation_id, "workspace_checkpoint_failed", {"error": str(snapshot_error)[:1000]}
            )
            if workspace_lock is not None:
                workspace_lock.__exit__(None, None, None)
            return 1

    host_control_state: dict[str, Any] | None = None
    host_operation_binding: dict[str, Any] | None = None
    host_user_process_baseline: set[tuple[int, float]] | None = None
    host_process_census_required = False
    host_control_locks: ExitStack | None = None
    if operation["tier"] == "approved_host":
        try:
            host_control_locks = ExitStack()
            lock_timeout = float(request["max_runtime_seconds"]) + 60
            # Approved Host can mutate every same-user control-plane file. Keep legitimate
            # WLMCP writers out of the guarded interval so a concurrent broker operation is
            # not mistaken for host tampering. This is serialization, not an authority claim:
            # the postflight digest remains the fail-closed tamper boundary.
            for lock_name in (
                "approval-staging",
                "audit-state",
                "binary-transfer",
                "sandbox-verification",
                "worker-context",
                "workspace-cas",
            ):
                host_control_locks.enter_context(
                    NamedControlPlaneLock(settings, lock_name, timeout=lock_timeout)
                )
            concurrent = [
                item["id"]
                for item in audit.list_active_operations()
                if item["id"] != operation_id
            ]
            if concurrent:
                raise RuntimeError(
                    "Approved Host requires an exclusive control-plane interval; "
                    f"active operations remain: {', '.join(concurrent[:5])}"
                )
            host_operation_binding = {
                "id": operation["id"],
                "tier": operation["tier"],
                "request_hash": operation.get("request_hash"),
                "claimed_at": operation.get("claimed_at"),
                "approval_status": operation.get("approval_status"),
                "request": operation["request"],
            }
            host_control_state = capture_critical_state(settings, operation_id)
            audit.add_event(
                operation_id,
                "approved_host_control_plane_guard_armed",
                host_control_state,
            )
        except Exception as guard_error:  # noqa: BLE001 - host must not launch unguarded
            audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="failed",
                finished_at=utc_now_iso(),
                error=f"Approved Host control-plane preflight failed: {guard_error}",
            )
            audit.add_event(
                operation_id,
                "approved_host_control_plane_guard_failed",
                {"error": str(guard_error)[:1000]},
            )
            if workspace_lock is not None:
                workspace_lock.__exit__(None, None, None)
            if host_control_locks is not None:
                host_control_locks.close()
            return 1

    child: Any | None = None
    child_identity: ProcessIdentity | None = None
    child_write_baseline: int | None = None
    stdout_capture: BoundedStreamCapture | None = None
    stderr_capture: BoundedStreamCapture | None = None
    status = "failed"
    exit_code: int | None = None
    error: str | None = None
    failure_class: str | None = None
    network_policy_payload: dict[str, object] | None = None
    wfp_guard_verification: dict[str, object] | None = None
    sandbox_backend_hold: Any | None = None
    guard_implementation_hold: Any | None = None
    sandbox_job: Any | None = None
    host_job: WindowsSandboxJob | None = None
    host_descendants_verified_empty = True
    executable_hold: Any | None = None

    try:
        _verify_adb_target(normalized, settings)
        if approved_tier:
            refreshed = audit.get_operation(operation_id, include_events=False)
            _ensure_approval_execution_fresh(refreshed)
        executable_identity = normalized.get("executable_identity")
        if not isinstance(executable_identity, dict):
            raise TypeError("execution has no immutable executable identity")
        executable_hold = hold_executable_identity(executable_identity)
        held_path = executable_hold.__enter__()
        if held_path != Path(str(executable)).resolve(strict=True):
            raise RuntimeError("held executable does not match the normalized command")
        if operation["tier"] == "codex_sandbox":
            if sandbox_backend is None:
                raise ApprovedSandboxUnavailable("Approved Sandbox backend is unavailable")
            sandbox_backend_hold = hold_codex_sandbox_backend(sandbox_backend)
            sandbox_backend = sandbox_backend_hold.__enter__()
            guard_implementation_hold = hold_wfp_guard_implementation()
            guard_implementation_hold.__enter__()
            sandbox_backend_version = probe_codex_version(sandbox_backend, settings)
            if sandbox_backend_version != sandbox_backend.version:
                raise ApprovedSandboxUnavailable(
                    "Approved Sandbox backend version changed before execution"
                )
            sandbox_live_evidence = require_codex_sandbox_live_verification(
                settings, sandbox_backend
            )
        child_env = build_command_environment(
            os.environ,
            extra_names=settings.child_environment_allowlist,
            nonce=nonce,
            git_command=normalized.get("program_key") == "git",
        )
        if operation["tier"] == "codex_sandbox" and sandbox_backend is not None:
            assert settings.sandbox_scratch_dir is not None
            sanitize_executable_search_path(
                child_env,
                forbidden_roots=(
                    settings.workspace_root,
                    settings.data_dir,
                    settings.sandbox_scratch_dir,
                ),
                prepend=(Path(sandbox_backend.executable).parent,),
            )
        if operation["tier"] == "broker":
            network_policy = safe_network_policy(
                str(normalized.get("program_key", "")),
                mode="broker",
            )
            apply_safe_network_environment(child_env, str(normalized.get("program_key", "")))
            network_policy_payload = network_policy.as_dict()
            network_policy_payload["enforcement_status"] = "prepared"
            audit.update_operation(
                operation_id, network_policy_json=canonical_json(network_policy_payload)
            )
            audit.add_event(operation_id, "network_policy_prepared", network_policy_payload)
        elif operation["tier"] == "codex_sandbox":
            network_policy = codex_sandbox_effective_policy(
                workspace_write=bool(request.get("workspace_write"))
            )
            network_policy.update(
                {
                    "backend_version": sandbox_backend_version,
                    "isolation_setup_status": "live_marker_verified",
                    "wfp_guard_status": "pending",
                    "enforcement_status": "prepared",
                }
            )
            audit.update_operation(
                operation_id, network_policy_json=canonical_json(network_policy)
            )
            audit.add_event(operation_id, "sandbox_policy_prepared", network_policy)
        else:
            network_policy = {
                "name": "approved-host-network",
                "internet": "allowed" if normalized.get("network_expected") else "not-requested",
                "lan": "allowed" if normalized.get("network_expected") else "not-requested",
                "loopback": "allowed",
                "enforcement": "human-approval",
            }
            audit.update_operation(operation_id, network_policy_json=canonical_json(network_policy))
            audit.add_event(operation_id, "network_policy_applied", network_policy)
        if operation["tier"] == "codex_sandbox":
            assert settings.sandbox_scratch_dir is not None
            runtime_root = settings.sandbox_scratch_dir / "runs" / operation_id
        else:
            runtime_root = settings.data_dir / "outputs" / f"{operation_id}-runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        try:
            Path(cwd).resolve(strict=True).relative_to(runtime_root.resolve(strict=True))
            if operation["tier"] == "codex_sandbox":
                raise ValueError("Codex launcher requires its installed user-local setup state")
            isolated_home = runtime_root / "home"
            isolated_temp = runtime_root / "temp"
            isolated_home.mkdir(exist_ok=True)
            isolated_temp.mkdir(exist_ok=True)
            child_env.update(
                {
                    "HOME": str(isolated_home),
                    "USERPROFILE": str(isolated_home),
                    "APPDATA": str(isolated_home / "AppData" / "Roaming"),
                    "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
                    "TEMP": str(isolated_temp),
                    "TMP": str(isolated_temp),
                    "PUB_CACHE": str(runtime_root / "empty-pub-cache"),
                }
            )
        except (ValueError, FileNotFoundError):
            pass
        if operation["tier"] == "broker" and normalized.get("program_key") == "adb":
            cwd = str(runtime_root)
        argv = build_process_argv(executable, args, cwd=cwd)
        runtime_limit = min(
            settings.approval_manifest_max_bytes + settings.max_write_bytes,
            settings.max_data_dir_bytes // 2,
        )
        runtime_entry_limit = max(128, settings.approval_manifest_max_files * 4)
        if operation["tier"] in {"broker", "codex_sandbox"}:
            _enforce_runtime_storage_preflight(
                runtime_root,
                byte_limit=runtime_limit,
                entry_limit=runtime_entry_limit,
            )
        # max_runtime_seconds is the admitted child/finalization budget. Trusted
        # preflight work happens before this point and must not consume that command budget.
        deadline = time.monotonic() + max_runtime
        if operation["tier"] == "codex_sandbox":
            if sandbox_backend is None:
                raise ApprovedSandboxUnavailable("Approved Sandbox backend is unavailable")
            if sandbox_live_evidence is None:
                raise ApprovedSandboxUnavailable(
                    "Approved Sandbox has no immutable C7 live marker evidence"
                )

            def record_guard_verified(payload: dict[str, object]) -> None:
                nonlocal wfp_guard_verification, network_policy
                wfp_guard_verification = dict(payload)
                network_policy["wfp_guard_status"] = "verified_before_launch"
                network_policy["wfp_guard"] = wfp_guard_verification
                audit.update_operation(
                    operation_id, network_policy_json=canonical_json(network_policy)
                )
                audit.add_event(operation_id, "wfp_guard_verified", wfp_guard_verification)

            try:
                child, sandbox_job, _sandbox_argv, _guard = guard_and_launch_codex_sandbox(
                    sandbox_backend,
                    settings=settings,
                    command=argv,
                    cwd=Path(cwd),
                    writable_roots=(runtime_root,),
                    environment=child_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    on_guard_verified=record_guard_verified,
                    expected_live_evidence=sandbox_live_evidence,
                )
            except ApprovedSandboxUnavailable as guard_error:
                network_policy["wfp_guard_status"] = "verification_failed"
                audit.update_operation(
                    operation_id, network_policy_json=canonical_json(network_policy)
                )
                audit.add_event(
                    operation_id,
                    "wfp_guard_verification_failed",
                    {"diagnostic": str(guard_error)[:1000], "host_fallback": False},
                )
                raise
        elif operation["tier"] == "approved_host" and os.name == "nt":
            # Capture the baseline immediately before launch. Job Objects do not account for
            # Win32_Process.Create processes, so postflight also waits for new same-user
            # processes observed after this point.
            host_process_census_required = True
            host_user_process_baseline = capture_current_user_processes()
            host_job = WindowsSandboxJob()
            child = host_job.popen(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creation_flags(),
                env=child_env,
            )
            host_descendants_verified_empty = False
        else:
            child = subprocess.Popen(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creation_flags(),
                start_new_session=(os.name != "nt"),
                env=child_env,
            )
        if child.stdout is None or child.stderr is None:
            raise RuntimeError("failed to create bounded output pipes")
        child_identity = capture_process_identity(child.pid, nonce)
        if operation["tier"] in {"broker", "codex_sandbox"}:
            child_write_baseline = process_tree_write_bytes(child_identity)
            if child_write_baseline is None:
                raise RuntimeError("sandbox filesystem write accounting is unavailable")
        if operation["tier"] == "broker" and network_policy_payload is not None:
            network_policy_payload["enforcement_status"] = "active"
            audit.update_operation(
                operation_id, network_policy_json=canonical_json(network_policy_payload)
            )
            audit.add_event(operation_id, "network_policy_applied", network_policy_payload)
        elif operation["tier"] == "codex_sandbox":
            network_policy["enforcement_status"] = "active"
            audit.update_operation(
                operation_id, network_policy_json=canonical_json(network_policy)
            )
            audit.add_event(operation_id, "sandbox_policy_applied", network_policy)
        audit.update_operation(
            operation_id,
            child_pid=child_identity.pid,
            child_create_time=child_identity.create_time,
            child_executable=child_identity.executable,
        )
        audit.add_event(
            operation_id,
            "child_started",
            {
                "child_pid": child.pid,
                "argv": redact_value(argv),
                "identity_verified": True,
            },
        )
        stdout_capture = BoundedStreamCapture(
            child.stdout, stdout_path, settings.max_output_bytes_per_stream
        )
        stderr_capture = BoundedStreamCapture(
            child.stderr, stderr_path, settings.max_output_bytes_per_stream
        )
        stdout_capture.start()
        stderr_capture.start()
        while True:
            if sandbox_job is not None and sandbox_job.violation is not None:
                sandbox_job.terminate()
                child.wait(timeout=10)
                exit_code = child.returncode
                status = "failed"
                error = f"sandbox OS resource limit exceeded: {sandbox_job.violation}"
                failure_class = "sandbox_resource_policy"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_launched_child(child, child_identity)
                exit_code = None
                status = "timed_out"
                error = f"maximum runtime exceeded: {max_runtime} seconds"
                failure_class = "runtime_limit"
                break
            try:
                exit_code = child.wait(timeout=min(0.5, remaining))
                if host_job is not None:
                    if exit_code != 0:
                        host_job.terminate()
                        if not host_job.wait_empty(timeout=10):
                            raise RuntimeError(
                                "Approved Host Job Object descendants did not terminate"
                            )
                    else:
                        descendants_deadline = max(0.0, deadline - time.monotonic())
                        if not host_job.wait_empty(timeout=descendants_deadline):
                            host_job.terminate()
                            exit_code = None
                            status = "timed_out"
                            error = f"maximum runtime exceeded: {max_runtime} seconds"
                            failure_class = "runtime_limit"
                            break
                if sandbox_job is not None and sandbox_job.violation is not None:
                    status = "failed"
                    error = f"sandbox OS resource limit exceeded: {sandbox_job.violation}"
                    failure_class = "sandbox_resource_policy"
                else:
                    status = "succeeded" if exit_code == 0 else "failed"
                    error = None if exit_code == 0 else f"command exited with code {exit_code}"
                    failure_class = None if exit_code == 0 else "command_failure"
                if operation["tier"] in {"broker", "codex_sandbox"}:
                    storage_error = _safe_runtime_storage_error(
                        runtime_root,
                        byte_limit=runtime_limit,
                        entry_limit=runtime_entry_limit,
                    )
                    if storage_error is not None:
                        status = "failed"
                        error = storage_error
                        failure_class = "sandbox_resource_policy"
                break
            except subprocess.TimeoutExpired:
                if operation["tier"] in {"broker", "codex_sandbox"}:
                    written = (
                        process_tree_write_bytes(child_identity)
                        if child_identity is not None
                        else None
                    )
                    if written is None or child_write_baseline is None:
                        _terminate_launched_child(child, child_identity)
                        exit_code = None
                        status = "failed"
                        error = "sandbox filesystem write accounting became unavailable"
                        failure_class = "sandbox_resource_policy"
                        break
                    if written - child_write_baseline > runtime_limit:
                        _terminate_launched_child(child, child_identity)
                        exit_code = None
                        status = "failed"
                        error = "sandbox filesystem write limit exceeded"
                        failure_class = "sandbox_resource_policy"
                        break
                    storage_error = _safe_runtime_storage_error(
                        runtime_root,
                        byte_limit=runtime_limit,
                        entry_limit=runtime_entry_limit,
                    )
                    if storage_error is not None:
                        _terminate_launched_child(child, child_identity)
                        exit_code = None
                        status = "failed"
                        error = storage_error
                        failure_class = "sandbox_resource_policy"
                        break
    except RuntimeStoragePolicyError as exc:
        exit_code = None
        status = "failed"
        failure_class = "sandbox_resource_policy"
        error = str(exc)
        audit.add_event(
            operation_id,
            "runtime_storage_preflight_failed",
            {"error": error[:1000]},
        )
    except ApprovalExecutionExpired as exc:
        if child_identity is not None:
            _terminate_launched_child(child, child_identity)
        elif child is not None:
            child.terminate()
        exit_code = None
        status = "expired"
        error = str(exc)
        audit.add_event(
            operation_id,
            "approval_expired_before_child_start",
            {"error": error[:1000]},
        )
    except OperationDeadlineExceeded as exc:
        exit_code = None
        status = "timed_out"
        error = str(exc)
        failure_class = "operation_deadline"
        audit.add_event(operation_id, "operation_deadline_exceeded", {"error": error})
    except ApprovedSandboxUnavailable as exc:
        if child_identity is not None:
            _terminate_launched_child(child, child_identity)
        elif child is not None:
            child.terminate()
        exit_code = None
        status = "failed"
        failure_class = "sandbox_backend_failure"
        error = f"Approved Sandbox unavailable; no host fallback occurred: {exc}"
        audit.add_event(
            operation_id,
            "approved_sandbox_unavailable",
            {"diagnostic": str(exc)[:1000], "host_fallback": False},
        )
    except Exception as exc:  # noqa: BLE001 - every child failure must become a terminal job
        if child_identity is not None:
            _terminate_launched_child(child, child_identity)
        elif child is not None:
            child.terminate()
        exit_code = None
        status = "failed"
        failure_class = "launcher_failure" if child is None else "execution_failure"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if host_job is not None:
            try:
                if not host_job.terminate():
                    raise RuntimeError("Approved Host Job Object termination failed")
                if not host_job.wait_empty(timeout=10):
                    raise RuntimeError("Approved Host Job Object descendants did not terminate")
                host_descendants_verified_empty = True
            except Exception as cleanup_error:  # noqa: BLE001 - containment must fail closed
                status = "failed"
                failure_class = "approved_host_cleanup_failure"
                error = f"{type(cleanup_error).__name__}: {cleanup_error}"
            finally:
                host_job.close()
        if sandbox_job is not None:
            try:
                sandbox_job.terminate()
                if not sandbox_job.wait_empty(timeout=10):
                    raise RuntimeError("Sandbox Job Object descendants did not terminate")
                sandbox_job.close()
            except Exception as cleanup_error:  # noqa: BLE001 - containment must fail closed
                status = "failed"
                failure_class = "sandbox_cleanup_failure"
                error = f"{type(cleanup_error).__name__}: {cleanup_error}"
        if stdout_capture is not None:
            stdout_capture.join()
        if stderr_capture is not None:
            stderr_capture.join()
        if child is not None and hasattr(child, "close"):
            try:
                child.close()
            except Exception as cleanup_error:  # noqa: BLE001 - stale ACL/profile is security state
                status = "failed"
                failure_class = "sandbox_cleanup_failure"
                error = f"{type(cleanup_error).__name__}: {cleanup_error}"

    if operation["tier"] == "approved_host" and host_control_state is not None:
        try:
            if not host_descendants_verified_empty:
                raise RuntimeError("Approved Host descendant termination was not verified")
            if os.name == "nt" and host_process_census_required:
                if host_user_process_baseline is None:
                    raise RuntimeError("Approved Host same-user process baseline is missing")
                if deadline is None:
                    raise RuntimeError("Approved Host execution deadline was not initialized")
                untracked_processes = wait_for_untracked_current_user_processes(
                    host_user_process_baseline,
                    deadline=deadline,
                    excluded_pids={os.getpid()},
                )
                if untracked_processes:
                    pids = sorted(pid for pid, _ in untracked_processes)
                    audit.add_event(
                        operation_id,
                        "approved_host_untracked_process_detected",
                        {"pids": pids},
                    )
                    raise RuntimeError(
                        "Approved Host observed same-user process(es) outside its Job Object "
                        f"that did not exit before the operation deadline: {', '.join(map(str, pids))}"
                    )
            fresh_operation = audit.get_operation(operation_id, include_events=False)
            fresh_binding = {
                "id": fresh_operation["id"],
                "tier": fresh_operation["tier"],
                "request_hash": fresh_operation.get("request_hash"),
                "claimed_at": fresh_operation.get("claimed_at"),
                "approval_status": fresh_operation.get("approval_status"),
                "request": fresh_operation["request"],
            }
            if fresh_binding != host_operation_binding:
                raise RuntimeError("Approved Host changed its immutable audit binding")
            if fresh_operation.get("status") not in {"running", "cancelled", "interrupted"}:
                raise RuntimeError("Approved Host changed the operation terminal state")
            if fresh_operation.get("result") is not None or fresh_operation.get("exit_code") is not None:
                raise RuntimeError("Approved Host forged operation result fields")
            if (
                int(fresh_operation.get("worker_pid") or 0) != worker_identity.pid
                or float(fresh_operation.get("worker_create_time") or 0)
                != worker_identity.create_time
                or str(fresh_operation.get("worker_executable") or "")
                != worker_identity.executable
            ):
                raise RuntimeError("Approved Host changed the worker process binding")
            if str(fresh_operation.get("process_nonce") or "") != nonce:
                raise RuntimeError("Approved Host changed the process nonce binding")
            if child_identity is not None and (
                int(fresh_operation.get("child_pid") or 0) != child_identity.pid
                or float(fresh_operation.get("child_create_time") or 0)
                != child_identity.create_time
                or str(fresh_operation.get("child_executable") or "")
                != child_identity.executable
            ):
                raise RuntimeError("Approved Host changed the child process identity")
            host_control_expected = expected_critical_state(settings, operation_id)
            host_control_after = capture_critical_state(settings, operation_id)
            if host_control_after != host_control_expected:
                marker = mark_control_plane_tamper(
                    settings, operation_id, host_control_expected, host_control_after
                )
                status = "failed"
                failure_class = "control_plane_tamper"
                error = (
                    "Approved Host modified security-critical control-plane state; "
                    f"future operations are blocked pending review: {marker}"
                )
                audit.add_event(
                    operation_id,
                    "approved_host_control_plane_tamper_detected",
                    {"before": host_control_expected, "after": host_control_after},
                )
        except Exception as guard_error:  # noqa: BLE001 - uncertainty fails closed
            marker = mark_control_plane_tamper(
                settings,
                operation_id,
                host_control_state,
                {"capture_error": f"{type(guard_error).__name__}: {guard_error}"},
            )
            status = "failed"
            failure_class = "control_plane_tamper_unknown"
            error = (
                "Approved Host control-plane postflight could not be verified; "
                f"future operations are blocked pending review: {marker}"
            )
        if host_control_locks is not None:
            host_control_locks.close()
            host_control_locks = None
    if guard_implementation_hold is not None:
        try:
            guard_implementation_hold.__exit__(None, None, None)
        except Exception as cleanup_error:  # noqa: BLE001 - Guard hold is security state
            status = "failed"
            failure_class = "sandbox_cleanup_failure"
            error = f"{type(cleanup_error).__name__}: {cleanup_error}"
    if sandbox_backend_hold is not None:
        try:
            sandbox_backend_hold.__exit__(None, None, None)
        except Exception as cleanup_error:  # noqa: BLE001 - launcher lock is security state
            status = "failed"
            failure_class = "sandbox_cleanup_failure"
            error = f"{type(cleanup_error).__name__}: {cleanup_error}"
    if executable_hold is not None:
        try:
            executable_hold.__exit__(None, None, None)
        except Exception as cleanup_error:  # noqa: BLE001 - executable lock is security state
            status = "failed"
            failure_class = "executable_identity_failure"
            error = f"{type(cleanup_error).__name__}: {cleanup_error}"

    postflight_error: str | None = None
    post_git = (
        capture_git_snapshot(
            settings=settings,
            operation_id=operation_id,
            stage="after",
            required=False,
        )
        if capture_live_git_telemetry
        else None
    )
    workspace_transaction_pending = False
    if staged_sandbox_commit and status == "succeeded":
        try:
            if pre_workspace is None:
                raise RuntimeError("sandbox commit has no source checkpoint")
            if not audit.transition_operation(
                operation_id,
                from_statuses={"running"},
                status="committing",
            ):
                current = audit.get_operation(operation_id, include_events=False)
                status = str(current["status"])
                error = "sandbox result was not committed because the operation was cancelled"
            else:
                changes, deletions = collect_staged_workspace_changes(
                    settings=settings,
                    operation_id=operation_id,
                    normalized=NormalizedCommand.model_validate(normalized),
                )
                if workspace_lock is None:
                    workspace_lock = WorkspaceExecutionLock(settings)
                    workspace_lock.__enter__()
                target_manifest = build_workspace_target_from_bytes(
                    settings,
                    operation_id,
                    pre_workspace.manifest_path,
                    changes,
                    deletions,
                )
                restore_workspace_state(
                    settings,
                    pre_workspace.manifest_path,
                    target_manifest,
                    operation_id=operation_id,
                )
                workspace_transaction_pending = True
                audit.add_event(
                    operation_id,
                    "sandbox_artifact_committed",
                    {"changed": sorted(changes), "deleted": sorted(deletions)},
                )
        except Exception as commit_error:  # noqa: BLE001 - recovery state is recorded below
            status = (
                "conflict"
                if "workspace changed" in str(commit_error).casefold()
                else "failed"
            )
            failure_class = (
                "workspace_conflict" if status == "conflict" else "sandbox_commit_failure"
            )
            error = f"{type(commit_error).__name__}: {commit_error}"
    workspace_change: dict[str, object] = {
        "changed_files": [],
        "added_lines": 0,
        "removed_lines": 0,
        "diff_path": None,
        "rollback_state": "not_applicable",
    }
    post_workspace = None
    if pre_workspace is not None and (not staged_sandbox_commit or workspace_lock is not None):
        try:
            post_workspace = capture_workspace_state(settings, operation_id, "after")
            workspace_change = compare_workspace_states(
                settings, pre_workspace.manifest_path, post_workspace.manifest_path, operation_id
            )
            workspace_change["rollback_state"] = (
                "complete" if workspace_change["changed_files"] else "not_applicable"
            )
            if approved_tier and normalized.get("program_key") == "git":
                # Approved host commands retain the user's OS token and can affect protected
                # workspace entries (for example .git) that MCP checkpoints intentionally omit.
                workspace_change["rollback_state"] = "partial"
            if _has_irreversible_effect(normalized):
                workspace_change["rollback_state"] = (
                    "partial" if workspace_change["changed_files"] else "unavailable"
                )
        except Exception as snapshot_error:  # noqa: BLE001 - result remains safely partial
            workspace_change = {
                "changed_files": [],
                "added_lines": 0,
                "removed_lines": 0,
                "diff_path": None,
                "rollback_state": "partial",
                "snapshot_error": f"{type(snapshot_error).__name__}: {snapshot_error}",
            }
    if workspace_lock is not None:
        workspace_lock.__exit__(None, None, None)
    if deadline is not None and time.monotonic() > deadline and status == "succeeded":
        status = "timed_out"
        failure_class = "operation_deadline"
        error = (
            f"operation exceeded its {max_runtime}-second deadline during required finalization"
        )
    duration_ms = int((time.monotonic() - operation_started) * 1000)
    stdout_preview = (
        stdout_capture.preview(settings.output_preview_characters) if stdout_capture else ""
    )
    stderr_preview = (
        stderr_capture.preview(settings.output_preview_characters) if stderr_capture else ""
    )
    stdout_preview = redact_text(stdout_preview)
    stderr_preview = redact_text(stderr_preview)
    result = {
        "operation_id": operation_id,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "stdout_total_bytes": stdout_capture.total_bytes if stdout_capture else 0,
        "stderr_total_bytes": stderr_capture.total_bytes if stderr_capture else 0,
        "stdout_truncated": stdout_capture.truncated if stdout_capture else False,
        "stderr_truncated": stderr_capture.truncated if stderr_capture else False,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "pre_git_path": pre_git,
        "post_git_path": post_git,
        "execution_tier": operation["tier"],
        "sandbox_backend": (
            request.get("sandbox_backend") if operation["tier"] == "codex_sandbox" else None
        ),
        "sandbox_backend_version": sandbox_backend_version,
        "wfp_guard_verification": wfp_guard_verification,
        "failure_class": failure_class,
        "postflight_error": postflight_error,
        "host_fallback_performed": False,
        **workspace_change,
    }
    update_fields: dict[str, object] = {
        "status": status,
        "finished_at": utc_now_iso(),
        "exit_code": exit_code,
        "post_git_path": post_git,
        "result_json": canonical_json(result),
        "error": error,
        "duration_ms": duration_ms,
        "diff_path": workspace_change.get("diff_path"),
        "pre_workspace_path": pre_workspace.manifest_path if pre_workspace else None,
        "post_workspace_path": post_workspace.manifest_path if post_workspace else None,
        "rollback_state": workspace_change.get("rollback_state"),
    }
    if status == "expired" and approved_tier:
        update_fields["approval_status"] = "expired"
    transitioned = audit.transition_operation(
        operation_id,
        from_statuses={"queued", "running", "committing"},
        **update_fields,
    )
    audit.add_event(
        operation_id,
        "worker_finished" if transitioned else "worker_terminalization_suppressed",
        {"status": status, "exit_code": exit_code},
    )
    if workspace_transaction_pending and transitioned:
        finalize_workspace_transaction(settings, operation_id)
    return 0 if status == "succeeded" else 1


def _requires_workspace_execution_lock(
    operation: dict[str, object],
    request: dict[str, object],
    normalized: dict[str, object],
) -> bool:
    """Return whether execution can mutate the original workspace and needs exclusivity."""
    tier = operation.get("tier")
    if tier in {"broker", "safe_sandbox", "safe_command"}:
        return False

    if tier in {
        "approved_host",
        "host_approval",
        "codex_sandbox",
        "approved_sandbox",
    }:
        # Staged project code can derive absolute paths back into the live workspace.
        # Revalidation therefore needs an exclusive Broker-mutation interval that remains
        # held until the child and all descendants have terminated (and any staged commit
        # has completed). This is required even when workspace_write is false.
        return True

    return True


def _terminate_launched_child(child: Any, identity: ProcessIdentity) -> None:
    del child
    terminate_process_tree(identity)


def _enforce_runtime_storage_preflight(
    runtime_root: Path, *, byte_limit: int, entry_limit: int
) -> None:
    storage_error = _safe_runtime_storage_error(
        runtime_root,
        byte_limit=byte_limit,
        entry_limit=entry_limit,
    )
    if storage_error is not None:
        raise RuntimeStoragePolicyError(storage_error)


def _safe_runtime_storage_error(
    runtime_root: Path, *, byte_limit: int, entry_limit: int
) -> str | None:
    try:
        usage = scan_directory_bounded(
            runtime_root,
            stop_after_bytes=byte_limit,
            stop_after_entries=entry_limit,
            reject_alternate_streams=True,
            reject_reparse_points=True,
        )
    except (OSError, RuntimeError) as exc:
        return f"safe runtime storage validation failed: {exc}"
    if usage.total_bytes > byte_limit or usage.entry_count > entry_limit:
        return (
            "safe runtime storage limit exceeded: "
            f"{byte_limit} bytes or {entry_limit} entries"
        )
    return None


def _has_irreversible_effect(normalized: dict[str, object]) -> bool:
    if bool(normalized.get("network_expected")):
        return True
    key = normalized.get("program_key")
    args = [str(value).casefold() for value in list(normalized.get("args") or [])]
    if key == "git" and args and args[0] in {"commit", "push", "fetch", "pull"}:
        return True
    return key == "adb" and any(
        value in {"install", "uninstall", "push", "shell", "emu"} for value in args
    )


def _ensure_approval_execution_fresh(operation: dict[str, object]) -> None:
    if operation.get("tier") not in {
        "codex_sandbox",
        "approved_sandbox",
        "approved_host",
        "host_approval",
    }:
        return
    if operation.get("approval_status") != "approved" or not operation.get("claimed_at"):
        raise RuntimeError("approval execution grant is not active")
    expires_value = operation.get("approval_expires_at")
    if not expires_value:
        raise ApprovalExecutionExpired("approval execution grant has no expiration")
    expires_at = datetime.fromisoformat(str(expires_value))
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        raise ApprovalExecutionExpired("approval execution grant expired before child start")


def _verify_adb_target(normalized: dict[str, object], settings: Settings) -> None:
    if normalized.get("program_key") != "adb" or not settings.adb_emulator_only:
        return
    args = list(normalized["args"])
    if len(args) < 2 or args[0] != "-s":
        return
    serial = args[1]
    result = run_safe_process(
        settings=settings,
        program_key="adb",
        command=[str(normalized["executable"]), "-s", serial, "emu", "avd", "name"],
        cwd=str(normalized["cwd"]),
        timeout=10,
        output_limit=4096,
    )
    if result.returncode == 0 and result.stdout.strip():
        return
    qemu = run_safe_process(
        settings=settings,
        program_key="adb",
        command=[
            str(normalized["executable"]),
            "-s",
            str(serial),
            "shell",
            "getprop",
            "ro.kernel.qemu",
        ],
        cwd=str(normalized["cwd"]),
        timeout=10,
        output_limit=4096,
    )
    if qemu.returncode != 0 or qemu.stdout.strip() != b"1":
        raise PermissionError("ADB target did not prove it is an Android Emulator")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--context-sha256", required=True)
    args = parser.parse_args()
    settings = load_worker_context(
        args.context, args.context_sha256, args.operation_id
    )
    raise SystemExit(run_operation(args.operation_id, settings))


if __name__ == "__main__":
    main()
