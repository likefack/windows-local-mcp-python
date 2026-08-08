from __future__ import annotations

import argparse
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .appcontainer import (
    AppContainerProcess,
    appcontainer_profile_name,
    launch_appcontainer_process,
)
from .approval import (
    collect_staged_workspace_write,
    materialize_execution_copy,
    settings_digest,
    verify_approval_bundle,
)
from .audit import AuditStore
from .child_env import build_command_environment
from .command_traits import dart_format_writes
from .config import Settings, load_settings
from .git_snapshot import capture_git_snapshot
from .network_isolation import apply_safe_network_environment, safe_network_policy
from .paths import Workspace
from .policy import CommandPolicy, NormalizedCommand, approved_request_hash
from .process_utils import (
    ProcessIdentity,
    build_process_argv,
    capture_process_identity,
    creation_flags,
    terminate_process_tree,
)
from .resources import (
    BoundedStreamCapture,
    WorkspaceExecutionLock,
    enforce_data_quota,
    scan_directory_bounded,
)
from .safe_process import SafeSandboxCompatibilityError, run_safe_process
from .sandbox_backend import (
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    build_codex_sandbox_argv,
    codex_sandbox_effective_policy,
    hold_codex_sandbox_backend,
    probe_codex_version,
    verify_codex_sandbox_backend,
)
from .util import canonical_json, utc_now_iso
from .workspace_history import (
    WorkspaceMutationError,
    build_workspace_target_from_bytes,
    capture_workspace_state,
    compare_workspace_states,
    finalize_workspace_transaction,
    restore_workspace_state,
    workspace_recovery_required,
)


class ApprovalExecutionExpired(RuntimeError):
    pass


def run_operation(operation_id: str) -> int:
    settings = load_settings()
    audit = AuditStore(settings)
    operation = audit.get_operation(operation_id, include_events=False)
    operation["tier"] = {
        "safe_command": "safe_sandbox",
        "host_approval": "approved_host",
    }.get(str(operation.get("tier")), operation.get("tier"))
    request = operation["request"]
    normalized = request["normalized_command"]
    approved_tier = operation["tier"] in {"approved_sandbox", "approved_host"}
    sandbox_backend: CodexSandboxBackend | None = None
    sandbox_backend_version: str | None = None
    workspace_lock: WorkspaceExecutionLock | None = None
    tracks_workspace = _requires_workspace_execution_lock(operation, request, normalized)
    if tracks_workspace:
        workspace_lock = WorkspaceExecutionLock(settings)
        try:
            workspace_lock.__enter__()
        except TimeoutError as lock_error:
            audit.update_operation(
                operation_id, status="failed", finished_at=utc_now_iso(), error=str(lock_error)
            )
            audit.add_event(
                operation_id, "workspace_lock_timeout", {"error": str(lock_error)[:1000]}
            )
            return 1
        if workspace_recovery_required(settings):
            workspace_lock.__exit__(None, None, None)
            audit.update_operation(
                operation_id,
                status="failed",
                finished_at=utc_now_iso(),
                error="workspace mutation is blocked pending recovery",
            )
            audit.add_event(operation_id, "workspace_recovery_required", {})
            return 1
    try:
        if operation["tier"] == "safe_sandbox" and request.get(
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
            if bool(request.get("workspace_write")):
                normalized = dict(request["normalized_command"])
            else:
                verified = materialize_execution_copy(
                    settings=settings, operation_id=operation_id, normalized=verified
                )
                normalized = verified.model_dump()
            if operation["tier"] == "approved_sandbox":
                expected_backend = request.get("sandbox_backend")
                if not isinstance(expected_backend, dict):
                    raise ApprovedSandboxUnavailable(
                        "Approved Sandbox request has no immutable backend binding"
                    )
                sandbox_backend = verify_codex_sandbox_backend(settings, expected_backend)
            audit.add_event(operation_id, "approval_bundle_verified", {})
        elif operation["tier"] == "safe_sandbox":
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
        audit.update_operation(
            operation_id,
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
    nonce = str(operation.get("process_nonce") or os.environ.get("WINDOWS_LOCAL_MCP_JOB_NONCE", ""))
    if not nonce:
        raise RuntimeError("worker process nonce is missing")

    stdout_path = settings.data_dir / "outputs" / f"{operation_id}.stdout.log"
    stderr_path = settings.data_dir / "outputs" / f"{operation_id}.stderr.log"
    enforce_data_quota(settings, incoming_bytes=2 * settings.max_output_bytes_per_stream)

    audit.update_operation(
        operation_id,
        status="running",
        started_at=utc_now_iso(),
        worker_pid=os.getpid(),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
    audit.add_event(operation_id, "worker_started", {"worker_pid": os.getpid()})

    try:
        pre_git = capture_git_snapshot(
            settings=settings, operation_id=operation_id, stage="before"
        )
    except SafeSandboxCompatibilityError as snapshot_error:
        if normalized.get("program_key") == "git":
            result = _sandbox_compatibility_result(
                operation_id,
                snapshot_error,
                phase="preflight",
                source_tier=str(operation["tier"]),
            )
            audit.update_operation(
                operation_id,
                status="failed",
                finished_at=utc_now_iso(),
                result_json=canonical_json(result),
                error=result["message"],
            )
            audit.add_event(operation_id, "safe_auxiliary_sandbox_incompatible", result)
            if workspace_lock is not None:
                workspace_lock.__exit__(None, None, None)
            return 1
        pre_git = None
        audit.add_event(
            operation_id,
            "optional_git_snapshot_sandbox_incompatible",
            {"phase": "preflight", "diagnostic": str(snapshot_error)[:1000]},
        )
    if pre_git:
        audit.update_operation(operation_id, pre_git_path=pre_git)
    pre_workspace = None
    if tracks_workspace:
        try:
            pre_workspace = capture_workspace_state(settings, operation_id, "before")
            audit.update_operation(operation_id, pre_workspace_path=pre_workspace.manifest_path)
        except Exception as snapshot_error:  # noqa: BLE001 - persist checkpoint failures
            audit.update_operation(
                operation_id,
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

    argv = build_process_argv(executable, args)
    started = time.monotonic()
    child: Any | None = None
    child_identity: ProcessIdentity | None = None
    stdout_capture: BoundedStreamCapture | None = None
    stderr_capture: BoundedStreamCapture | None = None
    status = "failed"
    exit_code: int | None = None
    error: str | None = None
    failure_class: str | None = None
    network_policy_payload: dict[str, object] | None = None
    sandbox_backend_hold: Any | None = None

    try:
        _verify_adb_target(normalized, settings)
        if approved_tier:
            refreshed = audit.get_operation(operation_id, include_events=False)
            _ensure_approval_execution_fresh(refreshed)
        if operation["tier"] == "approved_sandbox":
            if sandbox_backend is None:
                raise ApprovedSandboxUnavailable("Approved Sandbox backend is unavailable")
            sandbox_backend_hold = hold_codex_sandbox_backend(sandbox_backend)
            sandbox_backend = sandbox_backend_hold.__enter__()
            sandbox_backend_version = probe_codex_version(sandbox_backend)
        child_env = build_command_environment(
            os.environ,
            extra_names=settings.child_environment_allowlist,
            nonce=nonce,
            git_command=normalized.get("program_key") == "git",
        )
        if operation["tier"] == "approved_sandbox" and sandbox_backend is not None:
            helper_directory = str(Path(sandbox_backend.executable).parent)
            existing_path = child_env.get("PATH", "")
            child_env["PATH"] = (
                helper_directory
                if not existing_path
                else helper_directory + os.pathsep + existing_path
            )
        if operation["tier"] == "safe_sandbox":
            network_policy = safe_network_policy(
                str(normalized.get("program_key", "")),
                mode=settings.safe_network_isolation_mode,
            )
            apply_safe_network_environment(child_env, str(normalized.get("program_key", "")))
            network_policy_payload = network_policy.as_dict()
            if settings.safe_network_isolation_mode == "appcontainer":
                network_policy_payload.update(
                    {
                        "isolation_profile": appcontainer_profile_name(
                            settings,
                            str(normalized.get("program_key", "")),
                            workspace_write=tracks_workspace,
                            operation_id=operation_id,
                        ),
                        "descendant_enforcement": "inherited AppContainer token",
                    }
                )
            network_policy_payload["enforcement_status"] = "prepared"
            audit.update_operation(
                operation_id, network_policy_json=canonical_json(network_policy_payload)
            )
            audit.add_event(operation_id, "network_policy_prepared", network_policy_payload)
        elif operation["tier"] == "approved_sandbox":
            network_policy = codex_sandbox_effective_policy(
                workspace_write=bool(request.get("workspace_write"))
            )
            network_policy.update(
                {
                    "backend_version": sandbox_backend_version,
                    "isolation_setup_status": "verified_before_launch",
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
        runtime_root = settings.data_dir / "outputs" / f"{operation_id}-runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        try:
            Path(cwd).resolve(strict=True).relative_to(runtime_root.resolve(strict=True))
            if operation["tier"] == "approved_sandbox":
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
        if operation["tier"] == "safe_sandbox" and normalized.get("program_key") == "adb":
            cwd = str(runtime_root)
        if (
            operation["tier"] == "safe_sandbox"
            and settings.safe_network_isolation_mode == "appcontainer"
        ):
            try:
                child = launch_appcontainer_process(
                    settings=settings,
                    program_key=str(normalized.get("program_key", "")),
                    executable=argv[0],
                    args=argv[1:],
                    cwd=cwd,
                    environment=child_env,
                    creation_flags=creation_flags(),
                    workspace_write=tracks_workspace,
                    operation_id=operation_id,
                )
            except (OSError, PermissionError) as compatibility_error:
                raise SafeSandboxCompatibilityError(
                    "AppContainer setup/process launch was incompatible: "
                    f"{type(compatibility_error).__name__}: {compatibility_error}"
                ) from compatibility_error
        elif operation["tier"] == "approved_sandbox":
            if sandbox_backend is None:
                raise ApprovedSandboxUnavailable("Approved Sandbox backend is unavailable")
            child = subprocess.Popen(
                build_codex_sandbox_argv(sandbox_backend, command=argv, cwd=cwd),
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creation_flags(),
                start_new_session=(os.name != "nt"),
                env=child_env,
            )
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
        if operation["tier"] == "safe_sandbox" and network_policy_payload is not None:
            network_policy_payload["enforcement_status"] = "active"
            audit.update_operation(
                operation_id, network_policy_json=canonical_json(network_policy_payload)
            )
            audit.add_event(operation_id, "network_policy_applied", network_policy_payload)
        audit.update_operation(
            operation_id,
            child_pid=child_identity.pid,
            child_create_time=child_identity.create_time,
            child_executable=child_identity.executable,
        )
        audit.add_event(
            operation_id,
            "child_started",
            {"child_pid": child.pid, "argv": argv, "identity_verified": True},
        )
        stdout_capture = BoundedStreamCapture(
            child.stdout, stdout_path, settings.max_output_bytes_per_stream
        )
        stderr_capture = BoundedStreamCapture(
            child.stderr, stderr_path, settings.max_output_bytes_per_stream
        )
        stdout_capture.start()
        stderr_capture.start()
        deadline = time.monotonic() + max_runtime
        runtime_limit = min(
            settings.approval_manifest_max_bytes + settings.max_write_bytes,
            settings.max_data_dir_bytes // 2,
        )
        runtime_entry_limit = max(128, settings.approval_manifest_max_files * 4)
        while True:
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
                status = "succeeded" if exit_code == 0 else "failed"
                error = None if exit_code == 0 else f"command exited with code {exit_code}"
                failure_class = None if exit_code == 0 else "command_failure"
                if operation["tier"] == "safe_sandbox":
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
                if operation["tier"] == "safe_sandbox":
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
    except SafeSandboxCompatibilityError as exc:
        if child_identity is not None:
            _terminate_launched_child(child, child_identity)
        elif child is not None:
            child.terminate()
        exit_code = None
        status = "failed"
        failure_class = "sandbox_compatibility"
        error = (
            "Safe Sandboxでこの操作を実行できませんでした。Reason: sandbox/tool "
            "compatibility. Approved Sandboxなら人間承認後に再試行可能です。"
        )
        audit.add_event(
            operation_id,
            "safe_sandbox_compatibility_failure",
            {"diagnostic": str(exc)[:1000]},
        )
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
        if sandbox_backend_hold is not None:
            try:
                sandbox_backend_hold.__exit__(None, None, None)
            except Exception as cleanup_error:  # noqa: BLE001 - launcher lock is security state
                status = "failed"
                failure_class = "sandbox_cleanup_failure"
                error = f"{type(cleanup_error).__name__}: {cleanup_error}"

    if (
        operation["tier"] == "safe_sandbox"
        and status == "failed"
        and failure_class == "command_failure"
        and normalized.get("program_key") == "git"
        and b"fatal: Unable to read current working directory: Permission denied"
        in stderr_path.read_bytes()
    ):
        failure_class = "sandbox_compatibility"
        error = (
            "Safe Sandboxでこの操作を実行できませんでした。Reason: Git/AppContainer "
            "ancestor directory compatibility. Approved Sandboxなら人間承認後に再試行可能です。"
        )
        audit.add_event(
            operation_id,
            "safe_sandbox_compatibility_failure",
            {"diagnostic": "Git for Windows AppContainer cwd compatibility", "exit_code": exit_code},
        )

    workspace_transaction_applied = False
    if (
        status == "succeeded"
        and operation["tier"] == "safe_sandbox"
        and normalized.get("program_key") == "dart"
        and dart_format_writes(list(normalized.get("args") or []))
    ):
        try:
            if pre_workspace is None:
                raise RuntimeError("staged workspace write has no starting checkpoint")
            staged_changes = collect_staged_workspace_write(
                settings=settings,
                operation_id=operation_id,
                normalized=NormalizedCommand.model_validate(normalized),
            )
            if staged_changes:
                target_manifest = build_workspace_target_from_bytes(
                    settings,
                    operation_id,
                    pre_workspace.manifest_path,
                    staged_changes,
                )
                restore_workspace_state(
                    settings,
                    pre_workspace.manifest_path,
                    target_manifest,
                    operation_id=operation_id,
                )
                workspace_transaction_applied = True
        except WorkspaceMutationError as mutation_error:
            status = "failed"
            error = str(mutation_error)
        except Exception as staged_error:  # noqa: BLE001 - do not broker unapproved output
            status = "failed"
            error = f"staged workspace write rejected: {type(staged_error).__name__}: {staged_error}"

    duration_ms = int((time.monotonic() - started) * 1000)
    postflight_error: str | None = None
    try:
        post_git = capture_git_snapshot(
            settings=settings, operation_id=operation_id, stage="after"
        )
    except SafeSandboxCompatibilityError as snapshot_error:
        post_git = None
        postflight_error = f"Safe Sandbox postflight probe failed: {snapshot_error}"
        if status == "succeeded" and normalized.get("program_key") == "git":
            status = "failed"
            failure_class = "postflight_sandbox_failure"
            error = (
                "Command completed, but its required Safe Sandbox postflight audit failed; "
                "no tier fallback occurred"
            )
        audit.add_event(
            operation_id,
            "safe_postflight_sandbox_failure",
            {"diagnostic": str(snapshot_error)[:1000]},
        )
    workspace_change: dict[str, object] = {
        "changed_files": [],
        "added_lines": 0,
        "removed_lines": 0,
        "diff_path": None,
        "rollback_state": "not_applicable",
    }
    post_workspace = None
    if pre_workspace is not None:
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
    stdout_preview = (
        stdout_capture.preview(settings.output_preview_characters) if stdout_capture else ""
    )
    stderr_preview = (
        stderr_capture.preview(settings.output_preview_characters) if stderr_capture else ""
    )
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
            request.get("sandbox_backend") if operation["tier"] == "approved_sandbox" else None
        ),
        "sandbox_backend_version": sandbox_backend_version,
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
    audit.update_operation(operation_id, **update_fields)
    audit.add_event(operation_id, "worker_finished", {"status": status, "exit_code": exit_code})
    if workspace_transaction_applied:
        try:
            finalize_workspace_transaction(settings, operation_id)
        except Exception as finalization_error:  # noqa: BLE001 - startup reconciles journal
            audit.add_event(
                operation_id,
                "workspace_transaction_finalization_deferred",
                {"error": f"{type(finalization_error).__name__}: {finalization_error}"[:1000]},
            )
    return 0 if status == "succeeded" else 1


def _requires_workspace_execution_lock(
    operation: dict[str, object],
    request: dict[str, object],
    normalized: dict[str, object],
) -> bool:
    """Return whether execution can mutate the original workspace and needs exclusivity."""
    tier = operation.get("tier")
    if tier in {"safe_sandbox", "safe_command"}:
        if normalized.get("program_key") != "dart":
            return False
        args = list(normalized.get("args") or [])
        if not args or args[0] != "format":
            return False
        return dart_format_writes(args)

    if tier in {"approved_sandbox", "approved_host", "host_approval"}:
        if bool(request.get("workspace_write")):
            return True
        summary = request.get("approval_manifest_summary")
        # Old audit rows or non-snapshot host commands remain conservative. They may execute
        # against the real workspace, so keep the exclusive lock unless isolation is explicit.
        return not (isinstance(summary, dict) and summary.get("mode") == "staged-cwd")

    return True


def _terminate_launched_child(child: Any, identity: ProcessIdentity) -> None:
    if isinstance(child, AppContainerProcess):
        child.terminate()
    else:
        terminate_process_tree(identity)


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


def _sandbox_compatibility_result(
    operation_id: str,
    error: BaseException,
    *,
    phase: str,
    source_tier: str,
) -> dict[str, object]:
    safe_source = source_tier == "safe_sandbox"
    return {
        "operation_id": operation_id,
        "status": "failed",
        "execution_tier": source_tier,
        "failure_class": "sandbox_compatibility" if safe_source else "safe_auxiliary_failure",
        "failure_phase": phase,
        "message": (
            "Safe Sandboxでこの操作を実行できませんでした。Reason: sandbox/tool "
            "compatibility. Approved Sandboxなら人間承認後に再試行可能です。"
            if safe_source
            else "Required Safe Sandbox audit helper failed; the approved command was not run."
        ),
        "approved_sandbox_retry_available": safe_source,
        "approval_created": False,
        "host_fallback_performed": False,
        "diagnostic": f"{type(error).__name__}: {error}"[:1000],
    }


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
    if result.returncode != 0 or not result.stdout.strip():
        raise PermissionError("ADB target did not prove it is an Android Emulator")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-id", required=True)
    args = parser.parse_args()
    raise SystemExit(run_operation(args.operation_id))


if __name__ == "__main__":
    main()
