from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

from .approval import settings_digest
from .audit import AuditStore
from .config import Settings
from .control_plane import (
    assert_trusted_runtime,
    load_worker_context,
    verify_control_plane_generation,
)
from .git_broker_live_verify import require_git_broker_live_verification
from .git_broker_sandbox import GitBrokerUnavailable, run_git_broker_command
from .paths import Workspace
from .policy import CommandPolicy
from .process_utils import capture_process_identity
from .redaction import redact_text
from .util import canonical_json, utc_now_iso


def isolated_git_broker_worker_argv(
    settings: Settings,
    *,
    operation_id: str,
    context_path: Path,
    context_sha256: str,
) -> list[str]:
    """Launch the dedicated Git worker from the same trusted package closure as normal workers."""

    package = assert_trusted_runtime(settings)
    source_root = package.parent
    bootstrap = (
        "import runpy,sys;"
        f"sys.path.insert(0,{str(source_root)!r});"
        "runpy.run_module('windows_local_mcp.git_broker_worker',run_name='__main__')"
    )
    return [
        sys.executable,
        "-I",
        "-B",
        "-c",
        bootstrap,
        "--operation-id",
        operation_id,
        "--context",
        str(context_path),
        "--context-sha256",
        context_sha256,
    ]


def _terminal_failure(
    audit: AuditStore,
    operation_id: str,
    *,
    error: Exception | str,
    failure_class: str,
) -> int:
    message = str(error)
    if isinstance(error, Exception):
        message = f"{type(error).__name__}: {error}"
    audit.transition_operation(
        operation_id,
        from_statuses={"queued", "running"},
        status="failed",
        finished_at=utc_now_iso(),
        error=message,
        result_json=canonical_json(
            {
                "operation_id": operation_id,
                "status": "failed",
                "exit_code": None,
                "failure_class": failure_class,
                "error": message,
                "execution_tier": "broker",
                "host_fallback_performed": False,
                "changed_files": [],
                "rollback_state": "not_applicable",
            }
        ),
    )
    audit.add_event(
        operation_id,
        "git_broker_failed",
        {"failure_class": failure_class, "error": message[:1000]},
    )
    return 1


def run_operation(operation_id: str, settings: Settings) -> int:
    started = time.monotonic()
    audit = AuditStore(settings)
    operation = audit.get_operation(operation_id, include_events=False)
    request = operation.get("request")
    if operation.get("tier") not in {"broker", "safe_command", "safe_sandbox"}:
        return _terminal_failure(
            audit,
            operation_id,
            error="dedicated Git worker accepts Broker operations only",
            failure_class="route_mismatch",
        )
    if not isinstance(request, dict):
        return _terminal_failure(
            audit,
            operation_id,
            error="Git Broker operation request is missing",
            failure_class="request_binding",
        )
    try:
        verify_control_plane_generation(settings, request.get("control_plane_generation"))
        if request.get("settings_digest") != settings_digest(settings):
            raise RuntimeError("effective MCP settings changed before Automatic Git execution")
        safe_request = request.get("safe_request")
        if not isinstance(safe_request, dict):
            raise TypeError("Automatic Git command is missing its original validated request")
        policy = CommandPolicy(settings, Workspace(settings))
        fresh = policy.normalize_safe(
            program=str(safe_request["program"]),
            args=list(safe_request["args"]),
            cwd=str(safe_request["cwd"]),
        )
        if fresh.program_key != "git":
            raise PermissionError("dedicated Git worker received a non-Git Broker command")
        normalized = request.get("normalized_command")
        if not isinstance(normalized, dict) or fresh.model_dump() != normalized:
            raise RuntimeError("Automatic Git command changed between validation and execution")
    except Exception as error:  # noqa: BLE001 - every verification failure is terminal
        return _terminal_failure(
            audit,
            operation_id,
            error=error,
            failure_class="pre_execution_verification",
        )

    nonce = str(
        operation.get("process_nonce")
        or os.environ.get("WINDOWS_LOCAL_MCP_JOB_NONCE", "")
    )
    if not nonce:
        return _terminal_failure(
            audit,
            operation_id,
            error="Git Broker worker process nonce is missing",
            failure_class="worker_identity",
        )
    try:
        worker_identity = capture_process_identity(os.getpid(), nonce)
    except Exception as error:  # noqa: BLE001
        return _terminal_failure(
            audit,
            operation_id,
            error=error,
            failure_class="worker_identity",
        )

    stdout_path = settings.data_dir / "outputs" / f"{operation_id}.stdout.log"
    stderr_path = settings.data_dir / "outputs" / f"{operation_id}.stderr.log"
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
        return 1
    audit.add_event(
        operation_id,
        "git_broker_worker_started",
        {
            "worker_pid": worker_identity.pid,
            "worker_create_time": worker_identity.create_time,
            "worker_executable": worker_identity.executable,
            "source_workspace_access": "deny",
            "execution_input": "sanitized-disposable-repository-snapshot",
        },
    )

    max_runtime = int(request.get("max_runtime_seconds") or settings.default_max_runtime_seconds)
    status = "failed"
    failure_class: str | None = None
    error_message: str | None = None
    exit_code: int | None = None
    broker_result: Any | None = None
    try:
        git_identity = dict(fresh.executable_identity or {})
        live_marker = require_git_broker_live_verification(settings, git_identity)
        audit.add_event(
            operation_id,
            "git_broker_live_verification_rechecked",
            {
                "version": live_marker["version"],
                "context_digest": live_marker["context_digest"],
            },
        )
        broker_result = run_git_broker_command(
            settings=settings,
            git_identity=git_identity,
            command=[fresh.executable, *fresh.args],
            cwd=fresh.cwd,
            timeout=float(max_runtime),
            output_limit=settings.max_output_bytes_per_stream,
            token=operation_id,
            output_paths=(stdout_path, stderr_path),
        )
        exit_code = broker_result.returncode
        if exit_code == 0:
            status = "succeeded"
        else:
            status = "failed"
            failure_class = "command_failure"
            error_message = f"command exited with code {exit_code}"
    except TimeoutError as error:
        status = "timed_out"
        failure_class = "runtime_limit"
        error_message = str(error)
    except GitBrokerUnavailable as error:
        status = "failed"
        failure_class = "git_broker_containment"
        error_message = str(error)
    except Exception as error:  # noqa: BLE001 - all execution failures become durable
        status = "failed"
        failure_class = "execution_failure"
        error_message = f"{type(error).__name__}: {error}"

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout_bytes = stdout_path.read_bytes() if stdout_path.exists() else b""
    stderr_bytes = stderr_path.read_bytes() if stderr_path.exists() else b""
    stdout_preview = redact_text(
        stdout_bytes.decode("utf-8", errors="replace")[: settings.output_preview_characters]
    )
    stderr_preview = redact_text(
        stderr_bytes.decode("utf-8", errors="replace")[: settings.output_preview_characters]
    )
    result = {
        "operation_id": operation_id,
        "job_id": operation_id,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "stdout_total_bytes": len(stdout_bytes),
        "stderr_total_bytes": len(stderr_bytes),
        "stdout_truncated": bool(
            broker_result.stdout_truncated if broker_result is not None else False
        ),
        "stderr_truncated": bool(
            broker_result.stderr_truncated if broker_result is not None else False
        ),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "execution_tier": "broker",
        "git_broker_sandbox": "git-live-verified-codex-windows-sandbox",
        "sandbox_backend_version": (
            broker_result.backend_version if broker_result is not None else None
        ),
        "containment_policy_digest": (
            broker_result.containment_policy_digest if broker_result is not None else None
        ),
        "repository_snapshot_digest": (
            broker_result.snapshot_digest if broker_result is not None else None
        ),
        "wfp_guard_verification": (
            broker_result.wfp_guard_verification if broker_result is not None else None
        ),
        "source_workspace_access": "deny",
        "failure_class": failure_class,
        "host_fallback_performed": False,
        "changed_files": [],
        "added_lines": 0,
        "removed_lines": 0,
        "diff_path": None,
        "rollback_state": "not_applicable",
    }
    transitioned = audit.transition_operation(
        operation_id,
        from_statuses={"running"},
        status=status,
        finished_at=utc_now_iso(),
        exit_code=exit_code,
        result_json=canonical_json(result),
        error=error_message,
        duration_ms=duration_ms,
        rollback_state="not_applicable",
    )
    audit.add_event(
        operation_id,
        "git_broker_finished" if transitioned else "git_broker_terminalization_suppressed",
        {"status": status, "exit_code": exit_code, "failure_class": failure_class},
    )
    return 0 if status == "succeeded" else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--context-sha256", required=True)
    args = parser.parse_args()
    settings = load_worker_context(args.context, args.context_sha256, args.operation_id)
    raise SystemExit(run_operation(args.operation_id, settings))


if __name__ == "__main__":
    main()
