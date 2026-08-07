from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

from .approval import materialize_execution_copy, verify_approval_bundle
from .audit import AuditStore
from .config import load_settings
from .git_snapshot import capture_git_snapshot
from .paths import Workspace
from .policy import CommandPolicy
from .process_utils import (
    ProcessIdentity,
    build_process_argv,
    capture_process_identity,
    creation_flags,
    terminate_process_tree,
)
from .resources import BoundedStreamCapture, WorkspaceExecutionLock, enforce_data_quota
from .util import canonical_json, utc_now_iso


def run_operation(operation_id: str) -> int:
    settings = load_settings()
    audit = AuditStore(settings)
    execution_lock = WorkspaceExecutionLock(settings)
    execution_lock.__enter__()
    operation = audit.get_operation(operation_id, include_events=False)
    request = operation["request"]
    normalized = request["normalized_command"]
    try:
        if operation["tier"] == "host_approval":
            verified = verify_approval_bundle(
                settings=settings,
                operation_id=operation_id,
                expected_digest=request["approval_manifest_digest"],
            )
            verified = materialize_execution_copy(
                settings=settings, operation_id=operation_id, normalized=verified
            )
            normalized = verified.model_dump()
            audit.add_event(operation_id, "approval_bundle_verified", {})
        elif operation["tier"] == "safe_command":
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
        execution_lock.__exit__(None, None, None)
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

    pre_git = capture_git_snapshot(settings=settings, operation_id=operation_id, stage="before")
    if pre_git:
        audit.update_operation(operation_id, pre_git_path=pre_git)

    argv = build_process_argv(executable, args)
    started = time.monotonic()
    child: subprocess.Popen[bytes] | None = None
    child_identity: ProcessIdentity | None = None
    stdout_capture: BoundedStreamCapture | None = None
    stderr_capture: BoundedStreamCapture | None = None

    try:
        _verify_adb_target(normalized, settings.adb_emulator_only)
        child_env = os.environ.copy()
        for internal_name in (
            "LOCAL_MCP_CONFIG",
            "LOCAL_MCP_ROOT",
            "LOCAL_MCP_TRANSPORT",
            "LOCAL_MCP_HOST",
            "LOCAL_MCP_PORT",
        ):
            child_env.pop(internal_name, None)
        for injection_name in (
            "PYTHONPATH",
            "PYTHONHOME",
            "NODE_PATH",
            "NODE_OPTIONS",
            "PSModulePath",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "_JAVA_OPTIONS",
            "GRADLE_OPTS",
            "DART_VM_OPTIONS",
            "FLUTTER_TOOL_ARGS",
            "RUBYLIB",
            "PERL5LIB",
            "CLASSPATH",
        ):
            child_env.pop(injection_name, None)
        runtime_root = settings.data_dir / "outputs" / f"{operation_id}-runtime"
        try:
            Path(cwd).resolve(strict=True).relative_to(runtime_root.resolve(strict=True))
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
        child_env["WINDOWS_LOCAL_MCP_JOB_NONCE"] = nonce
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
        try:
            exit_code = child.wait(timeout=max_runtime)
            status = "succeeded" if exit_code == 0 else "failed"
            error = None if exit_code == 0 else f"command exited with code {exit_code}"
        except subprocess.TimeoutExpired:
            terminate_process_tree(child_identity)
            exit_code = None
            status = "timed_out"
            error = f"maximum runtime exceeded: {max_runtime} seconds"
    except Exception as exc:  # noqa: BLE001 - every child failure must become a terminal job
        if child_identity is not None:
            terminate_process_tree(child_identity)
        elif child is not None:
            child.terminate()
        exit_code = None
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if stdout_capture is not None:
            stdout_capture.join()
        if stderr_capture is not None:
            stderr_capture.join()

    duration_ms = int((time.monotonic() - started) * 1000)
    post_git = capture_git_snapshot(settings=settings, operation_id=operation_id, stage="after")
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
    }
    audit.update_operation(
        operation_id,
        status=status,
        finished_at=utc_now_iso(),
        exit_code=exit_code,
        post_git_path=post_git,
        result_json=canonical_json(result),
        error=error,
        duration_ms=duration_ms,
    )
    audit.add_event(operation_id, "worker_finished", {"status": status, "exit_code": exit_code})
    execution_lock.__exit__(None, None, None)
    return 0 if status == "succeeded" else 1


def _verify_adb_target(normalized: dict[str, object], emulator_only: bool) -> None:
    if normalized.get("program_key") != "adb" or not emulator_only:
        return
    args = list(normalized["args"])  # type: ignore[arg-type]
    if len(args) < 2 or args[0] != "-s":
        return
    serial = args[1]
    result = subprocess.run(
        [str(normalized["executable"]), "-s", serial, "emu", "avd", "name"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        shell=False,
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
