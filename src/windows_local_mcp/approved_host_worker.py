from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path
from typing import Any

from .approved_host_authority import AuthorityWorkerLease
from .approved_host_process_census import (
    capture_user_processes,
    requester_username,
    wait_for_untracked_user_processes,
)
from .control_plane import load_worker_context
from .windows_user_process import popen_as_requester_in_job


def _install_authority_hooks(
    lease: AuthorityWorkerLease,
    *,
    requester_pid: int,
    requester_create_time: float,
) -> None:
    """Move Approved Host launch/postflight authority into this LocalSystem worker."""
    from . import control_plane_guard, process_utils, windows_job

    original_popen = windows_job.WindowsSandboxJob.popen
    original_expected = control_plane_guard.expected_critical_state
    original_capture = control_plane_guard.capture_critical_state
    expected_state: dict[str, Any] | None = None
    username = requester_username(requester_pid, requester_create_time)

    def authority_popen(self: Any, argv: list[str], **kwargs: Any) -> Any:
        stdin = kwargs.pop("stdin", subprocess.DEVNULL)
        stdout = kwargs.pop("stdout", subprocess.PIPE)
        stderr = kwargs.pop("stderr", subprocess.PIPE)
        shell = kwargs.pop("shell", False)
        creationflags = int(kwargs.pop("creationflags", 0))
        environment = kwargs.pop("env", None)
        cwd = kwargs.pop("cwd", None)
        if kwargs:
            raise TypeError(
                f"unsupported Approved Host authority launch arguments: {sorted(kwargs)}"
            )
        if stdin != subprocess.DEVNULL or stdout != subprocess.PIPE or stderr != subprocess.PIPE:
            raise RuntimeError("Approved Host authority requires bounded inherited stdio pipes")
        if shell is not False:
            raise RuntimeError("Approved Host authority never launches through a shell")
        if not isinstance(environment, dict) or cwd is None:
            raise RuntimeError("Approved Host authority child environment or cwd is missing")
        return popen_as_requester_in_job(
            self,
            argv,
            requester_pid=requester_pid,
            requester_create_time=requester_create_time,
            cwd=str(cwd),
            environment={str(key): str(value) for key, value in environment.items()},
            creationflags=creationflags,
            on_process_created=lease.mark_child_started,
        )

    def authority_expected(settings: Any, operation_id: str) -> dict[str, Any]:
        nonlocal expected_state
        state = original_expected(settings, operation_id)
        if operation_id == lease.operation_id:
            expected_state = dict(state)
        return state

    def authority_capture(settings: Any, operation_id: str) -> dict[str, Any]:
        state = original_capture(settings, operation_id)
        if (
            operation_id == lease.operation_id
            and expected_state is not None
            and state == expected_state
            and lease.child_started
        ):
            lease.mark_postflight_verified()
        return state

    def authority_process_baseline() -> set[tuple[int, float]]:
        return capture_user_processes(username)

    def authority_wait_for_untracked(
        baseline: set[tuple[int, float]],
        *,
        deadline: float,
        excluded_pids: set[int] | None = None,
    ) -> set[tuple[int, float]]:
        return wait_for_untracked_user_processes(
            username,
            baseline,
            deadline=deadline,
            excluded_pids=excluded_pids or (),
        )

    windows_job.WindowsSandboxJob.popen = authority_popen
    control_plane_guard.expected_critical_state = authority_expected
    control_plane_guard.capture_critical_state = authority_capture
    process_utils.capture_current_user_processes = authority_process_baseline
    process_utils.wait_for_untracked_current_user_processes = authority_wait_for_untracked

    authority_popen.__wlmcp_original_popen__ = original_popen  # type: ignore[attr-defined]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--context-sha256", required=True)
    parser.add_argument("--approved-host-requester-pid", required=True, type=int)
    parser.add_argument("--approved-host-requester-create-time", required=True, type=float)
    parser.add_argument("--authority-service-epoch", required=True)
    parser.add_argument("--authority-nonce", required=True)
    parser.add_argument("--authority-proof-path", required=True, type=Path)
    args = parser.parse_args()

    os.environ["WINDOWS_LOCAL_MCP_AUTHORITY_WORKER"] = "1"
    lease = AuthorityWorkerLease(
        operation_id=args.operation_id,
        service_epoch=args.authority_service_epoch,
        authority_nonce=args.authority_nonce,
        proof_path=args.authority_proof_path,
    )
    _install_authority_hooks(
        lease,
        requester_pid=args.approved_host_requester_pid,
        requester_create_time=args.approved_host_requester_create_time,
    )
    settings = load_worker_context(args.context, args.context_sha256, args.operation_id)

    # Import only after the control-plane, census, and Job hooks are installed so worker.py's
    # direct imports bind to the independently privileged implementations.
    from .worker import run_operation

    exit_code = 1
    try:
        exit_code = int(run_operation(args.operation_id, settings))
    finally:
        lease.finalize(exit_code)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
