from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil

from .approval import verify_approval_bundle
from .approved_host_authority import (
    ApprovedHostAuthorityClient,
    ApprovedHostAuthorityUnavailable,
    ApprovedHostRecoveryRequired,
    default_authority_state_root,
)
from .approved_host_process_census import (
    capture_user_processes,
    requester_username,
)
from .approved_host_service import _process_token_details
from .audit import TERMINAL_STATUSES
from .control_plane import verify_control_plane_generation
from .policy import approved_request_hash

_ABNORMAL_CHILD_START_TIMEOUT_SECONDS = 120.0
_ABNORMAL_RECOVERY_POLL_SECONDS = 0.1
_ABNORMAL_RECOVERY_WAIT_GRACE_SECONDS = 120.0


def _approve_and_launch(runtime: Any, operation_id: str) -> None:
    operation = runtime.audit.get_operation(operation_id, include_events=False)
    request = operation["request"]
    if not isinstance(request, dict):
        raise TypeError("abnormal verification request is not an object")
    verify_control_plane_generation(
        runtime.settings,
        request.get("control_plane_generation"),
    )
    expected_hash = approved_request_hash(request)
    if expected_hash != operation.get("request_hash"):
        raise RuntimeError("abnormal verification request hash mismatch")
    verify_approval_bundle(
        settings=runtime.settings,
        operation_id=operation_id,
        expected_digest=str(request["approval_manifest_digest"]),
    )
    runtime.audit.approve_and_claim(
        operation_id,
        approver="approved-host-abnormal-verification",
        note="operator approved R2-001 worker-loss fault injection",
        expected_request_hash=expected_hash,
    )
    runtime.executor.launch(operation_id, 0)


def _wait_worker_and_child(
    runtime: Any,
    operation_id: str,
    timeout: float = _ABNORMAL_CHILD_START_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        operation = runtime.audit.get_operation(operation_id, include_events=False)
        if operation.get("worker_pid") and operation.get("child_pid"):
            return operation
        if operation["status"] in TERMINAL_STATUSES:
            raise AssertionError(
                f"abnormal verification operation terminated too early: {operation}"
            )
        time.sleep(0.05)
    raise TimeoutError("Approved Host worker/child did not start")


def _new_ping_helpers(
    *,
    username: str,
    baseline: set[tuple[int, float]],
    expected_ping: Path,
) -> list[dict[str, Any]]:
    expected = os.path.normcase(str(expected_ping.resolve(strict=True)))
    helpers: list[dict[str, Any]] = []
    for pid, create_time in sorted(capture_user_processes(username) - baseline):
        try:
            process = psutil.Process(pid)
            executable = os.path.normcase(str(Path(process.exe()).resolve(strict=True)))
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ):
            continue
        if executable != expected:
            continue
        helpers.append(
            {
                "pid": int(pid),
                "create_time": float(create_time),
                "executable": str(expected_ping.resolve(strict=True)),
            }
        )
    return helpers


def _require_live_helper(helper: dict[str, Any]) -> psutil.Process:
    pid = int(helper["pid"])
    expected_create_time = float(helper["create_time"])
    expected_executable = os.path.normcase(
        str(Path(str(helper["executable"])).resolve(strict=True))
    )
    try:
        process = psutil.Process(pid)
        actual_create_time = float(process.create_time())
        actual_executable = os.path.normcase(str(Path(process.exe()).resolve(strict=True)))
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError) as error:
        raise AssertionError(f"verified WMI helper is no longer available: PID={pid}") from error
    if abs(actual_create_time - expected_create_time) > 0.01:
        raise AssertionError(f"verified WMI helper PID was reused: PID={pid}")
    if actual_executable != expected_executable:
        raise AssertionError(
            "verified WMI helper executable identity changed: "
            f"expected={expected_executable} actual={actual_executable}"
        )
    return process


def _terminate_verified_helpers(helpers: list[dict[str, Any]]) -> None:
    processes = [_require_live_helper(helper) for helper in helpers]
    for process in processes:
        process.terminate()
    gone, alive = psutil.wait_procs(processes, timeout=5.0)
    del gone
    for process in alive:
        process.kill()
    if alive:
        _, still_alive = psutil.wait_procs(alive, timeout=5.0)
        if still_alive:
            raise RuntimeError(
                "failed to clean up verified WMI helper processes: "
                + ",".join(str(process.pid) for process in still_alive)
            )


def _wait_for_fault_injection_recovery(
    runtime: Any,
    operation_id: str,
    *,
    initial_service_epoch: str,
    timeout: float,
) -> dict[str, Any]:
    client = ApprovedHostAuthorityClient()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        probe: dict[str, Any] | None
        try:
            probe = client.probe()
        except ApprovedHostAuthorityUnavailable:
            # The administrator phase intentionally restarts the SCM service. A short period
            # without a pipe is therefore expected, but no unverified state is accepted.
            probe = None
        if probe is not None:
            active_operation_id = probe.get("active_operation_id")
            recovery_reason = str(probe.get("recovery_reason") or "")
            service_epoch = str(probe.get("service_epoch") or "")
            if active_operation_id not in (None, operation_id):
                raise AssertionError(
                    "authority active operation changed during fault injection: "
                    f"expected={operation_id} actual={active_operation_id}"
                )
            if (
                active_operation_id == operation_id
                and recovery_reason
                and service_epoch
                and service_epoch != initial_service_epoch
            ):
                return probe
            if bool(probe.get("healthy")):
                raise AssertionError(
                    "authority became healthy before worker-loss recovery was observed"
                )

        operation = runtime.audit.get_operation(operation_id, include_events=False)
        if operation["status"] in TERMINAL_STATUSES:
            raise AssertionError(
                "abnormal verification operation became terminal before the verified "
                f"worker-loss/service-restart handshake completed: {operation}"
            )
        time.sleep(_ABNORMAL_RECOVERY_POLL_SECONDS)
    raise TimeoutError(
        "timed out waiting for authenticated recovery state after worker-loss/service restart"
    )


def arm_abnormal(cwd: str, handoff: Path) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Approved Host abnormal verification requires native Windows")
    requester_sid, elevated = _process_token_details(os.getpid())
    if elevated:
        raise PermissionError("arm phase must run from the non-elevated runtime user")
    requester_create_time = float(psutil.Process(os.getpid()).create_time())
    username = requester_username(os.getpid(), requester_create_time)
    user_process_baseline = capture_user_processes(username)

    from . import server

    authority_before = ApprovedHostAuthorityClient().assert_available()
    initial_service_epoch = str(authority_before.get("service_epoch") or "")
    if not initial_service_epoch:
        raise RuntimeError("Approved Host authority probe returned no service epoch")

    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    wmic = system_root / "System32" / "wbem" / "WMIC.exe"
    if not wmic.is_file():
        raise RuntimeError(
            "WMIC.exe is unavailable. Enable the Windows WMIC optional feature or provide "
            "an equivalent preinstalled non-project-controlled WMI client before claiming "
            "the mandatory Win32_Process.Create abnormal-path verification."
        )
    ping = system_root / "System32" / "ping.exe"
    # -t keeps the WMI-created helper alive until the synchronized Check phase cleans up its
    # exact PID/create-time/executable identity. The worker remains bounded by the product's
    # normal operation deadline; this is not an unbounded Approved Host execution route.
    helper_command = f'"{ping}" -t 127.0.0.1'
    operation_runtime_seconds = int(server.runtime.settings.default_max_runtime_seconds)

    victim = server.request_host_command(
        command=[str(wmic), "process", "call", "create", helper_command],
        cwd=cwd,
        reason="WLMCP-R2-001 WMI helper plus SYSTEM-worker-loss verification",
        network_required=False,
        risk_summary="Win32_Process.Create creates a same-user process outside the Host Job",
        workspace_write=True,
        max_runtime_seconds=operation_runtime_seconds,
    )
    legacy = server.request_host_command(
        command=[str(system_root / "System32" / "whoami.exe"), "/user"],
        cwd=cwd,
        reason="legacy pending approval bypass regression",
        network_required=False,
        risk_summary="must remain blocked after abnormal Host recovery latch",
        workspace_write=True,
        max_runtime_seconds=20,
    )
    operation_id = str(victim["approval_id"])
    legacy_id = str(legacy["approval_id"])
    _approve_and_launch(server.runtime, operation_id)
    operation = _wait_worker_and_child(server.runtime, operation_id)

    # WMIC normally exits after WmiPrvSE accepts Create(). Confirm the requested ping helper
    # actually exists under the original runtime user before fault-injecting the SYSTEM worker.
    deadline = time.monotonic() + 8.0
    helpers: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        helpers = _new_ping_helpers(
            username=username,
            baseline=user_process_baseline,
            expected_ping=ping,
        )
        if helpers:
            break
        time.sleep(0.1)
    if not helpers:
        raise AssertionError(
            "Win32_Process.Create did not produce an observable requester-user ping.exe helper"
        )
    current = server.runtime.audit.get_operation(operation_id, include_events=False)
    if current["status"] in TERMINAL_STATUSES:
        raise AssertionError(
            "WMI abnormal verification operation became terminal before fault injection"
        )

    payload = {
        "version": 2,
        "operation_id": operation_id,
        "legacy_pending_approval_id": legacy_id,
        "worker_pid": int(operation["worker_pid"]),
        "worker_create_time": float(operation["worker_create_time"]),
        "worker_executable": str(operation["worker_executable"]),
        "process_nonce": str(operation["process_nonce"]),
        "requester_sid": requester_sid,
        "requester_username": username,
        "wmi_job_external_helpers": helpers,
        "config": os.environ.get("LOCAL_MCP_CONFIG"),
        "authority_state_root": str(default_authority_state_root()),
        "initial_service_epoch": initial_service_epoch,
        "operation_runtime_seconds": operation_runtime_seconds,
        "synchronized_fault_injection": True,
    }
    handoff.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        "ABNORMAL_ARM_READY: leave this non-elevated process running and execute "
        "KillAndRestart from a separate elevated Administrator PowerShell.",
        flush=True,
    )

    recovery = _wait_for_fault_injection_recovery(
        server.runtime,
        operation_id,
        initial_service_epoch=initial_service_epoch,
        timeout=operation_runtime_seconds + _ABNORMAL_RECOVERY_WAIT_GRACE_SECONDS,
    )
    payload["recovery_service_epoch"] = str(recovery.get("service_epoch") or "")
    payload["recovery_reason"] = str(recovery.get("recovery_reason") or "")
    payload["arm_observed_authenticated_recovery"] = True
    handoff.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def _expect_state_tamper_denied(root: Path) -> None:
    active = root / "active.json"
    replacement: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as output:
            output.write(b"{}")
            output.flush()
            os.fsync(output.fileno())
            replacement = Path(output.name)
        attempts: list[tuple[str, Any]] = [
            ("enumerate", lambda: list(root.iterdir())),
            ("create", lambda: (root / "user-forge.json").write_text("{}", encoding="utf-8")),
            ("delete", lambda: active.unlink()),
            ("replace", lambda: os.replace(replacement, active)),
        ]
        for label, action in attempts:
            try:
                action()
            except (PermissionError, OSError):
                continue
            raise AssertionError(
                f"runtime user unexpectedly succeeded in authority-state {label} operation"
            )
    finally:
        if replacement is not None:
            replacement.unlink(missing_ok=True)


def check_abnormal(handoff: Path) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Approved Host abnormal verification requires native Windows")
    _, elevated = _process_token_details(os.getpid())
    if elevated:
        raise PermissionError("check phase must run from the non-elevated runtime user")
    payload = json.loads(handoff.read_text(encoding="utf-8"))
    config = payload.get("config")
    if config:
        os.environ["LOCAL_MCP_CONFIG"] = str(config)

    helpers = payload.get("wmi_job_external_helpers")
    if not isinstance(helpers, list) or not helpers or not all(
        isinstance(helper, dict) for helper in helpers
    ):
        raise AssertionError("handoff contains no verified WMI job-external helper identity")
    typed_helpers = [dict(helper) for helper in helpers]
    for helper in typed_helpers:
        _require_live_helper(helper)

    try:
        probe = ApprovedHostAuthorityClient().probe()
        if bool(probe.get("healthy")):
            raise AssertionError("authority became healthy after abnormal SYSTEM-worker loss")
        if str(probe.get("active_operation_id") or "") != str(payload["operation_id"]):
            raise AssertionError("authority recovery latch belongs to a different operation")
        if not str(probe.get("recovery_reason") or ""):
            raise AssertionError("authority recovery latch has no recovery reason")
        try:
            ApprovedHostAuthorityClient().assert_available()
        except ApprovedHostRecoveryRequired:
            pass
        else:
            raise AssertionError("abnormal Host state did not require explicit recovery")

        if not bool(payload.get("arm_observed_authenticated_recovery")):
            raise AssertionError(
                "Arm phase did not observe authenticated recovery after the service restart"
            )
        initial_epoch = str(payload.get("initial_service_epoch") or "")
        recovery_epoch = str(payload.get("recovery_service_epoch") or "")
        if not initial_epoch or not recovery_epoch or initial_epoch == recovery_epoch:
            raise AssertionError("Arm phase did not prove an authority service epoch transition")
        if str(probe.get("service_epoch") or "") != recovery_epoch:
            raise AssertionError("authority service epoch changed after Arm recovery observation")

        root = Path(str(payload["authority_state_root"]))
        _expect_state_tamper_denied(root)

        from . import server

        legacy_id = str(payload["legacy_pending_approval_id"])
        legacy = server.runtime.audit.get_operation(legacy_id, include_events=False)
        request = legacy["request"]
        if not isinstance(request, dict):
            raise TypeError("legacy pending request is malformed")
        try:
            verify_control_plane_generation(
                server.runtime.settings,
                request.get("control_plane_generation"),
            )
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError):
            generation_blocked = True
        else:
            generation_blocked = False
        if not generation_blocked:
            raise AssertionError(
                "legacy pending approval retained a usable control-plane generation after abnormal Host"
            )

        # Even a caller that bypasses the normal approval UI and claims the old request cannot
        # spawn because Executor independently requires a healthy authenticated authority.
        expected_hash = approved_request_hash(request)
        server.runtime.audit.approve_and_claim(
            legacy_id,
            approver="approved-host-abnormal-verification",
            note="negative legacy bypass test",
            expected_request_hash=expected_hash,
        )
        try:
            server.runtime.executor.launch(legacy_id, 0)
        except PermissionError:
            pass
        else:
            raise AssertionError("legacy Approved Host approval bypassed recovery latch")
        legacy_after = server.runtime.audit.get_operation(legacy_id, include_events=False)
        if legacy_after.get("child_pid") is not None:
            raise AssertionError("legacy approval spawned a child after abnormal Host")

        result = {
            "status": "passed",
            "operation_id": payload["operation_id"],
            "legacy_pending_approval_id": legacy_id,
            "verified_wmi_job_external_helpers": typed_helpers,
            "wmi_helpers_survived_worker_loss_and_restart": True,
            "authority_healthy": False,
            "state_tamper_denied": True,
            "legacy_generation_blocked": True,
            "legacy_worker_spawn_blocked": True,
            "service_epoch_transition_verified": True,
            "recovery_reason": probe.get("recovery_reason"),
        }
    finally:
        _terminate_verified_helpers(typed_helpers)

    result["wmi_helpers_cleaned_up"] = True
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    arm = subparsers.add_parser("arm")
    arm.add_argument("--config", type=Path, required=True)
    arm.add_argument("--cwd", default=".")
    arm.add_argument("--handoff", type=Path, required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--handoff", type=Path, required=True)
    args = parser.parse_args()

    if args.mode == "arm":
        os.environ["LOCAL_MCP_CONFIG"] = str(args.config.resolve(strict=True))
        result = arm_abnormal(args.cwd, args.handoff.resolve())
    else:
        result = check_abnormal(args.handoff.resolve(strict=True))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
