from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from .approved_host_authority import (
    ApprovedHostAuthorityClient,
    ApprovedHostRecoveryRequired,
    default_authority_state_root,
)
from .approved_host_service import _process_token_details
from .approval import verify_approval_bundle
from .audit import TERMINAL_STATUSES
from .control_plane import verify_control_plane_generation
from .policy import approved_request_hash


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


def _wait_worker_and_child(runtime: Any, operation_id: str, timeout: float = 20.0) -> dict[str, Any]:
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


def arm_abnormal(cwd: str, handoff: Path) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Approved Host abnormal verification requires native Windows")
    requester_sid, elevated = _process_token_details(os.getpid())
    if elevated:
        raise PermissionError("arm phase must run from the non-elevated runtime user")

    from . import server

    system_root = Path(os.environ.get("SystemRoot") or r"C:\Windows")
    wmic = system_root / "System32" / "wbem" / "WMIC.exe"
    if not wmic.is_file():
        raise RuntimeError(
            "WMIC.exe is unavailable. Enable the Windows WMIC optional feature or provide "
            "an equivalent preinstalled non-project-controlled WMI client before claiming "
            "the mandatory Win32_Process.Create abnormal-path verification."
        )
    ping = system_root / "System32" / "ping.exe"
    helper_command = f'"{ping}" 127.0.0.1 -n 30 -w 1000'

    victim = server.request_host_command(
        command=[str(wmic), "process", "call", "create", helper_command],
        cwd=cwd,
        reason="WLMCP-R2-001 WMI helper plus SYSTEM-worker-loss verification",
        network_required=False,
        risk_summary="Win32_Process.Create creates a same-user process outside the Host Job",
        workspace_write=False,
        max_runtime_seconds=45,
    )
    legacy = server.request_host_command(
        command=[str(system_root / "System32" / "whoami.exe"), "/user"],
        cwd=cwd,
        reason="legacy pending approval bypass regression",
        network_required=False,
        risk_summary="must remain blocked after abnormal Host recovery latch",
        workspace_write=False,
        max_runtime_seconds=20,
    )
    operation_id = str(victim["approval_id"])
    legacy_id = str(legacy["approval_id"])
    _approve_and_launch(server.runtime, operation_id)
    operation = _wait_worker_and_child(server.runtime, operation_id)

    # WMIC normally exits after the provider accepts Create(). Give WmiPrvSE enough time to
    # create the job-external helper so the SYSTEM worker enters its postflight user census.
    time.sleep(2.0)
    current = server.runtime.audit.get_operation(operation_id, include_events=False)
    if current["status"] in TERMINAL_STATUSES:
        raise AssertionError(
            "WMI abnormal verification operation became terminal before fault injection"
        )

    payload = {
        "version": 1,
        "operation_id": operation_id,
        "legacy_pending_approval_id": legacy_id,
        "worker_pid": int(operation["worker_pid"]),
        "worker_create_time": float(operation["worker_create_time"]),
        "worker_executable": str(operation["worker_executable"]),
        "process_nonce": str(operation["process_nonce"]),
        "requester_sid": requester_sid,
        "config": os.environ.get("LOCAL_MCP_CONFIG"),
        "authority_state_root": str(default_authority_state_root()),
    }
    handoff.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def _expect_state_tamper_denied(root: Path) -> None:
    active = root / "active.json"
    attempts: list[tuple[str, Any]] = [
        ("enumerate", lambda: list(root.iterdir())),
        ("create", lambda: (root / "user-forge.json").write_text("{}", encoding="utf-8")),
        ("delete", lambda: active.unlink()),
        ("replace", lambda: os.replace(Path(__file__), active)),
    ]
    for label, action in attempts:
        try:
            action()
        except (PermissionError, OSError):
            continue
        raise AssertionError(
            f"runtime user unexpectedly succeeded in authority-state {label} operation"
        )


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

    probe = ApprovedHostAuthorityClient().probe()
    if bool(probe.get("healthy")):
        raise AssertionError("authority became healthy after abnormal SYSTEM-worker loss")
    try:
        ApprovedHostAuthorityClient().assert_available()
    except ApprovedHostRecoveryRequired:
        pass
    else:
        raise AssertionError("abnormal Host state did not require explicit recovery")

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
    except Exception:
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

    return {
        "status": "passed",
        "operation_id": payload["operation_id"],
        "legacy_pending_approval_id": legacy_id,
        "authority_healthy": False,
        "state_tamper_denied": True,
        "legacy_generation_blocked": True,
        "legacy_worker_spawn_blocked": True,
        "recovery_reason": probe.get("recovery_reason"),
    }


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
