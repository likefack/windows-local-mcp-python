from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from typing import Any

from .audit import TERMINAL_STATUSES, AuditStore
from .config import Settings
from .process_utils import (
    ProcessIdentity,
    capture_process_identity,
    creation_flags,
    process_identity_matches,
    terminate_process_tree,
)
from .util import utc_now_iso


class Executor:
    def __init__(self, settings: Settings, audit: AuditStore) -> None:
        self.settings = settings
        self.audit = audit
        self._reconcile_stale_jobs()

    def launch(self, operation_id: str, foreground_timeout_seconds: int) -> dict[str, Any]:
        nonce = uuid.uuid4().hex
        child_env = os.environ.copy()
        child_env["WINDOWS_LOCAL_MCP_JOB_NONCE"] = nonce
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "windows_local_mcp.worker",
                "--operation-id",
                operation_id,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creation_flags(),
            start_new_session=(os.name != "nt"),
            env=child_env,
        )
        identity = capture_process_identity(process.pid, nonce)
        self.audit.update_operation(
            operation_id,
            worker_pid=identity.pid,
            worker_create_time=identity.create_time,
            worker_executable=identity.executable,
            process_nonce=nonce,
        )
        self.audit.add_event(
            operation_id,
            "worker_spawned",
            {"worker_pid": process.pid, "identity_verified": True},
        )

        deadline = time.monotonic() + max(0, foreground_timeout_seconds)
        while time.monotonic() < deadline:
            operation = self.audit.get_operation(operation_id, include_events=False)
            if operation["status"] in TERMINAL_STATUSES:
                return self._public_result(operation)
            time.sleep(0.25)

        operation = self.audit.get_operation(operation_id, include_events=False)
        if operation["status"] in TERMINAL_STATUSES:
            return self._public_result(operation)
        return {
            "operation_id": operation_id,
            "job_id": operation_id,
            "status": operation["status"],
            "message": "Command continues in the background; use poll_job.",
        }

    def poll(self, operation_id: str) -> dict[str, Any]:
        return self._public_result(self.audit.get_operation(operation_id, include_events=False))

    def stop(self, operation_id: str) -> dict[str, Any]:
        operation = self.audit.get_operation(operation_id, include_events=False)
        if operation["status"] in TERMINAL_STATUSES:
            return self._public_result(operation)

        identities = self._identities(operation)
        if not identities:
            raise RuntimeError("job has no verifiable live process identity; refusing PID-only stop")
        matched = False
        for identity in identities:
            if terminate_process_tree(identity):
                matched = True
        if not matched:
            self.audit.update_operation(
                operation_id,
                status="interrupted",
                finished_at=utc_now_iso(),
                error="stale process identity; no process was terminated",
            )
            self.audit.add_event(operation_id, "stale_identity", {})
            return self._public_result(
                self.audit.get_operation(operation_id, include_events=False)
            )

        self.audit.update_operation(
            operation_id,
            status="cancelled",
            finished_at=utc_now_iso(),
            error="cancelled by local user or MCP host after identity verification",
        )
        self.audit.add_event(operation_id, "cancelled", {"identity_verified": True})
        return self._public_result(self.audit.get_operation(operation_id, include_events=False))

    def _reconcile_stale_jobs(self) -> None:
        for operation in self.audit.list_active_operations():
            identities = self._identities(operation)
            if identities and any(process_identity_matches(identity) for identity in identities):
                continue
            now = utc_now_iso()
            self.audit.update_operation(
                operation["id"],
                status="interrupted",
                finished_at=now,
                error="stale job reconciled at server startup; no PID-only termination attempted",
            )
            self.audit.add_event(operation["id"], "stale_job_reconciled", {})

    @staticmethod
    def _identities(operation: dict[str, Any]) -> list[ProcessIdentity]:
        nonce = operation.get("process_nonce")
        if not nonce:
            return []
        result: list[ProcessIdentity] = []
        for prefix in ("child", "worker"):
            pid = operation.get(f"{prefix}_pid")
            created = operation.get(f"{prefix}_create_time")
            executable = operation.get(f"{prefix}_executable")
            if pid and created is not None and executable:
                result.append(
                    ProcessIdentity(
                        pid=int(pid),
                        create_time=float(created),
                        executable=str(executable),
                        nonce=str(nonce),
                    )
                )
        return result

    @staticmethod
    def _public_result(operation: dict[str, Any]) -> dict[str, Any]:
        result = operation.get("result")
        if isinstance(result, dict):
            return result
        return {
            "operation_id": operation["id"],
            "job_id": operation["id"],
            "status": operation["status"],
            "exit_code": operation.get("exit_code"),
            "error": operation.get("error"),
            "stdout_path": operation.get("stdout_path"),
            "stderr_path": operation.get("stderr_path"),
        }
