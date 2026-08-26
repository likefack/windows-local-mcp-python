from __future__ import annotations

import os
import subprocess
import time
import uuid
from typing import Any

from .audit import TERMINAL_STATUSES, AuditStore
from .child_env import build_worker_environment
from .config import Settings
from .control_plane import create_worker_context, isolated_worker_argv
from .process_utils import (
    ProcessIdentity,
    capture_process_identity,
    creation_flags,
    process_identity_matches,
    terminate_process_tree,
)
from .runtime_immutability import assert_approved_host_runtime_immutable
from .util import utc_now_iso


class Executor:
    def __init__(self, settings: Settings, audit: AuditStore) -> None:
        self.settings = settings
        self.audit = audit
        self._reconcile_stale_jobs()

    def launch(self, operation_id: str, foreground_timeout_seconds: int) -> dict[str, Any]:
        # The operation being launched is already queued and therefore included in this count.
        if len(self.audit.list_active_operations()) > self.settings.max_concurrent_jobs:
            raise RuntimeError("concurrent job admission limit exceeded")
        operation = self.audit.get_operation(operation_id, include_events=False)
        tier = {
            "host_approval": "approved_host",
        }.get(str(operation.get("tier")), str(operation.get("tier")))
        if tier == "approved_host":
            try:
                runtime_trust = assert_approved_host_runtime_immutable()
            except Exception as error:
                self.audit.add_event(
                    operation_id,
                    "approved_host_runtime_immutability_failed",
                    {"error": f"{type(error).__name__}: {error}"[:1000]},
                )
                raise
            self.audit.add_event(
                operation_id,
                "approved_host_runtime_immutability_verified",
                {
                    "version": runtime_trust["version"],
                    "digest": runtime_trust["digest"],
                    "file_count": runtime_trust["file_count"],
                    "directory_count": runtime_trust["directory_count"],
                },
            )
        nonce = uuid.uuid4().hex
        child_env = build_worker_environment(
            os.environ,
            extra_names=self.settings.child_environment_allowlist,
            nonce=nonce,
        )
        context_path, context_sha256 = create_worker_context(self.settings, operation_id)
        process = subprocess.Popen(
            isolated_worker_argv(
                self.settings,
                operation_id=operation_id,
                context_path=context_path,
                context_sha256=context_sha256,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creation_flags(),
            start_new_session=(os.name != "nt"),
            env=child_env,
        )
        identity = capture_process_identity(process.pid, nonce)
        bootstrap_identity_recorded = self.audit.transition_operation(
            operation_id,
            from_statuses={"queued"},
            status="queued",
            worker_pid=identity.pid,
            worker_create_time=identity.create_time,
            worker_executable=identity.executable,
            process_nonce=nonce,
        )
        self.audit.add_event(
            operation_id,
            "worker_spawned",
            {
                "worker_pid": process.pid,
                "launcher_pid": identity.pid,
                "launcher_create_time": identity.create_time,
                "launcher_executable": identity.executable,
                "identity_role": "bootstrap_launcher",
                "identity_verified": True,
                "operation_identity_updated": bootstrap_identity_recorded,
                "immutable_context_sha256": context_sha256,
                "isolated_import_mode": True,
            },
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
        while True:
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
            if matched:
                break

            current_status = str(operation["status"])
            if current_status not in {"queued", "running"}:
                return self._public_result(operation)
            # If worker self-binding raced this stale bootstrap read, the status comparison
            # fails and the loop retries with the newly committed stable identity.
            transitioned = self.audit.transition_operation(
                operation_id,
                from_statuses={current_status},
                status="interrupted",
                finished_at=utc_now_iso(),
                error="stale process identity; no process was terminated",
            )
            if transitioned:
                self.audit.add_event(operation_id, "stale_identity", {})
                return self._public_result(
                    self.audit.get_operation(operation_id, include_events=False)
                )

        transitioned = self.audit.transition_operation(
            operation_id,
            from_statuses={"queued", "running"},
            status="cancelled",
            finished_at=utc_now_iso(),
            error="cancelled by local user or MCP host after identity verification",
        )
        if transitioned:
            self.audit.add_event(operation_id, "cancelled", {"identity_verified": True})
        return self._public_result(self.audit.get_operation(operation_id, include_events=False))

    def _reconcile_stale_jobs(self) -> None:
        for operation in self.audit.list_active_operations():
            while True:
                current = self.audit.get_operation(operation["id"], include_events=False)
                current_status = str(current["status"])
                if current_status not in {"queued", "running"}:
                    break
                identities = self._identities(current)
                if identities and any(
                    process_identity_matches(identity) for identity in identities
                ):
                    break
                transitioned = self.audit.transition_operation(
                    operation["id"],
                    from_statuses={current_status},
                    status="interrupted",
                    finished_at=utc_now_iso(),
                    error="stale job reconciled at server startup; no PID-only termination attempted",
                )
                if transitioned:
                    self.audit.add_event(operation["id"], "stale_job_reconciled", {})
                    break

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
