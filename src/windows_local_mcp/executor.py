from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Any

from .audit import AuditStore, TERMINAL_STATUSES
from .config import Settings
from .process_utils import creation_flags, terminate_process_tree
from .util import utc_now_iso


class Executor:
    def __init__(self, settings: Settings, audit: AuditStore) -> None:
        self.settings = settings
        self.audit = audit

    def launch(self, operation_id: str, foreground_timeout_seconds: int) -> dict[str, Any]:
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
        )
        self.audit.update_operation(operation_id, worker_pid=process.pid)
        self.audit.add_event(operation_id, "worker_spawned", {"worker_pid": process.pid})

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
            "message": "処理はバックグラウンドで継続しています。poll_jobで確認してください。",
        }

    def poll(self, operation_id: str) -> dict[str, Any]:
        return self._public_result(self.audit.get_operation(operation_id, include_events=False))

    def stop(self, operation_id: str) -> dict[str, Any]:
        operation = self.audit.get_operation(operation_id, include_events=False)
        if operation["status"] in TERMINAL_STATUSES:
            return self._public_result(operation)

        child_pid = operation.get("child_pid")
        worker_pid = operation.get("worker_pid")
        if child_pid:
            terminate_process_tree(int(child_pid))
        if worker_pid and worker_pid != child_pid:
            terminate_process_tree(int(worker_pid))

        self.audit.update_operation(
            operation_id,
            status="cancelled",
            finished_at=utc_now_iso(),
            error="ユーザーまたはMCPホストによって停止されました",
        )
        self.audit.add_event(operation_id, "cancelled", {"child_pid": child_pid, "worker_pid": worker_pid})
        return self._public_result(self.audit.get_operation(operation_id, include_events=False))

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
