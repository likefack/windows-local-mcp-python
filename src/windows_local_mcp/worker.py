from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

from .audit import AuditStore
from .config import load_settings
from .git_snapshot import capture_git_snapshot
from .process_utils import build_process_argv, creation_flags, terminate_process_tree
from .util import canonical_json, truncate_middle, utc_now_iso


def run_operation(operation_id: str) -> int:
    settings = load_settings()
    audit = AuditStore(settings)
    operation = audit.get_operation(operation_id, include_events=False)
    request = operation["request"]
    normalized = request["normalized_command"]
    executable = normalized["executable"]
    args = list(normalized["args"])
    cwd = normalized["cwd"]
    max_runtime = int(request["max_runtime_seconds"])

    stdout_path = settings.data_dir / "outputs" / f"{operation_id}.stdout.log"
    stderr_path = settings.data_dir / "outputs" / f"{operation_id}.stderr.log"

    audit.update_operation(
        operation_id,
        status="running",
        started_at=utc_now_iso(),
        worker_pid=os.getpid(),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
    )
    audit.add_event(operation_id, "worker_started", {"worker_pid": os.getpid()})

    pre_git = capture_git_snapshot(
        settings=settings,
        operation_id=operation_id,
        stage="before",
    )
    if pre_git:
        audit.update_operation(operation_id, pre_git_path=pre_git)

    argv = build_process_argv(executable, args)
    started = time.monotonic()
    child: subprocess.Popen[bytes] | None = None

    try:
        with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
            child = subprocess.Popen(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                creationflags=creation_flags(),
                start_new_session=(os.name != "nt"),
            )
            audit.update_operation(operation_id, child_pid=child.pid)
            audit.add_event(
                operation_id,
                "child_started",
                {"child_pid": child.pid, "argv": argv},
            )

            try:
                exit_code = child.wait(timeout=max_runtime)
                status = "succeeded" if exit_code == 0 else "failed"
                error = None if exit_code == 0 else f"コマンドが終了コード {exit_code} で失敗しました"
            except subprocess.TimeoutExpired:
                terminate_process_tree(child.pid)
                exit_code = None
                status = "timed_out"
                error = f"最大実行時間 {max_runtime} 秒を超えました"

    except Exception as exc:
        if child is not None:
            terminate_process_tree(child.pid)
        exit_code = None
        status = "failed"
        error = f"{type(exc).__name__}: {exc}"

    duration_ms = int((time.monotonic() - started) * 1000)
    post_git = capture_git_snapshot(
        settings=settings,
        operation_id=operation_id,
        stage="after",
    )

    stdout = (
        stdout_path.read_text(encoding="utf-8", errors="replace")
        if stdout_path.exists()
        else ""
    )
    stderr = (
        stderr_path.read_text(encoding="utf-8", errors="replace")
        if stderr_path.exists()
        else ""
    )

    result = {
        "operation_id": operation_id,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout_preview": truncate_middle(stdout, settings.output_preview_characters),
        "stderr_preview": truncate_middle(stderr, settings.output_preview_characters),
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
    return 0 if status == "succeeded" else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-id", required=True)
    args = parser.parse_args()
    raise SystemExit(run_operation(args.operation_id))


if __name__ == "__main__":
    main()
