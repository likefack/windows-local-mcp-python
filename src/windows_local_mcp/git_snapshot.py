from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

from .config import Settings
from .resources import BoundedStreamCapture, enforce_data_quota


def capture_git_snapshot(
    *,
    settings: Settings,
    operation_id: str,
    stage: str,
) -> str | None:
    if not settings.git_enabled:
        return None
    git = shutil.which("git.exe") or shutil.which("git")
    if not git:
        return None
    root = settings.workspace_root
    probe = subprocess.run(
        [git, "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        shell=False,
        check=False,
    )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return None

    commands = [
        ("branch", [git, "-C", str(root), "symbolic-ref", "--short", "HEAD"]),
        ("head", [git, "-C", str(root), "rev-parse", "HEAD"]),
        (
            "status",
            [git, "-C", str(root), "status", "--porcelain=v1", "--branch", "--untracked-files=all"],
        ),
        ("diff", [git, "-C", str(root), "diff", "--binary", "--no-ext-diff", "--no-textconv"]),
        (
            "staged",
            [git, "-C", str(root), "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv"],
        ),
        ("recent", [git, "-C", str(root), "--no-pager", "log", "-10", "--oneline", "--decorate"]),
        (
            "changed-files",
            [git, "-C", str(root), "diff", "--name-status", "--no-ext-diff", "HEAD"],
        ),
    ]
    per_stream_limit = max(4096, settings.max_diff_bytes // len(commands) // 2)
    parts: list[str] = []
    temp_paths: list[Path] = []
    try:
        for name, command in commands:
            token = uuid.uuid4().hex
            stdout_path = settings.data_dir / "outputs" / f"snapshot-{token}.out"
            stderr_path = settings.data_dir / "outputs" / f"snapshot-{token}.err"
            temp_paths.extend((stdout_path, stderr_path))
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                )
                if process.stdout is None or process.stderr is None:
                    raise RuntimeError("failed to capture Git snapshot output")
                stdout_capture = BoundedStreamCapture(process.stdout, stdout_path, per_stream_limit)
                stderr_capture = BoundedStreamCapture(process.stderr, stderr_path, per_stream_limit)
                stdout_capture.start()
                stderr_capture.start()
                try:
                    exit_code = process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    exit_code = -1
                stdout_capture.join()
                stderr_capture.join()
                parts.append(
                    f"===== {name} exit={exit_code} =====\n"
                    f"{stdout_capture.preview(per_stream_limit)}\n"
                    f"----- stderr -----\n{stderr_capture.preview(per_stream_limit)}\n"
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                parts.append(f"===== {name} error =====\n{error!r}\n")

        payload = "\n".join(parts).encode("utf-8")
        if len(payload) > settings.max_diff_bytes:
            payload = payload[: settings.max_diff_bytes]
        enforce_data_quota(settings, incoming_bytes=len(payload))
        path = settings.data_dir / "git-snapshots" / f"{operation_id}-{stage}.txt"
        path.write_bytes(payload)
        return str(path)
    finally:
        for path in temp_paths:
            path.unlink(missing_ok=True)
