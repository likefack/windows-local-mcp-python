from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

from .config import Settings
from .git_env import sanitized_git_environment
from .resources import BoundedStreamCapture, enforce_data_quota
from .tool_safety import ensure_external_tool_executable


def capture_git_snapshot(
    *,
    settings: Settings,
    operation_id: str,
    stage: str,
) -> str | None:
    if not settings.git_enabled:
        return None
    discovered_git = shutil.which("git.exe") or shutil.which("git")
    if not discovered_git:
        return None
    try:
        git = ensure_external_tool_executable(
            discovered_git,
            workspace_root=settings.workspace_root,
            data_dir=settings.data_dir,
        )
    except (FileNotFoundError, PermissionError):
        return None

    root = settings.workspace_root.resolve(strict=True)
    git_env = sanitized_git_environment()
    probe = subprocess.run(
        [git, "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        shell=False,
        check=False,
        env=git_env,
    )
    if probe.returncode != 0:
        return None
    try:
        discovered_root = Path(probe.stdout.strip()).resolve(strict=True)
    except (FileNotFoundError, OSError):
        return None
    if discovered_root != root:
        # Do not let a workspace nested inside a larger repository expose parent-repository
        # state through automatic snapshots or git_info.
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
        (
            "recent",
            [
                git,
                "-C",
                str(root),
                "--no-pager",
                "log",
                "-10",
                "--oneline",
                "--decorate",
                "--no-ext-diff",
                "--no-textconv",
            ],
        ),
        (
            "changed-files",
            [
                git,
                "-C",
                str(root),
                "diff",
                "--name-status",
                "--no-ext-diff",
                "--no-textconv",
                "HEAD",
            ],
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
                    env=git_env,
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
