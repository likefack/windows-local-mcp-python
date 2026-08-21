from __future__ import annotations

import os
import subprocess
import uuid
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

from .child_env import build_command_environment
from .config import Settings
from .network_isolation import apply_safe_network_environment
from .paths import hold_verified_path, release_verified_hold
from .process_utils import capture_process_identity, creation_flags, terminate_process_tree
from .resources import BoundedStreamCapture
from .tool_safety import hold_executable_identity, trusted_helper_identity


@dataclass(frozen=True)
class SafeProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


def _hold_cwd(path: str) -> Path:
    held = hold_verified_path(
        Path(path),
        allow_directory=True,
        allow_hardlinks=True,
    )
    if not held.is_dir():
        release_verified_hold(held)
        raise NotADirectoryError(f"safe subprocess cwd is not a directory: {path}")
    return held


def run_safe_process(
    *,
    settings: Settings,
    program_key: str,
    command: list[str],
    cwd: str,
    timeout: float,
    output_limit: int,
    executable_identity: dict[str, object] | None = None,
    executable_already_held: bool = False,
) -> SafeProcessResult:
    """Run a trusted, fixed-grammar helper as a bounded broker subprocess.

    This is not a general execution surface and does not claim an OS sandbox. Open-ended
    commands are routed to Codex Sandbox instead of accumulating tool-specific mitigations here.
    """
    if not command:
        raise ValueError("safe subprocess command cannot be empty")
    if executable_already_held and executable_identity is None:
        raise ValueError("an already-held executable requires its bound identity")
    executable_identity = executable_identity or trusted_helper_identity(
        settings, program_key
    )
    if Path(command[0]).resolve(strict=True) != Path(
        str(executable_identity["path"])
    ).resolve(strict=True):
        raise RuntimeError("broker helper command does not match its configured executable")
    token = uuid.uuid4().hex
    stdout_path = settings.data_dir / "outputs" / f"safe-probe-{token}.out"
    stderr_path = settings.data_dir / "outputs" / f"safe-probe-{token}.err"
    environment = build_command_environment(
        os.environ,
        extra_names=settings.child_environment_allowlist,
        nonce=token,
        git_command=program_key == "git",
    )
    apply_safe_network_environment(environment, program_key)
    effective_cwd = cwd
    runtime_root: Path | None = None
    if program_key == "adb":
        runtime_root = settings.data_dir / "outputs" / f"safe-probe-{token}-runtime"
        runtime_root.mkdir(parents=True, exist_ok=False)
        effective_cwd = str(runtime_root)

    process: subprocess.Popen[bytes] | None = None
    stdout_capture: BoundedStreamCapture | None = None
    stderr_capture: BoundedStreamCapture | None = None
    cwd_hold: Path | None = None
    try:
        cwd_hold = _hold_cwd(effective_cwd)
        effective_cwd = str(cwd_hold)
        hold = (
            nullcontext(Path(str(executable_identity["path"])))
            if executable_already_held
            else hold_executable_identity(executable_identity)
        )
        with hold:
            process = subprocess.Popen(
                command,
                cwd=effective_cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creation_flags(),
                start_new_session=(os.name != "nt"),
                env=environment,
            )
            identity = capture_process_identity(process.pid, token)
            if process.stdout is None or process.stderr is None:
                raise RuntimeError("broker helper did not create output pipes")
            stdout_capture = BoundedStreamCapture(process.stdout, stdout_path, output_limit)
            stderr_capture = BoundedStreamCapture(process.stderr, stderr_path, output_limit)
            stdout_capture.start()
            stderr_capture.start()
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                terminate_process_tree(identity)
                raise TimeoutError("broker helper timed out") from error
            stdout_capture.join()
            stderr_capture.join()
            stdout_bytes = stdout_path.read_bytes()
            stderr_bytes = stderr_path.read_bytes()
            return SafeProcessResult(
                returncode=returncode,
                stdout=stdout_bytes,
                stderr=stderr_bytes,
                stdout_truncated=stdout_capture.truncated,
                stderr_truncated=stderr_capture.truncated,
            )
    finally:
        if stdout_capture is not None:
            stdout_capture.join()
        if stderr_capture is not None:
            stderr_capture.join()
        if process is not None and hasattr(process, "close"):
            process.close()
        if cwd_hold is not None:
            release_verified_hold(cwd_hold)
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        if runtime_root is not None:
            import shutil

            shutil.rmtree(runtime_root, ignore_errors=True)


def run_safe_process_batch(
    *,
    settings: Settings,
    program_key: str,
    commands: list[list[str]],
    cwd: str,
    timeout: float,
    output_limit: int,
    executable_identity: dict[str, object] | None = None,
    executable_already_held: bool = False,
) -> list[SafeProcessResult]:
    """Run a fixed helper batch under one executable and cwd replacement-denial hold."""
    if not commands:
        return []
    if executable_already_held and executable_identity is None:
        raise ValueError("an already-held batch executable requires its bound identity")
    identity = executable_identity or trusted_helper_identity(settings, program_key)
    expected_path = Path(str(identity["path"])).resolve(strict=True)
    if any(Path(command[0]).resolve(strict=True) != expected_path for command in commands):
        raise RuntimeError("broker helper batch contains an unbound executable")
    hold = (
        nullcontext(expected_path)
        if executable_already_held
        else hold_executable_identity(identity)
    )
    cwd_hold = _hold_cwd(cwd)
    try:
        with hold:
            return [
                run_safe_process(
                    settings=settings,
                    program_key=program_key,
                    command=command,
                    cwd=str(cwd_hold),
                    timeout=timeout,
                    output_limit=output_limit,
                    executable_identity=identity,
                    executable_already_held=True,
                )
                for command in commands
            ]
    finally:
        release_verified_hold(cwd_hold)
