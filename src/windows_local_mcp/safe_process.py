from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .appcontainer import AppContainerProcess, launch_appcontainer_process
from .child_env import build_command_environment
from .config import Settings
from .network_isolation import apply_safe_network_environment
from .process_utils import creation_flags
from .resources import BoundedStreamCapture


class SafeSandboxCompatibilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class SafeProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


def run_safe_process(
    *,
    settings: Settings,
    program_key: str,
    command: list[str],
    cwd: str,
    timeout: float,
    output_limit: int,
) -> SafeProcessResult:
    """Run an automatic helper executable through the same Safe Sandbox broker."""
    if not command:
        raise ValueError("safe subprocess command cannot be empty")
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

    process: Any | None = None
    stdout_capture: BoundedStreamCapture | None = None
    stderr_capture: BoundedStreamCapture | None = None
    try:
        if settings.safe_network_isolation_mode == "appcontainer":
            try:
                process = launch_appcontainer_process(
                    settings=settings,
                    program_key=program_key,
                    executable=command[0],
                    args=command[1:],
                    cwd=effective_cwd,
                    environment=environment,
                    creation_flags=creation_flags(),
                    workspace_write=False,
                )
            except (OSError, PermissionError) as error:
                raise SafeSandboxCompatibilityError(
                    f"Safe Sandbox helper launch failed: {type(error).__name__}: {error}"
                ) from error
        else:
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
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("Safe Sandbox helper did not create output pipes")
        stdout_capture = BoundedStreamCapture(process.stdout, stdout_path, output_limit)
        stderr_capture = BoundedStreamCapture(process.stderr, stderr_path, output_limit)
        stdout_capture.start()
        stderr_capture.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            if isinstance(process, AppContainerProcess):
                process.terminate()
            else:
                process.kill()
            raise TimeoutError("Safe Sandbox helper timed out") from error
        stdout_capture.join()
        stderr_capture.join()
        stdout_bytes = stdout_path.read_bytes()
        stderr_bytes = stderr_path.read_bytes()
        if (
            settings.safe_network_isolation_mode == "appcontainer"
            and program_key == "git"
            and returncode != 0
            and b"fatal: Unable to read current working directory: Permission denied"
            in stderr_bytes
        ):
            raise SafeSandboxCompatibilityError(
                "Git for Windows requires ancestor directory read compatibility that the "
                "narrow AppContainer profile intentionally does not grant"
            )
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
        stdout_path.unlink(missing_ok=True)
        stderr_path.unlink(missing_ok=True)
        if runtime_root is not None:
            shutil.rmtree(runtime_root, ignore_errors=True)
