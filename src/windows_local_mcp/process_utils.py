from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import psutil

from .windows_system import windows_system_executable

CMD_META = set("&|<>^%!`\r\n")


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float
    executable: str
    nonce: str


def _quote_cmd_arg(value: str) -> str:
    if any(character in CMD_META for character in value):
        raise ValueError(f"unsafe cmd.exe metacharacter in argument: {value}")
    return subprocess.list2cmdline([value])


def build_process_argv(executable: str, args: list[str]) -> list[str]:
    suffix = Path(executable).suffix.casefold()
    if os.name == "nt" and suffix in {".bat", ".cmd"}:
        command_line = " ".join(
            [_quote_cmd_arg(executable), *(_quote_cmd_arg(arg) for arg in args)]
        )
        return [windows_system_executable("cmd.exe"), "/d", "/s", "/c", command_line]
    return [executable, *args]


def creation_flags() -> int:
    if os.name != "nt":
        return 0
    return (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )


def capture_process_identity(pid: int, nonce: str) -> ProcessIdentity:
    process = psutil.Process(pid)
    identity = ProcessIdentity(
        pid=pid,
        create_time=process.create_time(),
        executable=os.path.normcase(str(Path(process.exe()).resolve())),
        nonce=nonce,
    )
    if not _process_has_nonce(process, nonce):
        raise RuntimeError("process nonce could not be verified")
    return identity


def process_identity_matches(identity: ProcessIdentity) -> bool:
    try:
        process = psutil.Process(identity.pid)
        if abs(process.create_time() - identity.create_time) > 0.01:
            return False
        executable = os.path.normcase(str(Path(process.exe()).resolve()))
        if executable != identity.executable:
            return False
        return _process_has_nonce(process, identity.nonce)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return False


def _process_has_nonce(process: psutil.Process, nonce: str) -> bool:
    try:
        return process.environ().get("WINDOWS_LOCAL_MCP_JOB_NONCE") == nonce
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return False


def terminate_process_tree(identity: ProcessIdentity, timeout: float = 8.0) -> bool:
    """Terminate only when PID, creation time, executable, and nonce still match."""
    if not process_identity_matches(identity):
        return False
    try:
        process = psutil.Process(identity.pid)
    except psutil.NoSuchProcess:
        return True

    children = process.children(recursive=True)
    for child in children:
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    try:
        process.terminate()
    except psutil.NoSuchProcess:
        pass
    _, alive = psutil.wait_procs([*children, process], timeout=timeout)
    for remaining in alive:
        try:
            remaining.kill()
        except psutil.NoSuchProcess:
            pass
    return True
