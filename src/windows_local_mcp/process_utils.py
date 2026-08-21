from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from .paths import hold_verified_path
from .windows_system import windows_system_executable

CMD_META = set("&|<>^%!`\r\n")
_SAFE_GIT_PREFIX = (
    "--no-pager",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "diff.external=",
    "-c",
    "credential.helper=",
)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float
    executable: str
    nonce: str


ProcessKey = tuple[int, float]


class _HeldArgv(list[str]):
    """Keep validated filesystem leases alive for the child-process lifetime."""

    def __init__(self, values: list[str], holds: list[Path]) -> None:
        super().__init__(values)
        self._holds = tuple(holds)


def _quote_cmd_arg(value: str) -> str:
    if any(character in CMD_META for character in value):
        raise ValueError(f"unsafe cmd.exe metacharacter in argument: {value}")
    return subprocess.list2cmdline([value])


def _program_key(executable: str) -> str:
    key = Path(executable).name.casefold()
    for suffix in (".exe", ".bat", ".cmd"):
        key = key.removesuffix(suffix)
    return key


def _hold_broker_git_pathspecs(executable: str, args: list[str]) -> list[Path]:
    """Re-open validated broker Git pathspecs and pin them until Git exits."""

    if (
        _program_key(executable) != "git"
        or tuple(args[: len(_SAFE_GIT_PREFIX)]) != _SAFE_GIT_PREFIX
    ):
        return []
    try:
        separator = args.index("--")
    except ValueError:
        return []

    holds: list[Path] = []
    try:
        for value in args[separator + 1 :]:
            candidate = Path(value)
            if not candidate.is_absolute():
                raise RuntimeError("validated broker Git pathspec is no longer absolute")
            holds.append(
                hold_verified_path(
                    candidate,
                    allow_directory=True,
                    allow_hardlinks=False,
                )
            )
        return holds
    except Exception:
        holds.clear()
        raise


def _hold_process_cwd(cwd: str | Path) -> Path:
    held = hold_verified_path(
        Path(cwd),
        allow_directory=True,
        allow_hardlinks=True,
    )
    if not held.is_dir():
        raise NotADirectoryError(f"process cwd is not a directory: {cwd}")
    return held


def build_process_argv(
    executable: str,
    args: list[str],
    *,
    cwd: str | Path | None = None,
) -> list[str]:
    holds = _hold_broker_git_pathspecs(executable, args)
    try:
        if cwd is not None:
            holds.append(_hold_process_cwd(cwd))
        suffix = Path(executable).suffix.casefold()
        if os.name == "nt" and suffix in {".bat", ".cmd"}:
            command_line = " ".join(
                [_quote_cmd_arg(executable), *(_quote_cmd_arg(arg) for arg in args)]
            )
            values = [windows_system_executable("cmd.exe"), "/d", "/s", "/c", command_line]
        else:
            values = [executable, *args]
        return _HeldArgv(values, holds)
    except Exception:
        holds.clear()
        raise


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


def capture_current_user_processes() -> set[ProcessKey]:
    """Return PID/creation-time keys for processes running as this process's user."""
    try:
        username = psutil.Process(os.getpid()).username()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as error:
        raise RuntimeError("current Windows user identity could not be read") from error
    if not username:
        raise RuntimeError("current Windows user identity is empty")

    snapshot: set[ProcessKey] = set()
    for process in psutil.process_iter(["pid", "create_time", "username"]):
        try:
            info = process.info
            if info.get("username") != username:
                continue
            create_time = info.get("create_time")
            if create_time is None:
                raise RuntimeError(
                    f"process creation time could not be read for same-user PID {info.get('pid')}"
                )
            snapshot.add((int(info["pid"]), float(create_time)))
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied as error:
            raise RuntimeError("same-user process identity enumeration was denied") from error
    return snapshot


def wait_for_untracked_current_user_processes(
    baseline: set[ProcessKey],
    *,
    deadline: float,
    excluded_pids: set[int] | frozenset[int] = frozenset(),
) -> set[ProcessKey]:
    """Wait until same-user processes created after baseline have exited.

    This supplements, but does not replace, the Windows Job Object. It closes the
    WMI/provider process-creation path that is not represented in the Job's
    active-process count. An untracked process still alive at the deadline is
    returned so the caller can fail closed.
    """
    while True:
        current = capture_current_user_processes()
        untracked = {
            key for key in current - baseline if key[0] not in excluded_pids
        }
        if not untracked:
            return set()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return untracked
        time.sleep(min(0.05, remaining))


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


def process_tree_write_bytes(identity: ProcessIdentity) -> int | None:
    """Return cumulative filesystem writes for the bound process tree.

    None means the identity or one of its currently visible descendants could not be
    accounted for. Sandboxed callers treat that uncertainty as a failed resource boundary.
    """
    if not process_identity_matches(identity):
        return None
    try:
        process = psutil.Process(identity.pid)
        members = [process, *process.children(recursive=True)]
        total = 0
        for member in members:
            try:
                total += int(member.io_counters().write_bytes)
            except psutil.NoSuchProcess:
                continue
        return total
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None
