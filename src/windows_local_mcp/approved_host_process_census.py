from __future__ import annotations

import time
from collections.abc import Iterable

import psutil

ProcessStamp = tuple[int, float]


def requester_username(requester_pid: int, requester_create_time: float) -> str:
    try:
        process = psutil.Process(requester_pid)
        actual_create_time = float(process.create_time())
        if abs(actual_create_time - requester_create_time) > 0.01:
            raise RuntimeError("Approved Host requester PID was reused")
        username = str(process.username())
    except (psutil.AccessDenied, psutil.NoSuchProcess) as error:
        raise RuntimeError("Approved Host requester identity is unavailable") from error
    if not username:
        raise RuntimeError("Approved Host requester username is unavailable")
    return username


def capture_user_processes(username: str) -> set[ProcessStamp]:
    target = username.casefold()
    result: set[ProcessStamp] = set()
    for process in psutil.process_iter(("pid", "create_time", "username")):
        try:
            process_username = str(process.info.get("username") or "")
            if process_username.casefold() != target:
                continue
            create_time = process.info.get("create_time")
            if create_time is None:
                create_time = process.create_time()
            result.add((int(process.pid), float(create_time)))
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return result


def wait_for_untracked_user_processes(
    username: str,
    baseline: set[ProcessStamp],
    *,
    deadline: float,
    excluded_pids: Iterable[int] = (),
) -> set[ProcessStamp]:
    excluded = {int(pid) for pid in excluded_pids}
    while True:
        current = capture_user_processes(username)
        untracked = {
            stamp
            for stamp in current - baseline
            if stamp[0] not in excluded
        }
        if not untracked:
            return set()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return untracked
        time.sleep(min(0.1, remaining))
