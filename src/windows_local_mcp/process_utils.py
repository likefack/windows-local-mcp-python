from __future__ import annotations

import os
import subprocess
from pathlib import Path

import psutil


CMD_META = set("&|<>^%!`\r\n")


def _quote_cmd_arg(value: str) -> str:
    if any(character in CMD_META for character in value):
        raise ValueError(f"cmd.exeで危険な記号を含む引数を拒否しました: {value}")
    return subprocess.list2cmdline([value])


def build_process_argv(executable: str, args: list[str]) -> list[str]:
    suffix = Path(executable).suffix.casefold()
    if os.name == "nt" and suffix in {".bat", ".cmd"}:
        command_line = " ".join(
            [_quote_cmd_arg(executable), *(_quote_cmd_arg(arg) for arg in args)]
        )
        return ["cmd.exe", "/d", "/s", "/c", command_line]
    return [executable, *args]


def creation_flags() -> int:
    if os.name != "nt":
        return 0
    return (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )


def terminate_process_tree(pid: int, timeout: float = 8.0) -> None:
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

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
