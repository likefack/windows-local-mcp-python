"""起動時の誤中断を防ぐ実行所有者情報。認可やプロセス停止には使用しない。"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Literal

import psutil

OwnerLiveness = Literal["alive", "dead", "unknown"]


def _canonical_executable(executable: str) -> str:
    return os.path.normcase(str(Path(executable).resolve()))


def capture_execution_owner() -> dict[str, int | float | str]:
    """要求を実行する現在のプロセスを記録し、PID の再利用を区別する。"""
    process = psutil.Process(os.getpid())
    return {
        "pid": process.pid,
        "create_time": float(process.create_time()),
        "executable": _canonical_executable(process.exe()),
    }


def execution_owner_liveness(value: object) -> OwnerLiveness:
    """死亡と確認不能を区別し、生きた別サーバーの処理を整理しない。"""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return "dead"
    if not isinstance(value, dict):
        return "dead"
    pid = value.get("pid")
    created = value.get("create_time")
    executable = value.get("executable")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or not isinstance(created, (int, float))
        or isinstance(created, bool)
        or not math.isfinite(created)
        or created <= 0
        or not isinstance(executable, str)
        or not executable
    ):
        return "dead"
    try:
        process = psutil.Process(pid)
        # JSON の数値は往復しても精度を保つため、作成時刻を丸めずに比較できる。
        if process.create_time() != created:
            return "dead"
        if _canonical_executable(process.exe()) != executable:
            return "dead"
        return "alive" if process.is_running() else "dead"
    except psutil.NoSuchProcess:
        return "dead"
    except (psutil.AccessDenied, OSError, NotImplementedError):
        # 確認不能は死亡の証拠ではない。後の起動時確認へ持ち越す。
        return "unknown"
