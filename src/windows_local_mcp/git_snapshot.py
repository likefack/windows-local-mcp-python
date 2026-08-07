from __future__ import annotations

import shutil
import subprocess

from .config import Settings


def capture_git_snapshot(
    *,
    settings: Settings,
    operation_id: str,
    stage: str,
) -> str | None:
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
    )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return None

    commands = [
        ("status", [git, "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"]),
        ("diff", [git, "-C", str(root), "diff", "--binary", "--no-ext-diff"]),
        ("cached", [git, "-C", str(root), "diff", "--cached", "--binary", "--no-ext-diff"]),
    ]

    parts: list[str] = []
    for name, command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                shell=False,
            )
            parts.append(
                f"===== {name} exit={result.returncode} =====\n"
                f"{result.stdout}\n"
                f"----- stderr -----\n"
                f"{result.stderr}\n"
            )
        except Exception as error:
            parts.append(f"===== {name} error =====\n{error!r}\n")

    path = settings.data_dir / "git-snapshots" / f"{operation_id}-{stage}.txt"
    path.write_text("\n".join(parts), encoding="utf-8")
    return str(path)
