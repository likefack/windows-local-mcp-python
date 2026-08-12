from __future__ import annotations

from pathlib import Path

from .config import Settings
from .redaction import redact_text
from .resources import enforce_data_quota
from .safe_process import run_safe_process, run_safe_process_batch
from .tool_safety import hold_executable_identity, trusted_helper_identity


def capture_git_snapshot(
    *,
    settings: Settings,
    operation_id: str,
    stage: str,
) -> str | None:
    if not settings.git_enabled:
        return None
    try:
        identity = trusted_helper_identity(settings, "git")
        git = str(identity["path"])
    except (FileNotFoundError, PermissionError):
        return None

    root = settings.workspace_root.resolve(strict=True)
    git_base = [
        git,
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "diff.external=",
        "-c",
        "credential.helper=",
    ]
    commands = [
        ("branch", [*git_base, "-C", str(root), "symbolic-ref", "--short", "HEAD"]),
        ("head", [*git_base, "-C", str(root), "rev-parse", "HEAD"]),
        (
            "status",
            [*git_base, "-C", str(root), "status", "--porcelain=v1", "--branch", "--untracked-files=all"],
        ),
        (
            "diff",
            [*git_base, "-C", str(root), "diff", "--stat", "--name-status", "--no-ext-diff", "--no-textconv"],
        ),
        (
            "staged",
            [*git_base, "-C", str(root), "diff", "--cached", "--stat", "--name-status", "--no-ext-diff", "--no-textconv"],
        ),
        (
            "recent",
            [
                *git_base,
                "-C",
                str(root),
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
                *git_base,
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
    with hold_executable_identity(identity):
        probe = run_safe_process(
            settings=settings,
            program_key="git",
            command=[*git_base, "-C", str(root), "rev-parse", "--show-toplevel"],
            cwd=str(root),
            timeout=15,
            output_limit=4096,
            executable_identity=identity,
            executable_already_held=True,
        )
        if probe.returncode != 0:
            return None
        try:
            discovered_root = Path(
                probe.stdout.decode("utf-8", errors="replace").strip()
            ).resolve(strict=True)
        except (FileNotFoundError, OSError):
            return None
        if discovered_root != root:
            # Do not let a workspace nested inside a larger repository expose
            # parent-repository state through automatic snapshots or git_info.
            return None
        results = run_safe_process_batch(
            settings=settings,
            program_key="git",
            commands=[command for _name, command in commands],
            cwd=str(root),
            timeout=30,
            output_limit=per_stream_limit,
            executable_identity=identity,
            executable_already_held=True,
        )
    for (name, _command), result in zip(commands, results, strict=True):
        parts.append(
            f"===== {name} exit={result.returncode} =====\n"
            f"{result.stdout.decode('utf-8', errors='replace')}\n"
            "----- stderr -----\n"
            f"{result.stderr.decode('utf-8', errors='replace')}\n"
        )

    payload = redact_text("\n".join(parts)).encode("utf-8")
    if len(payload) > settings.max_diff_bytes:
        payload = payload[: settings.max_diff_bytes]
    enforce_data_quota(settings, incoming_bytes=len(payload))
    path = settings.data_dir / "git-snapshots" / f"{operation_id}-{stage}.txt"
    path.write_bytes(payload)
    return str(path)
