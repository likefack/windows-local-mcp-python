from __future__ import annotations

from pathlib import Path

from .config import Settings
from .git_broker_sandbox import run_git_broker_batch
from .git_metadata import GIT_STRUCTURAL_COMMIT_FORMAT
from .paths import hold_verified_path, release_verified_hold
from .redaction import redact_text
from .resources import enforce_data_quota
from .tool_safety import trusted_helper_identity


def capture_git_snapshot(
    *,
    settings: Settings,
    operation_id: str,
    stage: str,
    required: bool = False,
) -> str | None:
    if not settings.git_enabled:
        if required:
            raise PermissionError("git capability is disabled")
        return None
    try:
        identity = trusted_helper_identity(settings, "git")
        git = str(identity["path"])
    except (FileNotFoundError, PermissionError, RuntimeError):
        if required:
            raise
        return None

    root = settings.workspace_root.resolve(strict=True)
    root_hold = hold_verified_path(
        root,
        allow_directory=True,
        allow_hardlinks=True,
    )
    try:
        if not root_hold.is_dir():
            if required:
                raise RuntimeError("workspace root is not a directory")
            return None
        root = Path(str(root_hold))
        git_base = [
            git,
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-c",
            "diff.autoRefreshIndex=false",
            "-c",
            "diff.external=",
            "-c",
            "credential.helper=",
        ]
        commands = [
            ("branch", [*git_base, "symbolic-ref", "--short", "HEAD"]),
            ("head", [*git_base, "rev-parse", "HEAD"]),
            (
                "status",
                [
                    *git_base,
                    "status",
                    "--porcelain=v1",
                    "--branch",
                    "--untracked-files=all",
                ],
            ),
            (
                "diff",
                [
                    *git_base,
                    "diff",
                    "--stat",
                    "--name-status",
                    "--no-ext-diff",
                    "--no-textconv",
                ],
            ),
            (
                "staged",
                [
                    *git_base,
                    "diff",
                    "--cached",
                    "--stat",
                    "--name-status",
                    "--no-ext-diff",
                    "--no-textconv",
                ],
            ),
            (
                "recent",
                [
                    *git_base,
                    "log",
                    "-10",
                    GIT_STRUCTURAL_COMMIT_FORMAT,
                    "--no-ext-diff",
                    "--no-textconv",
                ],
            ),
            (
                "changed-files",
                [
                    *git_base,
                    "diff",
                    "--name-status",
                    "--no-ext-diff",
                    "--no-textconv",
                    "HEAD",
                ],
            ),
        ]
        per_stream_limit = max(4096, settings.max_diff_bytes // len(commands) // 2)
        try:
            results = run_git_broker_batch(
                settings=settings,
                git_identity=identity,
                commands=[command for _name, command in commands],
                cwd=str(root),
                timeout=60,
                output_limit=per_stream_limit,
                token=f"snapshot-{operation_id}-{stage}",
            )
        except (OSError, PermissionError, RuntimeError, TimeoutError):
            if required:
                raise
            return None
        parts: list[str] = []
        for (name, _command), result in zip(commands, results, strict=True):
            parts.append(
                f"===== {name} exit={result.returncode} =====\n"
                f"{result.stdout.decode('utf-8', errors='replace')}\n"
                "----- stderr -----\n"
                f"{result.stderr.decode('utf-8', errors='replace')}\n"
            )
    finally:
        release_verified_hold(root_hold)

    payload = redact_text("\n".join(parts)).encode("utf-8")
    if len(payload) > settings.max_diff_bytes:
        payload = payload[: settings.max_diff_bytes]
    enforce_data_quota(settings, incoming_bytes=len(payload))
    path = settings.data_dir / "git-snapshots" / f"{operation_id}-{stage}.txt"
    path.write_bytes(payload)
    return str(path)
