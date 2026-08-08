from __future__ import annotations

from pathlib import Path


def ensure_external_tool_executable(
    executable: str | Path,
    *,
    workspace_root: Path,
    data_dir: Path,
) -> str:
    """Require automatic tool binaries to live outside MCP-writable roots.

    Automatic Git/Dart/Flutter/ADB commands rely on the installed toolchain being trusted.
    Resolving one of those executables from the workspace or MCP data directory would let a
    writable project shadow a trusted command through PATH and cross the approval boundary.
    """
    resolved = Path(executable).resolve(strict=True)
    if not resolved.is_file():
        raise PermissionError(f"automatic tool executable is not a regular file: {resolved}")

    for label, root in (
        ("workspace", workspace_root.resolve(strict=True)),
        ("data_dir", data_dir.resolve(strict=True)),
    ):
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise PermissionError(
            f"automatic tool executable must not be loaded from the {label}: {resolved}"
        )
    return str(resolved)
