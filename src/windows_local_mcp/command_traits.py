from __future__ import annotations

from enum import StrEnum

from .policy import NormalizedCommand


class SafeExecutionKind(StrEnum):
    READ_ONLY = "read_only"
    WORKSPACE_WRITE = "workspace_write"
    ADB_READ = "adb_read"


_DART_NON_WRITING_OUTPUTS = {"--show", "--output=show", "--output=none"}


def dart_format_writes(args: list[str]) -> bool:
    """Return whether a normalized safe Dart format command writes source files."""
    return bool(args) and args[0] == "format" and not any(
        value in _DART_NON_WRITING_OUTPUTS for value in args
    )


def classify_safe_execution(normalized: NormalizedCommand) -> SafeExecutionKind:
    """Classify an already-normalized automatic command for MCP tool exposure.

    Authorization remains in CommandPolicy.normalize_safe(). This function only assigns a
    narrower tool surface after that deny-by-default validation has succeeded.
    """
    if normalized.program_key == "adb":
        return SafeExecutionKind.ADB_READ
    if normalized.program_key == "git":
        return SafeExecutionKind.READ_ONLY
    if normalized.program_key == "flutter":
        if normalized.args and normalized.args[0] == "analyze":
            return SafeExecutionKind.READ_ONLY
        raise PermissionError("normalized Flutter command is not eligible for a safe MCP tool")
    if normalized.program_key == "dart":
        if normalized.args and normalized.args[0] == "analyze":
            return SafeExecutionKind.READ_ONLY
        if normalized.args and normalized.args[0] == "format":
            return (
                SafeExecutionKind.WORKSPACE_WRITE
                if dart_format_writes(normalized.args)
                else SafeExecutionKind.READ_ONLY
            )
        raise PermissionError("normalized Dart command is not eligible for a safe MCP tool")
    raise PermissionError(f"unsupported automatic program kind: {normalized.program_key}")


def recommended_tool(kind: SafeExecutionKind) -> str:
    if kind == SafeExecutionKind.READ_ONLY:
        return "execute_readonly"
    if kind == SafeExecutionKind.WORKSPACE_WRITE:
        return "execute_workspace_write"
    return "adb_read"
