from __future__ import annotations

import re
from typing import Any

_KEY_SECRET = re.compile(
    r"(?:api[-_]?key|access[-_]?token|refresh[-_]?token|password|passwd|secret|credential|authorization|cookie)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+\-/]+=*")
_CREDENTIAL_URL = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/]+:)[^@\s]+@")
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[-_]?key|access[-_]?token|refresh[-_]?token|password|passwd|secret|credential)\s*[=:]\s*)([^\s,;]+)"
)
_TOKEN_SHAPES = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,})\b"
)
_SECRET_OPTION = re.compile(
    r"(?i)^--?(?:api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret|credential|authorization|cookie)$"
)


def redact_text(value: str) -> str:
    redacted = _CREDENTIAL_URL.sub(r"\1<redacted>@", value)
    redacted = _BEARER.sub(r"\1<redacted>", redacted)
    redacted = _ASSIGNMENT.sub(r"\1<redacted>", redacted)
    return _TOKEN_SHAPES.sub("<redacted-token>", redacted)


def redact_command_args(values: list[str] | tuple[str, ...]) -> list[str]:
    """Redact argv while preserving option names and the command's useful shape."""
    result: list[str] = []
    redact_next = False
    for value in values:
        text = str(value)
        if redact_next:
            result.append("<redacted>")
            redact_next = False
            continue
        result.append(redact_text(text))
        redact_next = bool(_SECRET_OPTION.fullmatch(text))
    return result


def redact_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "<depth-limited>"
    if isinstance(value, dict):
        return {
            str(key): (
                "<redacted>"
                if _KEY_SECRET.search(str(key))
                else redact_value(item, depth=depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        if all(isinstance(item, str) for item in value):
            return redact_command_args(value)
        return [redact_value(item, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        if all(isinstance(item, str) for item in value):
            return tuple(redact_command_args(value))
        return tuple(redact_value(item, depth=depth + 1) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value
