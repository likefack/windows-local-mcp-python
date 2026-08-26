from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Settings
from .policy import NormalizedCommand
from .tool_safety import trusted_helper_identity


# Approved Host is full Windows-user authority. Eligibility therefore cannot be inferred from
# an executable basename deny-list: an installed program with an unrecognised name may still
# load, build, test, or execute project-controlled inputs. Current v1 only admits targets whose
# complete host behavior has a dedicated policy and an independently pinned executable identity.
APPROVED_HOST_TARGETS = frozenset({"adb"})
_IDENTITY_FIELDS = ("path", "sha256", "size", "stable_file_identity", "mtime_ns")


def _same_executable_identity(
    actual: dict[str, Any] | None, expected: dict[str, Any]
) -> bool:
    if actual is None:
        return False
    return all(actual.get(field) == expected.get(field) for field in _IDENTITY_FIELDS)


def require_approved_host_target(
    settings: Settings, normalized: NormalizedCommand
) -> None:
    """Fail closed unless the command is a reviewed, identity-pinned Approved Host target."""
    if normalized.program_key not in APPROVED_HOST_TARGETS:
        raise PermissionError(
            "executable is not an explicitly reviewed Approved Host target; "
            "project-controlled or unclassified execution must use request_sandbox_command"
        )

    # ADB is intentionally reused from the broker trust policy: capability enablement, an
    # absolute configured path, configured SHA-256, external-root placement, and stable file
    # identity are all required. A PATH alias or same-name replacement therefore cannot acquire
    # Approved Host eligibility merely by being called "adb".
    if normalized.program_key == "adb":
        expected = trusted_helper_identity(settings, "adb")
        if not _same_executable_identity(normalized.executable_identity, expected):
            raise PermissionError(
                "Approved Host ADB executable does not match the configured trusted identity"
            )
        if Path(normalized.executable).resolve(strict=True) != Path(
            str(expected["path"])
        ).resolve(strict=True):
            raise PermissionError(
                "Approved Host ADB executable path does not match the configured trusted target"
            )
        return

    raise PermissionError("Approved Host target has no implemented security policy")
