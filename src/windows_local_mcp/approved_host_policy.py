from __future__ import annotations

import os
import subprocess
from typing import Any

from .approved_host_authority import (
    APPROVED_HOST_AUTHORITY_SERVICE_NAME,
    ApprovedHostAuthorityClient,
)
from .windows_system import windows_system_executable

APPROVED_HOST_UNAVAILABLE_REASON = (
    "Approved Host requires the independently privileged WindowsLocalMCPApprovedHost "
    "LocalSystem authority service and a healthy durable authority state."
)


def _authority_service_installed() -> bool:
    if os.name != "nt":
        return False
    completed = subprocess.run(
        [
            windows_system_executable("sc.exe"),
            "query",
            APPROVED_HOST_AUTHORITY_SERVICE_NAME,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
        shell=False,
    )
    return completed.returncode == 0


def install_approved_host_authority_health_gate() -> None:
    """Bind global control-plane health to a provisioned SYSTEM authority latch."""
    from . import control_plane_guard

    original = control_plane_guard.assert_control_plane_healthy
    if bool(getattr(original, "__wlmcp_approved_host_authority_gate__", False)):
        return

    def guarded(settings: Any) -> None:
        original(settings)
        if os.name != "nt":
            return
        if os.environ.get("WINDOWS_LOCAL_MCP_AUTHORITY_WORKER") == "1":
            # The active durable latch is expected while the SYSTEM worker owns postflight.
            return
        if not bool(getattr(settings, "approved_host_enabled", False)):
            return
        if not _authority_service_installed():
            # Broker and Sandbox remain usable on installations that never provisioned Host.
            # Approved Host launch itself separately requires the authority service.
            return
        ApprovedHostAuthorityClient().assert_available()

    guarded.__wlmcp_approved_host_authority_gate__ = True  # type: ignore[attr-defined]
    control_plane_guard.assert_control_plane_healthy = guarded


def assert_approved_host_authority_available() -> dict[str, Any]:
    """Require the authenticated SCM-backed authority before an Approved Host launch."""
    if os.name != "nt":
        raise PermissionError("Approved Host authority requires native Windows")
    try:
        return ApprovedHostAuthorityClient().assert_available()
    except Exception as error:
        raise PermissionError(
            f"{APPROVED_HOST_UNAVAILABLE_REASON} {type(error).__name__}: {error}"
        ) from error


def verify_approved_host_runtime_immutability_only() -> dict[str, Any]:
    """Verify the immutable runtime without making an Approved Host availability claim."""
    from .runtime_immutability import assert_approved_host_runtime_immutable

    return assert_approved_host_runtime_immutable()
