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
_SERVICE_DOES_NOT_EXIST_EXIT_CODE = 1060
_AUTHORITY_WORKER_ENV = "WINDOWS_LOCAL_MCP_AUTHORITY_WORKER"
_LOCAL_SYSTEM_SID = "S-1-5-18"


def _service_query_indicates_installed(returncode: int) -> bool:
    if returncode == 0:
        return True
    if returncode == _SERVICE_DOES_NOT_EXIST_EXIT_CODE:
        return False
    raise RuntimeError(
        "Approved Host authority SCM query failed closed: "
        f"sc.exe exited with {returncode}"
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
    return _service_query_indicates_installed(completed.returncode)


def _authority_worker_bypass_allowed() -> bool:
    """Allow the active-latch bypass only inside the independently privileged worker."""
    if os.name != "nt" or os.environ.get(_AUTHORITY_WORKER_ENV) != "1":
        return False
    try:
        from .approved_host_service import _current_process_sid

        return _current_process_sid().casefold() == _LOCAL_SYSTEM_SID.casefold()
    except Exception:
        # Failure to prove LocalSystem identity must never turn a user-controlled
        # environment variable into a durable-latch bypass.
        return False


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
        if _authority_worker_bypass_allowed():
            # The active durable latch is expected while the verified LocalSystem worker
            # owns postflight. A normal user process cannot obtain this bypass by setting
            # the environment variable alone.
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
