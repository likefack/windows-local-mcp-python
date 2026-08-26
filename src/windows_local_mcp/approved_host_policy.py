from __future__ import annotations

from typing import Any

from .config import Settings

APPROVED_HOST_UNAVAILABLE_REASON = (
    "Approved Host execution is unavailable in current v1 because its same-user child can "
    "terminate or bypass an in-process postflight monitor without a separately provisioned "
    "Windows security boundary. Same-desktop UAC elevation is not accepted as that boundary."
)


def approved_host_capability_status(settings: Settings) -> dict[str, Any]:
    """Report configured intent separately from the deliberately unavailable route."""

    if not settings.approved_host_enabled:
        reason = "disabled by configuration"
    else:
        reason = APPROVED_HOST_UNAVAILABLE_REASON
    return {
        "configured": settings.approved_host_enabled,
        "enabled": False,
        "available": False,
        "execution_route_available": False,
        "unit_tested": True,
        "live_verified": False,
        "windows_live_verified": False,
        "verification_scope": "capability_reduced_fail_closed",
        "execution_time_recheck": True,
        "unavailable_reason": reason,
    }


def assert_approved_host_route_available(settings: Settings) -> None:
    """Reject every Approved Host creation or launch until a real OS boundary exists."""

    if not settings.approved_host_enabled:
        raise PermissionError("Approved Host is disabled by configuration")
    raise PermissionError(APPROVED_HOST_UNAVAILABLE_REASON)
