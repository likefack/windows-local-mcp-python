from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

APPROVED_HOST_UNAVAILABLE_REASON = (
    "Approved Host execution is unavailable in current v1 because its same-user child can "
    "terminate or bypass an in-process postflight monitor without a separately provisioned "
    "Windows security boundary. Same-desktop UAC elevation is not accepted as that boundary."
)


def install_approved_host_fail_closed_gate() -> None:
    """Make every production Approved Host runtime check reject before worker creation."""

    from . import runtime_immutability

    original = runtime_immutability.assert_approved_host_runtime_immutable
    if bool(getattr(original, "__wlmcp_approved_host_fail_closed__", False)):
        return

    @wraps(original)
    def fail_closed(
        package_root: Any = None,
        *,
        inventory: Any = None,
        access_resolver: Callable[[Any], int] | None = None,
    ) -> dict[str, Any]:
        # access_resolver is an explicit test-only seam used to verify the lower-level
        # immutability algorithm without claiming that Approved Host itself is available.
        if access_resolver is not None:
            return original(
                package_root,
                inventory=inventory,
                access_resolver=access_resolver,
            )
        raise PermissionError(APPROVED_HOST_UNAVAILABLE_REASON)

    fail_closed.__wlmcp_approved_host_fail_closed__ = True  # type: ignore[attr-defined]
    runtime_immutability.assert_approved_host_runtime_immutable = fail_closed
