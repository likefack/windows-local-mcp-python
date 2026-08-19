from __future__ import annotations

import pytest

from windows_local_mcp.windows_wfp import WfpGuardError, WindowsWfpApi


def test_local_user_resolution_accepts_case_insensitive_local_computer_name() -> None:
    WindowsWfpApi._verify_local_user_resolution(
        account_name="CodexSandboxOffline",
        resolved_domain="THIS-PC",
        local_computer_name="this-pc",
        sid_name_use=1,
    )


@pytest.mark.parametrize(
    ("resolved_domain", "sid_name_use", "message"),
    [
        ("TRUSTED-DOMAIN", 1, "outside this computer"),
        ("THIS-PC", 2, "SID_NAME_USE=2"),
        ("THIS-PC", 9, "SID_NAME_USE=9"),
        ("", 1, "outside this computer"),
    ],
)
def test_local_user_resolution_rejects_wrong_domain_or_sid_type(
    resolved_domain: str, sid_name_use: int, message: str
) -> None:
    with pytest.raises(WfpGuardError, match=message):
        WindowsWfpApi._verify_local_user_resolution(
            account_name="CodexSandboxOffline",
            resolved_domain=resolved_domain,
            local_computer_name="THIS-PC",
            sid_name_use=sid_name_use,
        )
