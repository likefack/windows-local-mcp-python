from __future__ import annotations

from pathlib import Path


def _installer_text() -> str:
    return (Path(__file__).resolve().parents[1] / "install-approved-host-authority.ps1").read_text(
        encoding="utf-8"
    )


def _security_block() -> str:
    return _installer_text().split(
        "# Protect every replacement boundary in the durable authority namespace.",
        maxsplit=1,
    )[1].split("if ($null -ne $ExistingService)", maxsplit=1)[0]


def test_authority_installer_protects_parent_state_and_completed_boundaries() -> None:
    block = _security_block()

    protect_parent = block.index(
        'Protect-AuthorityDirectory -Path $AuthorityBase -Label "authority parent"'
    )
    protect_state = block.index(
        'Protect-AuthorityDirectory -Path $AuthorityStateRoot -Label "authority state root"'
    )
    protect_completed = block.index(
        'Protect-AuthorityDirectory -Path $CompletedStateRoot -Label "authority completed root"'
    )
    setowner = block.index('$AuthorityBase /setowner "*S-1-5-18" /T')
    verify_tree = block.index("$AuthorityBase /verify /T")

    assert protect_parent < protect_state < protect_completed < setowner < verify_tree


def test_authority_installer_protection_helper_grants_before_removing_inheritance() -> None:
    script = _installer_text()
    helper = script.split("function Protect-AuthorityDirectory", maxsplit=1)[1].split(
        "Assert-Administrator", maxsplit=1
    )[0]

    grant = helper.index("$Path /grant:r")
    protect = helper.index("$Path /inheritance:r")

    assert grant < protect
    assert '"*S-1-5-18:(OI)(CI)F"' in helper
    assert '"*S-1-5-32-544:(OI)(CI)F"' in helper
    assert "RuntimeSid" not in helper
    assert "$Path /grant:r /T" not in helper
    assert "$Path /inheritance:r /T" not in helper


def test_authority_installer_does_not_reset_protected_state_boundaries_to_inherited_acls() -> None:
    script = _installer_text()

    assert '$CompletedStateRoot = Join-Path $AuthorityStateRoot "completed"' in script
    assert "/reset /T" not in _security_block()
    assert '$AuthorityBase /setowner "*S-1-5-18" /T' in _security_block()
    assert "$AuthorityBase /verify /T" in _security_block()


def test_authority_installer_does_not_continue_after_acl_errors() -> None:
    script = _installer_text()
    helper = script.split("function Protect-AuthorityDirectory", maxsplit=1)[1].split(
        "Assert-Administrator", maxsplit=1
    )[0]
    block = _security_block()
    icacls_lines = [
        line.strip()
        for line in (helper + block).splitlines()
        if "icacls.exe" in line
    ]

    assert len(icacls_lines) == 4
    assert all(" /C" not in line and " /c" not in line for line in icacls_lines)


def test_authority_installer_blocks_active_or_recovery_state_before_service_reinstall() -> None:
    script = _installer_text()
    active_decl = script.index('$ActiveState = Join-Path $AuthorityStateRoot "active.json"')
    recovery_decl = script.index('$RecoveryState = Join-Path $AuthorityStateRoot "recovery_required"')
    active_check = script.index("Test-Path -LiteralPath $ActiveState -PathType Leaf")
    recovery_check = script.index("Test-Path -LiteralPath $RecoveryState")
    existing_service = script.index("$ExistingService = Get-Service")

    assert active_decl < recovery_decl < active_check < existing_service
    assert recovery_decl < recovery_check < existing_service
    assert "Approved Host authority has active/recovery state." in script


def test_authority_service_sddl_keeps_change_config_for_system_and_admin_only() -> None:
    script = _installer_text()
    sddl_line = next(line for line in script.splitlines() if line.startswith("$ServiceSddl ="))

    assert "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" in sddl_line
    assert "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" in sddl_line
    assert "(A;;LC;;;$RuntimeSid)" in sddl_line
    assert "(A;;DCLC;;;$RuntimeSid)" not in sddl_line

    sdset = script.index('Invoke-Sc -Arguments @("sdset", $ServiceName, $ServiceSddl)')
    failure = script.index('Invoke-Sc -Arguments @("failure", $ServiceName')
    failureflag = script.index('Invoke-Sc -Arguments @("failureflag", $ServiceName, "1")')
    start = script.index("Start-Service -Name $ServiceName")

    assert sdset < failure < failureflag < start
