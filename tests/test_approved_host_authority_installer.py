from __future__ import annotations

from pathlib import Path


def _installer_text() -> str:
    return (Path(__file__).resolve().parents[1] / "install-approved-host-authority.ps1").read_text(
        encoding="utf-8"
    )


def _security_block() -> str:
    return _installer_text().split(
        "# Build one protected ACL boundary for the complete WLMCP ProgramData authority namespace",
        maxsplit=1,
    )[1].split("if ($null -ne $ExistingService)", maxsplit=1)[0]


def test_authority_installer_builds_protected_root_before_recursive_owner_change() -> None:
    block = _security_block()

    root_grant = block.index("$AuthorityBase /grant:r")
    protect_root = block.index("$AuthorityBase /inheritance:r")
    reset_descendants = block.index("$AuthorityChildren /reset /T")
    setowner = block.index('$AuthorityBase /setowner "*S-1-5-18" /T')
    verify_tree = block.index("$AuthorityBase /verify /T")

    assert root_grant < protect_root < reset_descendants < setowner < verify_tree


def test_authority_installer_root_acl_is_exact_and_not_recursively_stripped() -> None:
    block = _security_block()
    lines = [line.strip() for line in block.splitlines()]
    grant_line_index = next(i for i, line in enumerate(lines) if "$AuthorityBase /grant:r" in line)
    inheritance_line = next(line for line in lines if "$AuthorityBase /inheritance:r" in line)
    grant_window = "\n".join(lines[grant_line_index : grant_line_index + 4])

    assert " /T" not in lines[grant_line_index]
    assert " /T" not in inheritance_line
    assert '"*S-1-5-18:(OI)(CI)F"' in grant_window
    assert '"*S-1-5-32-544:(OI)(CI)F"' in grant_window
    assert "RuntimeSid" not in grant_window


def test_authority_installer_descendants_inherit_from_protected_root() -> None:
    block = _security_block()

    assert '$AuthorityChildren = Join-Path $AuthorityBase "*"' in block
    assert "$AuthorityChildren /reset /T" in block
    assert '$AuthorityBase /setowner "*S-1-5-18" /T' in block
    assert "$AuthorityBase /verify /T" in block


def test_authority_installer_does_not_continue_after_acl_errors() -> None:
    block = _security_block()
    icacls_lines = [line.strip() for line in block.splitlines() if "icacls.exe" in line]

    assert len(icacls_lines) == 5
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
