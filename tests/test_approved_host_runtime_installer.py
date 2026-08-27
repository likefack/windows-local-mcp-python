from __future__ import annotations

from pathlib import Path


def _installer_text() -> str:
    return (Path(__file__).resolve().parents[1] / "install-approved-host-runtime.ps1").read_text(
        encoding="utf-8"
    )


def _security_block() -> str:
    return _installer_text().split(
        "# Build one protected ACL boundary at the install root",
        maxsplit=1,
    )[1].split("if ($Replace -and (Test-Path -LiteralPath $InstallRoot))", maxsplit=1)[0]


def _replace_block() -> str:
    return _installer_text().split(
        "if ($Replace -and (Test-Path -LiteralPath $InstallRoot))",
        maxsplit=1,
    )[1].split("Move-Item -LiteralPath $StagingRoot -Destination $InstallRoot", maxsplit=1)[0]


def test_runtime_installer_builds_protected_root_before_resetting_descendants() -> None:
    security_block = _security_block()

    setowner = security_block.index('/setowner "*S-1-5-32-544"')
    root_grant = security_block.index('/grant:r "*S-1-5-18:(OI)(CI)F"')
    protect_root = security_block.index("$StagingRoot /inheritance:r")
    reset_descendants = security_block.index("$StagingChildren /reset /T")
    verify_tree = security_block.index("$StagingRoot /verify /T")

    assert setowner < root_grant < protect_root < reset_descendants < verify_tree


def test_runtime_installer_root_acl_is_not_recursively_stripped() -> None:
    security_block = _security_block()
    lines = [line.strip() for line in security_block.splitlines()]
    grant_line = next(line for line in lines if "icacls.exe $StagingRoot /grant:r" in line)
    inheritance_line = next(
        line for line in lines if "icacls.exe $StagingRoot /inheritance:r" in line
    )

    assert " /T" not in grant_line
    assert " /T" not in inheritance_line
    assert "*${runtimeSid}:(OI)(CI)RX" in grant_line


def test_runtime_installer_descendants_are_reset_to_protected_root_acl() -> None:
    security_block = _security_block()

    assert '$StagingChildren = Join-Path $StagingRoot "*"' in security_block
    assert "icacls.exe $StagingChildren /reset /T" in security_block


def test_runtime_installer_does_not_continue_after_acl_errors() -> None:
    security_block = _security_block()
    icacls_lines = [line.strip() for line in security_block.splitlines() if "icacls.exe" in line]

    assert len(icacls_lines) == 5
    assert all(" /C" not in line and " /c" not in line for line in icacls_lines)


def test_runtime_installer_reclaims_legacy_runtime_before_recursive_delete() -> None:
    replace_block = _replace_block()

    takeown_path = replace_block.index(
        '$TakeownExe = Join-Path $env:SystemRoot "System32\\takeown.exe"'
    )
    takeown = replace_block.index("& $TakeownExe /F $InstallRoot /A /R /D Y /SKIPSL")
    reset_dacl = replace_block.index("icacls.exe $InstallRoot /reset /T")
    admin_grant = replace_block.index(
        'icacls.exe $InstallRoot /grant:r "*S-1-5-32-544:(OI)(CI)F" /T'
    )
    remove_tree = replace_block.index("Remove-Item -LiteralPath $InstallRoot -Recurse -Force")

    assert takeown_path < takeown < reset_dacl < admin_grant < remove_tree
    assert 'icacls.exe $InstallRoot /setowner "*S-1-5-32-544" /T' not in replace_block
    assert " /C" not in replace_block and " /c" not in replace_block
    assert "Reclaiming ownership of the previous Approved Host runtime failed." in replace_block
    assert "Resetting the previous Approved Host runtime DACL failed." in replace_block
    assert "Reclaiming Administrators access to the previous Approved Host runtime failed." in (
        replace_block
    )


def test_runtime_installer_legacy_recovery_replaces_dacl_before_admin_grant() -> None:
    replace_block = _replace_block()

    reset_dacl = replace_block.index("icacls.exe $InstallRoot /reset /T")
    admin_grant = replace_block.index(
        'icacls.exe $InstallRoot /grant:r "*S-1-5-32-544:(OI)(CI)F" /T'
    )

    assert reset_dacl < admin_grant
    assert "existing deny ACE still wins access evaluation" in replace_block


def test_runtime_installer_takeown_recovery_is_noninteractive_and_does_not_follow_links() -> None:
    replace_block = _replace_block()
    takeown_line = next(
        line.strip() for line in replace_block.splitlines() if "& $TakeownExe /F $InstallRoot" in line
    )

    assert " /A" in takeown_line
    assert " /R" in takeown_line
    assert " /D Y" in takeown_line
    assert " /SKIPSL" in takeown_line
    assert "Test-Path -LiteralPath $TakeownExe -PathType Leaf" in replace_block


def test_runtime_installer_replace_gate_checks_recovery_state_without_service_dependency() -> None:
    script = _installer_text()
    replace_gate = script.split("if ($Replace) {", maxsplit=1)[1].split(
        "if (Test-Path -LiteralPath $StagingRoot)", maxsplit=1
    )[0]

    assert '$AuthorityRecoveryState = Join-Path $AuthorityStateRoot "recovery_required"' in script
    assert "Test-Path -LiteralPath $AuthorityActiveState -PathType Leaf" in replace_gate
    assert "Test-Path -LiteralPath $AuthorityRecoveryState" in replace_gate
    recovery_check = replace_gate.index("Test-Path -LiteralPath $AuthorityRecoveryState")
    service_check = replace_gate.index("if ($null -ne $existingAuthorityService)")
    assert recovery_check < service_check
