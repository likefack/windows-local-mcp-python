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
