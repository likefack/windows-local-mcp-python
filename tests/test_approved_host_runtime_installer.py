from __future__ import annotations

from pathlib import Path


def _installer_text() -> str:
    return (Path(__file__).resolve().parents[1] / "install-approved-host-runtime.ps1").read_text(
        encoding="utf-8"
    )


def test_runtime_installer_grants_explicit_access_before_stripping_inheritance() -> None:
    script = _installer_text()
    security_block = script.split(
        "# Secure the complete staged runtime before it becomes the active installation.",
        maxsplit=1,
    )[1].split("if ($Replace -and (Test-Path -LiteralPath $InstallRoot))", maxsplit=1)[0]

    setowner = security_block.index('/setowner "*S-1-5-32-544"')
    grant = security_block.index('/grant:r "*S-1-5-18:(OI)(CI)F"')
    remove_inheritance = security_block.index("/inheritance:r")

    assert setowner < grant < remove_inheritance


def test_runtime_installer_does_not_continue_after_acl_errors() -> None:
    script = _installer_text()
    security_block = script.split(
        "# Secure the complete staged runtime before it becomes the active installation.",
        maxsplit=1,
    )[1].split("if ($Replace -and (Test-Path -LiteralPath $InstallRoot))", maxsplit=1)[0]

    icacls_lines = [line.strip() for line in security_block.splitlines() if "icacls.exe" in line]

    assert len(icacls_lines) == 3
    assert all(" /C" not in line and " /c" not in line for line in icacls_lines)
