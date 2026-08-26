from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = (
    "install-approved-host-runtime.ps1",
    "verify-approved-host-runtime.ps1",
    "run-server.ps1",
    "run-approvals.ps1",
)


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher validation is Windows-only")
@pytest.mark.parametrize("script_name", _SCRIPTS)
def test_powershell_script_parses(script_name: str) -> None:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell executable is unavailable")
    path = _REPOSITORY_ROOT / script_name
    command = (
        "$tokens=$null; $errors=$null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile({str(path)!r}, "
        "[ref]$tokens, [ref]$errors) | Out-Null; "
        "if ($errors.Count -gt 0) { "
        "$errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_approved_host_installer_requires_program_files_base_and_install_root() -> None:
    script = (_REPOSITORY_ROOT / "install-approved-host-runtime.ps1").read_text(
        encoding="utf-8"
    )

    assert 'Assert-UnderProgramFiles -Path $InstallRoot -Label "InstallRoot"' in script
    assert 'Assert-UnderProgramFiles -Path $BasePython -Label "BasePython"' in script
    assert 'Assert-UnderProgramFiles -Path $BasePrefix -Label "sys.base_prefix"' in script
    assert '-c "import sys; print(sys.base_prefix)"' in script
    assert '"*${runtimeSid}:(OI)(CI)RX"' in script
    assert '"*S-1-5-18:(OI)(CI)F"' in script
    assert '"*S-1-5-32-544:(OI)(CI)F"' in script
