from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _windows_powershell_51() -> Path:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        pytest.skip("SystemRoot is unavailable")
    shell = (
        Path(system_root)
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    if not shell.is_file():
        pytest.skip("Windows PowerShell 5.1 is unavailable")
    return shell


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 regression is Windows-only")
def test_invoke_python_preserves_complete_stderr_and_restores_encoding() -> None:
    shell = _windows_powershell_51()
    python = Path(sys.executable)
    setup = _REPOSITORY_ROOT / "setup-localmcp.ps1"
    child = (
        "import sys; "
        "print('stdout-before'); "
        "print('Traceback (most recent call last):', file=sys.stderr); "
        "print('DETAIL_日本語', file=sys.stderr); "
        "sys.exit(7)"
    )
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(setup)} -FunctionsOnly
$env:PYTHONIOENCODING = 'cp1252'
try {{
    Invoke-Python -PythonPath {_ps_literal(python)} -Arguments @('-I', '-B', '-c', {_ps_literal(child)}) | Out-Null
    throw 'Invoke-Python unexpectedly succeeded'
}} catch {{
    if ($_.Exception.Message -eq 'Invoke-Python unexpectedly succeeded') {{ throw }}
    if ($_.Exception.Message -notlike '*Traceback (most recent call last):*') {{
        throw 'first stderr line missing: ' + $_.Exception.Message
    }}
    if ($_.Exception.Message -notlike '*DETAIL_日本語*') {{
        throw 'later stderr line missing: ' + $_.Exception.Message
    }}
}}
if ($env:PYTHONIOENCODING -ne 'cp1252') {{
    throw 'PYTHONIOENCODING was not restored'
}}
'diagnostics-ok'
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "diagnostics-ok" in output


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 regression is Windows-only")
def test_invoke_python_uses_utf8_for_non_ascii_stdout() -> None:
    shell = _windows_powershell_51()
    python = Path(sys.executable)
    setup = _REPOSITORY_ROOT / "setup-localmcp.ps1"
    child = "print('日本語-path-ok')"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(setup)} -FunctionsOnly
Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue
$output = @(Invoke-Python -PythonPath {_ps_literal(python)} -Arguments @('-I', '-B', '-c', {_ps_literal(child)}))
if (($output -join "`n") -notlike '*日本語-path-ok*') {{
    throw 'non-ASCII stdout was not preserved'
}}
if (Test-Path Env:PYTHONIOENCODING) {{
    throw 'PYTHONIOENCODING should remain unset after invocation'
}}
'utf8-ok'
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "utf8-ok" in output
