"""Exercise the updater transaction with filesystem fixtures and mocked Windows services.

No test requests UAC, changes an ACL, launches a GUI, or touches the installed runtime.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "update-localmcp.ps1"
POWERSHELL = shutil.which("powershell.exe")
pytestmark = pytest.mark.skipif(os.name != "nt" or not POWERSHELL, reason="Windows PowerShell 5.1")


def ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_ps(tmp_path: Path, code: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "test.ps1"
    path.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n"
        f". {ps_literal(SCRIPT)}\n" + code,
        encoding="utf-8-sig",
    )
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)],
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


def test_update_script_parses_in_windows_powershell_and_has_bom(tmp_path: Path) -> None:
    assert SCRIPT.read_bytes().startswith(b"\xef\xbb\xbf")
    result = run_ps(tmp_path, f"""
$tokens = $null; $errors = $null
[Management.Automation.Language.Parser]::ParseFile({ps_literal(SCRIPT)}, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) {{ throw 'parse failed' }}
""")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure", ["none", "staged", "switched", "build", "idle"])
def test_update_transaction_preserves_previous_runtime(tmp_path: Path, failure: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "scripts").mkdir()
    (source / "scripts/runtime_update_support.py").write_text("# fixture\n", encoding="utf-8")
    (source / "install-approved-host-runtime.ps1").write_text(
        "param($BasePython, $InstallRoot, $RuntimeUser)\n"
        + ("throw 'build failed'\n" if failure == "build" else "")
        + "New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'runtime/Scripts') -Force | Out-Null\n"
        "Set-Content -LiteralPath (Join-Path $InstallRoot 'runtime/Scripts/python.exe') -Value 'new'\n"
        "Set-Content -LiteralPath (Join-Path $InstallRoot 'run-server.ps1') -Value 'new'\n",
        encoding="utf-8-sig",
    )
    install = tmp_path / "installed"
    (install / "runtime/Scripts").mkdir(parents=True)
    (install / "runtime/Scripts/python.exe").write_text("old", encoding="utf-8")
    (install / "run-server.ps1").write_text("old", encoding="utf-8")
    (tmp_path / "config.toml").write_text("# fixture", encoding="utf-8")
    (tmp_path / "constraints.txt").write_text("# fixture", encoding="utf-8")
    # Mock only OS effects and probes; real Move-Item and rollback paths run in tmp_path.
    result = run_ps(tmp_path, f"""
$env:ProgramFiles = {ps_literal(tmp_path)}
function Test-UpdateAdministrator {{ return $true }}
function Assert-UpdateSnapshot {{ param($Root, $ManifestHash) }}
function Assert-UpdateAuthorityIdle {{ if ({ps_literal(failure)} -eq 'idle') {{ throw 'busy' }} }}
function Invoke-UpdatePython {{ param($Python, $Helper, $Arguments) }}
function Start-Transcript {{ }}
function Stop-Transcript {{ }}
function icacls.exe {{ $global:LASTEXITCODE = 0 }}
function Get-CimInstance {{ return [PSCustomObject]@{{ State='Running'; PathName={ps_literal(install / 'runtime/Scripts/python.exe')} }} }}
function Stop-Service {{ $script:stopped = $true }}
function Start-Service {{ $script:stopped = $false }}
function Get-Service {{
    $service = [PSCustomObject]@{{ Status = $(if ($script:stopped) {{ 'Stopped' }} else {{ 'Running' }}) }}
    $service | Add-Member ScriptMethod WaitForStatus {{ param($status, $timeout) }}
    return $service
}}
function Wait-UpdateDecision {{ param($Plan, $Phase); if ($Phase -eq {ps_literal(failure)}) {{ throw 'verification failed' }} }}
$plan = [PSCustomObject]@{{
    task_root={ps_literal(tmp_path)}; source={ps_literal(source)}; install_root={ps_literal(install)}
    ready_root={ps_literal(tmp_path / 'ready')}; backup_root={ps_literal(tmp_path / 'backup')}
    failed_root={ps_literal(tmp_path / 'failed')}; protected_source={ps_literal(tmp_path / 'protected-source')}
    config={ps_literal(tmp_path / 'config.toml')}; config_sha256=(Get-UpdateHash {ps_literal(tmp_path / 'config.toml')})
    old_server_sha256=(Get-UpdateHash {ps_literal(install / 'run-server.ps1')})
    constraints_sha256=(Get-UpdateHash {ps_literal(tmp_path / 'constraints.txt')})
    user_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    runtime_user='fixture'; base_python='fixture'; manifest_sha256='fixture'; offline_arguments=@('offline')
}}
try {{ Invoke-ElevatedUpdate $plan }} catch {{ }}
if (-not (Test-Path {ps_literal(tmp_path / 'status.json')})) {{ throw 'No transaction status' }}
""")
    assert result.returncode == 0, result.stderr
    state = json.loads((tmp_path / "status.json").read_text(encoding="utf-8"))["status"]
    current = (install / "run-server.ps1").read_text(encoding="utf-8").strip()
    if failure == "none":
        assert state == "installed"
        assert current == "new"
        assert (tmp_path / "backup/run-server.ps1").read_text(encoding="utf-8") == "old"
    elif failure == "switched":
        assert state == "rolled_back"
        assert current == "old"
        assert (tmp_path / "failed/run-server.ps1").read_text(encoding="utf-8").strip() == "new"
    else:
        assert state == "failed_before_switch"
        assert current == "old"
        assert not (tmp_path / "backup").exists()


def test_update_path_rejects_program_files_itself_and_nested_or_outside_paths(tmp_path: Path) -> None:
    result = run_ps(tmp_path, f"""
$env:ProgramFiles = {ps_literal(tmp_path)}
$accepted = Assert-UpdatePath {ps_literal(tmp_path / 'runtime')}
foreach ($bad in @({ps_literal(tmp_path)}, {ps_literal(tmp_path / 'runtime/child')}, {ps_literal(tmp_path.parent / 'outside')})) {{
    $rejected = $false
    try {{ Assert-UpdatePath $bad | Out-Null }} catch {{ $rejected = $true }}
    if (-not $rejected) {{ throw 'unsafe path accepted' }}
}}
""")
    assert result.returncode == 0, result.stderr


def test_server_binding_rejects_concurrent_edits_and_preserves_other_fields(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"server_script_sha256": "old", "credential_target": "preserve", "enabled": True}), encoding="utf-8")
    server = tmp_path / "run-server.ps1"
    server.write_text("# new script", encoding="utf-8")
    result = run_ps(tmp_path, f"""
. {ps_literal(ROOT / 'secure-mcp-tunnel.ps1')}
$statePath = {ps_literal(state_path)}
$state = Get-Content -Raw -Encoding UTF8 $statePath | ConvertFrom-Json
$before = Get-UpdateHash $statePath
$rejected = $false
try {{ Update-ServerScriptBinding $state $statePath 'wrong-digest' {ps_literal(server)} }} catch {{ $rejected = $true }}
if (-not $rejected -or (Get-UpdateHash $statePath) -ne $before) {{ throw 'CAS failed' }}
$changed = Update-ServerScriptBinding $state $statePath $before {ps_literal(server)}
if (-not (Test-Path $changed.BackupPath)) {{ throw 'backup missing' }}
$readback = Get-Content -Raw -Encoding UTF8 $statePath | ConvertFrom-Json
if ($readback.credential_target -ne 'preserve' -or $readback.enabled -ne $true) {{ throw 'other fields changed' }}
if ($readback.server_script_sha256 -ne (Get-UpdateHash {ps_literal(server)})) {{ throw 'binding mismatch' }}
""")
    assert result.returncode == 0, result.stderr
