import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "secure-mcp-tunnel.ps1"
SETUP = ROOT / "setup-localmcp.ps1"


def _ps_literal(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _shell() -> str:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    return shell


def _run(command: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_shell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
        env=env,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell helper regression")
def test_doctor_json_is_structured_and_secret_redacted() -> None:
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(HELPER)}
$secretText = 'sk-test-secret-1234567890'
$secure = [Security.SecureString]::new()
foreach ($character in $secretText.ToCharArray()) {{ $secure.AppendChar($character) }}
$secure.MakeReadOnly()
$json = @{{
  result = 'fail'
  failed_checks = @('mcp_command_executable')
  next = ''
  checks = @(@{{
    id = 'mcp_command_executable'; status = 'FAIL'; summary = ('spawn failed ' + $secretText)
    why = 'stdio executable is required'; evidence = @('Authorization: Bearer ' + $secretText)
    next = @('fix command ' + $secretText)
  }})
}} | ConvertTo-Json -Depth 8
$report = ConvertFrom-TunnelDoctorJson -JsonText $json -Credential $secure
if ($null -eq $report) {{ throw 'report missing' }}
if ($report.FailedChecks[0] -ne 'mcp_command_executable') {{ throw 'failed checks lost' }}
$serialized = $report | ConvertTo-Json -Depth 8 -Compress
if ($serialized.Contains($secretText)) {{ throw 'secret leaked from structured report' }}
if (-not $serialized.Contains('[REDACTED]')) {{ throw 'redaction marker missing' }}
$class = Get-TunnelDoctorFailureClass -Report $report -Stdout '' -Stderr '' -ExitCode 2
if ($class -ne 'server_start_failed') {{ throw 'failure class mismatch: ' + $class }}
Show-TunnelDoctorDiagnostics -Doctor ([PSCustomObject]@{{ Succeeded=$false; ExitCode=2; Report=$report; FallbackText='' }})
$secure.Dispose()
'doctor-structured-ok'
"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "doctor-structured-ok" in output
    assert "失敗した確認項目" in output
    assert "sk-test-secret" not in output


@pytest.mark.skipif(os.name != "nt", reason="Windows tunnel-client candidate discovery")
def test_candidate_discovery_checks_desktop_downloads_shallowly(tmp_path: Path) -> None:
    user = tmp_path / "user"
    onedrive = tmp_path / "onedrive"
    candidate = onedrive / "Desktop" / "tunnel-client-v0.0.10-windows-amd64" / "tunnel-client.exe"
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(b"fake tunnel client")
    (user / "Desktop").mkdir(parents=True)
    (user / "Downloads").mkdir(parents=True)
    env = os.environ.copy()
    env["USERPROFILE"] = str(user)
    env["OneDrive"] = str(onedrive)
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(HELPER)}
$candidates = @(Get-TunnelClientCandidates -StateRoot {_ps_literal(tmp_path / 'state')} -ForbiddenRoots @())
$expected = [IO.Path]::GetFullPath({_ps_literal(candidate)})
if (-not ($candidates | Where-Object {{ $_.Path.Equals($expected, [StringComparison]::OrdinalIgnoreCase) }})) {{
    throw 'desktop candidate missing'
}}
'candidate-discovery-ok'
"""
    completed = _run(command, env=env)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "candidate-discovery-ok" in output


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 UTF-8 regression")
def test_setup_invoke_python_uses_utf8_even_with_isolated_mode() -> None:
    python = Path(shutil.which("python.exe") or shutil.which("python") or "")
    if not python.exists():
        pytest.skip("Python executable unavailable")
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(SETUP)} -FunctionsOnly
Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue
$output = @(Invoke-Python -PythonPath {_ps_literal(python)} -Arguments @('-I', '-B', '-c', "print('日本語-path-ok')"))
if (($output -join "`n") -notlike '*日本語-path-ok*') {{ throw 'UTF-8 output missing' }}
'isolated-utf8-ok'
"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "isolated-utf8-ok" in output


def test_profile_failure_message_does_not_claim_new_profile_was_modified() -> None:
    helper = HELPER.read_text(encoding="utf-8-sig")
    assert "Tunnel profile が不正または変更されています" not in helper
    assert "上の doctor 診断" in helper


@pytest.mark.skipif(os.name != "nt", reason="Windows profile matching diagnostics")
def test_generated_profile_matches_localmcp_command(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    config = tmp_path / "config.toml"
    config.write_text('workspace_root = "C:\\\\Users\\\\Public\\\\workspace"\n', encoding="utf-8")
    server = ROOT / "run-server.ps1"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(HELPER)}
$pidPath = {_ps_literal(tmp_path / 'state' / 'tunnel.pid')}
$healthPath = {_ps_literal(tmp_path / 'state' / 'tunnel.health')}
$content = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)} -PidFile $pidPath -HealthUrlFile $healthPath
[IO.File]::WriteAllText({_ps_literal(profile)}, $content, [Text.UTF8Encoding]::new($false))
$info = Get-TunnelProfileInfo -Path {_ps_literal(profile)} -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)}
$expectedServer = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath({_ps_literal(server)}))
$expectedConfig = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath({_ps_literal(config)}))
$expectedCommand = ConvertTo-TunnelYamlScalar -Value "powershell.exe -NoProfile -File $expectedServer -Config $expectedConfig"
if (-not $info.MatchesLocalMcp) {{
    throw ("profile mismatch`nEXPECTED=command: " + $expectedCommand + "`nCONTENT=`n" + $content)
}}
'profile-match-ok'
"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "profile-match-ok" in output


@pytest.mark.skipif(os.name != "nt", reason="Windows profile command binding")
def test_profile_command_binding_rejects_different_config(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    config = tmp_path / "config.toml"
    other_config = tmp_path / "other.toml"
    config.write_text('workspace_root = "C:\\\\Users\\\\Public\\\\workspace"\n', encoding="utf-8")
    other_config.write_text('workspace_root = "C:\\\\Users\\\\Public\\\\other"\n', encoding="utf-8")
    server = ROOT / "run-server.ps1"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(HELPER)}
$content = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)} -PidFile {_ps_literal(tmp_path / 'pid')} -HealthUrlFile {_ps_literal(tmp_path / 'health')}
[IO.File]::WriteAllText({_ps_literal(profile)}, $content, [Text.UTF8Encoding]::new($false))
$valid = Get-TunnelProfileInfo -Path {_ps_literal(profile)} -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)}
if (-not $valid.MatchesLocalMcp) {{ throw 'expected command was rejected' }}
$wrong = Get-TunnelProfileInfo -Path {_ps_literal(profile)} -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(other_config)}
if ($wrong.MatchesLocalMcp) {{ throw 'different config target was accepted' }}
'command-binding-ok'
"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "command-binding-ok" in output
