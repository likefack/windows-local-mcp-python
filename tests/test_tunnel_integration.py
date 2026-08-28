from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_HELPER = _REPOSITORY_ROOT / "secure-mcp-tunnel.ps1"


def _powershell() -> str:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell executable is unavailable")
    return shell


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _run_powershell(script: str, *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="Credential Manager and Tunnel helpers are Windows-only")
def test_secure_mcp_tunnel_helper_parses() -> None:
    command = (
        "$tokens=$null; $errors=$null; "
        f"[System.Management.Automation.Language.Parser]::ParseFile({_ps_literal(_HELPER)}, "
        "[ref]$tokens, [ref]$errors) | Out-Null; "
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
    )
    completed = _run_powershell(command)
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_tunnel_secret_storage_and_launch_contract_is_explicit() -> None:
    helper = _HELPER.read_text(encoding="utf-8")
    setup = (_REPOSITORY_ROOT / "setup-localmcp.ps1").read_text(encoding="utf-8-sig")
    runner = (_REPOSITORY_ROOT / "run-localmcp.ps1").read_text(encoding="utf-8-sig")

    assert "CredWrite" in helper
    assert "CredRead" in helper
    assert "CredDelete" in helper
    assert "CRED_PERSIST_LOCAL_MACHINE" in helper
    assert "api_key: env:WLMCP_TUNNEL_RUNTIME_API_KEY" in helper
    assert "RedirectStandardOutput = $true" in helper
    assert "RedirectStandardError = $true" in helper
    assert "--api-key" not in helper
    assert "-ApiKey" not in helper
    assert "Read-Host \"Runtime API Key（入力内容は表示されません）\" -AsSecureString" in setup
    assert "Test-TunnelProfileBinding" in runner
    assert "Invoke-TunnelClientDoctor" in runner
    assert "Start-TunnelClientProcess" in runner
    assert "run-server.ps1" in runner


@pytest.mark.skipif(os.name != "nt", reason="Credential Manager is Windows-only")
def test_credential_manager_roundtrip_rotation_removal_does_not_print_secret() -> None:
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$target = 'WindowsLocalMCP/Test/' + [Guid]::NewGuid().ToString('N')
$firstText = 'rotation-' + [Guid]::NewGuid().ToString('N')
$secondText = 'rotation-' + [Guid]::NewGuid().ToString('N')
$first = ConvertTo-SecureString -String $firstText -AsPlainText -Force
$second = ConvertTo-SecureString -String $secondText -AsPlainText -Force
try {{
    Set-TunnelCredential -Target $target -Secret $first
    if ((Get-TunnelCredential -Target $target) -ne $firstText) {{ throw 'first credential mismatch' }}
    Set-TunnelCredential -Target $target -Secret $second
    if ((Get-TunnelCredential -Target $target) -ne $secondText) {{ throw 'rotated credential mismatch' }}
    if (-not (Remove-TunnelCredential -Target $target)) {{ throw 'credential was not removed' }}
    if ($null -ne (Get-TunnelCredential -Target $target)) {{ throw 'credential remained' }}
    'credential-roundtrip-ok'
}} finally {{
    $null = Remove-TunnelCredential -Target $target
    $first.Dispose()
    $second.Dispose()
}}
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "credential-roundtrip-ok" in output
    assert "rotation-" not in output


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_profile_generation_and_secret_redaction_with_spaces() -> None:
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
    $marker = 'zzsecret-' + [Guid]::NewGuid().ToString('N')
$server = 'C:\\Program Files\\Windows Local MCP\\run-server.ps1'
$config = 'C:\\Users\\Public\\Local MCP\\config.toml'
$pidFile = 'C:\\Users\\22905\\AppData\\Local\\WindowsLocalMCP\\tunnel-state\\space.pid'
$healthFile = 'C:\\Users\\22905\\AppData\\Local\\WindowsLocalMCP\\tunnel-state\\space.health-url'
$profile = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript $server -ConfigPath $config -PidFile $pidFile -HealthUrlFile $healthFile
if ($profile -match [regex]::Escape($marker)) {{ throw 'marker leaked into profile' }}
if ($profile -notmatch 'api_key: env:WLMCP_TUNNEL_RUNTIME_API_KEY') {{ throw 'safe API key reference missing' }}
if ($profile -notmatch 'channel: main') {{ throw 'main channel missing' }}
if ($profile -notmatch 'powershell.exe -NoProfile -File') {{ throw 'canonical command missing' }}
$secure = ConvertTo-SecureString -String $marker -AsPlainText -Force
$prepared = New-TunnelProcessStartInfo -ClientPath $env:ComSpec -Arguments @('run', '--profile-file', 'C:\\Program Files\\Windows Local MCP\\profile.yaml') -Credential $secure
if ($prepared.StartInfo.Arguments -match [regex]::Escape($marker)) {{ throw 'secret leaked into argv' }}
if ($prepared.StartInfo.EnvironmentVariables['WLMCP_TUNNEL_RUNTIME_API_KEY'] -ne $marker) {{ throw 'child environment missing secret' }}
$class = Get-TunnelFailureClass -Stdout '' -Stderr $marker -ExitCode 1
if ($class -ne 'tunnel_client_failed') {{ throw 'unexpected failure classification' }}
$secure.Dispose()
'profile-secret-regression-ok'
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "profile-secret-regression-ok" in output
    assert "zzsecret-" not in output


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_tunnel_id_validation_and_profile_binding_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="wlmcp-tunnel-state-") as temporary_root:
        root = Path(temporary_root) / "tunnel state with spaces"
        _test_tunnel_id_validation_and_profile_binding(root)


def _test_tunnel_id_validation_and_profile_binding(root: Path) -> None:
    profile_root = root / "profiles"
    state_root = root / "state"
    profile_path = profile_root / "localmcp.yaml"
    config_path = root / "config.toml"
    server_path = _REPOSITORY_ROOT / "run-server.ps1"
    client_path = Path(os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe"))
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
if (-not (Test-TunnelId 'tunnel_0123456789abcdef0123456789abcdef')) {{ throw 'valid tunnel id rejected' }}
foreach ($bad in @('', 'tunnel_0123', 'tunnel_0123456789abcdef0123456789ABCDEG', 'tunnel_0123456789abcdef0123456789abcdefX')) {{
    if (Test-TunnelId $bad) {{ throw 'invalid tunnel id accepted' }}
}}
New-Item -ItemType Directory -Path {_ps_literal(profile_root)}, {_ps_literal(state_root)} -Force | Out-Null
[IO.File]::WriteAllText({_ps_literal(config_path)}, 'workspace_root = "C:\\Users\\Public\\workspace"`r`ndata_dir = "C:\\Users\\Public\\data"`r`n', [Text.UTF8Encoding]::new($false))
$pidFile = Join-Path {_ps_literal(state_root)} 'tunnel.pid'
$healthFile = Join-Path {_ps_literal(state_root)} 'tunnel.health-url'
$profileText = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server_path)} -ConfigPath {_ps_literal(config_path)} -PidFile $pidFile -HealthUrlFile $healthFile
[IO.File]::WriteAllText({_ps_literal(profile_path)}, $profileText, [Text.UTF8Encoding]::new($false))
$state = [PSCustomObject][ordered]@{{
    version = 1; enabled = $true; config_path = [IO.Path]::GetFullPath({_ps_literal(config_path)})
    profile_path = [IO.Path]::GetFullPath({_ps_literal(profile_path)}); profile_sha256 = Get-TunnelSha256 -Path {_ps_literal(profile_path)}
    profile_scope = 'managed'; tunnel_id = 'tunnel_0123456789abcdef0123456789abcdef'
    tunnel_client_path = [IO.Path]::GetFullPath({_ps_literal(client_path)}); tunnel_client_sha256 = Get-TunnelSha256 -Path {_ps_literal(client_path)}
    pid_file = [IO.Path]::GetFullPath($pidFile); health_url_file = [IO.Path]::GetFullPath($healthFile)
    credential_mode = 'credential_manager'; credential_target = Get-TunnelCredentialTarget -ConfigPath {_ps_literal(config_path)}
}}
$valid = Test-TunnelProfileBinding -State $state -ConfigPath {_ps_literal(config_path)} -ServerScript {_ps_literal(server_path)} -ProfileRoot {_ps_literal(profile_root)} -StateRoot {_ps_literal(state_root)} -ForbiddenRoots @({_ps_literal(_REPOSITORY_ROOT)})
if (-not $valid.Valid) {{ throw 'valid binding rejected: ' + $valid.ReasonCode }}
$state.profile_sha256 = ('0' * 64)
$invalid = Test-TunnelProfileBinding -State $state -ConfigPath {_ps_literal(config_path)} -ServerScript {_ps_literal(server_path)} -ProfileRoot {_ps_literal(profile_root)} -StateRoot {_ps_literal(state_root)} -ForbiddenRoots @({_ps_literal(_REPOSITORY_ROOT)})
if ($invalid.Valid -or $invalid.ReasonCode -ne 'profile_changed') {{ throw 'changed profile was accepted' }}
'binding-validation-ok'
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "binding-validation-ok" in output


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_existing_profile_candidate_is_detected_without_copying_or_literal_secret() -> None:
    with tempfile.TemporaryDirectory(prefix="wlmcp-tunnel-profile-") as temporary_root:
        _test_existing_profile_candidate(Path(temporary_root))


def _test_existing_profile_candidate(tmp_path: Path) -> None:
    profile_path = tmp_path / "existing.yaml"
    config_path = tmp_path / "config.toml"
    server_path = _REPOSITORY_ROOT / "run-server.ps1"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$profile = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server_path)} -ConfigPath {_ps_literal(config_path)} -PidFile 'C:\\Users\\22905\\AppData\\Local\\WindowsLocalMCP\\external.pid' -HealthUrlFile 'C:\\Users\\22905\\AppData\\Local\\WindowsLocalMCP\\external.health-url'
$profile = $profile.Replace('env:WLMCP_TUNNEL_RUNTIME_API_KEY', 'env:CONTROL_PLANE_API_KEY')
[IO.File]::WriteAllText({_ps_literal(config_path)}, 'config', [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText({_ps_literal(profile_path)}, $profile, [Text.UTF8Encoding]::new($false))
$old = $env:TUNNEL_CLIENT_PROFILE_FILE
$env:TUNNEL_CLIENT_PROFILE_FILE = {_ps_literal(profile_path)}
try {{
    $candidates = @(Find-TunnelProfileCandidates -StateRoot {_ps_literal(tmp_path)} -ServerScript {_ps_literal(server_path)} -ConfigPath {_ps_literal(config_path)} -ForbiddenRoots @({_ps_literal(_REPOSITORY_ROOT)}))
    if ($candidates.Count -ne 1) {{ throw 'existing profile was not detected' }}
    if ($candidates[0].ApiKeyMode -ne 'environment-reference') {{ throw 'profile reference was not classified' }}
    if ($candidates[0].ApiKeyReference -ne 'env:CONTROL_PLANE_API_KEY') {{ throw 'profile reference changed' }}
    'existing-profile-detected'
}} finally {{
    $env:TUNNEL_CLIENT_PROFILE_FILE = $old
}}
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "existing-profile-detected" in output
