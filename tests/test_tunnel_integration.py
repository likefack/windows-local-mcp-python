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


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_tunnel_server_runtime_defaults_to_development_and_rejects_untrusted_host_path() -> None:
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$development = Resolve-TunnelServerRuntime -ScriptRoot {_ps_literal(_REPOSITORY_ROOT)} -State $null
if (-not $development.Valid -or $development.Kind -ne 'development') {{ throw 'development runtime was not resolved' }}
if (-not $development.ServerScript.EndsWith('run-server.ps1')) {{ throw 'development server path is invalid' }}
$untrusted = [PSCustomObject]@{{
    server_runtime_kind = 'approved_host'
    server_script_path = {_ps_literal(_REPOSITORY_ROOT / 'run-server.ps1')}
    server_script_sha256 = ''
}}
$rejected = Resolve-TunnelServerRuntime -ScriptRoot {_ps_literal(_REPOSITORY_ROOT)} -State $untrusted
if ($rejected.Valid -or $rejected.Kind -ne 'approved_host') {{ throw 'mutable approved-host runtime was accepted' }}
'server-runtime-binding-ok'
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "server-runtime-binding-ok" in output


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_doctor_failure_classification_uses_failed_checks_without_leaking_output() -> None:
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$marker = 'diagnostic-secret-' + [Guid]::NewGuid().ToString('N')

# profile-file という語が案内に含まれていても、構造化された失敗 check を優先します。
$authText = "CHECK profile_load pass profile file: C:/safe/profile.yaml`nRESULT fail`nFAILED_CHECKS control_plane_api_key`nNEXT tunnel-client run --profile-file C:/safe/profile.yaml`n$marker"
$auth = Get-TunnelFailureDetail -Stdout $authText -Stderr '' -ExitCode 2
if ($auth.FailureClass -ne 'auth_failed' -or $auth.FailureCode -ne 'doctor_control_plane_api_key') {{ throw 'API key check was misclassified' }}
if (@($auth.FailedChecks).Count -ne 1 -or $auth.FailedChecks[0] -ne 'control_plane_api_key') {{ throw 'failed check was not preserved' }}
if (($auth | ConvertTo-Json -Compress) -match [regex]::Escape($marker)) {{ throw 'raw doctor output leaked into diagnostic result' }}

$cases = @(
    @('FAILED_CHECKS config_source', 'profile_invalid', 'doctor_config_source'),
    @('FAILED_CHECKS profile_load', 'profile_invalid', 'doctor_profile_load'),
    @('FAILED_CHECKS tunnel_id', 'tunnel_id_invalid', 'doctor_tunnel_id'),
    @('FAILED_CHECKS mcp_command_executable', 'server_start_failed', 'doctor_mcp_command_executable'),
    @('FAILED_CHECKS mcp_server_reachable', 'server_start_failed', 'doctor_mcp_server_reachable'),
    @('FAILED_CHECKS health_listener', 'health_listener_failed', 'doctor_health_listener'),
    @('FAILED_CHECKS oauth_metadata', 'oauth_metadata_failed', 'doctor_oauth_metadata'),
    @('FAILED_CHECKS control_plane_route', 'control_plane_failed', 'doctor_control_plane'),
    @('FAILED_CHECKS future_check', 'tunnel_client_failed', 'doctor_reported_checks')
)
foreach ($case in $cases) {{
    $detail = Get-TunnelFailureDetail -Stdout $case[0] -Stderr '' -ExitCode 2
    if ($detail.FailureClass -ne $case[1] -or $detail.FailureCode -ne $case[2]) {{
        throw "unexpected classification for $($case[0]): $($detail.FailureClass)/$($detail.FailureCode)"
    }}
}}

$parse = Get-TunnelFailureDetail -Stdout '' -Stderr 'parse config file C:/safe/profile.yaml: unsupported config_version 2' -ExitCode 1
if ($parse.FailureClass -ne 'profile_invalid' -or $parse.FailureCode -ne 'doctor_profile_parse') {{ throw 'profile parse fallback was not classified' }}
$unknown = Get-TunnelFailureDetail -Stdout 'profile file: C:/safe/profile.yaml' -Stderr 'unexpected failure' -ExitCode 1
if ($unknown.FailureClass -ne 'tunnel_client_failed' -or $unknown.FailureCode -ne 'doctor_unknown_failure') {{ throw 'generic profile word caused a false profile classification' }}
'doctor-classification-ok'
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "doctor-classification-ok" in output
    assert "diagnostic-secret-" not in output


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_managed_profile_staging_path_keeps_yaml_extension(tmp_path: Path) -> None:
    destination = tmp_path / "localmcp-test.yaml"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$staging = Write-TunnelProfileStaging -Content 'config_version: 1' -DestinationPath {_ps_literal(destination)}
try {{
    if ([IO.Path]::GetExtension($staging) -ne '.yaml') {{ throw "staging profile must end with .yaml: $staging" }}
    if (-not (Test-Path -LiteralPath $staging -PathType Leaf)) {{ throw 'staging profile was not created' }}
    'staging-yaml-extension-ok'
}} finally {{
    Remove-TunnelStagingFile -Path $staging
}}
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "staging-yaml-extension-ok" in output


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
    assert '$launcherVerifierPath = Join-Path $ScriptRoot "verify-approved-host-runtime.ps1"' in helper
    assert "Tunnel 対象ファイルの SHA-256 を確認できません: $($_.Exception.Message)" in helper
    assert "[Security.Cryptography.SHA256]::Create()" in helper
    assert "Get-FileHash" not in helper
    assert "--api-key" not in helper
    assert "-ApiKey" not in helper
    assert "Read-Host \"Runtime API Key（入力内容は表示されません）\" -AsSecureString" in setup
    assert "Test-TunnelProfileBinding" in runner
    assert "Invoke-TunnelClientDoctor" in runner
    assert "Show-TunnelDoctorFailureGuide" in runner
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
def test_profile_generation_normalizes_drive_space_and_japanese_paths() -> None:
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
    $marker = 'zzsecret-' + [Guid]::NewGuid().ToString('N')
$server = 'C:\\Program Files\\Windows Local MCP\\run-server.ps1'
$config = 'C:\\Users\\Public\\日本語 Local MCP\\config.toml'
$pidFile = 'C:\\Users\\22905\\AppData\\Local\\WindowsLocalMCP\\tunnel-state\\space.pid'
$healthFile = 'C:\\Users\\22905\\AppData\\Local\\WindowsLocalMCP\\tunnel-state\\space.health-url'
$profile = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript $server -ConfigPath $config -PidFile $pidFile -HealthUrlFile $healthFile
if ($profile -match [regex]::Escape($marker)) {{ throw 'marker leaked into profile' }}
if ($profile -notmatch 'api_key: env:WLMCP_TUNNEL_RUNTIME_API_KEY') {{ throw 'safe API key reference missing' }}
if ($profile -notmatch 'channel: main') {{ throw 'main channel missing' }}
if ($profile -notmatch 'powershell.exe -NoProfile -File') {{ throw 'canonical command missing' }}
if ($profile -notmatch 'C:/Program Files/Windows Local MCP/run-server.ps1') {{ throw 'drive path was not normalized' }}
if ($profile -notmatch 'C:/Users/Public/日本語 Local MCP/config.toml') {{ throw 'space or Japanese config path was not preserved' }}
if ($profile -match 'command:.*C:\\\\') {{ throw 'raw backslash remained in MCP command' }}
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
def test_secret_does_not_enter_config_state_logs_audit_or_temporary_files() -> None:
    with tempfile.TemporaryDirectory(prefix="wlmcp-secret-regression-") as temporary_root:
        root = Path(temporary_root) / "local mcp data"
        command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$root = {_ps_literal(root)}
$marker = 'file-secret-' + [Guid]::NewGuid().ToString('N')
$profileRoot = Join-Path $root 'profile'
$stateRoot = Join-Path $root 'state'
New-Item -ItemType Directory -Path $profileRoot, $stateRoot, (Join-Path $root 'logs'), (Join-Path $root 'audit') -Force | Out-Null
$configPath = Join-Path $root 'config.toml'
$profilePath = Join-Path $profileRoot 'localmcp.yaml'
$statePath = Join-Path $stateRoot 'state.json'
$pidFile = Join-Path $stateRoot 'tunnel.pid'
$healthFile = Join-Path $stateRoot 'tunnel.health-url'
$serverPath = {_ps_literal(_REPOSITORY_ROOT / 'run-server.ps1')}
$clientPath = $env:ComSpec
[IO.File]::WriteAllText($configPath, 'workspace_root = "C:\\Users\\Public\\workspace"', [Text.UTF8Encoding]::new($false))
$profile = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript $serverPath -ConfigPath $configPath -PidFile $pidFile -HealthUrlFile $healthFile
[IO.File]::WriteAllText($profilePath, $profile, [Text.UTF8Encoding]::new($false))
$state = [PSCustomObject][ordered]@{{
    version = 1; enabled = $true; config_path = [IO.Path]::GetFullPath($configPath)
    profile_path = [IO.Path]::GetFullPath($profilePath); profile_sha256 = Get-TunnelSha256 -Path $profilePath
    profile_scope = 'managed'; tunnel_id = 'tunnel_0123456789abcdef0123456789abcdef'
    tunnel_client_path = [IO.Path]::GetFullPath($clientPath); tunnel_client_sha256 = Get-TunnelSha256 -Path $clientPath
    pid_file = [IO.Path]::GetFullPath($pidFile); health_url_file = [IO.Path]::GetFullPath($healthFile)
    credential_mode = 'credential_manager'; credential_target = Get-TunnelCredentialTarget -ConfigPath $configPath
}}
$null = Save-TunnelStateAtomic -State $state -StatePath $statePath
$secure = ConvertTo-SecureString -String $marker -AsPlainText -Force
$prepared = New-TunnelProcessStartInfo -ClientPath $clientPath -Arguments @('run', '--profile-file', $profilePath) -Credential $secure
if ($prepared.StartInfo.Arguments -match [regex]::Escape($marker)) {{ throw 'secret leaked into command line' }}
if ($prepared.StartInfo.EnvironmentVariables['WLMCP_TUNNEL_RUNTIME_API_KEY'] -ne $marker) {{ throw 'child environment contract missing' }}
foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force)) {{
    $text = [IO.File]::ReadAllText($file.FullName, [Text.UTF8Encoding]::new($false, $true))
    if ($text.IndexOf($marker, [StringComparison]::Ordinal) -ge 0) {{ throw 'secret leaked into file: ' + $file.FullName }}
}}
$secure.Dispose()
'secret-file-regression-ok'
"""
        completed = _run_powershell(command)
        output = completed.stdout + completed.stderr
        assert completed.returncode == 0, output
        assert "secret-file-regression-ok" in output
        assert "file-secret-" not in output


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
