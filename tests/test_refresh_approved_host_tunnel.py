"""対話なしの再接続設定が、既存の検証と失敗時復元を通ることを確認する。"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell is required")


def _ps(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _run(command: str) -> subprocess.CompletedProcess[str]:
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    return subprocess.run(
        [str(shell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", base64.b64encode(command.encode("utf-16-le")).decode("ascii")],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        check=False,
    )


@pytest.mark.parametrize("scenario", [
    "success", "running", "runtime", "authority", "credential", "save", "external",
])
def test_refresh_reuses_validation_without_prompts(tmp_path: Path, scenario: str) -> None:
    config = tmp_path / "日本語 config.toml"
    config.write_text("# existing config\n", encoding="utf-8")
    selector = tmp_path / "active-config.txt"
    selector.write_text(str(config), encoding="utf-8")
    runtime = tmp_path / "installed runtime"
    command = """
$ErrorActionPreference = 'Stop'
. __SETUP__ -FunctionsOnly
$SelectorPath = __SELECTOR__
$expectedConfig = __CONFIG__
$expectedRuntime = __RUNTIME__
$scenario = __SCENARIO__
$script:steps = [Collections.Generic.List[string]]::new()
$script:enabled = $false
function Read-Host { throw 'unexpected-prompt' }
function Find-Python { return @{ Path = 'test-python' } }
function Get-TunnelStateForConfig {
    param($ConfigPath)
    if ($ConfigPath -ne $expectedConfig) { throw 'wrong-config' }
    return [pscustomobject]@{
        server_runtime_kind = 'approved_host'
        server_script_path = (Join-Path $expectedRuntime 'run-server.ps1')
        profile_scope = $(if ($scenario -eq 'external') { 'external' } else { 'managed' })
        credential_mode = 'credential_manager'
        tunnel_client_path = 'test-client'
        tunnel_id = 'test-tunnel'
    }
}
function Assert-TunnelNotRunning {
    param($State)
    if ($scenario -eq 'running') { throw 'test-running' }
}
function Get-TunnelConfigContext { return @{} }
function Resolve-TunnelServerRuntime {
    param($ScriptRoot, $State, [switch]$VerifyApprovedHostRuntime)
    if (-not $VerifyApprovedHostRuntime -or
        $State.server_script_path -ne (Join-Path $expectedRuntime 'run-server.ps1')) {
        throw 'wrong-runtime-verification'
    }
    $script:steps.Add('runtime')
    return @{ Valid = ($scenario -ne 'runtime'); Message = 'test-runtime';
              PythonPath = 'verified-python'; ServerScript = $State.server_script_path }
}
function Invoke-Python {
    param($PythonPath, $Arguments)
    if ($PythonPath -ne 'verified-python') { throw 'unverified-authority-python' }
    $script:steps.Add('authority')
    if ($scenario -eq 'authority') { throw 'test-authority' }
}
function Get-ConfigurationInfo { return @{ approved_host_enabled = $script:enabled } }
function Get-TunnelSavedCredential {
    $script:steps.Add('credential')
    if ($scenario -eq 'credential') { return $null }
    return [Security.SecureString]::new()
}
function Save-ConfigBooleanValue {
    param($PythonPath, $ConfigPath, $SettingName, $Value)
    $script:steps.Add("enabled=$Value")
    $script:enabled = $Value
}
function Save-TunnelManagedIntegration {
    param($ConfigPath, $ClientPath, $TunnelId, $Credential, $PreviousState,
          $ServerRuntimeKind, $ServerScriptPath)
    if ($ClientPath -ne 'test-client' -or $TunnelId -ne 'test-tunnel' -or
        $ServerRuntimeKind -ne 'approved_host' -or
        $ServerScriptPath -ne (Join-Path $expectedRuntime 'run-server.ps1')) {
        throw 'existing-binding-not-preserved'
    }
    $script:steps.Add('save')
    return ($scenario -ne 'save')
}
$failed = $false
try { Update-ApprovedHostTunnelForSetup } catch {
    $failed = $true
    if ($_.Exception.Message -match 'unexpected-prompt|wrong-|unverified-|not-preserved') { throw }
}
if ($failed -ne ($scenario -ne 'success')) { throw 'wrong-result' }
$expected = switch ($scenario) {
    success { 'runtime,authority,credential,enabled=True,save' }
    running { '' }
    external { '' }
    runtime { 'runtime' }
    authority { 'runtime,authority' }
    credential { 'runtime,authority,credential' }
    save { 'runtime,authority,credential,enabled=True,save,enabled=False' }
}
if (($script:steps -join ',') -ne $expected) { throw "wrong-call-order: $script:steps" }
if ($script:enabled -ne ($scenario -eq 'success')) { throw 'config-not-restored' }
'refresh-regression-ok'
"""
    replacements = {
        "__SETUP__": ROOT / "setup-localmcp.ps1", "__SELECTOR__": selector,
        "__CONFIG__": config, "__RUNTIME__": runtime, "__SCENARIO__": scenario,
    }
    for key, value in replacements.items():
        command = command.replace(key, _ps(value))
    result = _run(command)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refresh-regression-ok" in result.stdout
    assert selector.read_text(encoding="utf-8") == str(config)
    assert config.read_text(encoding="utf-8") == "# existing config\n"


def test_refresh_cli_missing_config_exits_without_menu(tmp_path: Path) -> None:
    result = _run(
        f"& {_ps(ROOT / 'setup-localmcp.ps1')} -RefreshApprovedHostTunnel "
        f"-Config {_ps(tmp_path / 'missing.toml')}; exit $LASTEXITCODE"
    )
    assert result.returncode == 1
    assert "設定ファイルが見つかりません" in result.stdout
    assert "Read-Host" not in result.stdout + result.stderr
