from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_WINDOWS_POWERSHELL_51_LAUNCHERS = (
    "setup-localmcp.ps1",
    "run-localmcp.ps1",
    "run-server.ps1",
    "run-approvals.ps1",
    "secure-mcp-tunnel.ps1",
)


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


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


def _assert_powershell_script_parses(path: Path) -> None:
    # PowerShell 7 accepts BOM-less UTF-8, so it cannot detect the Windows
    # PowerShell 5.1 source-decoding regression covered by this test.
    shell = _windows_powershell_51()
    command = (
        "$tokens=$null; $errors=$null; "
        "if ($PSVersionTable.PSVersion.Major -ne 5 -or "
        "$PSVersionTable.PSVersion.Minor -ne 1) { exit 3 }; "
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


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher validation is Windows-only")
@pytest.mark.parametrize("script_name", _WINDOWS_POWERSHELL_51_LAUNCHERS)
def test_launcher_parses_with_windows_powershell_51(script_name: str) -> None:
    _assert_powershell_script_parses(_REPOSITORY_ROOT / script_name)


def test_windows_powershell_51_launchers_use_utf8_bom_and_keep_japanese() -> None:
    for script_name in _WINDOWS_POWERSHELL_51_LAUNCHERS:
        payload = (_REPOSITORY_ROOT / script_name).read_bytes()
        assert payload.startswith(b"\xef\xbb\xbf"), script_name
        payload.decode("utf-8-sig", errors="strict")

    assert "設定ファイルが見つかりません" in (
        _REPOSITORY_ROOT / "run-localmcp.ps1"
    ).read_text(encoding="utf-8-sig")
    assert "Tunnel client の SHA-256 を確認できません" in (
        _REPOSITORY_ROOT / "secure-mcp-tunnel.ps1"
    ).read_text(encoding="utf-8-sig")


def test_start_launcher_delegates_to_setup_script() -> None:
    script = (_REPOSITORY_ROOT / "start-localmcp.bat").read_text(encoding="utf-8")

    # A compatibility wrapper may delegate to the newer settings entry point;
    # the effective entry point must still reach the same setup PowerShell.
    if "configure-localmcp.bat" in script:
        script = (_REPOSITORY_ROOT / "configure-localmcp.bat").read_text(encoding="utf-8")
    assert "setup-localmcp.ps1" in script
    assert "powershell.exe -NoLogo -NoProfile" in script
    assert "-ExecutionPolicy Bypass" in script


def test_configure_launcher_is_formal_entry_and_start_is_compatible() -> None:
    configure = (_REPOSITORY_ROOT / "configure-localmcp.bat").read_text(encoding="utf-8")
    legacy = (_REPOSITORY_ROOT / "start-localmcp.bat").read_text(encoding="utf-8")

    assert "Primary settings-management entry point" in configure
    assert "setup-localmcp.ps1" in configure
    assert "Deprecated compatibility wrapper" in legacy
    assert "configure-localmcp.bat" in legacy


@pytest.mark.skipif(os.name != "nt", reason="Interactive PowerShell launcher validation is Windows-only")
def test_settings_menu_displays_summary_and_atomically_changes_workspace(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell executable is unavailable")

    local_app_data = tmp_path / "local app data"
    state_root = local_app_data / "WindowsLocalMCP"
    state_root.mkdir(parents=True)
    old_workspace = tmp_path / "workspace old"
    new_workspace = tmp_path / "\u65e5\u672c\u8a9e workspace"
    data_dir = tmp_path / "local mcp data"
    external_directory = tempfile.TemporaryDirectory(prefix="wlmcp-settings-data-")
    request.addfinalizer(external_directory.cleanup)
    new_data_dir = Path(external_directory.name) / "local mcp data new"
    scratch_dir = tmp_path / "local mcp scratch"
    for directory in (old_workspace, new_workspace, data_dir, scratch_dir):
        directory.mkdir(parents=True)

    def toml_path(value: Path) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    config = state_root / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{toml_path(old_workspace)}"',
                f'data_dir = "{toml_path(data_dir)}"',
                f'sandbox_scratch_dir = "{toml_path(scratch_dir)}"',
                "filesystem_enabled = true",
                "git_enabled = false",
                "protect_data_dir_acl = false",
                "approved_sandbox_enabled = false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_app_data)
    environment.pop("LOCAL_MCP_CONFIG", None)
    environment.pop("LOCAL_MCP_ROOT", None)
    environment["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [
            shell,
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_REPOSITORY_ROOT / "setup-localmcp.ps1"),
        ],
        input=f"2\n1\n1\n{new_workspace}\n{new_data_dir}\n0\nn\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
        shell=False,
        env=environment,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "Runtime API Key" in output
    assert "workspace" in output
    assert "Runtime API Key" in output
    assert "secret" in output.lower()
    assert f'workspace_root = "{toml_path(new_workspace)}"' in config.read_text(
        encoding="utf-8"
    ), output
    configured_data = Path(tomllib.loads(config.read_text(encoding="utf-8"))["data_dir"])
    assert configured_data.resolve() == new_data_dir.resolve()


@pytest.mark.skipif(os.name != "nt", reason="PowerShell config replacement is Windows-only")
def test_candidate_validation_is_side_effect_free_and_save_config_rolls_back(
    tmp_path: Path,
) -> None:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    python = _REPOSITORY_ROOT / ".venv" / "Scripts" / "python.exe"
    if shell is None or not python.is_file():
        pytest.skip("PowerShell or the repository Python runtime is unavailable")

    old_workspace = tmp_path / "old workspace"
    new_workspace = tmp_path / "日本語 workspace"
    old_data = tmp_path / "old data"
    old_scratch = tmp_path / "old scratch"
    new_data = tmp_path / "new data"
    new_scratch = tmp_path / "new scratch"
    for directory in (old_workspace, new_workspace, old_data, old_scratch):
        directory.mkdir(parents=True)

    def toml_path(value: Path) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    config = tmp_path / "settings" / "config.toml"
    config.parent.mkdir()
    old_content = "\n".join(
        (
            f'workspace_root = "{toml_path(old_workspace)}"',
            f'data_dir = "{toml_path(old_data)}"',
            f'sandbox_scratch_dir = "{toml_path(old_scratch)}"',
            "filesystem_enabled = false",
            "git_enabled = false",
            "protect_data_dir_acl = false",
            "approved_sandbox_enabled = false",
        )
    ) + "\n"
    config.write_text(old_content, encoding="utf-8")
    valid_candidate = tmp_path / "valid-candidate.toml"
    valid_candidate.write_text(
        old_content
        .replace(toml_path(old_workspace), toml_path(new_workspace))
        .replace(toml_path(old_data), toml_path(new_data))
        .replace(toml_path(old_scratch), toml_path(new_scratch)),
        encoding="utf-8",
    )
    invalid_candidate = tmp_path / "invalid-candidate.toml"
    invalid_candidate.write_text(
        valid_candidate.read_text(encoding="utf-8").replace(
            toml_path(new_data), toml_path(new_workspace / "data")
        ),
        encoding="utf-8",
    )
    rollback_candidate = tmp_path / "rollback-candidate.toml"
    rollback_candidate.write_text(
        valid_candidate.read_text(encoding="utf-8").replace(
            "filesystem_enabled = false", "filesystem_enabled = true"
        ),
        encoding="utf-8",
    )

    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_REPOSITORY_ROOT / 'setup-localmcp.ps1')} -FunctionsOnly
Test-ConfigurationCandidate -PythonPath {_ps_literal(python)} -ConfigPath {_ps_literal(valid_candidate)} -FinalConfigPath {_ps_literal(config)}
if ((Test-Path -LiteralPath {_ps_literal(new_data)}) -or (Test-Path -LiteralPath {_ps_literal(new_scratch)})) {{ throw 'candidate validation created directories' }}
$valid = [IO.File]::ReadAllText({_ps_literal(valid_candidate)}, [Text.Encoding]::UTF8)
Save-Config -Content $valid -Path {_ps_literal(config)} -PythonPath {_ps_literal(python)} -AllowExistingReplacement
$markerPath = Join-Path {_ps_literal(new_data)} 'control-plane/namespace.json'
$marker = Get-Content -Raw -Encoding UTF8 -LiteralPath $markerPath | ConvertFrom-Json
if (-not ([IO.Path]::GetFullPath([string]$marker.config_path).Equals([IO.Path]::GetFullPath({_ps_literal(config)}), [StringComparison]::OrdinalIgnoreCase))) {{ throw 'namespace marker was not bound to final config' }}
if ([string]$marker.config_path -match '\\.tmp-') {{ throw 'namespace marker was bound to temporary config' }}
$saved = [IO.File]::ReadAllBytes({_ps_literal(config)})
$backupCount = @(Get-ChildItem -LiteralPath (Split-Path -Parent {_ps_literal(config)}) -Filter 'config.toml.backup-*' -File).Count
if ($backupCount -ne 1) {{ throw 'valid replacement did not retain exactly one backup' }}
try {{
    $invalid = [IO.File]::ReadAllText({_ps_literal(invalid_candidate)}, [Text.Encoding]::UTF8)
    Save-Config -Content $invalid -Path {_ps_literal(config)} -PythonPath {_ps_literal(python)} -AllowExistingReplacement
    throw 'invalid candidate was accepted'
}} catch {{
    if ($_.Exception.Message -eq 'invalid candidate was accepted') {{ throw }}
}}
if (@(Compare-Object $saved ([IO.File]::ReadAllBytes({_ps_literal(config)}))).Count -ne 0) {{ throw 'invalid candidate changed existing config' }}
if (@(Get-ChildItem -LiteralPath (Split-Path -Parent {_ps_literal(config)}) -Filter 'config.toml.backup-*' -File).Count -ne 1) {{ throw 'invalid candidate created a backup' }}
function Test-Configuration {{ throw 'forced final validation failure' }}
try {{
    $rollback = [IO.File]::ReadAllText({_ps_literal(rollback_candidate)}, [Text.Encoding]::UTF8)
    Save-Config -Content $rollback -Path {_ps_literal(config)} -PythonPath {_ps_literal(python)} -AllowExistingReplacement
    throw 'forced final validation failure was ignored'
}} catch {{
    if ($_.Exception.Message -eq 'forced final validation failure was ignored') {{ throw }}
}}
if (@(Compare-Object $saved ([IO.File]::ReadAllBytes({_ps_literal(config)}))).Count -ne 0) {{ throw 'final validation failure did not restore existing config' }}
if (@(Get-ChildItem -LiteralPath (Split-Path -Parent {_ps_literal(config)}) -Filter 'config.toml.backup-*' -File).Count -ne 1) {{ throw 'rollback left an extra backup' }}
if (@(Get-ChildItem -LiteralPath (Split-Path -Parent {_ps_literal(config)}) -Filter 'config.toml.tmp-*' -File).Count -ne 0) {{ throw 'temporary config remained' }}
if (@(Get-ChildItem -LiteralPath (Split-Path -Parent {_ps_literal(config)}) -Filter 'config.toml.rollback-*' -File).Count -ne 0) {{ throw 'rollback file remained' }}
'candidate-save-regression-ok'
"""
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
        shell=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "candidate-save-regression-ok" in output


def test_run_launcher_delegates_selector_handling_to_powershell() -> None:
    script = (_REPOSITORY_ROOT / "run-localmcp.bat").read_text(encoding="utf-8")

    assert "run-localmcp.ps1" in script
    assert "%*" in script
    assert "active-config.txt" not in script
    assert "run-server.ps1" not in script
    assert "start-localmcp.bat" not in script


def test_setup_wizard_preserves_security_relevant_setup_contract() -> None:
    script = (_REPOSITORY_ROOT / "setup-localmcp.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert "LOCALAPPDATA" in script
    assert "approved_host_enabled = true" in script
    assert "approved_sandbox_require_live_verification = true" in script
    assert "Set-ActiveConfig" in script
    assert "Test-Configuration" in script
    assert "Find-TrustedGit" in script
    assert "adb_allowed_serials = []" in script
    assert "かんたんセットアップ" in script
    assert (
        "既存の設定を使う" in script
        or "現在の設定を確認・変更する" in script
    )
    assert "初心者向け" not in script
    assert "環境設定済み" not in script
    assert "操作対象フォルダーの場所" in script
    assert "PythonWindowsDownloadUrl" in script
    assert "CodexCliDocsUrl" in script
    assert "Resolve-CodexSandboxBackend" in script
    assert "resolve-codex-sandbox" in script
    assert "Set-CodexSandboxPath" in script
    assert "approved_sandbox_codex_path" in script
    assert "Get-Command codex.exe" not in script
    assert "Find-CodexCli" not in script
    assert "Show-ManualConfigGuidance" in script
    assert "secure-mcp-tunnel.ps1" in script
    assert "Configure-TunnelIntegration" in script
    assert "Read-TunnelRuntimeApiKeyForSetup" in script
    assert "Save-TunnelManagedIntegration" in script
    assert "Remove-TunnelSavedCredentialForSetup" in script
    assert "現在の設定" in script
    assert "Invoke-SettingsMenu" in script
    assert "Save-WorkspaceConfig" in script
    assert "Update-TunnelRuntimeApiKey" in script
    assert "Enable-TunnelIntegrationForSetup" in script
    assert "保持済み Tunnel profile、Tunnel ID、Runtime API Key を変更せず" in script
    assert "validate_configuration_candidate" in script
    assert "-FinalConfigPath $Path" in script
    assert "Test-Configuration -PythonPath $PythonPath -ConfigPath $Path" in script
    assert "$FunctionsOnly" in script
    assert "[IO.File]::Replace" in script
    assert "今すぐ Windows Local MCP を起動しますか" in script
    assert "secret は表示しません" in script


def test_run_launcher_preserves_tunnel_fail_closed_and_direct_compatibility() -> None:
    script = (_REPOSITORY_ROOT / "run-localmcp.ps1").read_text(encoding="utf-8-sig")

    assert "Get-TunnelStatePath" in script
    assert "Test-TunnelLocalMcpConfiguration" in script
    assert "Test-TunnelProfileBinding" in script
    assert "Invoke-TunnelClientDoctor" in script
    assert "Start-TunnelClientProcess" in script
    assert "二重起動を避けるため停止します" in script
    assert "Tunnel を迂回" not in script


def test_stdio_startup_guidance_is_written_only_to_stderr() -> None:
    cli = (_REPOSITORY_ROOT / "src" / "windows_local_mcp" / "cli.py").read_text(
        encoding="utf-8"
    )

    assert "Windows Local MCP の起動に成功しました" in cli
    assert "ChatGPT からの接続を待っています" in cli
    assert "このウィンドウを閉じないでください" in cli
    assert "終了するには Ctrl+C" in cli
    assert cli.count("file=sys.stderr") >= 2


def test_tunnel_reenable_reuses_validated_state_without_rebuilding_profile() -> None:
    setup = (_REPOSITORY_ROOT / "setup-localmcp.ps1").read_text(encoding="utf-8-sig")
    start = setup.index("function Enable-TunnelIntegrationForSetup")
    end = setup.index("function Remove-TunnelSavedCredentialForSetup", start)
    function = setup[start:end]

    assert "Test-TunnelProfileBinding" in function
    assert "Invoke-TunnelClientDoctor" in function
    assert "$copy.enabled = $true" in function
    assert "Save-TunnelStateAtomic" in function
    assert "New-TunnelProfileContent" not in function
    assert "Save-TunnelManagedIntegration" not in function


def test_tunnel_onboarding_and_failure_guidance_are_beginner_facing() -> None:
    setup = (_REPOSITORY_ROOT / "setup-localmcp.ps1").read_text(encoding="utf-8-sig")
    helper = (_REPOSITORY_ROOT / "secure-mcp-tunnel.ps1").read_text(encoding="utf-8")
    runner = (_REPOSITORY_ROOT / "run-localmcp.ps1").read_text(encoding="utf-8-sig")

    assert "ChatGPT Secure MCP Tunnel を設定しますか" in setup
    assert "既存 profile を使用する" in setup
    assert "今回はスキップする" in setup
    assert "Tunnel ID は接続先の識別子です" in helper
    assert "Tunnel ID の確認・作成" in helper
    assert "秘密情報の全文は作成時だけ表示され" in helper
    assert "Restricted key" in helper
    assert "Show-TunnelClientInstallGuide" in setup
    assert "tunnel-client が見つかりません" in helper
    assert "tool refresh" in runner
    assert "Get-TunnelMutexName" in setup
    assert "Save-TunnelStateAtomic" in setup
    assert "Restore-TunnelFileBackup" in setup


def test_launcher_docs_explain_manual_setup_and_single_root_boundary() -> None:
    docs = (_REPOSITORY_ROOT / "docs" / "LOCAL_LAUNCHERS.md").read_text(
        encoding="utf-8"
    )

    assert "アドレスバー" in docs
    assert "https://www.python.org/downloads/windows/" in docs
    assert "https://developers.openai.com/codex/cli/" in docs
    assert "同じプロセスから複数フォルダーを同時に操作する機能" in docs
    assert "Credential Manager" in docs
    assert "configure-localmcp.bat → かんたんセットアップ → workspace → Tunnel → 完了 → 今すぐ起動" in docs
    assert "通常:       run-localmcp.bat" in docs
    assert "設定変更:   configure-localmcp.bat → 現在の設定を確認・変更する" in docs
    assert "platform.openai.com/settings/organization/tunnels" in docs
    assert "platform.openai.com/settings/organization/api-keys" in docs
