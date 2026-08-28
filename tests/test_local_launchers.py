from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _assert_powershell_script_parses(path: Path) -> None:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell executable is unavailable")
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


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher validation is Windows-only")
def test_setup_localmcp_powershell_script_parses() -> None:
    _assert_powershell_script_parses(_REPOSITORY_ROOT / "setup-localmcp.ps1")


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher validation is Windows-only")
def test_run_localmcp_powershell_script_parses() -> None:
    _assert_powershell_script_parses(_REPOSITORY_ROOT / "run-localmcp.ps1")


@pytest.mark.skipif(os.name != "nt", reason="PowerShell launcher validation is Windows-only")
def test_secure_mcp_tunnel_helper_powershell_script_parses() -> None:
    _assert_powershell_script_parses(_REPOSITORY_ROOT / "secure-mcp-tunnel.ps1")


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
    assert f'data_dir = "{toml_path(new_data_dir)}"' in config.read_text(encoding="utf-8")


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
