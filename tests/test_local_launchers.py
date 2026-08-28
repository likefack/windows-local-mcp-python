from __future__ import annotations

import os
import shutil
import subprocess
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


def test_start_launcher_delegates_to_setup_script() -> None:
    script = (_REPOSITORY_ROOT / "start-localmcp.bat").read_text(encoding="utf-8")

    assert "setup-localmcp.ps1" in script
    assert "powershell.exe -NoLogo -NoProfile" in script
    assert "-ExecutionPolicy Bypass" in script


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
    assert "既存の設定を使う" in script
    assert "初心者向け" not in script
    assert "環境設定済み" not in script
    assert "操作対象フォルダーの場所" in script
    assert "PythonWindowsDownloadUrl" in script
    assert "CodexCliDocsUrl" in script
    assert "Find-CodexCli" in script
    assert "Show-ManualConfigGuidance" in script


def test_launcher_docs_explain_manual_setup_and_single_root_boundary() -> None:
    docs = (_REPOSITORY_ROOT / "docs" / "LOCAL_LAUNCHERS.md").read_text(
        encoding="utf-8"
    )

    assert "アドレスバー" in docs
    assert "https://www.python.org/downloads/windows/" in docs
    assert "https://developers.openai.com/codex/cli/" in docs
    assert "同じプロセスから複数フォルダーを同時に操作する機能" in docs
