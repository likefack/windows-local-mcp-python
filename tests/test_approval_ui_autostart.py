from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_approval_ui_autostart_defaults_on_and_can_be_disabled(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    assert settings.approval_ui_autostart is True

    disabled = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "disabled-data",
        protect_data_dir_acl=False,
        approval_ui_autostart=False,
    )
    assert disabled.approval_ui_autostart is False


def test_run_launcher_starts_only_the_selected_runtime_sibling_approval_ui() -> None:
    runner = (_REPOSITORY_ROOT / "run-localmcp.ps1").read_text(encoding="utf-8-sig")

    assert "Get-LocalMcpApprovalUiAutostart" in runner
    assert "approval_ui_autostart" in runner
    assert 'Join-Path $runtimeRoot "run-approvals.ps1"' in runner
    assert 'Join-Path $env:SystemRoot "System32\\WindowsPowerShell\\v1.0\\powershell.exe"' in runner
    assert "-WindowStyle Normal" in runner
    assert "-Config" in runner
    assert "CloseMainWindow" in runner
    assert "Python承認UIが孤立" in runner
    assert "Stop-LocalMcpApprovalUi" in runner
    # The selected ServerScript is the sole source of the sibling approval launcher.
    start = runner.index("function Start-LocalMcpApprovalUi")
    end = runner.index("function Stop-LocalMcpApprovalUi", start)
    function = runner[start:end]
    assert "$ScriptRoot" not in function
    assert "-ApiKey" not in function
    assert "Runtime API Key" not in function
    stop_start = end
    stop_end = runner.index("\ntry {", stop_start)
    stop_function = runner[stop_start:stop_end]
    assert "$Process.Kill()" not in stop_function


def test_approval_launcher_holds_a_config_scoped_mutex_and_keeps_secrets_out_of_argv() -> None:
    approvals = (_REPOSITORY_ROOT / "run-approvals.ps1").read_text(encoding="utf-8-sig")

    assert "Get-ApprovalConfigMutexName" in approvals
    assert "SHA256" in approvals
    assert "GetFullPath($ConfigPath)" in approvals
    assert "[Threading.Mutex]::new" in approvals
    assert "WaitOne(0)" in approvals
    assert "ReleaseMutex" in approvals
    assert "LOCAL_MCP_CONFIG" in approvals
    assert "-m windows_local_mcp.cli approvals" in approvals
    assert "--api-key" not in approvals
    assert "Runtime API Key" not in approvals


def test_launcher_scripts_retain_utf8_bom() -> None:
    for name in ("run-localmcp.ps1", "run-approvals.ps1"):
        assert (_REPOSITORY_ROOT / name).read_bytes().startswith(b"\xef\xbb\xbf")


@pytest.mark.skipif(os.name != "nt", reason="named mutex is Windows-only")
def test_approval_launcher_mutex_blocks_a_second_process_for_same_config(
    tmp_path: Path,
) -> None:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    config = tmp_path / "config.toml"
    config.write_text("# mutex identity only\n", encoding="utf-8")
    ready = tmp_path / "mutex-ready.txt"
    launcher = _REPOSITORY_ROOT / "run-approvals.ps1"

    def literal(value: Path) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    holder_command = (
        f". {literal(launcher)} -FunctionsOnly; "
        f"$name=Get-ApprovalConfigMutexName -ConfigPath {literal(config)}; "
        "$mutex=[Threading.Mutex]::new($false,$name); "
        "if(-not $mutex.WaitOne(0)){exit 2}; "
        f"Set-Content -LiteralPath {literal(ready)} -Value 'ready'; Start-Sleep -Seconds 10"
    )
    holder = subprocess.Popen(
        [shell, "-NoProfile", "-NonInteractive", "-Command", holder_command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.is_file() and holder.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if not ready.is_file():
            holder.terminate()
            stdout, stderr = holder.communicate(timeout=10)
            pytest.fail(f"mutex holder did not start: {stdout}{stderr}")
        contender_command = (
            f". {literal(launcher)} -FunctionsOnly; "
            f"$name=Get-ApprovalConfigMutexName -ConfigPath {literal(config)}; "
            "$mutex=[Threading.Mutex]::new($false,$name); "
            "if($mutex.WaitOne(0)){exit 3}; Write-Output 'mutex-blocked'"
        )
        contender = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command", contender_command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            shell=False,
        )
        assert contender.returncode == 0, contender.stdout + contender.stderr
        assert "mutex-blocked" in contender.stdout
    finally:
        holder.terminate()
        try:
            holder.wait(timeout=10)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait(timeout=10)
