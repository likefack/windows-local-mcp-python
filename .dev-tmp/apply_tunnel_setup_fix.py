from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8-sig")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, got {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8-sig" if path.endswith(".ps1") else "utf-8")


setup = "setup-localmcp.ps1"
helper = "secure-mcp-tunnel.ps1"

# Python -I implies -E, so PYTHONIOENCODING alone cannot force UTF-8. Keep the
# host encoding alignment, but also opt the isolated child into UTF-8 mode.
replace_once(
    setup,
    '$output = @(& $PythonPath @Arguments 2>&1)',
    '$output = @(& $PythonPath -X utf8 @Arguments 2>&1)',
)
replace_once(
    helper,
    '$output = @(& $PythonPath -I -B -c $probe 2>$null)',
    '$output = @(& $PythonPath -I -X utf8 -B -c $probe 2>$null)',
)

# Search a few conventional user download locations, shallowly. Every found
# candidate still goes through the existing forbidden-root/reparse/hash checks
# and remains an explicit user selection in the setup UI.
old_candidates = '''    foreach ($name in @("tunnel-client.exe", "tunnel-client")) {
        try {
            $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $command -and $command.Source) {
                $null = $paths.Add($command.Source)
            }
        } catch {
            # PATH 上の候補を確認できない場合は次の候補へ進みます。
        }
    }

    $profileRoots = [System.Collections.Generic.List[string]]::new()
'''
new_candidates = '''    foreach ($name in @("tunnel-client.exe", "tunnel-client")) {
        try {
            $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $command -and $command.Source) {
                $null = $paths.Add($command.Source)
            }
        } catch {
            # PATH 上の候補を確認できない場合は次の候補へ進みます。
        }
    }

    $downloadRoots = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Downloads"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:OneDrive)) {
        $null = $downloadRoots.Add((Join-Path $env:OneDrive "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:OneDrive "Downloads"))
    }
    foreach ($root in @($downloadRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $null = $paths.Add((Join-Path $root "tunnel-client.exe"))
        foreach ($directory in @(Get-ChildItem -LiteralPath $root -Directory -Force -Filter "tunnel-client*" -ErrorAction SilentlyContinue | Select-Object -First 50)) {
            $null = $paths.Add((Join-Path $directory.FullName "tunnel-client.exe"))
        }
    }

    $profileRoots = [System.Collections.Generic.List[string]]::new()
'''
replace_once(helper, old_candidates, new_candidates)

# Let a user paste the containing folder, but only accept the exact direct child
# after confirmation. Do not broaden this convenience to generic executable
# resolution because that function also validates profile files.
old_select = '''        if (-not [IO.Path]::IsPathRooted($selection)) {
            Write-Warn "絶対 path を指定してください。"
            continue
        }
        try {
            $resolved = Resolve-TunnelExecutable -Path $selection -ForbiddenRoots $ForbiddenRoots
            return [PSCustomObject]@{ Path = $resolved; Hash = Get-TunnelSha256 -Path $resolved }
        } catch {
            Write-Warn "指定した tunnel-client を安全に確認できません。公式配布物の path を指定してください。"
        }
'''
new_select = '''        if (-not [IO.Path]::IsPathRooted($selection)) {
            Write-Warn "絶対 path を指定してください。"
            continue
        }
        try {
            if (Test-Path -LiteralPath $selection -PathType Container) {
                $directChild = Join-Path $selection "tunnel-client.exe"
                if (-not (Test-Path -LiteralPath $directChild -PathType Leaf)) {
                    Write-Warn "指定したフォルダー直下に tunnel-client.exe がありません。実行ファイルまで含む path を指定してください。"
                    continue
                }
                Write-Info "フォルダー直下の tunnel-client.exe を検出しました: $directChild"
                if (-not (Read-YesNo -Prompt "この tunnel-client.exe を使用しますか" -Default $true)) {
                    continue
                }
                $selection = $directChild
            }
            $resolved = Resolve-TunnelExecutable -Path $selection -ForbiddenRoots $ForbiddenRoots
            return [PSCustomObject]@{ Path = $resolved; Hash = Get-TunnelSha256 -Path $resolved }
        } catch {
            Write-Warn "指定した tunnel-client を安全に確認できません。公式配布物の path を指定してください。"
        }
'''
replace_once(setup, old_select, new_select)

# Structured doctor parsing and redaction. The v0.0.10 doctor JSON schema is
# result/failed_checks/next/checks, with each check containing id/status/summary,
# why/evidence/next. Reconstruct a sanitized object rather than returning raw
# stdout/stderr to setup code.
anchor = '''function Get-TunnelFailureClass {
'''
insert = r'''function Protect-TunnelDiagnosticText {
    param(
        [AllowNull()][string]$Text,
        [Security.SecureString]$Credential
    )

    if ($null -eq $Text) { return "" }
    $safe = [string]$Text
    $plain = $null
    try {
        if ($null -ne $Credential) {
            $plain = ConvertFrom-TunnelSecureString -Secret $Credential
            if (-not [string]::IsNullOrEmpty($plain)) {
                $safe = $safe.Replace($plain, "[REDACTED]")
            }
        }
    } finally {
        $plain = $null
    }
    $safe = [regex]::Replace($safe, '(?i)\b(?:sk|rk|sess)-[A-Za-z0-9_-]{8,}\b', '[REDACTED]')
    $safe = [regex]::Replace($safe, '(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+', '$1[REDACTED]')
    return $safe
}

function ConvertFrom-TunnelDoctorJson {
    param(
        [AllowNull()][string]$JsonText,
        [Security.SecureString]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($JsonText)) { return $null }
    try {
        $parsed = $JsonText | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
    if ($null -eq $parsed -or [string]::IsNullOrWhiteSpace([string]$parsed.result)) {
        return $null
    }

    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($check in @($parsed.checks)) {
        if ($null -eq $check) { continue }
        $evidence = @($check.evidence | ForEach-Object { Protect-TunnelDiagnosticText -Text ([string]$_) -Credential $Credential })
        $next = @($check.next | ForEach-Object { Protect-TunnelDiagnosticText -Text ([string]$_) -Credential $Credential })
        $null = $checks.Add([PSCustomObject]@{
            Id = Protect-TunnelDiagnosticText -Text ([string]$check.id) -Credential $Credential
            Status = ([string]$check.status).ToUpperInvariant()
            Summary = Protect-TunnelDiagnosticText -Text ([string]$check.summary) -Credential $Credential
            Why = Protect-TunnelDiagnosticText -Text ([string]$check.why) -Credential $Credential
            Evidence = $evidence
            Next = $next
        })
    }
    return [PSCustomObject]@{
        Result = ([string]$parsed.result).ToLowerInvariant()
        FailedChecks = @($parsed.failed_checks | ForEach-Object { Protect-TunnelDiagnosticText -Text ([string]$_) -Credential $Credential })
        Next = Protect-TunnelDiagnosticText -Text ([string]$parsed.next) -Credential $Credential
        Checks = @($checks)
    }
}

function Get-TunnelDoctorFailureClass {
    param(
        [object]$Report,
        [string]$Stdout,
        [string]$Stderr,
        [int]$ExitCode
    )

    $failed = @()
    if ($null -ne $Report) { $failed = @($Report.FailedChecks) }
    if ($failed -contains "tunnel_id") { return "tunnel_id_invalid" }
    if ($failed -contains "control_plane_api_key") { return "credential_configuration" }
    if ($failed -contains "mcp_target" -or $failed -contains "mcp_command_executable") { return "server_start_failed" }
    if (@($failed | Where-Object { $_ -in @("profile_load", "config_source", "config_validation", "control_plane_base_url", "control_plane_url_path") }).Count -gt 0) {
        return "profile_invalid"
    }
    return Get-TunnelFailureClass -Stdout $Stdout -Stderr $Stderr -ExitCode $ExitCode
}

function Show-TunnelDoctorDiagnostics {
    param([Parameter(Mandatory = $true)][object]$Doctor)

    if ([bool]$Doctor.Succeeded) { return }
    Write-Host "tunnel-client doctor の事前検証に失敗しました（終了コード $($Doctor.ExitCode)）。" -ForegroundColor Yellow
    if ($null -ne $Doctor.Report) {
        $failedChecks = @($Doctor.Report.FailedChecks)
        if ($failedChecks.Count -gt 0) {
            Write-Host ("失敗した確認項目: " + ($failedChecks -join ", ")) -ForegroundColor Yellow
        }
        foreach ($check in @($Doctor.Report.Checks | Where-Object { $_.Status -eq "FAIL" })) {
            Write-Host ("  - {0}: {1}" -f $check.Id, $check.Summary) -ForegroundColor Yellow
            foreach ($line in @($check.Evidence | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                Write-Host ("    根拠: " + [string]$line) -ForegroundColor Gray
            }
            foreach ($line in @($check.Next | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                Write-Host ("    対応候補: " + [string]$line) -ForegroundColor Gray
            }
        }
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$Doctor.FallbackText)) {
        Write-Host "構造化診断を読み取れなかったため、安全化した tunnel-client 出力を表示します:" -ForegroundColor Yellow
        foreach ($line in @(([string]$Doctor.FallbackText -split "`r?`n") | Select-Object -First 30)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Host ("  " + $line) -ForegroundColor Gray }
        }
    }
}

function Get-TunnelFailureClass {
'''
replace_once(helper, anchor, insert)

old_doctor = '''function Invoke-TunnelClientDoctor {
    param(
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Security.SecureString]$Credential
    )
    $process = $null
    $plain = $null
    try {
        $prepared = New-TunnelProcessStartInfo -ClientPath $ClientPath -Arguments @(
            "doctor", "--profile-file", $ProfilePath, "--explain"
        ) -Credential $Credential
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $prepared.StartInfo
        if (-not $process.Start()) { throw "start failed" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
        return [PSCustomObject]@{
            Succeeded = ($exitCode -eq 0)
            ExitCode = $exitCode
            FailureClass = Get-TunnelFailureClass -Stdout $stdout -Stderr $stderr -ExitCode $exitCode
        }
    } catch {
        return [PSCustomObject]@{ Succeeded = $false; ExitCode = -1; FailureClass = "tunnel_client_unavailable" }
    } finally {
        $plain = $null
        if ($null -ne $process) { $process.Dispose() }
    }
}
'''
new_doctor = '''function Invoke-TunnelClientDoctor {
    param(
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Security.SecureString]$Credential
    )
    $process = $null
    try {
        $prepared = New-TunnelProcessStartInfo -ClientPath $ClientPath -Arguments @(
            "doctor", "--profile-file", $ProfilePath, "--json"
        ) -Credential $Credential
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $prepared.StartInfo
        if (-not $process.Start()) { throw "start failed" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
        $report = ConvertFrom-TunnelDoctorJson -JsonText $stdout -Credential $Credential
        $safeStdout = Protect-TunnelDiagnosticText -Text $stdout -Credential $Credential
        $safeStderr = Protect-TunnelDiagnosticText -Text $stderr -Credential $Credential
        $fallback = (($safeStdout, $safeStderr | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join [Environment]::NewLine).Trim()
        if ($fallback.Length -gt 12000) { $fallback = $fallback.Substring(0, 12000) + "`n[truncated]" }
        return [PSCustomObject]@{
            Succeeded = ($exitCode -eq 0 -and ($null -eq $report -or $report.Result -eq "ok"))
            ExitCode = $exitCode
            FailureClass = Get-TunnelDoctorFailureClass -Report $report -Stdout $safeStdout -Stderr $safeStderr -ExitCode $exitCode
            Report = $report
            FallbackText = $fallback
        }
    } catch {
        $safeError = Protect-TunnelDiagnosticText -Text $_.Exception.Message -Credential $Credential
        return [PSCustomObject]@{
            Succeeded = $false
            ExitCode = -1
            FailureClass = "tunnel_client_unavailable"
            Report = $null
            FallbackText = $safeError
        }
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}
'''
replace_once(helper, old_doctor, new_doctor)

# Show structured diagnostics before the user-facing remediation guide at both
# existing-state diagnostics and new managed-profile creation.
replace_once(
    setup,
    '''        if (-not $doctor.Succeeded) {
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }
        Write-Ok "既存の Tunnel profile、tunnel-client、認証参照を検証しました。"
''',
    '''        if (-not $doctor.Succeeded) {
            Show-TunnelDoctorDiagnostics -Doctor $doctor
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }
        Write-Ok "既存の Tunnel profile、tunnel-client、認証参照を検証しました。"
''',
)
replace_once(
    setup,
    '''        if (-not $doctor.Succeeded) {
            Remove-TunnelStagingFile -Path $stagingPath
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }
''',
    '''        if (-not $doctor.Succeeded) {
            Show-TunnelDoctorDiagnostics -Doctor $doctor
            Remove-TunnelStagingFile -Path $stagingPath
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }
''',
)

# The staging profile was generated moments ago, so do not imply that a doctor
# failure proves it was modified. Structured details above carry the root cause.
replace_once(
    helper,
    '''        "profile_invalid" {
            Write-Host "Tunnel profile が不正または変更されています。configure-localmcp.bat の Tunnel 設定変更を選び、検証済み profile を再生成してください。" -ForegroundColor Yellow
        }
''',
    '''        "credential_configuration" {
            Write-Host "Runtime API Key の参照または設定を tunnel-client doctor が確認できません。上の診断詳細を確認し、必要なら key を再入力してください。" -ForegroundColor Yellow
        }
        "profile_invalid" {
            Write-Host "Tunnel profile の検証に失敗しました。上の doctor 診断を確認し、必要な場合だけ configure-localmcp.bat の Tunnel 設定変更から profile を再生成してください。" -ForegroundColor Yellow
        }
''',
)

# Add focused Windows regression coverage without needing a real API key or
# network connection. A tiny fake doctor emits the same v0.0.10 JSON schema.
tests = r'''import os
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
    shell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
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
$secure = ConvertTo-SecureString -String $secretText -AsPlainText -Force
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
'''
Path("tests/test_tunnel_setup_diagnostics.py").write_text(tests, encoding="utf-8")
