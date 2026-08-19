[CmdletBinding()]
param(
    [int]$PollMilliseconds = 100,
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$markerPath = Join-Path $PSScriptRoot ".c6-4-wfp-helper-pause"
$resultPath = Join-Path $env:TEMP "wlmcp-c6-4-helper-kill.json"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "PowerShell A は管理者として実行してください。"
}
if ($PollMilliseconds -lt 20 -or $PollMilliseconds -gt 1000) {
    throw "PollMilliseconds は 20～1000 の範囲で指定してください。"
}
if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 300) {
    throw "TimeoutSeconds は 5～300 の範囲で指定してください。"
}

Set-Content -LiteralPath $markerPath -Value "C6.4 elevated WFP helper crash window" -Encoding UTF8
Write-Host "C6.4 marker armed: $markerPath"
Write-Host "PowerShell B から Codex Sandbox operation を開始し、UAC で [はい] を選択してください。"
Write-Host "elevated WFP helper を待機中..."

$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
$result = $null
try {
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $targets = @(
            Get-CimInstance Win32_Process |
                Where-Object {
                    $null -ne $_.CommandLine -and
                    $_.CommandLine.Contains("windows_local_mcp.wfp_guard_runtime") -and
                    $_.CommandLine.Contains("--elevated-ensure")
                }
        )

        if ($targets.Count -gt 0) {
            $snapshot = @(
                $targets |
                    Select-Object ProcessId, ParentProcessId, Name, CommandLine
            )
            Write-Host "TARGET FOUND:"
            $snapshot | Format-List

            # Python 3.14 の venv launcher と、その直下の base-Python helper の双方が
            # 同じ elevated-ensure 引数を持ち得るため、該当 process をすべて終了する。
            foreach ($target in ($targets | Sort-Object ProcessId -Descending)) {
                Stop-Process -Id $target.ProcessId -Force -ErrorAction SilentlyContinue
            }

            # launcher の直後に base-Python child が生成される競合も潰す。
            for ($attempt = 0; $attempt -lt 10; $attempt++) {
                Start-Sleep -Milliseconds 100
                $remaining = @(
                    Get-CimInstance Win32_Process |
                        Where-Object {
                            $null -ne $_.CommandLine -and
                            $_.CommandLine.Contains("windows_local_mcp.wfp_guard_runtime") -and
                            $_.CommandLine.Contains("--elevated-ensure")
                        }
                )
                if ($remaining.Count -eq 0) {
                    break
                }
                foreach ($target in ($remaining | Sort-Object ProcessId -Descending)) {
                    Stop-Process -Id $target.ProcessId -Force -ErrorAction SilentlyContinue
                }
            }

            $result = [ordered]@{
                diagnostic = "C6.4 elevated WFP helper crash"
                killed_at = [DateTimeOffset]::UtcNow.ToString("o")
                repository_root = $repositoryRoot
                marker = $markerPath
                processes = $snapshot
            }
            break
        }

        Start-Sleep -Milliseconds $PollMilliseconds
    }

    if ($null -eq $result) {
        throw "制限時間内に elevated WFP helper を検出できませんでした。"
    }

    $json = $result | ConvertTo-Json -Depth 6
    $json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Host "C6.4: elevated WFP helper を強制終了しました。"
    Write-Host "Evidence: $resultPath"
    Write-Output $json
}
finally {
    Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    Write-Host "C6.4 marker disarmed."
}
