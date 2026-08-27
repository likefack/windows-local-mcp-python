[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Arm", "KillAndRestart", "Check")]
    [string]$Phase,

    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),
    [string]$ConfigPath = $env:LOCAL_MCP_CONFIG,
    [string]$Cwd = ".",
    [string]$HandoffPath = (Join-Path $env:TEMP "wlmcp-r2-001-abnormal.json")
)

$ErrorActionPreference = "Stop"
$ServiceName = "WindowsLocalMCPApprovedHost"
$Python = Join-Path $InstallRoot "runtime\Scripts\python.exe"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NonElevatedRuntimeUser {
    if (Test-IsAdministrator) {
        throw "$Phase must run from the normal non-elevated WLMCP runtime-user token."
    }
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw "$Phase must run from an elevated Administrator PowerShell session."
    }
}

function Get-UnixCreateTimeSeconds {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    return [DateTimeOffset]::new($Process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000.0
}

function Assert-WorkerIdentity {
    param([Parameter(Mandatory = $true)]$Handoff)
    $pidValue = [int]$Handoff.worker_pid
    $process = Get-Process -Id $pidValue -ErrorAction Stop
    $actualCreate = Get-UnixCreateTimeSeconds -Process $process
    $expectedCreate = [double]$Handoff.worker_create_time
    if ([Math]::Abs($actualCreate - $expectedCreate) -gt 1.0) {
        throw "SYSTEM worker PID was reused before fault injection: PID=$pidValue"
    }
    $actualPath = [IO.Path]::GetFullPath($process.Path)
    $expectedPath = [IO.Path]::GetFullPath([string]$Handoff.worker_executable)
    if (-not $actualPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "SYSTEM worker executable identity changed: expected=$expectedPath actual=$actualPath"
    }
    return $process
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Approved Host runtime Python was not found: $Python"
}

switch ($Phase) {
    "Arm" {
        Assert-NonElevatedRuntimeUser
        if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
            throw "ConfigPath is required. Pass -ConfigPath or set LOCAL_MCP_CONFIG."
        }
        $ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
        $confirmation = Read-Host "This will approve one WMIC Win32_Process.Create Host operation. Type ARM to continue"
        if ($confirmation -cne "ARM") {
            throw "Abnormal verification arm phase cancelled by operator."
        }
        & $Python -I -B -m windows_local_mcp.approved_host_abnormal_verification `
            arm `
            --config $ConfigPath `
            --cwd $Cwd `
            --handoff $HandoffPath
        if ($LASTEXITCODE -ne 0) {
            throw "Abnormal verification arm phase failed with exit code $LASTEXITCODE."
        }
        Write-Output "Arm phase PASSED."
        Write-Output "The handoff file records a live LocalSystem worker and an observed requester-user Win32_Process.Create helper."
        Write-Output "Next run this script as Administrator with -Phase KillAndRestart -HandoffPath `"$HandoffPath`"."
    }

    "KillAndRestart" {
        Assert-Administrator
        $HandoffPath = (Resolve-Path -LiteralPath $HandoffPath).Path
        $handoff = Read-JsonFile -Path $HandoffPath
        $stateRoot = [IO.Path]::GetFullPath([string]$handoff.authority_state_root)
        $activePath = Join-Path $stateRoot "active.json"
        $statusPath = Join-Path $stateRoot "active-status.json"
        if (-not (Test-Path -LiteralPath $activePath -PathType Leaf)) {
            throw "Immutable authority active latch is missing before fault injection: $activePath"
        }
        $activeBeforeHash = (Get-FileHash -LiteralPath $activePath -Algorithm SHA256).Hash

        $worker = Assert-WorkerIdentity -Handoff $handoff
        $confirmation = Read-Host "Type KILL to terminate only the verified LocalSystem worker and restart the service"
        if ($confirmation -cne "KILL") {
            throw "Fault injection cancelled by operator."
        }
        Stop-Process -Id $worker.Id -Force
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while ((Get-Process -Id $worker.Id -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (Get-Process -Id $worker.Id -ErrorAction SilentlyContinue) {
            throw "SYSTEM worker did not terminate after fault injection."
        }

        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        $status = $null
        while ([DateTime]::UtcNow -lt $deadline) {
            if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
                $status = Read-JsonFile -Path $statusPath
                if ([string]$status.state -eq "recovery_required") {
                    break
                }
            }
            Start-Sleep -Milliseconds 100
        }
        if ($null -eq $status -or [string]$status.state -ne "recovery_required") {
            throw "Authority watcher did not persist recovery_required after SYSTEM worker loss."
        }
        if (-not (Test-Path -LiteralPath $activePath -PathType Leaf)) {
            throw "Immutable authority latch disappeared after worker loss."
        }
        $activeAfterKillHash = (Get-FileHash -LiteralPath $activePath -Algorithm SHA256).Hash
        if ($activeAfterKillHash -cne $activeBeforeHash) {
            throw "Immutable authority active latch changed after worker loss."
        }

        Restart-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(30)
        )
        Start-Sleep -Milliseconds 500
        if (-not (Test-Path -LiteralPath $activePath -PathType Leaf)) {
            throw "Authority active latch disappeared across service restart."
        }
        $activeAfterRestartHash = (Get-FileHash -LiteralPath $activePath -Algorithm SHA256).Hash
        if ($activeAfterRestartHash -cne $activeBeforeHash) {
            throw "Immutable authority active latch changed across service restart."
        }
        $status = Read-JsonFile -Path $statusPath
        if ([string]$status.state -ne "recovery_required") {
            throw "Authority restart did not retain recovery_required state."
        }

        $adminEvidencePath = "$HandoffPath.admin.json"
        @{
            version = 1
            operation_id = [string]$handoff.operation_id
            worker_pid = [int]$handoff.worker_pid
            worker_identity_verified_before_kill = $true
            active_hash_before = $activeBeforeHash
            active_hash_after_kill = $activeAfterKillHash
            active_hash_after_restart = $activeAfterRestartHash
            recovery_state_after_kill = "recovery_required"
            recovery_state_after_restart = [string]$status.state
            service_restarted = $true
            verified_at = [DateTimeOffset]::UtcNow.ToString("o")
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $adminEvidencePath -Encoding UTF8

        Write-Output "KillAndRestart phase PASSED."
        Write-Output "The same immutable active latch survived worker termination and service restart."
        Write-Output "Next return to the normal non-elevated runtime-user session and run -Phase Check."
    }

    "Check" {
        Assert-NonElevatedRuntimeUser
        $HandoffPath = (Resolve-Path -LiteralPath $HandoffPath).Path
        $adminEvidencePath = "$HandoffPath.admin.json"
        if (-not (Test-Path -LiteralPath $adminEvidencePath -PathType Leaf)) {
            throw "Administrator fault-injection evidence is missing: $adminEvidencePath"
        }
        & $Python -I -B -m windows_local_mcp.approved_host_abnormal_verification `
            check `
            --handoff $HandoffPath
        if ($LASTEXITCODE -ne 0) {
            throw "Abnormal verification check phase failed with exit code $LASTEXITCODE."
        }
        Write-Output "Abnormal worker-loss/WMI/restart/legacy-approval verification PASSED."
        Write-Output "The authority intentionally remains recovery_required. Review the evidence before running recover-approved-host-authority.ps1."
    }
}
