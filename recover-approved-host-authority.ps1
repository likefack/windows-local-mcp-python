[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$AuthorityStateRoot = (Join-Path $env:ProgramData "WindowsLocalMCP\ApprovedHostAuthority"),
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),
    [string]$ConfigPath = $env:LOCAL_MCP_CONFIG,
    [switch]$AcknowledgeReviewedState,
    [switch]$AcknowledgeMissingPostflightMarker
)

$ErrorActionPreference = "Stop"
$ServiceName = "WindowsLocalMCPApprovedHost"
$Python = Join-Path $InstallRoot "runtime\Scripts\python.exe"

function Get-UnixCreateTimeSeconds {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    return [DateTimeOffset]::new($Process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000.0
}

function Invoke-RecoveryPythonJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = & $Python -I -B -m windows_local_mcp.approved_host_recovery @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Approved Host postflight recovery verifier failed with exit code $LASTEXITCODE."
    }
    return (($output -join "`n") | ConvertFrom-Json)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Approved Host authority recovery must run from an elevated administrator session."
}
if (-not $AcknowledgeReviewedState) {
    throw "Review the active authority state and rerun with -AcknowledgeReviewedState to clear it."
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Approved Host immutable runtime Python was not found: $Python"
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    throw "ConfigPath is required so recovery can bind the user-owned postflight marker to the same operation."
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path

$AuthorityStateRoot = [IO.Path]::GetFullPath($AuthorityStateRoot).TrimEnd('\', '/')
$ActiveState = Join-Path $AuthorityStateRoot "active.json"
$StatusState = Join-Path $AuthorityStateRoot "active-status.json"
$CompletedRoot = Join-Path $AuthorityStateRoot "completed"
if (-not (Test-Path -LiteralPath $ActiveState -PathType Leaf)) {
    if (Test-Path -LiteralPath $StatusState -PathType Leaf) {
        throw "Authority status exists without active.json; do not delete it manually. Investigate the inconsistent durable state."
    }
    Write-Output "No Approved Host authority active/recovery state exists."
    Write-Output "If an older recovery already cleared authority state but left a postflight marker, use recover-approved-host-postflight.ps1 with the SYSTEM-owned recovery archive."
    return
}

$active = Get-Content -LiteralPath $ActiveState -Raw -Encoding UTF8 | ConvertFrom-Json
$status = $null
if (Test-Path -LiteralPath $StatusState -PathType Leaf) {
    $status = Get-Content -LiteralPath $StatusState -Raw -Encoding UTF8 | ConvertFrom-Json
}
$operationId = [string]$active.operation_id
if ([string]::IsNullOrWhiteSpace($operationId)) {
    throw "Authority active state contains no operation id."
}

Write-Output "Immutable authority state requiring operator review:"
$active | ConvertTo-Json -Depth 10 | Write-Output
if ($null -ne $status) {
    Write-Output "Authority status sidecar:"
    $status | ConvertTo-Json -Depth 10 | Write-Output
}

# Never clear a latch while the recorded LocalSystem worker identity is still live. The
# recovery action is for an already-lost trusted completion path, not an alternate stop API.
if ($null -ne $status -and $null -ne $status.worker_pid -and $null -ne $status.worker_create_time) {
    $worker = Get-Process -Id ([int]$status.worker_pid) -ErrorAction SilentlyContinue
    if ($null -ne $worker) {
        $actualCreate = Get-UnixCreateTimeSeconds -Process $worker
        $expectedCreate = [double]$status.worker_create_time
        if ([Math]::Abs($actualCreate - $expectedCreate) -le 1.0) {
            $expectedPath = [IO.Path]::GetFullPath([string]$status.worker_executable)
            $actualPath = [IO.Path]::GetFullPath($worker.Path)
            if ($actualPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Recorded Approved Host SYSTEM worker is still live. Recovery refuses to become a monitor-stop mechanism."
            }
        }
    }
}

$postflight = Invoke-RecoveryPythonJson -Arguments @(
    "inspect",
    "--config", $ConfigPath,
    "--operation-id", $operationId
)
Write-Output "Bound user-owned Approved Host postflight recovery state:"
$postflight | ConvertTo-Json -Depth 20 | Write-Output
$hasBoundPostflight = [bool]$postflight.present -or [bool]$postflight.quarantined
if (-not $hasBoundPostflight -and -not $AcknowledgeMissingPostflightMarker) {
    throw "The bound Approved Host postflight marker is missing. Treat absence as possible tamper; review it and rerun only with -AcknowledgeMissingPostflightMarker if intentional."
}

if (-not $PSCmdlet.ShouldProcess(
    $ActiveState,
    "archive and clear reviewed Approved Host authority and bound postflight recovery state"
)) {
    return
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
    Stop-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(30)
    )
}

$recoveryArchive = $null
$archive = $null
try {
    New-Item -ItemType Directory -Path $CompletedRoot -Force | Out-Null
    $proofs = @(
        Get-ChildItem -LiteralPath $AuthorityStateRoot -Filter "completion-*.json" -File -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name
    )
    $recoveryId = "recovery-{0}-{1}.json" -f ([DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")), ([Guid]::NewGuid().ToString("N"))
    $recoveryArchive = Join-Path $CompletedRoot $recoveryId
    $archive = @{
        version = 2
        state = "operator_recovered"
        recovered_at = [DateTimeOffset]::UtcNow.ToString("o")
        service_name = $ServiceName
        active = $active
        status = $status
        abandoned_completion_proofs = $proofs
        postflight_preflight = $postflight
        postflight_quarantine = $null
        acknowledgement = "administrator reviewed durable authority and bound postflight state"
    }
    $archive | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $recoveryArchive -Encoding UTF8 -NoNewline

    # The user-owned postflight marker is subordinate to the independently privileged authority
    # latch. Quarantine the exact reviewed marker first. If this step races, mismatches, or fails,
    # active.json is still present and the product remains fail closed. If a previous recovery was
    # interrupted after quarantine, the immutable runtime verifies that exact digest-bound object
    # and resumes without requiring the operator to weaken the missing-marker rule.
    if ($hasBoundPostflight) {
        $postflightRecovered = Invoke-RecoveryPythonJson -Arguments @(
            "quarantine",
            "--config", $ConfigPath,
            "--operation-id", $operationId,
            "--expected-sha256", ([string]$postflight.marker_identity.sha256)
        )
        $archive.postflight_quarantine = $postflightRecovered
        $archive | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $recoveryArchive -Encoding UTF8 -NoNewline
    }

    # Completion proofs/status and the user-owned postflight marker are subordinate to the
    # immutable SYSTEM latch. Remove active.json last so interruption at every earlier point stays
    # fail closed.
    Get-ChildItem -LiteralPath $AuthorityStateRoot -Filter "completion-*.json" -File -ErrorAction SilentlyContinue |
        Remove-Item -Force
    Remove-Item -LiteralPath $StatusState -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ActiveState -Force
}
finally {
    # A failed recovery remains latched, but it must not strand the authority service stopped.
    # Restarting with active.json still present deterministically returns to recovery_required.
    if ($null -ne $service) {
        $currentService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $currentService -and $currentService.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
            Start-Service -Name $ServiceName
            (Get-Service -Name $ServiceName).WaitForStatus(
                [ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(30)
            )
        }
    }
}

Write-Output "Approved Host authority and bound postflight recovery state cleared after explicit administrator acknowledgement."
Write-Output "Recovery evidence archived at: $recoveryArchive"
if ($hasBoundPostflight) {
    Write-Output "Reviewed postflight marker quarantined at: $($archive.postflight_quarantine.quarantine_path)"
}
Write-Output "Independent control-plane tamper markers are never cleared by this recovery path."
