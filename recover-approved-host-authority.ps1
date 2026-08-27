[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$AuthorityStateRoot = (Join-Path $env:ProgramData "WindowsLocalMCP\ApprovedHostAuthority"),
    [switch]$AcknowledgeReviewedState
)

$ErrorActionPreference = "Stop"
$ServiceName = "WindowsLocalMCPApprovedHost"

function Get-UnixCreateTimeSeconds {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)
    return [DateTimeOffset]::new($Process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000.0
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Approved Host authority recovery must run from an elevated administrator session."
}
if (-not $AcknowledgeReviewedState) {
    throw "Review the active authority state and rerun with -AcknowledgeReviewedState to clear it."
}

$AuthorityStateRoot = [IO.Path]::GetFullPath($AuthorityStateRoot).TrimEnd('\', '/')
$ActiveState = Join-Path $AuthorityStateRoot "active.json"
$StatusState = Join-Path $AuthorityStateRoot "active-status.json"
$CompletedRoot = Join-Path $AuthorityStateRoot "completed"
if (-not (Test-Path -LiteralPath $ActiveState -PathType Leaf)) {
    if (Test-Path -LiteralPath $StatusState -PathType Leaf) {
        throw "Authority status exists without active.json; do not delete it manually. Investigate the inconsistent durable state."
    }
    Write-Output "No Approved Host authority active/recovery state exists."
    return
}

$active = Get-Content -LiteralPath $ActiveState -Raw -Encoding UTF8 | ConvertFrom-Json
$status = $null
if (Test-Path -LiteralPath $StatusState -PathType Leaf) {
    $status = Get-Content -LiteralPath $StatusState -Raw -Encoding UTF8 | ConvertFrom-Json
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

if (-not $PSCmdlet.ShouldProcess(
    $ActiveState,
    "archive and clear reviewed Approved Host authority recovery state"
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

New-Item -ItemType Directory -Path $CompletedRoot -Force | Out-Null
$proofs = @(
    Get-ChildItem -LiteralPath $AuthorityStateRoot -Filter "completion-*.json" -File -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name
)
$recoveryId = "recovery-{0}-{1}.json" -f ([DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")), ([Guid]::NewGuid().ToString("N"))
$recoveryArchive = Join-Path $CompletedRoot $recoveryId
@{
    version = 1
    state = "operator_recovered"
    recovered_at = [DateTimeOffset]::UtcNow.ToString("o")
    service_name = $ServiceName
    active = $active
    status = $status
    abandoned_completion_proofs = $proofs
    acknowledgement = "administrator reviewed durable authority state"
} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $recoveryArchive -Encoding UTF8 -NoNewline

# Proofs/status are subordinate to the immutable latch. Remove the latch last so interruption
# at any earlier point remains fail closed on the next service start.
Get-ChildItem -LiteralPath $AuthorityStateRoot -Filter "completion-*.json" -File -ErrorAction SilentlyContinue |
    Remove-Item -Force
Remove-Item -LiteralPath $StatusState -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ActiveState -Force

if ($null -ne $service) {
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )
}

Write-Output "Approved Host authority recovery state cleared after explicit administrator acknowledgement."
Write-Output "Recovery evidence archived at: $recoveryArchive"
Write-Output "If the user-owned control-plane tamper/postflight marker also remains, review that state separately; this script does not erase it."
