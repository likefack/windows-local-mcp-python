[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)]
    [string]$AuthorityRecoveryArchive,

    [string]$AuthorityStateRoot = (Join-Path $env:ProgramData "WindowsLocalMCP\ApprovedHostAuthority"),
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),
    [string]$ConfigPath = $env:LOCAL_MCP_CONFIG,
    [switch]$AcknowledgeReviewedState
)

$ErrorActionPreference = "Stop"
$ServiceName = "WindowsLocalMCPApprovedHost"
$Python = Join-Path $InstallRoot "runtime\Scripts\python.exe"

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
    throw "Legacy Approved Host postflight recovery must run from an elevated administrator session."
}
if (-not $AcknowledgeReviewedState) {
    throw "Review the prior SYSTEM-owned recovery archive and rerun with -AcknowledgeReviewedState."
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Approved Host immutable runtime Python was not found: $Python"
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    throw "ConfigPath is required to locate and validate the bound postflight marker."
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path

$AuthorityStateRoot = [IO.Path]::GetFullPath($AuthorityStateRoot).TrimEnd('\', '/')
$ActiveState = Join-Path $AuthorityStateRoot "active.json"
$StatusState = Join-Path $AuthorityStateRoot "active-status.json"
$CompletedRoot = Join-Path $AuthorityStateRoot "completed"
if (Test-Path -LiteralPath $ActiveState -PathType Leaf) {
    throw "Authority active.json still exists. Use recover-approved-host-authority.ps1 so the SYSTEM latch remains the last-cleared boundary."
}
if (Test-Path -LiteralPath $StatusState -PathType Leaf) {
    throw "Authority status exists without active.json. Investigate the inconsistent durable state instead of using compatibility recovery."
}

$completedResolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $CompletedRoot).Path).TrimEnd('\', '/')
$archiveResolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $AuthorityRecoveryArchive).Path)
$completedPrefix = $completedResolved + [IO.Path]::DirectorySeparatorChar
if (-not $archiveResolved.StartsWith($completedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Authority recovery archive must be a file under the protected ApprovedHostAuthority\completed directory."
}
$archiveItem = Get-Item -LiteralPath $archiveResolved -Force
if ($archiveItem.PSIsContainer) {
    throw "Authority recovery archive is not a file."
}
if (($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Authority recovery archive must not be a reparse point."
}
$priorRecovery = Get-Content -LiteralPath $archiveResolved -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$priorRecovery.version -ne 1 -or [string]$priorRecovery.state -cne "operator_recovered") {
    throw "Compatibility recovery accepts only the historical version-1 operator recovery archive."
}
$operationId = [string]$priorRecovery.active.operation_id
if ([string]::IsNullOrWhiteSpace($operationId)) {
    throw "Historical recovery archive contains no active operation id."
}
if ([string]$priorRecovery.status.state -cne "recovery_required") {
    throw "Historical recovery archive does not record recovery_required authority state."
}
if ([string]$priorRecovery.status.operation_id -cne $operationId) {
    throw "Historical recovery archive active/status operation binding is inconsistent."
}
if ([string]$priorRecovery.acknowledgement -cne "administrator reviewed durable authority state") {
    throw "Historical recovery archive does not contain the expected administrator acknowledgement."
}

Write-Output "Historical SYSTEM-owned authority recovery archive requiring compatibility completion:"
$priorRecovery | ConvertTo-Json -Depth 20 | Write-Output

$postflight = Invoke-RecoveryPythonJson -Arguments @(
    "inspect",
    "--config", $ConfigPath,
    "--operation-id", $operationId
)
Write-Output "Bound user-owned Approved Host postflight recovery state:"
$postflight | ConvertTo-Json -Depth 20 | Write-Output
$hasBoundPostflight = [bool]$postflight.present -or [bool]$postflight.quarantined
if (-not $hasBoundPostflight) {
    throw "No bound postflight marker or resumable quarantine exists for the historical recovery operation. Do not clear anything manually."
}

if (-not $PSCmdlet.ShouldProcess(
    [string]$postflight.marker_path,
    "complete historical Approved Host recovery by quarantining the exact reviewed postflight marker"
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

$compatibilityId = "postflight-recovery-{0}-{1}.json" -f ([DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")), ([Guid]::NewGuid().ToString("N"))
$compatibilityArchive = Join-Path $CompletedRoot $compatibilityId
$compatibilityEvidence = @{
    version = 1
    state = "postflight_recovery_in_progress"
    started_at = [DateTimeOffset]::UtcNow.ToString("o")
    service_name = $ServiceName
    operation_id = $operationId
    authority_recovery_archive = $archiveResolved
    authority_recovery_archive_sha256 = (Get-FileHash -LiteralPath $archiveResolved -Algorithm SHA256).Hash
    postflight_preflight = $postflight
    postflight_quarantine = $null
    acknowledgement = "administrator reviewed historical split recovery state"
}
$compatibilityEvidence | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $compatibilityArchive -Encoding UTF8 -NoNewline

try {
    $recovered = Invoke-RecoveryPythonJson -Arguments @(
        "quarantine",
        "--config", $ConfigPath,
        "--operation-id", $operationId,
        "--expected-sha256", ([string]$postflight.marker_identity.sha256)
    )
    $compatibilityEvidence.state = "postflight_recovery_completed"
    $compatibilityEvidence.completed_at = [DateTimeOffset]::UtcNow.ToString("o")
    $compatibilityEvidence.postflight_quarantine = $recovered
    $compatibilityEvidence | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $compatibilityArchive -Encoding UTF8 -NoNewline
}
finally {
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

Write-Output "Historical split Approved Host recovery completed after explicit administrator acknowledgement."
Write-Output "Compatibility recovery evidence archived at: $compatibilityArchive"
Write-Output "Reviewed postflight marker quarantined at: $($compatibilityEvidence.postflight_quarantine.quarantine_path)"
Write-Output "Future recoveries must use the coordinated recover-approved-host-authority.ps1 path."
