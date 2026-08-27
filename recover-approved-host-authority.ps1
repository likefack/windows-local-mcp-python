[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$AuthorityStateRoot = (Join-Path $env:ProgramData "WindowsLocalMCP\ApprovedHostAuthority"),
    [switch]$AcknowledgeReviewedState
)

$ErrorActionPreference = "Stop"
$ServiceName = "WindowsLocalMCPApprovedHost"

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
if (-not (Test-Path -LiteralPath $ActiveState -PathType Leaf)) {
    Write-Output "No Approved Host authority active/recovery state exists."
    return
}

Write-Output "Authority state requiring operator review:"
Get-Content -LiteralPath $ActiveState -Raw | Write-Output

if (-not $PSCmdlet.ShouldProcess(
    $ActiveState,
    "clear reviewed Approved Host authority recovery state"
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

# A completion proof from a dead service epoch is never accepted. Remove any abandoned proof
# files together with the reviewed active state before starting a fresh service epoch.
Get-ChildItem -LiteralPath $AuthorityStateRoot -Filter "completion-*.json" -File -ErrorAction SilentlyContinue |
    Remove-Item -Force
Remove-Item -LiteralPath $ActiveState -Force

if ($null -ne $service) {
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )
}

Write-Output "Approved Host authority recovery state cleared after explicit administrator acknowledgement."
Write-Output "If the user-owned control-plane tamper/postflight marker also remains, review that state separately; this script does not erase it."
