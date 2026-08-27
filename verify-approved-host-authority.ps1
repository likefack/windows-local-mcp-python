[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),
    [string]$ConfigPath = $env:LOCAL_MCP_CONFIG,
    [string]$Cwd = "."
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this live verification from the normal non-elevated WLMCP runtime-user token."
}

$Python = Join-Path $InstallRoot "runtime\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Approved Host runtime Python was not found: $Python"
}
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    throw "ConfigPath is required. Pass -ConfigPath or set LOCAL_MCP_CONFIG."
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path

Write-Host "This verification will create and explicitly approve one Approved Host request."
Write-Host "The command is Windows System32 ping.exe against 127.0.0.1 for several seconds."
Write-Host "It also attempts sensitive process/thread/service/state access from this non-elevated token."
$confirmation = Read-Host "Type VERIFY to continue"
if ($confirmation -cne "VERIFY") {
    throw "Live verification cancelled by operator."
}

& $Python -I -B -m windows_local_mcp.approved_host_live_verification `
    --config $ConfigPath `
    --cwd $Cwd `
    --execute
if ($LASTEXITCODE -ne 0) {
    throw "Approved Host authority live verification failed with exit code $LASTEXITCODE."
}

Write-Output "Approved Host authority normal-path live verification PASSED."
Write-Output "This does not by itself close WLMCP-R2-001; run the abnormal worker-loss verification as documented before claiming fixed."
