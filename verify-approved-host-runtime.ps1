[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP")
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this verification from the normal non-elevated WLMCP user token."
}

$Python = Join-Path $InstallRoot "runtime\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Approved Host runtime Python was not found: $Python"
}

$Probe = 'import json; from windows_local_mcp.approved_host_policy import verify_approved_host_runtime_immutability_only; print(json.dumps(verify_approved_host_runtime_immutability_only(), ensure_ascii=False, sort_keys=True))'
& $Python -I -B -c $Probe
if ($LASTEXITCODE -ne 0) {
    throw "Approved Host runtime immutability verification failed."
}

Write-Output "Approved Host immutable-runtime verification PASSED."
Write-Output "This check covers only Program Files/runtime immutability. Approved Host execution additionally requires the authenticated LocalSystem authority service and both normal/abnormal Windows live verification before WLMCP-R2-001 can be claimed fixed."
