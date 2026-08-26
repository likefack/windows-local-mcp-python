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

$Probe = 'import json; from windows_local_mcp.runtime_immutability import assert_approved_host_runtime_immutable; print(json.dumps(assert_approved_host_runtime_immutable(), ensure_ascii=False, sort_keys=True))'
& $Python -I -B -c $Probe
if ($LASTEXITCODE -ne 0) {
    throw "Approved Host runtime immutability verification failed."
}

Write-Output "Approved Host runtime immutability verification passed."
