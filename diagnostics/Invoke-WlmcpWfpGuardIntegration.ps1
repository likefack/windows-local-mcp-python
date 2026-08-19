[CmdletBinding()]
param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Repository virtual environment not found: $python"
}

# この診断は、通常権限の親からUACを発生させるため、管理者PowerShellからは実行しない。
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "通常権限のPowerShellから実行してください。管理者として開始すると一気通貫経路を証明できません。"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $env:TEMP "wlmcp-wfp-guard-integration-$timestamp"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$resultPath = Join-Path $OutputDirectory "result.json"

Push-Location $repositoryRoot
try {
    # & で起動するPythonも通常権限のまま。UACはPython内のShellExecuteExWが発生させる。
    $output = (& $python -m windows_local_mcp.wfp_guard_runtime --integration-diagnostic 2>&1 | Out-String).TrimEnd()
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

$output | Set-Content -LiteralPath $resultPath -Encoding UTF8
Write-Host "WLMCP WFP Guard integration result: $resultPath"
Write-Output $output
exit $exitCode
