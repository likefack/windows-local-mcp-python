param(
    [Parameter(Mandatory = $true)]
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$LauncherRoot = $PSScriptRoot
$ProductionPython = Join-Path $LauncherRoot "runtime\Scripts\python.exe"
$DevelopmentPython = Join-Path $LauncherRoot ".venv\Scripts\python.exe"

if (Test-Path -LiteralPath $ProductionPython -PathType Leaf) {
    $Python = $ProductionPython
} elseif (Test-Path -LiteralPath $DevelopmentPython -PathType Leaf) {
    $Python = $DevelopmentPython
} else {
    throw "No WLMCP runtime found. Install the Approved Host runtime or create the repository .venv."
}

if ($Config -ne "") {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        throw "Config file does not exist: $Config"
    }
    $env:LOCAL_MCP_CONFIG = (Resolve-Path -LiteralPath $Config).Path
    Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
}

& $Python -I -B -m windows_local_mcp.cli approvals
exit $LASTEXITCODE
