param(
    [Parameter(Mandatory = $true)]
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Repository virtual environment not found. Run setup first."
}

if ($Config -ne "") {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        throw "Config file does not exist: $Config"
    }
    $env:LOCAL_MCP_CONFIG = (Resolve-Path -LiteralPath $Config).Path
    Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
}

& $Python -m windows_local_mcp.cli approvals
exit $LASTEXITCODE
