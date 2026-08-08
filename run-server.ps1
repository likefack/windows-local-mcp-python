 [CmdletBinding(DefaultParameterSetName = "Config")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Root")]
    [string]$Root = "",

    [Parameter(Mandatory = $true, ParameterSetName = "Config")]
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Repository virtual environment not found. Run: py -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e `".[dev]`""
}

if ($Root -ne "") {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "workspace_root does not exist: $Root"
    }
    $env:LOCAL_MCP_ROOT = (Resolve-Path -LiteralPath $Root).Path
    Remove-Item Env:LOCAL_MCP_CONFIG -ErrorAction SilentlyContinue
}

if ($Config -ne "") {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        throw "Config file does not exist: $Config"
    }
    $env:LOCAL_MCP_CONFIG = (Resolve-Path -LiteralPath $Config).Path
    Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
}

& $Python -m windows_local_mcp.cli server
exit $LASTEXITCODE
