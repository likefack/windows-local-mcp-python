param(
    [Parameter(Mandatory = $true)]
    [string]$Config
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
$resolvedConfig = (Resolve-Path -LiteralPath $Config).Path

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Repository virtual environment is missing: $python"
}

& $python -m windows_local_mcp.cli setup-network-isolation --config $resolvedConfig
if ($LASTEXITCODE -ne 0) {
    throw "Safe Tier AppContainer setup failed. No compatibility fallback was enabled."
}
