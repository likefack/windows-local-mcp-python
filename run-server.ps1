param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $false)]
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "作業フォルダが存在しません: $Root"
}

$env:LOCAL_MCP_ROOT = (Resolve-Path -LiteralPath $Root).Path

if ($Config -ne "") {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        throw "設定ファイルが存在しません: $Config"
    }
    $env:LOCAL_MCP_CONFIG = (Resolve-Path -LiteralPath $Config).Path
}

python -m windows_local_mcp.cli server
