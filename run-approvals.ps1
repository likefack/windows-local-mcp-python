param(
    [Parameter(Mandatory = $false)]
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"

if ($Config -ne "") {
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        throw "設定ファイルが存在しません: $Config"
    }
    $env:LOCAL_MCP_CONFIG = (Resolve-Path -LiteralPath $Config).Path
}

python -m windows_local_mcp.cli approvals
