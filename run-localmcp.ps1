[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Config = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$LocalAppData = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    [Environment]::GetFolderPath("LocalApplicationData")
} else {
    $env:LOCALAPPDATA
}
$StateRoot = Join-Path $LocalAppData "WindowsLocalMCP"
$SelectorPath = Join-Path $StateRoot "active-config.txt"
$DefaultConfigPath = Join-Path $StateRoot "config.toml"
$ServerScript = Join-Path $ScriptRoot "run-server.ps1"

try {
    # The selector is UTF-8, so paths containing Japanese characters survive the
    # batch-to-PowerShell boundary without depending on the active code page.
    if ([string]::IsNullOrWhiteSpace($Config)) {
        if (Test-Path -LiteralPath $SelectorPath -PathType Leaf) {
            $Config = (Get-Content -Raw -Encoding UTF8 -LiteralPath $SelectorPath).Trim()
        }
        if ([string]::IsNullOrWhiteSpace($Config)) {
            $Config = $DefaultConfigPath
        }
    }

    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        Write-Error "設定ファイルが見つかりません。先に start-localmcp.bat を実行してください。" -ErrorAction Continue
        exit 2
    }
    if (-not (Test-Path -LiteralPath $ServerScript -PathType Leaf)) {
        throw "run-server.ps1 が見つかりません。配布パッケージ全体を展開し直してください。"
    }

    $resolvedConfig = (Resolve-Path -LiteralPath $Config).Path
    & $ServerScript -Config $resolvedConfig
    exit $LASTEXITCODE
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
