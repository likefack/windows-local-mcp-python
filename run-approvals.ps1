param(
    [string]$Config = "",
    [switch]$FunctionsOnly
)

$ErrorActionPreference = "Stop"
$LauncherRoot = $PSScriptRoot
$ProductionPython = Join-Path $LauncherRoot "runtime\Scripts\python.exe"
$DevelopmentPython = Join-Path $LauncherRoot ".venv\Scripts\python.exe"

function Get-ApprovalConfigMutexName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    # 絶対 path を大文字化してハッシュ化し、同じ設定の手動起動と自動起動が
    # 同じ名前付き Mutex を共有できるようにします。秘密情報はこの値に含めません。
    $canonical = [IO.Path]::GetFullPath($ConfigPath).ToUpperInvariant()
    $encoding = [Text.UTF8Encoding]::new($false)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($encoding.GetBytes($canonical))
        $hex = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
    return "Local\WindowsLocalMCP-ApprovalUI-$hex"
}

if ($FunctionsOnly) { return }

if ([string]::IsNullOrWhiteSpace($Config)) {
    $Config = $env:LOCAL_MCP_CONFIG
}
if ([string]::IsNullOrWhiteSpace($Config)) {
    throw "設定ファイルを -Config で指定してください。"
}
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    throw "設定ファイルが見つかりません: $Config"
}
$resolvedConfig = (Resolve-Path -LiteralPath $Config -ErrorAction Stop).Path
$env:LOCAL_MCP_CONFIG = $resolvedConfig
Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue

if (Test-Path -LiteralPath $ProductionPython -PathType Leaf) {
    $Python = $ProductionPython
} elseif (Test-Path -LiteralPath $DevelopmentPython -PathType Leaf) {
    $Python = $DevelopmentPython
} else {
    throw "WLMCP runtime が見つかりません。Approved Host runtime を導入するか、リポジトリの .venv を作成してください。"
}

try { $Host.UI.RawUI.WindowTitle = "Windows Local MCP - ローカル承認" } catch { }

$mutexName = Get-ApprovalConfigMutexName -ConfigPath $resolvedConfig
$mutex = [Threading.Mutex]::new($false, $mutexName)
$ownsMutex = $false
$exitCode = 0
try {
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        # 前のUIが異常終了して解放されなかった場合も、このプロセスが所有権を
        # 引き継いでいるため、通常どおりUIを起動できます。
        $ownsMutex = $true
    }
    if (-not $ownsMutex) {
        Write-Host "同じ設定のローカル承認UIは既に起動しています。重複起動を行いません。"
    } else {
        & $Python -I -B -m windows_local_mcp.cli approvals
        $exitCode = $LASTEXITCODE
    }
} finally {
    if ($ownsMutex) {
        try { $mutex.ReleaseMutex() } catch { }
    }
    $mutex.Dispose()
}
exit $exitCode
