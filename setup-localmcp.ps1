[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$LocalAppData = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { [Environment]::GetFolderPath("LocalApplicationData") } else { $env:LOCALAPPDATA }
$StateRoot = Join-Path $LocalAppData "WindowsLocalMCP"
$DefaultConfigPath = Join-Path $StateRoot "config.toml"
$SelectorPath = Join-Path $StateRoot "active-config.txt"
$MinimumPython = [Version]::new(3, 11)
$PythonWindowsDownloadUrl = "https://www.python.org/downloads/windows/"
$CodexCliDocsUrl = "https://developers.openai.com/codex/cli/"

try {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
} catch {
    # コンソールのエンコーディングを変更できない環境でも導入処理は続けます。
}

function Write-Title {
    param([string]$Message)
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Gray
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[注意] $Message" -ForegroundColor Yellow
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,
        [bool]$Default = $true
    )

    $suffix = if ($Default) { " [Y/n]" } else { " [y/N]" }
    $answer = (Read-Host "$Prompt$suffix").Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Default
    }
    return $answer -in @("y", "yes")
}

function ConvertTo-TomlString {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Test-PathInside {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $candidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    return $candidatePath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith($parentPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Get-PythonVersion {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    try {
        $output = & $PythonPath -I -B -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>&1
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        $text = ($output | Select-Object -Last 1).ToString().Trim()
        return [Version]$text
    } catch {
        return $null
    }
}

function Find-Python {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @(
        (Join-Path $ScriptRoot ".venv\Scripts\python.exe"),
        (Join-Path $ScriptRoot "runtime\Scripts\python.exe")
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $candidates.Add((Resolve-Path -LiteralPath $path).Path)
        }
    }

    foreach ($commandName in @("python.exe", "python", "py.exe", "py")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $command -and $command.Source) {
            $candidates.Add($command.Source)
        }
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        $version = Get-PythonVersion -PythonPath $candidate
        if ($null -ne $version -and $version -ge $MinimumPython) {
            return [PSCustomObject]@{ Path = $candidate; Version = $version }
        }
    }
    return $null
}

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = & $PythonPath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $details = ($output | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($details)) {
            $details = "終了コード $exitCode"
        }
        throw "Python の処理に失敗しました: $details"
    }
    return $output
}

function Test-WlmcpImport {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    try {
        $null = & $PythonPath -I -B -c "import windows_local_mcp" 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Show-PythonInstallGuidance {
    Write-Host ""
    Write-Warn "Python 3.11 以上が見つかりません。"
    Write-Host "Python の公式ダウンロードページ:" -ForegroundColor Yellow
    Write-Host "  $PythonWindowsDownloadUrl" -ForegroundColor Cyan
    Write-Host "Windows 用の Python 3.11 以上をインストールし、完了後に新しく PowerShell を開いてください。"
    Write-Host "確認できたら、この画面を閉じて start-localmcp.bat をもう一度実行します。"
    Write-Host "会社や学校の PC でインストールできない場合は、管理者または PC の管理担当者に相談してください。"
}

function Show-PythonRecoveryGuidance {
    Write-Host ""
    Write-Warn "Python の専用環境を準備できませんでした。"
    Write-Host "ネットワーク接続と、Python 3.11 以上を実行できることを確認してから再実行してください。"
    Write-Host "手動で試す場合は、配布フォルダーで次を実行します:" -ForegroundColor Yellow
    Write-Host "  py -3.11 -m venv .venv" -ForegroundColor Gray
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -e ." -ForegroundColor Gray
    Write-Host "Python の入手先: $PythonWindowsDownloadUrl" -ForegroundColor Cyan
}

function Ensure-PythonRuntime {
    Write-Info "Python 3.11 以上と Windows Local MCP の導入状態を確認しています。"

    $python = Find-Python
    if ($null -ne $python -and (Test-WlmcpImport -PythonPath $python.Path)) {
        Write-Ok "使用する Python: $($python.Path) ($($python.Version))"
        return $python
    }

    $venvPath = Join-Path $ScriptRoot ".venv"
    $basePython = $null
    foreach ($commandName in @("py.exe", "py", "python.exe", "python")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $command -or -not $command.Source) {
            continue
        }
        $candidateVersion = Get-PythonVersion -PythonPath $command.Source
        if ($null -ne $candidateVersion -and $candidateVersion -ge $MinimumPython) {
            $basePython = [PSCustomObject]@{ Path = $command.Source; Version = $candidateVersion }
            break
        }
    }

    if ($null -eq $basePython) {
        Show-PythonInstallGuidance
        throw "Python 3.11 以上を準備してから再実行してください。"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $ScriptRoot "pyproject.toml") -PathType Leaf)) {
        throw "pyproject.toml が見つかりません。このバッチはリリースパッケージまたはリポジトリのルートから実行してください。"
    }

    if (-not (Test-Path -LiteralPath (Join-Path $venvPath "Scripts\python.exe") -PathType Leaf)) {
        try {
            Write-Info "専用の .venv を作成しています。"
            if ($basePython.Path -match "\\py(?:\.exe)?$") {
                Invoke-Python -PythonPath $basePython.Path -Arguments @("-3.11", "-m", "venv", $venvPath) | Out-Host
            } else {
                Invoke-Python -PythonPath $basePython.Path -Arguments @("-m", "venv", $venvPath) | Out-Host
            }
        } catch {
            Show-PythonRecoveryGuidance
            throw
        }
    }

    $venvPythonPath = Join-Path $venvPath "Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $venvPythonPath -PathType Leaf)) {
        throw ".venv の Python が作成されませんでした: $venvPythonPath"
    }

    try {
        Write-Info "依存パッケージをインストールしています。ネットワーク接続が必要です。"
        Invoke-Python -PythonPath $venvPythonPath -Arguments @("-I", "-B", "-m", "pip", "install", "-e", $ScriptRoot) | Out-Host
        if (-not (Test-WlmcpImport -PythonPath $venvPythonPath)) {
            throw "Windows Local MCP を import できません。依存パッケージの導入結果を確認してください。"
        }
    } catch {
        Show-PythonRecoveryGuidance
        throw
    }

    $version = Get-PythonVersion -PythonPath $venvPythonPath
    Write-Ok "専用 Python を準備しました: $venvPythonPath ($version)"
    return [PSCustomObject]@{ Path = $venvPythonPath; Version = $version }
}

function Read-WorkspacePath {
    Write-Host ""
    Write-Host "MCP から操作したいプロジェクトのフォルダーを指定します。" -ForegroundColor Cyan
    Write-Host "場所の調べ方: エクスプローラーでそのフォルダーを開き、上のアドレスバーをクリックして Ctrl+C。"
    Write-Host "この画面に戻って Ctrl+V で貼り付けます。フォルダー名までを指定し、ファイル名は入力しません。"
    Write-Host "例: C:\Users\あなたの名前\Documents\my-project" -ForegroundColor Gray

    while ($true) {
        $value = (Read-Host "操作対象フォルダーの場所").Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Warn "操作対象フォルダーの場所は必須です。"
            continue
        }

        try {
            $item = Get-Item -LiteralPath $value -Force -ErrorAction Stop
        } catch {
            Write-Warn "フォルダーが見つかりません: $value"
            continue
        }
        if (-not $item.PSIsContainer) {
            Write-Warn "フォルダーを指定してください。"
            continue
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-Warn "ショートカットや junction など、実体を別の場所へ見せるフォルダーは指定できません。"
            continue
        }

        $resolved = $item.FullName.TrimEnd('\', '/')
        $root = [IO.Path]::GetPathRoot($resolved).TrimEnd('\', '/')
        if ($resolved.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warn "ドライブ直下ではなく、プロジェクトのフォルダーを指定してください。"
            continue
        }
        if (Test-PathInside -Candidate $resolved -Parent $StateRoot) {
            Write-Warn "$StateRoot の中は操作対象にできません。設定・監査用の場所と分けてください。"
            continue
        }
        return $resolved
    }
}

function Find-ExistingConfig {
    $candidates = @(
        $DefaultConfigPath,
        (Join-Path $ScriptRoot "config.local.toml"),
        (Join-Path $ScriptRoot "config.toml"),
        (Join-Path $ScriptRoot ".local-mcp\config.toml")
    )
    if (Test-Path -LiteralPath $SelectorPath -PathType Leaf) {
        $selected = (Get-Content -Raw -Encoding UTF8 -LiteralPath $SelectorPath).Trim()
        if (-not [string]::IsNullOrWhiteSpace($selected)) {
            $candidates = @($selected) + $candidates
        }
    }
    return @(
        $candidates |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
            ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
            Select-Object -Unique
    )
}

function Select-ExistingConfig {
    $candidates = @(Find-ExistingConfig)
    if ($candidates.Count -gt 0) {
        Write-Host ""
        Write-Host "検出した設定ファイル:" -ForegroundColor Cyan
        for ($index = 0; $index -lt $candidates.Count; $index++) {
            Write-Host ("  {0}. {1}" -f ($index + 1), $candidates[$index])
        }
    } else {
        Write-Host ""
        Write-Host "検出済みの設定ファイルはありません。既存 config.toml のパスを指定してください。" -ForegroundColor Yellow
    }

    $selectionPrompt = if ($candidates.Count -gt 0) {
        "使う番号、または config のパス（空欄で 1 番）"
    } else {
        "既存 config.toml のパス"
    }
    $selection = (Read-Host $selectionPrompt).Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($selection)) {
        if ($candidates.Count -gt 0) {
            return $candidates[0]
        }
        throw "既存の config.toml のパスが指定されていません。"
    }
    if ($selection -match "^\d+$" -and [int]$selection -ge 1 -and [int]$selection -le $candidates.Count) {
        return $candidates[[int]$selection - 1]
    }
    if (Test-Path -LiteralPath $selection -PathType Leaf) {
        return (Resolve-Path -LiteralPath $selection).Path
    }
    throw "設定ファイルが見つかりません: $selection"
}

function Find-TrustedGit {
    $candidates = @()
    foreach ($programFiles in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
        if ([string]::IsNullOrWhiteSpace($programFiles)) {
            continue
        }
        $candidates += Join-Path $programFiles "Git\mingw64\bin\git.exe"
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $resolved = (Resolve-Path -LiteralPath $candidate).Path
            return [PSCustomObject]@{
                Path = $resolved
                Hash = Get-Sha256 -Path $resolved
            }
        }
    }
    return $null
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [IO.File]::OpenRead($Path)
        $bytes = $algorithm.ComputeHash($stream)
        return ([BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        $algorithm.Dispose()
    }
}

function New-ConfigContent {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspacePath,
        [PSCustomObject]$GitInfo
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# start-localmcp.bat が生成したローカル設定です。")
    $lines.Add("# workspace の中には置かず、秘密情報も保存しないでください。")
    $lines.Add("workspace_root = $(ConvertTo-TomlString -Value $WorkspacePath)")
    $lines.Add('data_dir = ""')
    $lines.Add("filesystem_enabled = true")
    $lines.Add("git_enabled = true")
    $lines.Add("flutter_enabled = false")
    $lines.Add("dart_enabled = false")
    $lines.Add("adb_enabled = false")
    $lines.Add("powershell_enabled = false")
    $lines.Add("approved_sandbox_enabled = true")
    $lines.Add('approved_sandbox_backend = "codex_cli"')
    $lines.Add('approved_sandbox_windows_mode = "elevated"')
    $lines.Add('approved_sandbox_permission_profile = ":workspace"')
    $lines.Add("approved_sandbox_require_live_verification = true")
    $lines.Add("approved_host_enabled = true")
    $lines.Add("adb_emulator_only = true")
    $lines.Add("adb_allowed_serials = []")
    $lines.Add("protect_data_dir_acl = true")
    $lines.Add("http_enabled = false")
    $lines.Add("http_multi_principal_enabled = false")
    if ($null -ne $GitInfo) {
        $lines.Add("git_executable_path = $(ConvertTo-TomlString -Value $GitInfo.Path)")
        $lines.Add("git_executable_sha256 = `"$($GitInfo.Hash)`"")
    } else {
        $lines.Add('git_executable_path = ""')
        $lines.Add('git_executable_sha256 = ""')
    }
    return ($lines -join [Environment]::NewLine) + [Environment]::NewLine
}

function Save-Config {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Path
    )

    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backup = "$Path.backup-$stamp"
        Copy-Item -LiteralPath $Path -Destination $backup -ErrorAction Stop
        Write-Info "既存設定をバックアップしました: $backup"
    }
    $temporary = "$Path.tmp-$PID-$([Guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-ActiveConfig {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    $temporary = "$SelectorPath.tmp-$PID-$([Guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText($temporary, $ConfigPath + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $SelectorPath -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-Configuration {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    Write-Info "設定と操作対象フォルダーの境界を確認しています。"
    $previousConfig = $env:LOCAL_MCP_CONFIG
    $previousRoot = $env:LOCAL_MCP_ROOT
    try {
        $env:LOCAL_MCP_CONFIG = $ConfigPath
        Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        $probe = @(
            "from windows_local_mcp.config import load_settings",
            "settings = load_settings()",
            "print('workspace_root=' + str(settings.workspace_root))",
            "print('data_dir=' + str(settings.data_dir))",
            "print('sandbox_scratch_dir=' + str(settings.sandbox_scratch_dir))"
        ) -join "; "
        $output = Invoke-Python -PythonPath $PythonPath -Arguments @("-I", "-B", "-c", $probe)
        $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } finally {
        if ($null -eq $previousConfig) {
            Remove-Item Env:LOCAL_MCP_CONFIG -ErrorAction SilentlyContinue
        } else {
            $env:LOCAL_MCP_CONFIG = $previousConfig
        }
        if ($null -eq $previousRoot) {
            Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        } else {
            $env:LOCAL_MCP_ROOT = $previousRoot
        }
    }
    Write-Ok "設定ファイルの検証が完了しました。"
}

function Find-CodexCli {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $command = Get-Command codex.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command -and $command.Source) {
        $null = $candidates.Add($command.Source)
    }

    $cacheRoot = Join-Path $LocalAppData "OpenAI\Codex\bin"
    if (Test-Path -LiteralPath $cacheRoot -PathType Container) {
        foreach ($versionDirectory in @(Get-ChildItem -LiteralPath $cacheRoot -Directory -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)) {
            $null = $candidates.Add((Join-Path $versionDirectory.FullName "codex.exe"))
        }
    }
    $null = $candidates.Add((Join-Path $LocalAppData "Programs\OpenAI\Codex\bin\codex.exe"))
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $candidates.Add((Join-Path $env:USERPROFILE ".codex\packages\standalone\current\bin\codex.exe"))
        $null = $candidates.Add((Join-Path $env:USERPROFILE ".codex\packages\standalone\current\codex.exe"))
    }

    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        try {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        } catch {
            # 候補がない、または検証できない場合は次の候補を確認します。
        }
    }
    return $null
}

function Show-OptionalChecks {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    $git = Find-TrustedGit
    if ($null -ne $git) {
        Write-Ok "Git runtime を検出しました。SHA-256 を設定しました。"
    } else {
        Write-Warn "Git runtime は自動設定していません。Automatic Git は明示的な path/hash と実機検証が必要です。"
    }

    $codex = Find-CodexCli
    if ($null -eq $codex) {
        Write-Warn "Codex CLI の実行ファイルが見つかりませんでした。"
        Write-Host "ファイルの読み書きはこのまま利用できます。Python、テスト、ビルドなどの Sandbox 経路はまだ利用できません。" -ForegroundColor Yellow
        Write-Host "導入案内（OpenAI 公式）: $CodexCliDocsUrl" -ForegroundColor Cyan
        Write-Host "導入後に start-localmcp.bat を再実行してください。手動設定では approved_sandbox_codex_path に codex.exe の絶対パスを指定できます。"
    } else {
        Write-Info "Codex CLI の実行ファイル候補を検出しました: $codex"
        Write-Info "実行時には署名・ハッシュ・実体の識別情報を再確認します。検出だけでは Sandbox 利用可能とは判定しません。"
        Write-Info "Sandbox のライブ検証は通常の操作から自動実行せず、必要時に明示します。"
    }

    $adbRoots = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $adb = $adbRoots | ForEach-Object { Join-Path $_ "platform-tools\adb.exe" } | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1
    if ($null -ne $adb) {
        Write-Warn "ADB は検出しましたが、許可する emulator serial を確認していないため自動有効化していません。"
    }
    Write-Info "設定ファイル: $ConfigPath"
}

function Show-ManualConfigGuidance {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    Write-Host ""
    Write-Host "設定を手動で変更する場合:" -ForegroundColor Cyan
    Write-Host "1. 次の config.toml をメモ帳やエディターで開きます。"
    Write-Host "   $ConfigPath" -ForegroundColor Gray
    Write-Host "2. workspace_root は MCP から操作したいフォルダー、data_dir はその外側の保存場所です。"
    Write-Host "3. 保存後、次のコマンドで設定を検証して起動します。"
    Write-Host "   run-localmcp.bat -Config '$ConfigPath'" -ForegroundColor Gray
    Write-Host "別の設定ファイルへ切り替える場合は、start-localmcp.bat の「既存の設定を使う」を選択します。"
    Write-Host "active-config.txt はこのウィザードが管理するため、通常は直接編集しません。"
}

try {
    Write-Title "Windows Local MCP セットアップ"
    Write-Host "この画面では、設定ファイルを作成または既存設定を診断します。"
    Write-Host "通常のサーバーは管理者権限で起動しません。"

    $existing = @(Find-ExistingConfig)
    Write-Host ""
    Write-Host "1. かんたんセットアップ（必要なものを確認して新しい設定を作る）"
    if ($existing.Count -gt 0) {
        Write-Host "2. 既存の設定を使う（設定ファイルを確認して利用する）"
    } else {
        Write-Host "2. 既存の設定を使う（config.toml の場所を指定する）"
    }
    Write-Host "0. 終了"
    $mode = (Read-Host "番号").Trim()

    if ($mode -eq "0") {
        Write-Info "終了しました。"
        exit 0
    }
    if ($mode -eq "2") {
        $configPath = Select-ExistingConfig
        $python = Ensure-PythonRuntime
        Test-Configuration -PythonPath $python.Path -ConfigPath $configPath
        Set-ActiveConfig -ConfigPath $configPath
        Write-Ok "既存設定を通常起動の対象にしました。"
    } elseif ($mode -eq "1") {
        $workspacePath = Read-WorkspacePath
        $python = Ensure-PythonRuntime
        $gitInfo = Find-TrustedGit
        $content = New-ConfigContent -WorkspacePath $workspacePath -GitInfo $gitInfo
        Save-Config -Content $content -Path $DefaultConfigPath
        Test-Configuration -PythonPath $python.Path -ConfigPath $DefaultConfigPath
        Set-ActiveConfig -ConfigPath $DefaultConfigPath
        $configPath = $DefaultConfigPath
        Show-OptionalChecks -ConfigPath $configPath
        Write-Ok "初回設定が完了しました。"
    } else {
        throw "メニューの番号が正しくありません。"
    }

    Write-Host ""
    Show-ManualConfigGuidance -ConfigPath $configPath
    Write-Host "次回からは run-localmcp.bat を実行してください。" -ForegroundColor Cyan
    Write-Host "Secure MCP Tunnel には、引き続き次の明示的な起動引数を登録します:" -ForegroundColor Gray
    Write-Host "powershell.exe -NoProfile -File `"$ScriptRoot\run-server.ps1`" -Config `"$configPath`"" -ForegroundColor Gray
    Write-Host ""
    if (Read-YesNo -Prompt "今すぐサーバーを起動しますか" -Default $true) {
        $runBatch = Join-Path $ScriptRoot "run-localmcp.bat"
        if (-not (Test-Path -LiteralPath $runBatch -PathType Leaf)) {
            throw "run-localmcp.bat が見つかりません。"
        }
        & $runBatch
        exit $LASTEXITCODE
    }
    exit 0
} catch {
    Write-Host ""
    Write-Host "[失敗] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "設定は既存ファイルを上書きせず、作成途中の一時ファイルだけを削除します。" -ForegroundColor Gray
    exit 1
}
