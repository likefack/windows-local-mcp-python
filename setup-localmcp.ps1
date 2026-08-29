[CmdletBinding()]
param(
    # 回帰テストでは対話 UI を起動せず、設定関数だけを読み込みます。
    [switch]$FunctionsOnly
)

$ErrorActionPreference = "Stop"
$ScriptRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$LocalAppData = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { [Environment]::GetFolderPath("LocalApplicationData") } else { $env:LOCALAPPDATA }
$StateRoot = Join-Path $LocalAppData "WindowsLocalMCP"
$DefaultConfigPath = Join-Path $StateRoot "config.toml"
$SelectorPath = Join-Path $StateRoot "active-config.txt"
$MinimumPython = [Version]::new(3, 11)
$PythonWindowsDownloadUrl = "https://www.python.org/downloads/windows/"
$CodexCliDocsUrl = "https://developers.openai.com/codex/cli/"
$TunnelHelperPath = Join-Path $ScriptRoot "secure-mcp-tunnel.ps1"
if (-not (Test-Path -LiteralPath $TunnelHelperPath -PathType Leaf)) {
    throw "secure-mcp-tunnel.ps1 が見つかりません。配布パッケージ全体を展開し直してください。"
}
. $TunnelHelperPath

try {
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
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

    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw "Python executable が見つかりません: $PythonPath"
    }

    # Windows PowerShell 5.1 treats native stderr records as PowerShell errors when
    # $ErrorActionPreference is Stop. Temporarily collect them non-terminating so a
    # multi-line Python traceback is preserved and can be reported with the exit code.
    # Force UTF-8 only for this child process so non-ASCII paths do not depend on the
    # host console code page, then restore the caller's environment exactly.
    $previousErrorActionPreference = $ErrorActionPreference
    $previousPythonIoEncoding = $env:PYTHONIOENCODING
    $output = @()
    $exitCode = $null
    try {
        $ErrorActionPreference = "Continue"
        $env:PYTHONIOENCODING = "utf-8"
        $output = @(& $PythonPath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
        if ($null -eq $previousPythonIoEncoding) {
            Remove-Item Env:PYTHONIOENCODING -ErrorAction SilentlyContinue
        } else {
            $env:PYTHONIOENCODING = $previousPythonIoEncoding
        }
    }

    $lines = @($output | ForEach-Object { $_.ToString() })
    if ($null -eq $exitCode) {
        throw "Python の処理を開始できませんでした: $PythonPath"
    }
    if ($exitCode -ne 0) {
        $details = ($lines -join [Environment]::NewLine).Trim()
        if ([string]::IsNullOrWhiteSpace($details)) {
            $details = "標準出力・標準エラーに詳細はありません。"
        }
        throw "Python の処理に失敗しました（終了コード $exitCode）: $details"
    }
    return $lines
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
    Write-Host "確認できたら、この画面を閉じて configure-localmcp.bat をもう一度実行します。"
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
    param([string]$CurrentPath = "")

    Write-Host ""
    Write-Host "MCP から操作したいプロジェクトのフォルダーを指定します。" -ForegroundColor Cyan
    Write-Host "場所の調べ方: エクスプローラーでそのフォルダーを開き、上のアドレスバーをクリックして Ctrl+C。"
    Write-Host "この画面に戻って Ctrl+V で貼り付けます。フォルダー名までを指定し、ファイル名は入力しません。"
    Write-Host "例: C:\Users\あなたの名前\Documents\my-project" -ForegroundColor Gray

    while ($true) {
        $value = (Read-Host "操作対象フォルダーの場所（空欄で現在の場所を維持）").Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($value)) {
            if (-not [string]::IsNullOrWhiteSpace($CurrentPath)) {
                return [IO.Path]::GetFullPath($CurrentPath)
            }
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
        "使用する設定の番号または config のパスを入力してください（Enter で 1 番を使用）"
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
    $lines.Add("# configure-localmcp.bat が生成したローカル設定です。")
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
    $lines.Add('approved_sandbox_codex_path = ""')
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
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$PythonPath = "",
        [switch]$AllowExistingReplacement
    )

    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $existing = Test-Path -LiteralPath $Path -PathType Leaf
    if ($existing -and -not $AllowExistingReplacement) {
        throw "既存の設定を置き換えるには、設定画面で明示的に確認してください。"
    }
    $temporary = "$Path.tmp-$PID-$([Guid]::NewGuid().ToString('N'))"
    $backup = $null
    try {
        [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
        if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
            # 一時ファイルでは副作用のない候補検証だけを行い、namespace marker を一時 path に結び付けません。
            Test-ConfigurationCandidate -PythonPath $PythonPath -ConfigPath $temporary -FinalConfigPath $Path
        }
        if ($existing) {
            $stamp = Get-Date -Format "yyyyMMdd-HHmmssfff"
            $backup = "$Path.backup-$stamp-$([Guid]::NewGuid().ToString('N'))"
            [IO.File]::Replace($temporary, $Path, $backup, $true)
        } else {
            Move-Item -LiteralPath $temporary -Destination $Path -Force
        }
        $temporary = $null

        if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
            try {
                # 永続 state、ACL、filesystem probe は最終 config path にだけ結び付けます。
                Test-Configuration -PythonPath $PythonPath -ConfigPath $Path
            } catch {
                $validationError = $_.Exception
                try {
                    if ($existing) {
                        $failed = "$Path.rollback-$PID-$([Guid]::NewGuid().ToString('N'))"
                        [IO.File]::Replace($backup, $Path, $failed, $true)
                        $backup = $null
                        Remove-Item -LiteralPath $failed -Force -ErrorAction SilentlyContinue
                    } elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
                        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
                    }
                } catch {
                    throw "最終設定の検証に失敗し、旧 config の自動復元も完了できませんでした。config と backup を保全して診断してください。"
                }
                throw $validationError
            }
        }
        if ($existing) {
            Write-Info "既存設定をバックアップしました: $backup"
        }
    } finally {
        if (-not [string]::IsNullOrWhiteSpace($temporary) -and (Test-Path -LiteralPath $temporary)) {
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

function Test-ConfigurationCandidate {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$FinalConfigPath
    )

    # 一時 config を load_settings() に渡すと namespace marker が一時 path に結び付くため、
    # ここでは副作用のない TOML/Settings 検証だけを行います。実体の namespace と filesystem
    # probe は、原子置換後の最終 config で Test-Configuration が確認します。
    $probe = @(
        "import sys",
        "from windows_local_mcp.config import validate_configuration_candidate",
        "validate_configuration_candidate(sys.argv[1], final_config_path=sys.argv[2])",
        "print('candidate-ok')"
    ) -join "; "
    Invoke-Python -PythonPath $PythonPath -Arguments @("-I", "-B", "-c", $probe, $ConfigPath, $FinalConfigPath) | Out-Null
}

function Get-TunnelConfigContext {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $context = Test-TunnelLocalMcpConfiguration -PythonPath $PythonPath -ConfigPath $ConfigPath
    if (-not $context.Valid) {
        throw "LocalMCP の設定を Tunnel 用に検証できません。"
    }
    return $context
}

function Get-TunnelForbiddenRoots {
    param([Parameter(Mandatory = $true)][object]$Context)

    return @(
        $ScriptRoot,
        $Context.WorkspaceRoot,
        $Context.DataDir
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
}

function Get-TunnelStateForConfig {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    $statePath = Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return $null
    }
    try {
        $state = Read-TunnelState -StatePath $statePath
        if ($null -ne $state -and -not [string]::IsNullOrWhiteSpace([string]$state.config_path) -and
            [IO.Path]::GetFullPath([string]$state.config_path).Equals([IO.Path]::GetFullPath($ConfigPath), [StringComparison]::OrdinalIgnoreCase)) {
            return $state
        }
        throw "この config に対応する Tunnel state の config path が一致しません。既存 state は変更しません。"
    } catch {
        throw "この config に対応する Tunnel state を安全に読み取れません。既存 state は変更しません。"
    }
}

function Get-ConfigurationInfo {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $previousConfig = $env:LOCAL_MCP_CONFIG
    $previousRoot = $env:LOCAL_MCP_ROOT
    try {
        $env:LOCAL_MCP_CONFIG = $ConfigPath
        Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        $probe = @(
            "import json; from windows_local_mcp.config import load_settings; settings = load_settings(); print(json.dumps({",
            "'workspace_root': str(settings.workspace_root),",
            "'data_dir': str(settings.data_dir),",
            "'sandbox_scratch_dir': str(settings.sandbox_scratch_dir),",
            "'filesystem_enabled': bool(settings.filesystem_enabled),",
            "'git_enabled': bool(settings.git_enabled),",
            "'adb_enabled': bool(settings.adb_enabled),",
            "'powershell_enabled': bool(settings.powershell_enabled),",
            "'approved_sandbox_enabled': bool(settings.approved_sandbox_enabled),",
            "'approved_host_enabled': bool(settings.approved_host_enabled)",
            "}, ensure_ascii=False))"
        ) -join " "
        $output = Invoke-Python -PythonPath $PythonPath -Arguments @("-I", "-B", "-c", $probe)
        $jsonLines = @(
            $output |
                ForEach-Object { $_.ToString().Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        if ($jsonLines.Count -eq 0) {
            throw "設定概要を取得できませんでした。"
        }
        $info = $jsonLines[-1] | ConvertFrom-Json -ErrorAction Stop
        $info | Add-Member -NotePropertyName config_path -NotePropertyValue ([IO.Path]::GetFullPath($ConfigPath))
        return $info
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
}

function Save-WorkspaceConfig {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$WorkspacePath,
        [string]$DataDirPath = "",
        [string]$SandboxScratchPath = ""
    )

    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $content = [IO.File]::ReadAllText($ConfigPath, $encoding)
    $replacements = [ordered]@{
        workspace_root = ConvertTo-TomlString -Value ([IO.Path]::GetFullPath($WorkspacePath))
    }
    if (-not [string]::IsNullOrWhiteSpace($DataDirPath)) {
        $replacements.data_dir = ConvertTo-TomlString -Value ([IO.Path]::GetFullPath($DataDirPath))
    }
    if (-not [string]::IsNullOrWhiteSpace($SandboxScratchPath)) {
        $replacements.sandbox_scratch_dir = ConvertTo-TomlString -Value ([IO.Path]::GetFullPath($SandboxScratchPath))
    }

    $updated = $content
    foreach ($key in $replacements.Keys) {
        $match = [regex]::Match($updated, '(?m)^[ \t]*' + [regex]::Escape($key) + '[ \t]*=[^\r\n]*')
        $replacement = "$key = $($replacements[$key])"
        if ($match.Success) {
            $updated = $updated.Substring(0, $match.Index) + $replacement + $updated.Substring($match.Index + $match.Length)
        } elseif ($key -eq "workspace_root") {
            throw "既存 config に workspace_root がないため、設定を変更しません。"
        } else {
            $newline = if ($updated.Contains("`r`n")) { "`r`n" } else { "`n" }
            if (-not $updated.EndsWith("`n")) { $updated += $newline }
            $updated += $replacement + $newline
        }
    }

    # Save-Config は一時ファイルを検証してから File.Replace するため、失敗時は旧設定を維持します。
    Save-Config -Content $updated -Path $ConfigPath -PythonPath $PythonPath -AllowExistingReplacement
}

function Read-DataDirectoryPath {
    param(
        [Parameter(Mandatory = $true)][string]$WorkspacePath,
        [Parameter(Mandatory = $true)][string]$CurrentDataPath
    )

    Write-Host "現在の data_dir は以前の workspace と結び付いているため、そのまま再利用しません。" -ForegroundColor Yellow
    Write-Host "新しい workspace 用の保存先を指定してください。既存データは削除・移動しません。"
    while ($true) {
        $value = (Read-Host "新しい data_dir の場所").Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Warn "新しい data_dir の場所は必須です。"
            continue
        }
        try {
            $candidate = [IO.Path]::GetFullPath($value)
            $root = [IO.Path]::GetPathRoot($candidate).TrimEnd('\', '/')
            if ($candidate.TrimEnd('\', '/').Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw "ドライブ直下は指定できません。"
            }
            foreach ($parent in @($WorkspacePath, $StateRoot, $ScriptRoot)) {
                if (Test-PathInside -Candidate $candidate -Parent $parent) {
                    throw "workspace、設定領域、リポジトリの中は指定できません。"
                }
            }
            if (Test-Path -LiteralPath $candidate) {
                $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
                if (-not $item.PSIsContainer) { throw "フォルダーを指定してください。" }
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "reparse point のフォルダーは指定できません。"
                }
            } else {
                $parentPath = Split-Path -Parent $candidate
                if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
                    throw "親フォルダーが見つかりません。先に作成してください。"
                }
            }
            return $candidate.TrimEnd('\', '/')
        } catch {
            Write-Warn "data_dir を利用できません: $($_.Exception.Message)"
        }
    }
}

function Update-WorkspaceForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $info = Get-ConfigurationInfo -PythonPath $PythonPath -ConfigPath $ConfigPath
    $newPath = Read-WorkspacePath -CurrentPath ([string]$info.workspace_root)
    if ([IO.Path]::GetFullPath($newPath).Equals([IO.Path]::GetFullPath([string]$info.workspace_root), [StringComparison]::OrdinalIgnoreCase)) {
        Write-Info "workspace_root は変更していません。"
        return
    }
    $dataDirPath = ""
    $scratchPath = ""
    $namespaceMarker = Join-Path ([string]$info.data_dir) "control-plane\namespace.json"
    if (Test-Path -LiteralPath $namespaceMarker -PathType Leaf) {
        $dataDirPath = Read-DataDirectoryPath -WorkspacePath $newPath -CurrentDataPath ([string]$info.data_dir)
        if ([string]::IsNullOrWhiteSpace($dataDirPath)) {
            throw "新しい data_dir が指定されていないため、workspace を変更しません。"
        }
        $dataName = [IO.Path]::GetFileName($dataDirPath.TrimEnd('\', '/'))
        $scratchPath = Join-Path (Split-Path -Parent $dataDirPath) "$dataName-sandbox-scratch"
        foreach ($parent in @($newPath, $StateRoot, $ScriptRoot, $dataDirPath)) {
            if (Test-PathInside -Candidate $scratchPath -Parent $parent) {
                throw "workspace、設定領域、data_dir と重ならない新しい scratch path を作成できません。"
            }
        }
    }
    Save-WorkspaceConfig `
        -PythonPath $PythonPath `
        -ConfigPath $ConfigPath `
        -WorkspacePath $newPath `
        -DataDirPath $dataDirPath `
        -SandboxScratchPath $scratchPath
    Write-Ok "workspace_root を更新し、新しい設定の検証に成功しました。"
}

function Get-TunnelSettingsSummary {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [AllowNull()][object]$State
    )

    $summary = [ordered]@{
        Status = "未設定"
        TunnelId = "未設定"
        ApiKeyStatus = "未登録"
        ClientStatus = "未検出"
        ClientPath = ""
        ProfilePath = ""
        ProcessStatus = "停止"
    }
    $forbiddenRoots = @(Get-TunnelForbiddenRoots -Context $Context)
    if ($null -eq $State) {
        $candidate = @(Get-TunnelClientCandidates -StateRoot $StateRoot -ForbiddenRoots $forbiddenRoots) | Select-Object -First 1
        if ($null -ne $candidate) {
            $summary.ClientStatus = "検出済み（未設定）"
            $summary.ClientPath = [string]$candidate.Path
        }
        return [PSCustomObject]$summary
    }

    $summary.TunnelId = if (Test-TunnelId -TunnelId ([string]$State.tunnel_id)) { [string]$State.tunnel_id } else { "形式不正" }
    $summary.ProfilePath = [string]$State.profile_path
    if ([bool]$State.enabled -ne $true) {
        $summary.Status = "無効"
    } else {
        $summary.Status = "設定済み"
        $binding = Test-TunnelProfileBinding `
            -State $State `
            -ConfigPath $ConfigPath `
            -ServerScript (Join-Path $ScriptRoot "run-server.ps1") `
            -ProfileRoot (Join-Path $StateRoot "tunnel-profiles") `
            -StateRoot $StateRoot `
            -ForbiddenRoots $forbiddenRoots
        if ($binding.Valid) {
            $summary.ClientStatus = "検出済み"
            $summary.ClientPath = [string]$binding.ClientPath
            $summary.ProfilePath = [string]$binding.ProfilePath
            $processStatus = Get-TunnelCurrentProcessStatus -State $State
            $summary.ProcessStatus = switch ($processStatus.Status) {
                "running" { "起動中" }
                "indeterminate" { "要確認" }
                default { "停止" }
            }
        } else {
            $summary.Status = "要診断"
            if (-not [string]::IsNullOrWhiteSpace([string]$State.tunnel_client_path)) {
                $summary.ClientStatus = "要診断"
            }
        }
    }

    if ([string]$State.credential_mode -eq "credential_manager") {
        $credential = $null
        try {
            $credential = Get-TunnelSavedCredential -ConfigPath $ConfigPath
            if ($null -ne $credential) { $summary.ApiKeyStatus = "登録済み" }
        } finally {
            if ($null -ne $credential) { $credential.Dispose() }
        }
    } elseif ([string]$State.credential_mode -eq "profile_reference") {
        $summary.ApiKeyStatus = "profile の参照設定あり"
    }
    return [PSCustomObject]$summary
}

function Show-ConfigurationSummary {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $info = Get-ConfigurationInfo -PythonPath $PythonPath -ConfigPath $ConfigPath
    $context = Get-TunnelConfigContext -PythonPath $PythonPath -ConfigPath $ConfigPath
    $state = $null
    $stateError = $null
    try {
        $state = Get-TunnelStateForConfig -ConfigPath $ConfigPath
    } catch {
        # 破損した state を未設定として扱わず、概要だけ表示して変更処理を止めます。
        $stateError = $_.Exception.Message
    }

    Write-Title "現在の設定"
    Write-Host "操作対象フォルダー: $($info.workspace_root)" -ForegroundColor Cyan
    Write-Host "LocalMCP config: $($info.config_path)" -ForegroundColor Cyan
    Write-Host "data_dir: $($info.data_dir)" -ForegroundColor Gray
    Write-Host "sandbox scratch: $($info.sandbox_scratch_dir)" -ForegroundColor Gray
    if ($null -ne $stateError) {
        Write-Host "Secure MCP Tunnel: 要診断" -ForegroundColor Yellow
        Write-Host "Tunnel ID: 確認できません" -ForegroundColor Gray
        Write-Host "Runtime API Key: 確認できません（secret は表示しません）" -ForegroundColor Gray
        Write-Host "tunnel-client: 確認できません" -ForegroundColor Gray
        Write-Host "Tunnel state の読み取りに失敗しました。変更せず 6. 設定を診断するを選んでください。" -ForegroundColor Yellow
    } else {
        $tunnel = Get-TunnelSettingsSummary -Context $context -ConfigPath $ConfigPath -State $state
        Write-Host "Secure MCP Tunnel: $($tunnel.Status)" -ForegroundColor Cyan
        Write-Host "Tunnel ID: $($tunnel.TunnelId)" -ForegroundColor Gray
        Write-Host "Runtime API Key: $($tunnel.ApiKeyStatus)（secret は表示しません）" -ForegroundColor Gray
        if ([string]::IsNullOrWhiteSpace([string]$tunnel.ClientPath)) {
            Write-Host "tunnel-client: $($tunnel.ClientStatus)" -ForegroundColor Gray
        } else {
            Write-Host "tunnel-client: $($tunnel.ClientStatus) ($($tunnel.ClientPath))" -ForegroundColor Gray
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$tunnel.ProfilePath)) {
            Write-Host "Tunnel profile: $($tunnel.ProfilePath)" -ForegroundColor Gray
        }
        Write-Host "Tunnel process: $($tunnel.ProcessStatus)" -ForegroundColor Gray
    }
    Write-Host ("オプション: filesystem={0}, git={1}, ADB={2}, PowerShell={3}, Codex Sandbox={4}, Approved Host={5}" -f `
        $info.filesystem_enabled, $info.git_enabled, $info.adb_enabled, $info.powershell_enabled,
        $info.approved_sandbox_enabled, $info.approved_host_enabled) -ForegroundColor Gray
}

function Get-TunnelCurrentProcessStatus {
    param([Parameter(Mandatory = $true)][object]$State)

    try {
        return Get-TunnelProcessStatus -PidFile ([string]$State.pid_file) -ClientPath ([string]$State.tunnel_client_path) -ProfilePath ([string]$State.profile_path)
    } catch {
        return [PSCustomObject]@{ Status = "indeterminate"; ProcessId = $null }
    }
}

function Assert-TunnelNotRunning {
    param([object]$State)

    if ($null -eq $State -or [bool]$State.enabled -ne $true) {
        return
    }
    $status = Get-TunnelCurrentProcessStatus -State $State
    if ($status.Status -eq "running") {
        throw "Tunnel が起動中です。現在の起動ウィンドウで Ctrl+C を押してから設定を変更してください。"
    }
    if ($status.Status -eq "indeterminate") {
        throw "Tunnel の起動状態を安全に確認できないため、設定を変更しません。PID/profile の状態を確認してください。"
    }
}

function Select-TunnelClient {
    param(
        [object]$State,
        [Parameter(Mandatory = $true)][string[]]$ForbiddenRoots
    )

    $preferred = if ($null -ne $State) { [string]$State.tunnel_client_path } else { $null }
    $candidates = @(Get-TunnelClientCandidates -PreferredPath $preferred -StateRoot $StateRoot -ForbiddenRoots $ForbiddenRoots)
    if ($candidates.Count -gt 0) {
        Write-Host "検出した tunnel-client:" -ForegroundColor Cyan
        for ($index = 0; $index -lt $candidates.Count; $index++) {
            Write-Host ("  {0}. {1}" -f ($index + 1), $candidates[$index].Path)
        }
        Write-Host "実行ファイルは workspace、data_dir、リポジトリの中から自動採用しません。" -ForegroundColor Gray
    } else {
        Show-TunnelClientInstallGuide
    }

    while ($true) {
        $prompt = if ($candidates.Count -gt 0) {
            "使う番号、または tunnel-client.exe の絶対 path（空欄で 1 番、0 でキャンセル）"
        } else {
            "tunnel-client.exe の絶対 path（空欄でキャンセル）"
        }
        $selection = (Read-Host $prompt).Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($selection)) {
            if ($candidates.Count -gt 0) { return $candidates[0] }
            return $null
        }
        if ($selection -eq "0") { return $null }
        if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $candidates.Count) {
            return $candidates[[int]$selection - 1]
        }
        if (-not [IO.Path]::IsPathRooted($selection)) {
            Write-Warn "絶対 path を指定してください。"
            continue
        }
        try {
            $resolved = Resolve-TunnelExecutable -Path $selection -ForbiddenRoots $ForbiddenRoots
            return [PSCustomObject]@{ Path = $resolved; Hash = Get-TunnelSha256 -Path $resolved }
        } catch {
            Write-Warn "指定した tunnel-client を安全に確認できません。公式配布物の path を指定してください。"
        }
    }
}

function Read-TunnelIdForSetup {
    param([string]$CurrentTunnelId)

    Show-TunnelOnboardingGuide
    while ($true) {
        $suffix = if (Test-TunnelId -TunnelId $CurrentTunnelId) { "（空欄で現在の ID を再利用）" } else { "" }
        $value = (Read-Host "Tunnel ID $suffix").Trim()
        if ([string]::IsNullOrWhiteSpace($value) -and (Test-TunnelId -TunnelId $CurrentTunnelId)) {
            return $CurrentTunnelId
        }
        if (Test-TunnelId -TunnelId $value) {
            return $value
        }
        Write-Warn "Tunnel ID は tunnel_ に続く 32 桁の小文字 hexadecimal で指定してください。"
    }
}

function Read-TunnelRuntimeApiKeyForSetup {
    while ($true) {
        $secret = Read-Host "Runtime API Key（入力内容は表示されません）" -AsSecureString
        if ($null -ne $secret -and $secret.Length -ge 8 -and $secret.Length -le 256) {
            return $secret
        }
        if ($null -ne $secret) { $secret.Dispose() }
        Write-Warn "Runtime API Key は 8～256 文字で入力してください。値そのものは表示・保存しません。"
    }
}

function Get-TunnelSavedCredential {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    try {
        return Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $ConfigPath)
    } catch {
        Write-Warn "保存済み Runtime API Key を安全に読み取れません。再入力が必要です。"
        return $null
    }
}

function Get-TunnelCredentialForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [object]$State
    )

    $saved = $null
    if ($null -ne $State -and [string]$State.credential_mode -eq "credential_manager") {
        $saved = Get-TunnelSavedCredential -ConfigPath $ConfigPath
    }
    if ($null -ne $saved -and (Read-YesNo -Prompt "保存済みの Runtime API Key を再利用しますか" -Default $true)) {
        return $saved
    }
    if ($null -ne $saved) { $saved.Dispose() }
    return Read-TunnelRuntimeApiKeyForSetup
}

function Get-TunnelFailureClassForSetup {
    param([Parameter(Mandatory = $true)][string]$ReasonCode)

    switch ($ReasonCode) {
        "credential_missing" { return "auth_failed" }
        "credential_binding" { return "auth_failed" }
        "state_incomplete" { return "profile_invalid" }
        "state_location" { return "profile_invalid" }
        "profile_scope" { return "profile_invalid" }
        "profile_location" { return "profile_invalid" }
        "profile_changed" { return "profile_invalid" }
        "client_changed" { return "tunnel_client_unavailable" }
        "tunnel_id_invalid" { return "tunnel_id_invalid" }
        "config_mismatch" { return "profile_invalid" }
        default { return "profile_invalid" }
    }
}

function Test-TunnelIntegrationForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$State
    )

    Assert-TunnelNotRunning -State $State
    $forbiddenRoots = @(Get-TunnelForbiddenRoots -Context $Context)
    $binding = Test-TunnelProfileBinding `
        -State $State `
        -ConfigPath $ConfigPath `
        -ServerScript (Join-Path $ScriptRoot "run-server.ps1") `
        -ProfileRoot (Join-Path $StateRoot "tunnel-profiles") `
        -StateRoot $StateRoot `
        -ForbiddenRoots $forbiddenRoots
    if (-not $binding.Valid) {
        Show-TunnelFailureGuide -FailureClass (Get-TunnelFailureClassForSetup -ReasonCode $binding.ReasonCode)
        return $false
    }

    $credential = $null
    try {
        if ([string]$State.credential_mode -eq "credential_manager") {
            $credential = Get-TunnelSavedCredential -ConfigPath $ConfigPath
            if ($null -eq $credential) {
                Show-TunnelFailureGuide -FailureClass "auth_failed"
                return $false
            }
        }
        $doctor = Invoke-TunnelClientDoctor -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath -Credential $credential
        if (-not $doctor.Succeeded) {
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }
        Write-Ok "既存の Tunnel profile、tunnel-client、認証参照を検証しました。"
        return $true
    } finally {
        if ($null -ne $credential) { $credential.Dispose() }
    }
}

function New-TunnelManagedState {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$TunnelId,
        [Parameter(Mandatory = $true)][string]$PidFile,
        [Parameter(Mandatory = $true)][string]$HealthUrlFile,
        [Parameter(Mandatory = $true)][string]$CredentialMode,
        [string]$CredentialTarget = "",
        [string]$ProfileScope = "managed"
    )

    return [PSCustomObject][ordered]@{
        version = 1
        enabled = $true
        config_path = [IO.Path]::GetFullPath($ConfigPath)
        profile_path = [IO.Path]::GetFullPath($ProfilePath)
        profile_sha256 = (Get-TunnelSha256 -Path $ProfilePath)
        profile_scope = $ProfileScope
        tunnel_id = $TunnelId
        tunnel_client_path = [IO.Path]::GetFullPath($ClientPath)
        tunnel_client_sha256 = (Get-TunnelSha256 -Path $ClientPath)
        pid_file = [IO.Path]::GetFullPath($PidFile)
        health_url_file = [IO.Path]::GetFullPath($HealthUrlFile)
        credential_mode = $CredentialMode
        credential_target = $CredentialTarget
    }
}

function Save-TunnelManagedIntegration {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$TunnelId,
        [Parameter(Mandatory = $true)][Security.SecureString]$Credential,
        [Parameter(Mandatory = $true)][AllowNull()][object]$PreviousState
    )

    Assert-TunnelNotRunning -State $PreviousState
    $mutex = [Threading.Mutex]::new($false, (Get-TunnelMutexName -ConfigPath $ConfigPath))
    $hasMutex = $false
    $stagingPath = $null
    $profileInstall = $null
    $stateSave = $null
    $oldCredential = $null
    $credentialChanged = $false
    try {
        try { $hasMutex = $mutex.WaitOne(0) } catch { $hasMutex = $false }
        if (-not $hasMutex) {
            throw "Tunnel が別の起動処理で使用中です。現在の処理が終わってから再実行してください。"
        }

        $resolvedConfig = [IO.Path]::GetFullPath($ConfigPath)
        $serverScript = (Resolve-Path -LiteralPath (Join-Path $ScriptRoot "run-server.ps1") -ErrorAction Stop).Path
        $profilePath = Get-TunnelProfilePath -StateRoot $StateRoot -ConfigPath $resolvedConfig
        $fingerprint = (Get-TunnelCredentialTarget -ConfigPath $resolvedConfig).Split('/')[-1]
        $pidFile = Join-Path $StateRoot "tunnel-state\$fingerprint.pid"
        $healthUrlFile = Join-Path $StateRoot "tunnel-state\$fingerprint.health-url"
        $profileContent = New-TunnelProfileContent `
            -TunnelId $TunnelId `
            -ServerScript $serverScript `
            -ConfigPath $resolvedConfig `
            -PidFile ([IO.Path]::GetFullPath($pidFile)) `
            -HealthUrlFile ([IO.Path]::GetFullPath($healthUrlFile))
        $stagingPath = Write-TunnelProfileStaging -Content $profileContent -DestinationPath $profilePath

        $doctor = Invoke-TunnelClientDoctor -ClientPath $ClientPath -ProfilePath $stagingPath -Credential $Credential
        if (-not $doctor.Succeeded) {
            Remove-TunnelStagingFile -Path $stagingPath
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }

        try {
            $oldCredential = Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $resolvedConfig)
        } catch {
            throw "保存済み Runtime API Key を安全に読み取れないため、既存設定を変更しません。"
        }

        $profileInstall = Install-TunnelProfileStaging -StagingPath $stagingPath -DestinationPath $profilePath
        $stagingPath = $null
        $credentialChanged = $true
        Set-TunnelCredential -Target (Get-TunnelCredentialTarget -ConfigPath $resolvedConfig) -Secret $Credential
        $state = New-TunnelManagedState `
            -ConfigPath $resolvedConfig `
            -ProfilePath $profilePath `
            -ClientPath $ClientPath `
            -TunnelId $TunnelId `
            -PidFile $pidFile `
            -HealthUrlFile $healthUrlFile `
            -CredentialMode "credential_manager" `
            -CredentialTarget (Get-TunnelCredentialTarget -ConfigPath $resolvedConfig)
        $stateSave = Save-TunnelStateAtomic -State $state -StatePath (Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $resolvedConfig)
        Write-Ok "Tunnel profile と設定を保存しました。API Key は Windows のユーザー資格情報領域に保存しています。"
        return $true
    } catch {
        $rollbackFailed = $false
        try {
            if ($null -ne $stateSave) {
                Restore-TunnelFileBackup -DestinationPath $stateSave.StatePath -BackupPath $stateSave.BackupPath
            }
        } catch { $rollbackFailed = $true }
        try {
            if ($null -ne $profileInstall) {
                Restore-TunnelFileBackup -DestinationPath $profileInstall.DestinationPath -BackupPath $profileInstall.BackupPath
            }
        } catch { $rollbackFailed = $true }
        if ($credentialChanged) {
            try {
                $target = Get-TunnelCredentialTarget -ConfigPath $ConfigPath
                if ($null -ne $oldCredential) {
                    Set-TunnelCredential -Target $target -Secret $oldCredential
                } else {
                    $null = Remove-TunnelCredential -Target $target
                }
            } catch { $rollbackFailed = $true }
        }
        if ($rollbackFailed) {
            Write-Warn "自動復元の一部を確認できません。既存設定を使用せず、Tunnel の state/profile と資格情報を診断してください。"
        }
        throw "新しい Tunnel 設定を保存できませんでした。既存設定は可能な範囲で復元しました。"
    } finally {
        Remove-TunnelStagingFile -Path $stagingPath
        if ($null -ne $oldCredential) { $oldCredential.Dispose() }
        if ($hasMutex) { try { $mutex.ReleaseMutex() } catch { } }
        $mutex.Dispose()
    }
}

function Save-TunnelExternalIntegration {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][AllowNull()][object]$PreviousState
    )

    Assert-TunnelNotRunning -State $PreviousState
    $mutex = [Threading.Mutex]::new($false, (Get-TunnelMutexName -ConfigPath $ConfigPath))
    $hasMutex = $false
    $credential = $null
    $oldCredential = $null
    $credentialChanged = $false
    $stateSave = $null
    try {
        try { $hasMutex = $mutex.WaitOne(0) } catch { $hasMutex = $false }
        if (-not $hasMutex) {
            throw "Tunnel が別の起動処理で使用中です。現在の処理が終わってから再実行してください。"
        }

        $credentialMode = "profile_reference"
        $credentialTarget = ""
        if ([string]$Candidate.ApiKeyReference -ieq "env:WLMCP_TUNNEL_RUNTIME_API_KEY") {
            try {
                $oldCredential = Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $ConfigPath)
            } catch {
                throw "保存済み Runtime API Key を安全に読み取れないため、既存 profile の利用設定を変更しません。"
            }
            if ($null -eq $oldCredential) {
                Write-Info "既存 profile はこのセットアップの Credential Manager 参照を使用します。"
                $credential = Read-TunnelRuntimeApiKeyForSetup
            } else {
                $credential = $oldCredential
            }
            $credentialMode = "credential_manager"
            $credentialTarget = Get-TunnelCredentialTarget -ConfigPath $ConfigPath
        }

        $doctor = Invoke-TunnelClientDoctor -ClientPath $ClientPath -ProfilePath $Candidate.Path -Credential $credential
        if (-not $doctor.Succeeded) {
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            return $false
        }

        if ($credentialMode -eq "credential_manager") {
            if ($null -eq $credential) {
                throw "Runtime API Key がないため、既存 profile の利用設定を保存しません。"
            }
            $credentialChanged = $true
            Set-TunnelCredential -Target $credentialTarget -Secret $credential
        }

        $fingerprint = (Get-TunnelCredentialTarget -ConfigPath $ConfigPath).Split('/')[-1]
        $pidFile = Join-Path $StateRoot "tunnel-state\$fingerprint.pid"
        $healthUrlFile = Join-Path $StateRoot "tunnel-state\$fingerprint.health-url"
        $state = New-TunnelManagedState `
            -ConfigPath $ConfigPath `
            -ProfilePath $Candidate.Path `
            -ClientPath $ClientPath `
            -TunnelId ([string]$Candidate.TunnelId) `
            -PidFile $pidFile `
            -HealthUrlFile $healthUrlFile `
            -CredentialMode $credentialMode `
            -CredentialTarget $credentialTarget `
            -ProfileScope "external"
        $stateSave = Save-TunnelStateAtomic -State $state -StatePath (Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $ConfigPath)
        Write-Ok "既存 Tunnel profile を変更せず、通常起動から再利用する設定を保存しました。"
        return $true
    } catch {
        $rollbackFailed = $false
        try {
            if ($null -ne $stateSave) {
                Restore-TunnelFileBackup -DestinationPath $stateSave.StatePath -BackupPath $stateSave.BackupPath
            }
        } catch { $rollbackFailed = $true }
        if ($credentialChanged) {
            try {
                if ($null -ne $oldCredential) {
                    Set-TunnelCredential -Target (Get-TunnelCredentialTarget -ConfigPath $ConfigPath) -Secret $oldCredential
                } else {
                    $null = Remove-TunnelCredential -Target (Get-TunnelCredentialTarget -ConfigPath $ConfigPath)
                }
            } catch { $rollbackFailed = $true }
        }
        if ($rollbackFailed) {
            Write-Warn "既存 profile の利用設定を自動復元できません。Tunnel を起動せず、state と Credential Manager を診断してください。"
        }
        throw "既存 Tunnel profile の利用設定を保存できませんでした。既存設定は可能な範囲で復元しました。"
    } finally {
        if ($null -ne $credential) { $credential.Dispose() }
        if ($null -ne $oldCredential -and -not [object]::ReferenceEquals($oldCredential, $credential)) { $oldCredential.Dispose() }
        if ($hasMutex) { try { $mutex.ReleaseMutex() } catch { } }
        $mutex.Dispose()
    }
}

function Copy-TunnelStateForSetup {
    param([Parameter(Mandatory = $true)][object]$State)
    return ($State | ConvertTo-Json -Depth 8 -Compress | ConvertFrom-Json -ErrorAction Stop)
}

function Disable-TunnelIntegrationForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$State
    )

    Assert-TunnelNotRunning -State $State
    $copy = Copy-TunnelStateForSetup -State $State
    $copy.enabled = $false
    $null = Save-TunnelStateAtomic -State $copy -StatePath (Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $ConfigPath)
    Write-Ok "Tunnel integration を無効にしました。profile と保存済み key は削除していません。"
    Write-Host "次回の run-localmcp.bat は LocalMCP 単体を起動します。" -ForegroundColor Gray
    return $copy
}

function Enable-TunnelIntegrationForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$State
    )

    Assert-TunnelNotRunning -State $State
    $binding = Test-TunnelProfileBinding `
        -State $State `
        -ConfigPath $ConfigPath `
        -ServerScript (Join-Path $ScriptRoot "run-server.ps1") `
        -ProfileRoot (Join-Path $StateRoot "tunnel-profiles") `
        -StateRoot $StateRoot `
        -ForbiddenRoots @(Get-TunnelForbiddenRoots -Context $Context)
    if (-not $binding.Valid) {
        Show-TunnelFailureGuide -FailureClass (Get-TunnelFailureClassForSetup -ReasonCode $binding.ReasonCode)
        Write-Warn "保持済み Tunnel 設定を安全に再利用できないため、有効化していません。"
        return $false
    }

    $credential = $null
    try {
        if ([string]$State.credential_mode -eq "credential_manager") {
            $credential = Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $ConfigPath)
            if ($null -eq $credential) {
                Show-TunnelFailureGuide -FailureClass "auth_failed"
                Write-Warn "保存済み Runtime API Key がないため、有効化していません。"
                return $false
            }
        }
        $doctor = Invoke-TunnelClientDoctor -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath -Credential $credential
        if (-not $doctor.Succeeded) {
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            Write-Warn "保持済み Tunnel 設定の検証に失敗したため、有効化していません。"
            return $false
        }
        $copy = Copy-TunnelStateForSetup -State $State
        $copy.enabled = $true
        $null = Save-TunnelStateAtomic -State $copy -StatePath (Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $ConfigPath)
        Write-Ok "保持済み Tunnel profile、Tunnel ID、Runtime API Key を変更せず再び有効にしました。"
        return $true
    } finally {
        if ($null -ne $credential) { $credential.Dispose() }
    }
}

function Remove-TunnelSavedCredentialForSetup {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [object]$State
    )

    if ($null -ne $State -and [bool]$State.enabled -eq $true) {
        $State = Disable-TunnelIntegrationForSetup -ConfigPath $ConfigPath -State $State
    }
    $target = Get-TunnelCredentialTarget -ConfigPath $ConfigPath
    try {
        $removed = Remove-TunnelCredential -Target $target
    } catch {
        throw "保存済み Runtime API Key を削除できませんでした。"
    }
    if ($null -ne $State) {
        $copy = Copy-TunnelStateForSetup -State $State
        $copy.enabled = $false
        $copy.credential_mode = "none"
        $copy.credential_target = ""
        $null = Save-TunnelStateAtomic -State $copy -StatePath (Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $ConfigPath)
    }
    if ($removed) {
        Write-Ok "保存済み Runtime API Key を削除しました。profile は残しています。"
    } else {
        Write-Info "削除対象の Runtime API Key は見つかりませんでした。"
    }
}

function Configure-NewTunnelIntegration {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$Context,
        [AllowNull()][object]$PreviousState
    )

    $forbiddenRoots = @(Get-TunnelForbiddenRoots -Context $Context)
    $client = Select-TunnelClient -State $PreviousState -ForbiddenRoots $forbiddenRoots
    if ($null -eq $client) {
        Write-Info "Tunnel 設定は変更していません。LocalMCP 単体の起動は引き続き利用できます。"
        return $false
    }
    $currentTunnelId = if ($null -ne $PreviousState) { [string]$PreviousState.tunnel_id } else { "" }
    $tunnelId = Read-TunnelIdForSetup -CurrentTunnelId $currentTunnelId
    $credential = $null
    try {
        $credential = Get-TunnelCredentialForSetup -ConfigPath $ConfigPath -State $PreviousState
        return Save-TunnelManagedIntegration `
            -ConfigPath $ConfigPath `
            -ClientPath $client.Path `
            -TunnelId $tunnelId `
            -Credential $credential `
            -PreviousState $PreviousState
    } finally {
        if ($null -ne $credential) { $credential.Dispose() }
    }
}

function Configure-ExistingTunnelProfile {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Candidate,
        [AllowNull()][object]$PreviousState
    )

    $forbiddenRoots = @(Get-TunnelForbiddenRoots -Context $Context)
    $client = Select-TunnelClient -State $PreviousState -ForbiddenRoots $forbiddenRoots
    if ($null -eq $client) {
        Write-Info "既存 profile は変更せず、Tunnel の利用設定も変更していません。"
        return $false
    }
    return Save-TunnelExternalIntegration `
        -ConfigPath $ConfigPath `
        -Candidate $Candidate `
        -ClientPath $client.Path `
        -PreviousState $PreviousState
}

function Configure-TunnelIntegration {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $context = Get-TunnelConfigContext -PythonPath $PythonPath -ConfigPath $ConfigPath
    $state = Get-TunnelStateForConfig -ConfigPath $ConfigPath
    $forbiddenRoots = @(Get-TunnelForbiddenRoots -Context $context)
    Write-Title "ChatGPT Secure MCP Tunnel"
    Write-Host "Tunnel を設定すると、以後は run-localmcp.bat から tunnel-client と LocalMCP をまとめて起動できます。"
    Write-Host "Tunnel を使わない場合は、いつでもスキップできます。"

    if ($null -ne $state -and [bool]$state.enabled -eq $true) {
        Write-Host "現在の Tunnel 設定: $([string]$state.tunnel_id)" -ForegroundColor Cyan
        Write-Host "profile: $([string]$state.profile_path)" -ForegroundColor Gray
        Write-Host "1. 既存設定を検証して使用する"
        Write-Host "2. Runtime API Key だけを変更する（Tunnel と profile は維持）"
        Write-Host "3. 設定を変更する（Tunnel ID / client / managed profile）"
        Write-Host "4. Tunnel integration を無効化する"
        Write-Host "5. 保存済み Runtime API Key を削除する"
        Write-Host "0. 戻る"
        $choice = (Read-Host "番号").Trim()
        switch ($choice) {
            "1" { return Test-TunnelIntegrationForSetup -PythonPath $PythonPath -ConfigPath $ConfigPath -Context $context -State $state }
            "2" { return Update-TunnelRuntimeApiKey -PythonPath $PythonPath -ConfigPath $ConfigPath -Context $context -State $state }
            "3" { return Configure-NewTunnelIntegration -ConfigPath $ConfigPath -Context $context -PreviousState $state }
            "4" { Disable-TunnelIntegrationForSetup -ConfigPath $ConfigPath -State $state | Out-Null; return $false }
            "5" { Remove-TunnelSavedCredentialForSetup -ConfigPath $ConfigPath -State $state; return $false }
            "0" { return $true }
            default { throw "Tunnel 設定メニューの番号が正しくありません。" }
        }
    }

    if ($null -ne $state -and [bool]$state.enabled -ne $true) {
        Write-Host "Tunnel integration は現在無効です。保存済み profile は削除していません。" -ForegroundColor Gray
        Write-Host "1. Tunnel を有効化または設定変更する"
        Write-Host "2. 保存済み Runtime API Key を削除する"
        Write-Host "3. 今回はスキップする"
        Write-Host "0. 戻る"
        $choice = (Read-Host "番号").Trim()
        switch ($choice) {
            "1" { return Configure-NewTunnelIntegration -ConfigPath $ConfigPath -Context $context -PreviousState $state }
            "2" { Remove-TunnelSavedCredentialForSetup -ConfigPath $ConfigPath -State $state; return $false }
            "3" { return $false }
            "0" { return $false }
            default { throw "Tunnel 設定メニューの番号が正しくありません。" }
        }
    }

    $profiles = @(Find-TunnelProfileCandidates `
        -StateRoot $StateRoot `
        -ServerScript (Join-Path $ScriptRoot "run-server.ps1") `
        -ConfigPath $ConfigPath `
        -ForbiddenRoots $forbiddenRoots)
    if ($profiles.Count -gt 0) {
        Write-Host "この config と一致する既存 Tunnel profile を検出しました:" -ForegroundColor Cyan
        for ($index = 0; $index -lt $profiles.Count; $index++) {
            Write-Host ("  {0}. {1}  ({2})" -f ($index + 1), $profiles[$index].Path, $profiles[$index].TunnelId)
        }
        Write-Host "1. 既存 profile を使用する（profile 自体は変更しません）"
        Write-Host "2. 新しい managed profile を設定する"
        Write-Host "3. 今回はスキップする"
        $choice = (Read-Host "番号（空欄で 1）").Trim()
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
        if ($choice -eq "1") {
            $profileIndex = 1
            if ($profiles.Count -gt 1) {
                $profileChoice = (Read-Host "使用する profile の番号（空欄で 1）").Trim()
                if (-not [string]::IsNullOrWhiteSpace($profileChoice)) { $profileIndex = [int]$profileChoice }
            }
            if ($profileIndex -lt 1 -or $profileIndex -gt $profiles.Count) {
                throw "profile の番号が正しくありません。"
            }
            return Configure-ExistingTunnelProfile `
                -ConfigPath $ConfigPath `
                -Context $context `
                -Candidate $profiles[$profileIndex - 1] `
                -PreviousState $state
        }
        if ($choice -eq "3") { return $false }
        if ($choice -ne "2") { throw "Tunnel 設定メニューの番号が正しくありません。" }
    } elseif (-not (Read-YesNo -Prompt "ChatGPT Secure MCP Tunnel を設定しますか" -Default $true)) {
        Write-Info "Tunnel 設定をスキップしました。run-localmcp.bat は LocalMCP 単体を起動します。"
        return $false
    }

    return Configure-NewTunnelIntegration -ConfigPath $ConfigPath -Context $context -PreviousState $state
}

function Update-TunnelRuntimeApiKey {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$State
    )

    if ([bool]$State.enabled -ne $true) {
        Write-Warn "Tunnel integration が有効な設定だけ、Runtime API Key を単独で変更できます。"
        return $false
    }
    if ([string]$State.credential_mode -ne "credential_manager") {
        Write-Warn "この Tunnel は既存 profile 側の認証参照を使用しています。profile を変更せずに安全な保存先を追加できないため、Key は変更していません。"
        return $false
    }

    Assert-TunnelNotRunning -State $State
    $forbiddenRoots = @(Get-TunnelForbiddenRoots -Context $Context)
    $binding = Test-TunnelProfileBinding `
        -State $State `
        -ConfigPath $ConfigPath `
        -ServerScript (Join-Path $ScriptRoot "run-server.ps1") `
        -ProfileRoot (Join-Path $StateRoot "tunnel-profiles") `
        -StateRoot $StateRoot `
        -ForbiddenRoots $forbiddenRoots
    if (-not $binding.Valid) {
        Show-TunnelFailureGuide -FailureClass (Get-TunnelFailureClassForSetup -ReasonCode $binding.ReasonCode)
        return $false
    }

    Write-Host "新しい Runtime API Key を入力します。既存 Tunnel、Tunnel ID、profile、connector は変更しません。" -ForegroundColor Cyan
    $newCredential = $null
    $oldCredential = $null
    try {
        $newCredential = Read-TunnelRuntimeApiKeyForSetup
        try {
            $oldCredential = Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $ConfigPath)
        } catch {
            throw "既存の Runtime API Key を安全に確認できないため、Key は変更していません。"
        }

        # 新しい credential で先に doctor を実行し、成功するまで保存済み key は触りません。
        $doctor = Invoke-TunnelClientDoctor -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath -Credential $newCredential
        if (-not $doctor.Succeeded) {
            Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
            Write-Info "認証に失敗したため、以前の Runtime API Key は維持しています。"
            return $false
        }

        $target = Get-TunnelCredentialTarget -ConfigPath $ConfigPath
        try {
            Set-TunnelCredential -Target $target -Secret $newCredential
        } catch {
            try {
                if ($null -ne $oldCredential) {
                    Set-TunnelCredential -Target $target -Secret $oldCredential
                } else {
                    $null = Remove-TunnelCredential -Target $target
                }
            } catch {
                throw "新しい Runtime API Key の保存に失敗し、以前の key の復元も確認できません。Tunnel を起動せず診断してください。"
            }
            throw "新しい Runtime API Key の保存に失敗しました。以前の key を維持しています。"
        }
        Write-Ok "Runtime API Key だけを更新しました。Tunnel ID、profile、tunnel-client、connector は維持しています。"
        Write-Host "Platform 上の以前の key は自動削除していません。動作確認後、不要なら手動で失効してください。" -ForegroundColor Gray
        return $true
    } finally {
        if ($null -ne $newCredential) { $newCredential.Dispose() }
        if ($null -ne $oldCredential) { $oldCredential.Dispose() }
    }
}

function Invoke-SettingsMenu {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    while ($true) {
        Show-ConfigurationSummary -PythonPath $PythonPath -ConfigPath $ConfigPath
        Write-Host ""
        Write-Host "設定を変更する操作:" -ForegroundColor Cyan
        Write-Host "1. workspace を変更する（検証成功時だけ反映）"
        Write-Host "2. Tunnel ID / tunnel-client / profile を設定・変更する"
        Write-Host "3. Runtime API Key だけを変更する"
        Write-Host "4. Tunnel 設定を有効化 / 無効化する"
        Write-Host "5. active config を変更する"
        Write-Host "6. 設定を診断する"
        Write-Host "7. 保存済み Runtime API Key を削除する"
        Write-Host "0. 変更せず終了する"
        $choice = (Read-Host "番号").Trim()

        try {
            switch ($choice) {
                "1" {
                    Update-WorkspaceForSetup -PythonPath $PythonPath -ConfigPath $ConfigPath
                    break
                }
                "2" {
                    $null = Configure-TunnelIntegration -PythonPath $PythonPath -ConfigPath $ConfigPath
                    break
                }
                "3" {
                    $context = Get-TunnelConfigContext -PythonPath $PythonPath -ConfigPath $ConfigPath
                    $state = Get-TunnelStateForConfig -ConfigPath $ConfigPath
                    if ($null -eq $state) {
                        Write-Warn "Tunnel がまだ設定されていません。先に 2 または 4 を選んでください。"
                    } else {
                        $null = Update-TunnelRuntimeApiKey -PythonPath $PythonPath -ConfigPath $ConfigPath -Context $context -State $state
                    }
                    break
                }
                "4" {
                    $context = Get-TunnelConfigContext -PythonPath $PythonPath -ConfigPath $ConfigPath
                    $state = Get-TunnelStateForConfig -ConfigPath $ConfigPath
                    if ($null -ne $state -and [bool]$state.enabled -eq $true) {
                        Disable-TunnelIntegrationForSetup -ConfigPath $ConfigPath -State $state | Out-Null
                    } elseif ($null -ne $state) {
                        $null = Enable-TunnelIntegrationForSetup -ConfigPath $ConfigPath -Context $context -State $state
                    } else {
                        $null = Configure-NewTunnelIntegration -ConfigPath $ConfigPath -Context $context -PreviousState $state
                    }
                    break
                }
                "5" {
                    $candidate = Select-ExistingConfig
                    Test-Configuration -PythonPath $PythonPath -ConfigPath $candidate
                    Set-ActiveConfig -ConfigPath $candidate
                    $ConfigPath = $candidate
                    Write-Ok "active config を変更しました。"
                    break
                }
                "6" {
                    Test-Configuration -PythonPath $PythonPath -ConfigPath $ConfigPath
                    $context = Get-TunnelConfigContext -PythonPath $PythonPath -ConfigPath $ConfigPath
                    $state = Get-TunnelStateForConfig -ConfigPath $ConfigPath
                    if ($null -ne $state -and [bool]$state.enabled -eq $true) {
                        $null = Test-TunnelIntegrationForSetup -PythonPath $PythonPath -ConfigPath $ConfigPath -Context $context -State $state
                    } else {
                        Write-Ok "LocalMCP 設定を検証しました。Tunnel は未設定または無効です。"
                    }
                    break
                }
                "7" {
                    $state = Get-TunnelStateForConfig -ConfigPath $ConfigPath
                    if (Read-YesNo -Prompt "保存済み Runtime API Key を削除しますか（Tunnel も無効化します）" -Default $false) {
                        Remove-TunnelSavedCredentialForSetup -ConfigPath $ConfigPath -State $state
                    }
                    break
                }
                "0" { return $ConfigPath }
                default { Write-Warn "番号が正しくありません。" }
            }
        } catch {
            Write-Warn "変更を適用しませんでした: $($_.Exception.Message)"
        }
    }
}

function Resolve-CodexSandboxBackend {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    # セットアップは runtime と別の探索ロジックを持たず、同じ production resolver の
    # identity、署名、helper、version 検証結果だけを表示・保存します。wrapper は Python 側で
    # locator としてのみ扱い、実行ファイルとして返されることはありません。
    $previousConfig = $env:LOCAL_MCP_CONFIG
    $previousRoot = $env:LOCAL_MCP_ROOT
    try {
        $env:LOCAL_MCP_CONFIG = $ConfigPath
        Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        $output = @(& $PythonPath -I -B -m windows_local_mcp.cli resolve-codex-sandbox 2>&1)
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            return $null
        }
        $jsonText = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
        $backend = $jsonText | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $backend -or [string]::IsNullOrWhiteSpace([string]$backend.executable)) {
            return $null
        }
        if ([string]$backend.signature_status -ne "Valid" -or
            [string]$backend.signer_subject -notmatch "OpenAI OpCo, LLC" -or
            @($backend.helper_dependencies).Count -eq 0) {
            return $null
        }
        return $backend
    } catch {
        return $null
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
}

function Set-CodexSandboxPath {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$NativePath
    )

    if (-not [IO.Path]::IsPathRooted($NativePath)) {
        throw "Codex Sandbox backend の path が絶対 path ではありません。"
    }
    $tomlValue = ConvertTo-TomlString -Value $NativePath
    $lines = [System.Collections.Generic.List[string]]::new()
    [IO.File]::ReadAllLines($ConfigPath, [Text.UTF8Encoding]::new($false, $true)) |
        ForEach-Object { $lines.Add($_) }
    $updated = $false
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match '^\s*approved_sandbox_codex_path\s*=') {
            $lines[$index] = "approved_sandbox_codex_path = $tomlValue"
            $updated = $true
            break
        }
    }
    if (-not $updated) {
        $lines.Add("approved_sandbox_codex_path = $tomlValue")
    }
    $content = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
    Save-Config -Content $content -Path $ConfigPath -PythonPath $PythonPath -AllowExistingReplacement
}

function Show-OptionalChecks {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [object]$CodexBackend
    )

    $git = Find-TrustedGit
    if ($null -ne $git) {
        Write-Ok "Git runtime を検出しました。SHA-256 を設定しました。"
    } else {
        Write-Warn "Git runtime は自動設定していません。Automatic Git は明示的な path/hash と実機検証が必要です。"
    }

    if ($null -eq $CodexBackend) {
        Write-Warn "利用可能な Codex Sandbox backend を安全に解決できませんでした。"
    Write-Host "ファイルの読み書きはこのまま利用できます。Python、テスト、ビルドなどの Sandbox 経路はまだ利用できません。" -ForegroundColor Yellow
    Write-Host "導入案内（OpenAI 公式）: $CodexCliDocsUrl" -ForegroundColor Cyan
        Write-Host "導入後に configure-localmcp.bat を再実行してください。手動設定では信頼できる native codex.exe の絶対パスを approved_sandbox_codex_path に指定できます。"
    } else {
        Write-Ok "Codex Sandbox backend を検出しました: $($CodexBackend.executable)"
        Write-Info "version: $($CodexBackend.version)。native executable と helper の署名・ハッシュ・実体の識別情報を実行時にも再確認します。"
        Write-Info "npm wrapper は trusted executable として使用しません。"
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
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [bool]$TunnelEnabled = $false
    )

    Write-Host ""
    Write-Host "設定を手動で変更する場合:" -ForegroundColor Cyan
    Write-Host "1. 次の config.toml をメモ帳やエディターで開きます。"
    Write-Host "   $ConfigPath" -ForegroundColor Gray
    Write-Host "2. workspace_root は MCP から操作したいフォルダー、data_dir はその外側の保存場所です。"
    Write-Host "3. 保存後、次のコマンドで設定を検証して起動します。"
    Write-Host "   run-localmcp.bat -Config '$ConfigPath'" -ForegroundColor Gray
    Write-Host "別の設定ファイルへ切り替える場合は、configure-localmcp.bat の「現在の設定を確認・変更する」を選択します。"
    Write-Host "active-config.txt はこのウィザードが管理するため、通常は直接編集しません。"
    $currentState = Get-TunnelStateForConfig -ConfigPath $ConfigPath
    if ($TunnelEnabled -or ($null -ne $currentState -and [bool]$currentState.enabled -eq $true)) {
        Write-Host ""
        Write-Host "Secure MCP Tunnel は設定済みです。次回からは run-localmcp.bat だけで tunnel-client と LocalMCP を起動します。" -ForegroundColor Cyan
        Write-Host "ChatGPT 側で接続が表示されない場合は、Tunnel/connector の tool refresh を行ってください。"
    } else {
        Write-Host ""
        Write-Host "Secure MCP Tunnel はスキップまたは未設定です。run-localmcp.bat は従来どおり LocalMCP 単体を起動します。"
        Write-Host "後から設定・診断する場合は、configure-localmcp.bat の「現在の設定を確認・変更する」を選んでください。"
    }
}

if ($FunctionsOnly) {
    return
}

try {
    Write-Title "Windows Local MCP セットアップ"
    Write-Host "この画面は、初回セットアップと現在の設定の確認・変更を行う入口です。"
    Write-Host "通常のサーバーは管理者権限で起動しません。"

    $existing = @(Find-ExistingConfig)
    Write-Host ""
    Write-Host "1. かんたんセットアップ（必要なものを確認して新しい設定を作る）"
    if ($existing.Count -gt 0) {
        Write-Host "2. 現在の設定を確認・変更する（workspace、Tunnel、active config など）"
    } else {
        Write-Host "2. 現在の設定を確認・変更する（config.toml の場所を指定する）"
    }
    Write-Host "3. Secure MCP Tunnel の設定・診断だけを行う（LocalMCP 設定は初期化しない）"
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
        $codexBackend = Resolve-CodexSandboxBackend -PythonPath $python.Path -ConfigPath $configPath
        Show-OptionalChecks -ConfigPath $configPath -CodexBackend $codexBackend
        Write-Ok "既存設定を通常起動の対象にしました。"
        $configPath = Invoke-SettingsMenu -PythonPath $python.Path -ConfigPath $configPath
        $stateAfterSettings = Get-TunnelStateForConfig -ConfigPath $configPath
        $tunnelEnabled = $null -ne $stateAfterSettings -and [bool]$stateAfterSettings.enabled -eq $true
    } elseif ($mode -eq "1") {
        $python = Ensure-PythonRuntime
        $workspacePath = Read-WorkspacePath
        $gitInfo = Find-TrustedGit
        $content = New-ConfigContent -WorkspacePath $workspacePath -GitInfo $gitInfo
        $defaultExists = Test-Path -LiteralPath $DefaultConfigPath -PathType Leaf
        if ($defaultExists) {
            $existingStatePath = Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $DefaultConfigPath
            if (Test-Path -LiteralPath $existingStatePath -PathType Leaf) {
                throw "既存の Tunnel state があるため、かんたんセットアップで設定を置き換えません。2. 現在の設定を確認・変更するを選んでください。"
            }
            Write-Warn "既存の config.toml は自動では置き換えません。"
            if (-not (Read-YesNo -Prompt "既存の config.toml を明示的に置き換えますか" -Default $false)) {
                throw "既存設定を維持しました。2. 現在の設定を確認・変更するから続行できます。"
            }
        }
        Save-Config -Content $content -Path $DefaultConfigPath -PythonPath $python.Path -AllowExistingReplacement
        Test-Configuration -PythonPath $python.Path -ConfigPath $DefaultConfigPath
        Set-ActiveConfig -ConfigPath $DefaultConfigPath
        $configPath = $DefaultConfigPath
        $codexBackend = Resolve-CodexSandboxBackend -PythonPath $python.Path -ConfigPath $configPath
        if ($null -ne $codexBackend) {
            Set-CodexSandboxPath -PythonPath $python.Path -ConfigPath $configPath -NativePath ([string]$codexBackend.executable)
            Test-Configuration -PythonPath $python.Path -ConfigPath $configPath
            # 保存後の明示 path でも同じ resolver が成功することを確認してから成功表示します。
            $codexBackend = Resolve-CodexSandboxBackend -PythonPath $python.Path -ConfigPath $configPath
        }
        Show-OptionalChecks -ConfigPath $configPath -CodexBackend $codexBackend
        Write-Ok "初回設定が完了しました。"
        $tunnelEnabled = Configure-TunnelIntegration -PythonPath $python.Path -ConfigPath $configPath
    } elseif ($mode -eq "3") {
        $configPath = Select-ExistingConfig
        $python = Ensure-PythonRuntime
        Test-Configuration -PythonPath $python.Path -ConfigPath $configPath
        Set-ActiveConfig -ConfigPath $configPath
        $tunnelEnabled = Configure-TunnelIntegration -PythonPath $python.Path -ConfigPath $configPath
    } else {
        throw "メニューの番号が正しくありません。"
    }

    Write-Host ""
    Show-ConfigurationSummary -PythonPath $python.Path -ConfigPath $configPath
    Show-ManualConfigGuidance -ConfigPath $configPath -TunnelEnabled ([bool]$tunnelEnabled)
    Write-Host "次回からは run-localmcp.bat を実行してください。" -ForegroundColor Cyan
    Write-Host ""
    if (Read-YesNo -Prompt "今すぐ Windows Local MCP を起動しますか" -Default $true) {
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
