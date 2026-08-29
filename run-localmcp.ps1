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
$TunnelHelperPath = Join-Path $ScriptRoot "secure-mcp-tunnel.ps1"

function Get-RunTunnelFailureClass {
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

try {
    if (-not (Test-Path -LiteralPath $TunnelHelperPath -PathType Leaf)) {
        throw "secure-mcp-tunnel.ps1 が見つかりません。配布パッケージ全体を展開し直してください。"
    }
    . $TunnelHelperPath

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
        Write-Error "設定ファイルが見つかりません。先に configure-localmcp.bat を実行してください。" -ErrorAction Continue
        exit 2
    }
    if (-not (Test-Path -LiteralPath $ServerScript -PathType Leaf)) {
        throw "run-server.ps1 が見つかりません。配布パッケージ全体を展開し直してください。"
    }

    $resolvedConfig = (Resolve-Path -LiteralPath $Config).Path
    $statePath = Get-TunnelStatePath -StateRoot $StateRoot -ConfigPath $resolvedConfig
    $state = $null
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $state = Read-TunnelState -StatePath $statePath
    } else {
        # 旧版の単一 state は、記録された config が今回の config と一致する
        # 場合だけ後方互換として使用します。
        $legacyStatePath = Get-TunnelStatePath -StateRoot $StateRoot
        if (Test-Path -LiteralPath $legacyStatePath -PathType Leaf) {
            $legacyState = Read-TunnelState -StatePath $legacyStatePath
            if (-not [string]::IsNullOrWhiteSpace([string]$legacyState.config_path) -and
                [IO.Path]::GetFullPath([string]$legacyState.config_path).Equals($resolvedConfig, [StringComparison]::OrdinalIgnoreCase)) {
                $state = $legacyState
            }
        }
    }

    if ($null -eq $state -or [bool]$state.enabled -ne $true) {
        if ($null -ne $state -and -not [string]::IsNullOrWhiteSpace([string]$state.pid_file) -and
            -not [string]::IsNullOrWhiteSpace([string]$state.tunnel_client_path) -and
            -not [string]::IsNullOrWhiteSpace([string]$state.profile_path)) {
            $disabledStatus = Get-TunnelProcessStatus `
                -PidFile ([string]$state.pid_file) `
                -ClientPath ([string]$state.tunnel_client_path) `
                -ProfilePath ([string]$state.profile_path)
            if ($disabledStatus.Status -eq "running") {
                throw "無効化した Tunnel のプロセスがまだ起動中です。現在の起動ウィンドウで Ctrl+C を押してください。"
            }
            if ($disabledStatus.Status -eq "indeterminate") {
                throw "無効化した Tunnel の起動状態を安全に確認できません。重複起動を避けるため停止します。"
            }
        }

        # Tunnel 未設定の既存ユーザーは、従来どおり LocalMCP 単体を起動します。
        & $ServerScript -Config $resolvedConfig
        exit $LASTEXITCODE
    }

    Write-Host "LocalMCP の active config と Secure MCP Tunnel の設定を確認しています。" -ForegroundColor Cyan
    $pythonPath = Get-TunnelLocalMcpPythonPath -ScriptRoot $ScriptRoot
    if ([string]::IsNullOrWhiteSpace($pythonPath)) {
        Show-TunnelFailureGuide -FailureClass "server_start_failed"
        throw "Tunnel 起動に必要な専用 Python が見つかりません。"
    }
    $context = Test-TunnelLocalMcpConfiguration -PythonPath $pythonPath -ConfigPath $resolvedConfig
    if (-not $context.Valid) {
        Show-TunnelFailureGuide -FailureClass "server_start_failed"
        throw "LocalMCP の active config を検証できません。"
    }
    $forbiddenRoots = @($ScriptRoot, $context.WorkspaceRoot, $context.DataDir) |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -Unique
    $binding = Test-TunnelProfileBinding `
        -State $state `
        -ConfigPath $resolvedConfig `
        -ServerScript $ServerScript `
        -ProfileRoot (Join-Path $StateRoot "tunnel-profiles") `
        -StateRoot $StateRoot `
        -ForbiddenRoots $forbiddenRoots
    if (-not $binding.Valid) {
        Show-TunnelFailureGuide -FailureClass (Get-RunTunnelFailureClass -ReasonCode $binding.ReasonCode)
        throw "Secure MCP Tunnel の profile/runtime 整合性を確認できません。"
    }

    $credential = $null
    if ([string]$state.credential_mode -eq "credential_manager") {
        $credential = Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $resolvedConfig)
        if ($null -eq $credential) {
            Show-TunnelFailureGuide -FailureClass "auth_failed"
            throw "Runtime API Key を安全な資格情報領域から取得できません。"
        }
    }

    $doctor = Invoke-TunnelClientDoctor -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath -Credential $credential
    if (-not $doctor.Succeeded) {
        Show-TunnelDoctorDiagnostics -Doctor $doctor
        Show-TunnelFailureGuide -FailureClass $doctor.FailureClass
        throw "Tunnel の起動前検証に失敗しました。"
    }

    $mutex = [Threading.Mutex]::new($false, (Get-TunnelMutexName -ConfigPath $resolvedConfig))
    $hasMutex = $false
    $exitCode = 0
    try {
        try { $hasMutex = $mutex.WaitOne(0) } catch { $hasMutex = $false }
        if (-not $hasMutex) {
            throw "Tunnel が別の起動処理で使用中です。二重起動を避けるため停止します。"
        }

        $status = Get-TunnelProcessStatus `
            -PidFile ([string]$state.pid_file) `
            -ClientPath $binding.ClientPath `
            -ProfilePath $binding.ProfilePath
        if ($status.Status -eq "running") {
            Write-Host "既存の Tunnel client は起動済みです。" -ForegroundColor Green
            $exitCode = 0
        } elseif ($status.Status -eq "indeterminate") {
            throw "既存 Tunnel のプロセス識別情報を確認できません。重複起動を避けるため停止します。"
        } else {
            if ($status.Status -eq "stale" -and (Test-Path -LiteralPath $state.pid_file -PathType Leaf)) {
                Remove-Item -LiteralPath $state.pid_file -Force -ErrorAction Stop
            }
            if (Test-Path -LiteralPath $state.health_url_file -PathType Leaf) {
                Remove-Item -LiteralPath $state.health_url_file -Force -ErrorAction Stop
            }
            $started = Start-TunnelClientProcess -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath -Credential $credential
            $ready = Wait-TunnelReady -HealthUrlFile $state.health_url_file -TimeoutSeconds 20
            if ($ready.Ready) {
                Write-Host "Tunnel は起動し、ローカル ready 応答を確認しました。" -ForegroundColor Green
                Write-Host "ChatGPT 側で新しい接続が表示されない場合は、Tunnel/connector の tool refresh を行ってください。" -ForegroundColor Gray
            } else {
                Write-Warning "Tunnel client は起動しましたが、20 秒以内にローカル ready 応答を確認できませんでした。プロセスは維持します。"
                Show-TunnelFailureGuide -FailureClass "tunnel_client_failed"
            }
            $exitCode = Wait-TunnelClientProcess -Started $started
            if ($exitCode -ne 0) {
                Show-TunnelFailureGuide -FailureClass "tunnel_client_failed"
            }
        }
    } finally {
        if ($hasMutex) { try { $mutex.ReleaseMutex() } catch { } }
        $mutex.Dispose()
        if ($null -ne $credential) { $credential.Dispose() }
    }
    exit $exitCode
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
