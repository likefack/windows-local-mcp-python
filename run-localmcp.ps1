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

function Start-LocalMcpActivityMonitor {
    param(
        [AllowNull()][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [switch]$StdoutOnly
    )

    if ([string]::IsNullOrWhiteSpace($PythonPath) -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        Write-Warning "Live Activity 監視用の専用 Python が見つからないため、活動表示だけを開始できません。LocalMCP の起動は継続します。"
        return $null
    }

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PythonPath
    $startInfo.Arguments = "-I -B -m windows_local_mcp.activity_monitor --config " + (ConvertTo-TunnelCommandArgument -Value $ConfigPath)
    if ($StdoutOnly) { $startInfo.Arguments += " --stdout-only" }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $false
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "活動監視プロセスを開始できません。"
        }
        if ($process.WaitForExit(500)) {
            $exitCode = $process.ExitCode
            $process.Dispose()
            Write-Warning "Live Activity 監視が起動直後に終了しました（終了コード: $exitCode）。LocalMCP の起動は継続します。"
            return $null
        }
        Write-Host "監査操作とローカル承認要求をこのウィンドウへ表示します。" -ForegroundColor Cyan
        return $process
    } catch {
        $process.Dispose()
        Write-Warning "Live Activity 監視を開始できません。LocalMCP の起動は継続します。"
        return $null
    }
}

function Stop-LocalMcpActivityMonitor {
    param([AllowNull()][Diagnostics.Process]$Process)

    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            $Process.Kill()
            $Process.WaitForExit(3000) | Out-Null
        }
    } catch {
        Write-Warning "Live Activity 監視プロセスの終了を確認できませんでした。"
    } finally {
        $Process.Dispose()
    }
}

function Get-LocalMcpApprovalUiAutostart {
    param(
        [AllowNull()][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    if ([string]::IsNullOrWhiteSpace($PythonPath) -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        return [PSCustomObject]@{ Valid = $false; Enabled = $false }
    }
    $previousConfig = $env:LOCAL_MCP_CONFIG
    $previousRoot = $env:LOCAL_MCP_ROOT
    try {
        $env:LOCAL_MCP_CONFIG = $ConfigPath
        Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        $probe = @(
            "from windows_local_mcp.config import load_settings",
            "settings = load_settings()",
            "print('approval_ui_autostart=' + ('true' if settings.approval_ui_autostart else 'false'))"
        ) -join "; "
        $output = @(& $PythonPath -I -B -c $probe 2>$null)
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ Valid = $false; Enabled = $false }
        }
        $line = $output |
            Where-Object { $_.ToString().StartsWith("approval_ui_autostart=", [StringComparison]::Ordinal) } |
            Select-Object -Last 1
        if ($null -eq $line) {
            return [PSCustomObject]@{ Valid = $false; Enabled = $false }
        }
        $value = $line.ToString().Substring("approval_ui_autostart=".Length).ToLowerInvariant()
        if ($value -eq "true") {
            return [PSCustomObject]@{ Valid = $true; Enabled = $true }
        }
        if ($value -eq "false") {
            return [PSCustomObject]@{ Valid = $true; Enabled = $false }
        }
        return [PSCustomObject]@{ Valid = $false; Enabled = $false }
    } catch {
        return [PSCustomObject]@{ Valid = $false; Enabled = $false }
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

function ConvertTo-LocalMcpProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -match '[\r\n]') {
        throw "承認UIの引数に改行は使用できません。"
    }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Start-LocalMcpApprovalUi {
    param(
        [Parameter(Mandatory = $true)][string]$ServerScriptPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    # ServerScriptPath は Resolve-TunnelServerRuntime が選択・検証した値です。
    # ここでも sibling だけを解決し、Approved Host から repository へ戻る候補は作りません。
    $runtimeRoot = Split-Path -Parent $ServerScriptPath
    $approvalScriptPath = Join-Path $runtimeRoot "run-approvals.ps1"
    if (-not (Test-Path -LiteralPath $approvalScriptPath -PathType Leaf)) {
        Write-Warning "選択済み LocalMCP runtime の run-approvals.ps1 が見つからないため、承認UIを自動起動できません。LocalMCP の起動は継続します。"
        return $null
    }
    $windowsPowerShell51 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    if (-not (Test-Path -LiteralPath $windowsPowerShell51 -PathType Leaf)) {
        Write-Warning "Windows PowerShell 5.1 が見つからないため、承認UIを自動起動できません。LocalMCP の起動は継続します。"
        return $null
    }

    $process = $null
    try {
        $arguments = @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            (ConvertTo-LocalMcpProcessArgument -Value $approvalScriptPath),
            "-Config",
            (ConvertTo-LocalMcpProcessArgument -Value $ConfigPath)
        )
        $process = Start-Process `
            -FilePath $windowsPowerShell51 `
            -ArgumentList $arguments `
            -WorkingDirectory $runtimeRoot `
            -WindowStyle Normal `
            -PassThru `
            -ErrorAction Stop
        if ($null -eq $process) {
            throw "承認UIプロセスを開始できません。"
        }
        # Mutex重複時は run-approvals.ps1 がすぐ終了します。終了済みなら追跡対象に
        # せず、既存の手動UIを後段の終了処理で触らないようにします。
        if ($process.WaitForExit(750)) {
            $exitCode = $process.ExitCode
            $process.Dispose()
            $process = $null
            if ($exitCode -eq 0) {
                Write-Host "同じ設定のローカル承認UIは既に起動しています。自動起動を重複させません。" -ForegroundColor Gray
            } else {
                Write-Warning "ローカル承認UIが起動直後に終了しました（終了コード: $exitCode）。LocalMCP の起動は継続します。"
            }
            return $null
        }
        Write-Host "ローカル承認UIを別の Windows PowerShell 5.1 ウィンドウで起動しました。" -ForegroundColor Cyan
        return $process
    } catch {
        if ($null -ne $process) {
            try { $process.Dispose() } catch { }
        }
        Write-Warning "ローカル承認UIを自動起動できません。LocalMCP の起動は継続します。"
        return $null
    }
}

function Stop-LocalMcpApprovalUi {
    param([AllowNull()][Diagnostics.Process]$Process)

    if ($null -eq $Process) { return }
    try {
        if ($Process.HasExited) { return }
        # まず通常のウィンドウ終了を試します。PowerShellだけを強制終了すると子の
        # Python承認UIが孤立し得るため、応答しない場合は利用者へ手動終了を案内します。
        $null = $Process.CloseMainWindow()
        if (-not $Process.WaitForExit(3000)) {
            Write-Warning "自動起動したローカル承認UIが終了していません。承認ウィンドウを確認して閉じてください。"
        }
    } catch {
        Write-Warning "自動起動したローカル承認UIの終了を確認できませんでした。"
    } finally {
        $Process.Dispose()
    }
}

function Wait-LocalMcpExistingTunnel {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    # Get-TunnelProcessStatus and /readyz were verified before this call. Hold a
    # process handle so PID reuse cannot attach this window to a later process.
    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    try {
        Write-Host "既存の Tunnel を使用しています。このウィンドウは Tunnel の終了まで開いたままです。" -ForegroundColor Cyan
        while (-not $process.WaitForExit(1000)) {
            # Bounded waits let PowerShell process Ctrl+C and run the approval
            # window cleanup without terminating the existing Tunnel.
        }
        Write-Warning "既存の Tunnel が終了しました。再起動するには run-localmcp.bat を実行してください。"
        return $process.ExitCode
    } finally {
        $process.Dispose()
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

    $serverRuntime = Resolve-TunnelServerRuntime `
        -ScriptRoot $ScriptRoot `
        -State $state `
        -VerifyApprovedHostRuntime:($null -ne $state -and [string]$state.server_runtime_kind -eq "approved_host")
    if (-not $serverRuntime.Valid) {
        throw "LocalMCP server runtime を安全に確認できません: $($serverRuntime.Message)"
    }
    $ServerScript = $serverRuntime.ServerScript

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
        $approvalUiProcess = $null
        $approvalUiAutostart = Get-LocalMcpApprovalUiAutostart `
            -PythonPath $serverRuntime.PythonPath `
            -ConfigPath $resolvedConfig
        if (-not $approvalUiAutostart.Valid) {
            Write-Warning "承認UIの自動起動設定を確認できません。承認UIは自動起動せず、LocalMCP の起動は継続します。"
        }
        $activityMonitor = Start-LocalMcpActivityMonitor -PythonPath $serverRuntime.PythonPath -ConfigPath $resolvedConfig
        if ($approvalUiAutostart.Valid -and $approvalUiAutostart.Enabled) {
            $approvalUiProcess = Start-LocalMcpApprovalUi `
                -ServerScriptPath $ServerScript `
                -ConfigPath $resolvedConfig
        }
        try {
            & $ServerScript -Config $resolvedConfig
            $directExitCode = $LASTEXITCODE
        } finally {
            Stop-LocalMcpApprovalUi -Process $approvalUiProcess
            Stop-LocalMcpActivityMonitor -Process $activityMonitor
        }
        exit $directExitCode
    }

    Write-Host "LocalMCP の active config と Secure MCP Tunnel の設定を確認しています。" -ForegroundColor Cyan
    $pythonPath = $serverRuntime.PythonPath
    if ([string]::IsNullOrWhiteSpace($pythonPath)) {
        Show-TunnelFailureGuide -FailureClass "server_start_failed"
        throw "Tunnel 起動に必要な専用 Python が見つかりません。"
    }
    $context = Test-TunnelLocalMcpConfiguration -PythonPath $pythonPath -ConfigPath $resolvedConfig
    if (-not $context.Valid) {
        Show-TunnelFailureGuide `
            -FailureClass "server_start_failed" `
            -ReasonCode ([string]$context.ReasonCode) `
            -Detail ([string]$context.Message)
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
        Show-TunnelFailureGuide -FailureClass (Get-RunTunnelFailureClass -ReasonCode $binding.ReasonCode) -ReasonCode $binding.ReasonCode -Detail $binding.Message
        throw "Secure MCP Tunnel の profile/runtime 整合性を確認できません。"
    }

    $credential = $null
    $mutex = [Threading.Mutex]::new($false, (Get-TunnelMutexName -ConfigPath $resolvedConfig))
    $hasMutex = $false
    $exitCode = 0
    $activityMonitor = $null
    $approvalUiProcess = $null
    $existingTunnelPid = $null
    $approvalUiAutostart = Get-LocalMcpApprovalUiAutostart `
        -PythonPath $pythonPath `
        -ConfigPath $resolvedConfig
    if (-not $approvalUiAutostart.Valid) {
        Write-Warning "承認UIの自動起動設定を確認できません。承認UIは自動起動せず、Tunnel/LocalMCP の安全性検証と起動は継続します。"
    }
    try {
        try { $hasMutex = $mutex.WaitOne(0) } catch { $hasMutex = $false }
        if (-not $hasMutex) {
            # 正常な既存 Tunnel の再クリックは idempotent に扱います。mutex だけを
            # 根拠に成功とはせず、同じ client/profile と loopback ready 応答の両方を
            # 確認します。起動途中の場合も bounded wait の間だけ待機します。
            $ready = Wait-TunnelReady -HealthUrlFile $state.health_url_file -TimeoutSeconds 20
            $status = Get-TunnelProcessStatus `
                -PidFile ([string]$state.pid_file) `
                -ClientPath $binding.ClientPath `
                -ProfilePath $binding.ProfilePath
            if ($ready.Ready -and $status.Status -eq "running") {
                Write-Host "Tunnel は既に起動済みで、ローカル ready 応答を確認しました。Tunnel は追加起動しません。" -ForegroundColor Green
                $existingTunnelPid = [int]$status.ProcessId
            } elseif ($status.Status -eq "indeterminate") {
                throw "別の Tunnel 起動処理を検出しましたが、プロセス識別情報を安全に確認できません。二重起動を避けるため停止します。"
            } else {
                throw "別の Tunnel 起動処理を検出しましたが、20 秒以内に正規プロセスとローカル ready 応答を確認できません。二重起動を避けるため停止します。"
            }
        } else {
            # 初回起動または mutex を安全に取得できた recovery path だけが
            # Credential Manager と doctor を使用します。正常な既存 Tunnel の
            # 再クリックでは秘密情報や追加の診断 process を起動しません。
            if ([string]$state.credential_mode -eq "credential_manager") {
                $credential = Get-TunnelCredentialSecure -Target (Get-TunnelCredentialTarget -ConfigPath $resolvedConfig)
                if ($null -eq $credential) {
                    Show-TunnelFailureGuide -FailureClass "auth_failed"
                    throw "Runtime API Key を安全な資格情報領域から取得できません。"
                }
            }

            $doctor = Invoke-TunnelClientDoctor -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath -Credential $credential
            if (-not $doctor.Succeeded) {
                Show-TunnelDoctorFailureGuide -DoctorResult $doctor
                throw "Tunnel の起動前検証に失敗しました。"
            }

            $status = Get-TunnelProcessStatus `
                -PidFile ([string]$state.pid_file) `
                -ClientPath $binding.ClientPath `
                -ProfilePath $binding.ProfilePath
            if ($status.Status -eq "running") {
                $ready = Wait-TunnelReady -HealthUrlFile $state.health_url_file -TimeoutSeconds 20
                if (-not $ready.Ready) {
                    throw "既存の Tunnel client は起動中ですが、ローカル ready 応答を確認できません。"
                }
                Write-Host "Tunnel は既に起動済みで、ローカル ready 応答を確認しました。Tunnel は追加起動しません。" -ForegroundColor Green
                $existingTunnelPid = [int]$status.ProcessId
            } elseif ($status.Status -eq "indeterminate") {
                throw "既存 Tunnel のプロセス識別情報を確認できません。重複起動を避けるため停止します。"
            } else {
                if ($status.Status -eq "stale" -and (Test-Path -LiteralPath $state.pid_file -PathType Leaf)) {
                    Remove-Item -LiteralPath $state.pid_file -Force -ErrorAction Stop
                }
                if (Test-Path -LiteralPath $state.health_url_file -PathType Leaf) {
                    Remove-Item -LiteralPath $state.health_url_file -Force -ErrorAction Stop
                }
                $activityMonitor = Start-LocalMcpActivityMonitor -PythonPath $pythonPath -ConfigPath $resolvedConfig
                if ($approvalUiAutostart.Valid -and $approvalUiAutostart.Enabled) {
                    $approvalUiProcess = Start-LocalMcpApprovalUi `
                        -ServerScriptPath $ServerScript `
                        -ConfigPath $resolvedConfig
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
        }
        if ($null -ne $existingTunnelPid) {
            if ($env:WLMCP_NO_PAUSE -eq "1") {
                # Noninteractive callers only need the verified status and exit code.
                $exitCode = 0
            } else {
                # Reopening the launcher restores the local approval window if its
                # prior owner disappeared; the approval mutex prevents duplicates.
                # This observer only displays audit changes. The original owner
                # remains the sole writer of the rotating activity log.
                $activityMonitor = Start-LocalMcpActivityMonitor -PythonPath $pythonPath -ConfigPath $resolvedConfig -StdoutOnly
                if ($approvalUiAutostart.Valid -and $approvalUiAutostart.Enabled) {
                    $approvalUiProcess = Start-LocalMcpApprovalUi `
                        -ServerScriptPath $ServerScript `
                        -ConfigPath $resolvedConfig
                }
                $exitCode = Wait-LocalMcpExistingTunnel -ProcessId $existingTunnelPid
            }
        }
    } finally {
        Stop-LocalMcpApprovalUi -Process $approvalUiProcess
        Stop-LocalMcpActivityMonitor -Process $activityMonitor
        if ($hasMutex) { try { $mutex.ReleaseMutex() } catch { } }
        $mutex.Dispose()
        if ($null -ne $credential) { $credential.Dispose() }
    }
    exit $exitCode
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
