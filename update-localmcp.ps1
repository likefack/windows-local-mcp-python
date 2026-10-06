[CmdletBinding()]
param(
    [string]$Config = '',
    [switch]$Check,
    [switch]$PrepareOnly,
    [switch]$NoRestart,
    # Internal parameters are used only by the hash-bound UAC child.
    [switch]$Elevated,
    [string]$PlanPath = '',
    [string]$PlanSha256 = ''
)

$ErrorActionPreference = 'Stop'

function Get-UpdateHash([string]$Path) {
    # PowerShell 5.1 may not auto-load Get-FileHash when launched from another runtime.
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

function Write-UpdateJson([string]$Path, [object]$Value) {
    $temporary = "$Path.tmp-$PID"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Test-UpdateAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-UpdatePath([string]$Path) {
    # All directory moves are restricted to a direct child of Program Files.
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) |
        Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
    if ((Split-Path -Parent $full) -notin $roots) { throw 'Unexpected runtime update path.' }
    if (Test-Path -LiteralPath $full) {
        if ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Runtime update paths must not be reparse points.'
        }
    }
    return $full
}

function Assert-UpdateSnapshot([string]$Root, [string]$ManifestHash) {
    $manifestPath = Join-Path $Root 'update-manifest.json'
    if ((Get-UpdateHash $manifestPath) -ne $ManifestHash) { throw 'Update manifest changed.' }
    $manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
    $seen = @{}
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Root)
    while ($queue.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $queue.Dequeue() -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Update snapshot contains a link.' }
            if ($item.PSIsContainer) { $queue.Enqueue($item.FullName); continue }
            $relative = $item.FullName.Substring($Root.Length + 1).Replace('\', '/')
            if ($relative -eq 'update-manifest.json') { continue }
            $expected = $manifest.files.PSObject.Properties[$relative]
            if ($null -eq $expected -or (Get-UpdateHash $item.FullName) -ne $expected.Value) {
                throw 'Update snapshot content changed.'
            }
            $seen[$relative] = $true
        }
    }
    if ($seen.Count -ne @($manifest.files.PSObject.Properties).Count) { throw 'Update snapshot is incomplete.' }
}

function Invoke-UpdatePython([string]$Python, [string]$Helper, [string[]]$Arguments, [switch]$QuietFailure) {
    # stderrも捕捉する。終了待ちの一時的な失敗は最後の診断だけを表示する。
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Python -I -B -X utf8 $Helper @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($code -ne 0) {
        $detail = ($output | ForEach-Object { $_.ToString() }) -join "`n"
        if (-not $QuietFailure -and $detail) { Write-Host $detail }
        throw "更新の検査に失敗しました: $($Arguments[0])`n$detail"
    }
    if ($output.Count) { return (($output -join "`n") | ConvertFrom-Json) }
}

function Assert-UpdateAuthorityIdle {
    $root = Join-Path $env:ProgramData 'WindowsLocalMCP\ApprovedHostAuthority'
    # Enumerating as Administrator must succeed; unreadable state is never treated as absent.
    $names = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop | Select-Object -ExpandProperty Name)
    foreach ($name in @('active.json', 'active-status.json', 'recovery_required')) {
        if ($name -in $names) { throw 'Approved Host has active or recovery state. Update cancelled.' }
    }
}

function Stop-UpdateTunnel([object]$State, [object]$Binding) {
    $status = Get-TunnelProcessStatus -PidFile $State.pid_file -ClientPath $Binding.ClientPath -ProfilePath $Binding.ProfilePath
    if ($status.Status -in @('absent', 'stale')) { return }
    if ($status.Status -ne 'running') { throw '終了するTunnelを識別できません。更新を中止します。' }
    $process = Get-Process -Id $status.ProcessId -ErrorAction Stop
    try {
        # ハンドルを先に確保し、PIDの再利用や曖昧なprofile一致による誤終了を防ぐ。
        $null = $process.Handle
        $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction Stop
        $profilePattern = '(?i)(?:^|\s)--profile-file\s+(?:"' + [regex]::Escape($Binding.ProfilePath) + '"|' + [regex]::Escape($Binding.ProfilePath) + ')(?=\s|$)'
        if ($process.HasExited -or $null -eq $cim -or
            -not ([string]$cim.ExecutablePath).Equals($Binding.ClientPath, [StringComparison]::OrdinalIgnoreCase) -or
            ([string]$cim.CommandLine) -notmatch $profilePattern) {
            throw 'Tunnelの識別情報が変わったため終了しませんでした。'
        }
        Write-Host '更新対象のTunnelを終了し、サーバーと起動ウィンドウの終了処理を待ちます。'
        # 対象の接続だけを閉じる。子サーバー・承認UI・authorityの一括強制終了はしない。
        $process.Kill()
        if (-not $process.WaitForExit(10000)) { throw 'Tunnelの終了を確認できませんでした。' }
    } finally { $process.Dispose() }
}

function Start-UpdateAuthority([string]$InstallRoot, [string]$UserSid) {
    if (-not (Test-UpdateAdministrator)) { throw '監視サービスの開始には管理者権限が必要です。' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $UserSid) { throw '同じユーザーのUAC承認が必要です。' }
    $root = Assert-UpdatePath $InstallRoot
    $python = Join-Path $root 'runtime\Scripts\python.exe'
    $stateRoot = Join-Path $env:ProgramData 'WindowsLocalMCP\ApprovedHostAuthority'
    $expected = '"' + $python + '" -I -B -m windows_local_mcp.approved_host_service_entry --runtime-sid "' + $UserSid + '" --state-root "' + $stateRoot + '"'
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='WindowsLocalMCPApprovedHost'"
    if ($null -eq $service -or $service.StartName -ne 'LocalSystem' -or $service.PathName -ne $expected) {
        throw '監視サービスの登録先が更新対象と一致しません。'
    }
    # 登録・ACL・復旧状態は変更せず、確認済みの既存サービスだけを開始する。
    if ($service.State -eq 'Stopped') { Start-Service -Name 'WindowsLocalMCPApprovedHost' }
    elseif ($service.State -ne 'Running') { throw '監視サービスは状態移行中です。後で再実行してください。' }
    (Get-Service -Name 'WindowsLocalMCPApprovedHost').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}

function Ensure-UpdateAuthority([string]$InstallRoot) {
    $service = Get-Service -Name 'WindowsLocalMCPApprovedHost' -ErrorAction Stop
    if ($service.Status -eq 'Running') { return }
    if ($service.Status -ne 'Stopped') { throw '監視サービスは状態移行中です。後で再実行してください。' }
    Write-Host '監視サービスが停止しています。Windowsの確認で「はい」を選ぶと既存サービスを開始します。'
    $scriptPath = (Join-Path $PSScriptRoot 'update-localmcp.ps1').Replace("'", "''")
    $root = $InstallRoot.Replace("'", "''")
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $hash = Get-UpdateHash (Join-Path $PSScriptRoot 'update-localmcp.ps1')
    # UAC起動までにスクリプトが変わっていないことを、読み込み前に検査する。
    $code = "`$ErrorActionPreference='Stop'; try { if ((Get-FileHash -LiteralPath '$scriptPath' -Algorithm SHA256).Hash -ne '$hash') { throw 'Updater changed' }; . '$scriptPath'; Start-UpdateAuthority '$root' '$sid'; exit 0 } catch { exit 1 }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -Verb RunAs -WindowStyle Hidden -PassThru
    try {
        if (-not $child.WaitForExit(60000)) { throw '監視サービス開始の確認が時間切れになりました。更新は行いません。' }
        if ($child.ExitCode -ne 0 -or (Get-Service -Name 'WindowsLocalMCPApprovedHost').Status -ne 'Running') {
            throw '監視サービスを開始できませんでした。サービスの登録と状態を確認してください。'
        }
    } finally { $child.Dispose() }
}

function Wait-UpdateOffline([string]$Python, [string]$Helper, [string[]]$Arguments) {
    # 接続終了後、stdioのEOFと起動側finallyによる後片付けを最大30秒待つ。
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        try { Invoke-UpdatePython $Python $Helper $Arguments -QuietFailure | Out-Null; return }
        catch { if ([DateTime]::UtcNow -ge $deadline) { throw } }
        Start-Sleep -Milliseconds 500
    } while ($true)
}

function Wait-UpdateDecision([object]$Plan, [string]$Phase) {
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    $path = Join-Path $Plan.task_root "$Phase.decision.json"
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $path) {
            $decision = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
            if ($decision.accept -ne $true) { throw 'Normal-user verification rejected the update.' }
            return
        }
        $parent = Get-Process -Id $Plan.parent_pid -ErrorAction SilentlyContinue
        if ($null -eq $parent -or $parent.StartTime.ToUniversalTime().Ticks.ToString() -ne $Plan.parent_started) {
            throw 'The normal-user updater exited. Update cancelled.'
        }
        Start-Sleep -Milliseconds 250
    }
    throw 'Normal-user verification timed out. Update cancelled.'
}

function Set-UpdateStatus([object]$Plan, [string]$Status) {
    Write-UpdateJson (Join-Path $Plan.task_root 'status.json') @{
        status = $Status; time_utc = [DateTime]::UtcNow.ToString('o')
    }
}

function Update-ServerScriptBinding([object]$State, [string]$StatePath, [string]$ExpectedHash, [string]$ServerScript) {
    if ((Get-UpdateHash $StatePath) -ne $ExpectedHash) { throw '更新中にTunnelの設定が変更されました。' }
    $newHash = Get-UpdateHash $ServerScript
    if ($State.server_script_sha256 -eq $newHash) { return $null }
    $State.server_script_sha256 = $newHash
    $saved = Save-TunnelStateAtomic -State $State -StatePath $StatePath
    return [PSCustomObject]@{ BackupPath = $saved.BackupPath; Hash = Get-UpdateHash $StatePath }
}

function Invoke-ElevatedUpdate([object]$Plan) {
    if (-not (Test-UpdateAdministrator)) { throw 'Administrator maintenance token required.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $Plan.user_sid) {
        throw 'Use UAC elevation of the same runtime user, not a different administrator account.'
    }
    $install = Assert-UpdatePath $Plan.install_root
    $ready = Assert-UpdatePath $Plan.ready_root
    $backup = Assert-UpdatePath $Plan.backup_root
    $failed = Assert-UpdatePath $Plan.failed_root
    $protectedSource = Assert-UpdatePath $Plan.protected_source
    foreach ($path in @($ready, $backup, $failed, $protectedSource, "$ready.staging-$PID")) {
        if (Test-Path -LiteralPath $path) { throw 'An update destination already exists.' }
    }
    $oldPython = Join-Path $install 'runtime\Scripts\python.exe'
    $helper = Join-Path $Plan.source 'scripts\runtime_update_support.py'
    $retired = $false
    $published = $false
    $serviceStopped = $false
    $serviceName = 'WindowsLocalMCPApprovedHost'
    Start-Transcript -LiteralPath (Join-Path $Plan.task_root 'installation.log') | Out-Null
    try {
        Assert-UpdateSnapshot $Plan.source $Plan.manifest_sha256
        if ((Get-UpdateHash $Plan.config) -ne $Plan.config_sha256) { throw 'Configuration changed.' }
        if ((Get-UpdateHash (Join-Path $install 'run-server.ps1')) -ne $Plan.old_server_sha256) { throw 'Installed launcher changed.' }
        Assert-UpdateAuthorityIdle
        Invoke-UpdatePython $oldPython $helper $Plan.offline_arguments | Out-Null
        $service = Get-Service -Name $serviceName
        $serviceImage = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName").ImagePath
        if ($service.Status -ne 'Running' -or
            $serviceImage.IndexOf($install + '\', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw 'The installed Approved Host authority service must be running from this runtime.'
        }

        # Copy only the reviewed snapshot, then protect it before running the installer.
        New-Item -ItemType Directory -Path $protectedSource | Out-Null
        & icacls.exe $protectedSource /setowner '*S-1-5-32-544' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect the update source owner.' }
        & icacls.exe $protectedSource /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($Plan.user_sid):(OI)(CI)RX" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect the update source.' }
        Get-ChildItem -LiteralPath $Plan.source -Force | Copy-Item -Destination $protectedSource -Recurse
        Assert-UpdateSnapshot $protectedSource $Plan.manifest_sha256
        $helper = Join-Path $protectedSource 'scripts\runtime_update_support.py'
        $constraints = Join-Path $Plan.task_root 'constraints.txt'
        if ((Get-UpdateHash $constraints) -ne $Plan.constraints_sha256) { throw 'Dependency constraints changed.' }
        Copy-Item -LiteralPath $constraints -Destination (Join-Path $protectedSource 'update-constraints.txt')
        if ((Get-UpdateHash (Join-Path $protectedSource 'update-constraints.txt')) -ne $Plan.constraints_sha256) { throw 'Dependency constraints changed during copying.' }
        # pip はこの環境変数を空白で分割する。file URI で空白・日本語を保持する。
        $env:PIP_CONSTRAINT = ([Uri](Join-Path $protectedSource 'update-constraints.txt')).AbsoluteUri
        Set-UpdateStatus $Plan 'building'
        # Never use -Replace: the working runtime and its ACLs remain intact while building.
        & (Join-Path $protectedSource 'install-approved-host-runtime.ps1') `
            -BasePython $Plan.base_python -InstallRoot $ready -RuntimeUser $Plan.runtime_user
        if (-not (Test-Path -LiteralPath (Join-Path $ready 'runtime\Scripts\python.exe'))) {
            throw 'The candidate runtime was not created.'
        }
        Set-UpdateStatus $Plan 'staged'
        Wait-UpdateDecision $Plan 'staged'

        if ((Get-UpdateHash $Plan.config) -ne $Plan.config_sha256) { throw 'Configuration changed during the build.' }
        Invoke-UpdatePython $oldPython $helper $Plan.offline_arguments | Out-Null
        Assert-UpdateAuthorityIdle
        $serviceStopped = $true
        Stop-Service -Name $serviceName
        (Get-Service $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        # Direct stdio launches bypass the Tunnel mutex; recheck immediately before moving.
        Invoke-UpdatePython $oldPython $helper $Plan.offline_arguments | Out-Null
        Assert-UpdateAuthorityIdle
        Assert-UpdatePath $install | Out-Null
        Assert-UpdatePath $ready | Out-Null
        Assert-UpdatePath $backup | Out-Null
        Move-Item -LiteralPath $install -Destination $backup
        $retired = $true
        Move-Item -LiteralPath $ready -Destination $install
        $published = $true
        Start-Service -Name $serviceName
        (Get-Service $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $serviceStopped = $false
        Set-UpdateStatus $Plan 'switched'
        Wait-UpdateDecision $Plan 'switched'
        Set-UpdateStatus $Plan 'installed'
    } catch {
        Write-Warning $_.Exception.Message
        try {
            if ($retired) {
                # A new operation/recovery marker prevents automatic rollback as well.
                Assert-UpdateAuthorityIdle
                $probePython = if ($published) { Join-Path $install 'runtime\Scripts\python.exe' } else { Join-Path $backup 'runtime\Scripts\python.exe' }
                Invoke-UpdatePython $probePython $helper $Plan.offline_arguments | Out-Null
                if ((Get-Service $serviceName).Status -ne 'Stopped') {
                    Stop-Service $serviceName
                    (Get-Service $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                }
                foreach ($path in @($install, $backup, $failed)) { Assert-UpdatePath $path | Out-Null }
                if ($published) { Move-Item -LiteralPath $install -Destination $failed }
                Move-Item -LiteralPath $backup -Destination $install
                Start-Service $serviceName
                (Get-Service $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                Set-UpdateStatus $Plan 'rolled_back'
            } else {
                if ($serviceStopped) { Start-Service $serviceName }
                Set-UpdateStatus $Plan 'failed_before_switch'
            }
        } catch {
            Set-UpdateStatus $Plan 'recovery_required'
            Write-Warning 'Automatic restore could not finish. Preserve the runtime, backup and installation log.'
        }
        throw
    } finally { Stop-Transcript | Out-Null }
}

function Invoke-LocalMcpUpdate {
    if (Test-UpdateAdministrator) { throw '通常のユーザーで update-localmcp.bat を起動してください。必要な段階だけUACを表示します。' }
    if ($Check -and $PrepareOnly) { throw '-Check と -PrepareOnly は同時に指定できません。' }
    $sourceRoot = $PSScriptRoot
    . (Join-Path $sourceRoot 'secure-mcp-tunnel.ps1')
    $stateRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'WindowsLocalMCP'
    if (-not $Config) {
        $selector = Join-Path $stateRoot 'active-config.txt'
        $Config = if (Test-Path -LiteralPath $selector) { (Get-Content -Raw -Encoding UTF8 -LiteralPath $selector).Trim() } else { Join-Path $stateRoot 'config.toml' }
    }
    $Config = (Resolve-Path -LiteralPath $Config).Path
    $statePath = Get-TunnelStatePath -StateRoot $stateRoot -ConfigPath $Config
    if (-not (Test-Path -LiteralPath $statePath)) { $statePath = Get-TunnelStatePath -StateRoot $stateRoot }
    $stateHash = Get-UpdateHash $statePath
    $state = Read-TunnelState -StatePath $statePath
    if ((Get-UpdateHash $statePath) -ne $stateHash) { throw '読み取り中にTunnelの設定が変更されました。再実行してください。' }
    if ($null -eq $state -or $state.server_runtime_kind -ne 'approved_host' -or -not $state.enabled) {
        throw 'この更新は、設定済みの Approved Host 運用版と有効なTunnelを対象にします。先に configure-localmcp.bat で設定してください。'
    }
    if ([IO.Path]::GetFullPath($state.config_path) -ne $Config) { throw '選択した設定とTunnelの設定が一致しません。' }
    $runtime = Resolve-TunnelServerRuntime -ScriptRoot $sourceRoot -State $state
    if (-not $runtime.Valid) { throw $runtime.Message }
    $install = Assert-UpdatePath (Split-Path -Parent $runtime.ServerScript)
    # This first updater handles one configured workspace per installed runtime.
    # A different profile must not retain an old launcher hash or an unexamined pending approval.
    $otherStates = @()
    $statesDirectory = Join-Path $stateRoot 'tunnel-state'
    if (Test-Path -LiteralPath $statesDirectory) {
        $otherStates = @(Get-ChildItem -LiteralPath $statesDirectory -Filter '*.json' -ErrorAction Stop)
    }
    $legacyPath = Get-TunnelStatePath -StateRoot $stateRoot
    if (Test-Path -LiteralPath $legacyPath) { $otherStates += Get-Item -LiteralPath $legacyPath }
    foreach ($file in $otherStates) {
        if ($file.FullName -eq $statePath) { continue }
        $other = Read-TunnelState -StatePath $file.FullName
        if ($other.server_script_path -eq $runtime.ServerScript -and $other.config_path -ne $Config) {
            throw '同じ運用版を複数の設定で共有しています。このバッチは設定1つの構成が対象です。共有構成では個別の更新計画が必要です。'
        }
    }
    $mutex = [Threading.Mutex]::new($false, (Get-TunnelMutexName -ConfigPath $Config))
    $held = $false
    $taskRoot = $null
    $stateBackup = $null
    $changedStateHash = $null
    $installed = $false
    $finalStatus = ''
    try {
        try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
        $binding = Test-TunnelProfileBinding -State $state -ConfigPath $Config -ServerScript $runtime.ServerScript `
            -ProfileRoot (Join-Path $stateRoot 'tunnel-profiles') -StateRoot $stateRoot
        if (-not $binding.Valid) { throw $binding.Message }
        $helper = Join-Path $sourceRoot 'scripts\runtime_update_support.py'
        $offlineArguments = @('offline', '--config', $Config, '--install-root', $install, '--launcher-root', $sourceRoot, '--profile', $state.profile_path)
        Write-Host '[1/5] 対象と停止状態を確認しています。'
        if (-not $PrepareOnly) {
            if ($Check) {
                if (-not $held) { throw 'LocalMCP が起動中です。確認のみのためサーバーは終了しません。' }
                Invoke-UpdatePython $runtime.PythonPath $helper $offlineArguments | Out-Null
            } else {
                Ensure-UpdateAuthority $install
                Invoke-UpdatePython $runtime.PythonPath $helper @('authority') | Out-Null
                # 処理・承認・復旧待ちを確認してから接続を終了する。
                Invoke-UpdatePython $runtime.PythonPath $helper @('idle', '--config', $Config) | Out-Null
                if ((Get-UpdateHash $statePath) -ne $stateHash) { throw '終了前にTunnelの設定が変更されました。' }
                Stop-UpdateTunnel $state $binding
                Invoke-UpdatePython $runtime.PythonPath $helper @('close-ui', '--config', $Config, '--install-root', $install) | Out-Null
                if (-not $held) {
                    try { $held = $mutex.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $held = $true }
                    if (-not $held) { throw 'サーバー起動側の終了を30秒以内に確認できませんでした。' }
                }
                Wait-UpdateOffline $runtime.PythonPath $helper $offlineArguments
            }
            $status = Get-TunnelProcessStatus -PidFile $state.pid_file -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath
            if ($status.Status -notin @('absent', 'stale')) { throw '対象のTunnelが起動中、または識別できません。LocalMCPを閉じてから再実行してください。' }
        }
        if ((Get-UpdateHash $statePath) -ne $stateHash) { throw '検査中にTunnelの設定が変更されました。再実行してください。' }
        $configHash = Get-UpdateHash $Config
        Write-Host "更新元: $sourceRoot"
        Write-Host "更新先: $install"
        if ($Check) { Write-Host '読み取り専用の確認が完了しました。運用版は変更していません。'; return }
        $dependencies = @(& $runtime.PythonPath -I -B -X utf8 -m pip check)
        if ($LASTEXITCODE -ne 0) {
            $dependencies | ForEach-Object { Write-Warning $_ }
            throw '既存の運用版に依存パッケージの不足・不整合があります。入れ替えは行いません。依存関係を復旧してから再実行してください。'
        }
        $runtime = Resolve-TunnelServerRuntime -ScriptRoot $sourceRoot -State $state -VerifyApprovedHostRuntime
        if (-not $runtime.Valid) { throw $runtime.Message }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $basePython = (@(& $runtime.PythonPath -I -B -c 'import sys; print(sys._base_executable)') -join '').Trim()
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $basePython)) { throw '運用版の基盤Pythonを確認できません。' }
        $id = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $taskRoot = Join-Path $sourceRoot ".dev-tmp\runtime-updates\$id"
        New-Item -ItemType Directory -Path $taskRoot | Out-Null
        $snapshot = Join-Path $taskRoot 'source'
        Write-Host '[2/5] 現在のDEVを固定し、隔離した作業場所でMCPの起動と読み取りを検査します。'
        Invoke-UpdatePython $runtime.PythonPath $helper @('snapshot', '--source', $sourceRoot, '--destination', $snapshot) | Out-Null
        $helper = Join-Path $snapshot 'scripts\runtime_update_support.py'
        $constraints = Join-Path $taskRoot 'constraints.txt'
        Invoke-UpdatePython $runtime.PythonPath $helper @('constraints', '--output', $constraints) | Out-Null
        $before = Invoke-UpdatePython $runtime.PythonPath $helper @('smoke', '--scratch', (Join-Path $taskRoot 'old-probe'))
        $candidate = Invoke-UpdatePython $runtime.PythonPath $helper @('smoke', '--scratch', (Join-Path $taskRoot 'source-probe'), '--source', $snapshot)
        $refresh = $before.tool_schema_sha256 -ne $candidate.tool_schema_sha256
        if ($PrepareOnly) { Write-Host "準備と起動テストが完了しました。運用版は未変更です。記録: $taskRoot"; return }
        $process = Get-Process -Id $PID
        $plan = [ordered]@{
            task_root = $taskRoot; source = $snapshot; config = $Config; config_sha256 = $configHash
            manifest_sha256 = Get-UpdateHash (Join-Path $snapshot 'update-manifest.json')
            constraints_sha256 = Get-UpdateHash $constraints; install_root = $install
            ready_root = "$install.ready-$id"; backup_root = "$install.before-$id"
            failed_root = "$install.failed-$id"; protected_source = "$install.source-$id"
            runtime_user = $identity.Name; user_sid = $identity.User.Value; base_python = $basePython
            old_server_sha256 = Get-UpdateHash $runtime.ServerScript; offline_arguments = $offlineArguments
            parent_pid = $PID; parent_started = $process.StartTime.ToUniversalTime().Ticks.ToString()
        }
        $planFile = Join-Path $taskRoot 'plan.json'
        Write-UpdateJson $planFile $plan
        $script = Join-Path $snapshot 'update-localmcp.ps1'
        # EncodedCommand transports literal Unicode paths; it is not a secrecy mechanism.
        $quotedScript = $script.Replace("'", "''")
        $quotedPlan = $planFile.Replace("'", "''")
        $bootstrap = "`$a=[Security.Cryptography.SHA256]::Create(); `$s=[IO.File]::OpenRead('$quotedScript'); try { `$h=[BitConverter]::ToString(`$a.ComputeHash(`$s)).Replace('-','').ToLowerInvariant() } finally { `$s.Dispose(); `$a.Dispose() }; if (`$h -ne '$(Get-UpdateHash $script)') { exit 2 }; & '$quotedScript' -Elevated -PlanPath '$quotedPlan' -PlanSha256 '$(Get-UpdateHash $planFile)'"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        Write-Host '[3/5] 運用版を構築します。Windowsの確認で「はい」を選んでください。'
        $child = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -Verb RunAs -WindowStyle Hidden -PassThru
        $handled = @{}
        $deadline = [DateTime]::UtcNow.AddMinutes(45)
        $finalStatus = ''
        while ([DateTime]::UtcNow -lt $deadline) {
            $statusPath = Join-Path $taskRoot 'status.json'
            if (Test-Path -LiteralPath $statusPath) {
                $phase = (Get-Content -Raw -Encoding UTF8 -LiteralPath $statusPath | ConvertFrom-Json).status
                if ($phase -in @('staged', 'switched') -and -not $handled.ContainsKey($phase)) {
                    $handled[$phase] = $true
                    $accepted = $false
                    try {
                        if ((Get-UpdateHash $Config) -ne $configHash -or (Get-UpdateHash $statePath) -ne $stateHash) { throw '更新中に設定が変更されました。' }
                        $probeRoot = if ($phase -eq 'staged') { $plan.ready_root } else { $install }
                        Write-Host "[4/5] 通常ユーザーの権限で検証しています: $phase"
                        & $powershell -NoProfile -File (Join-Path $snapshot 'verify-approved-host-runtime.ps1') -InstallRoot $probeRoot
                        if ($LASTEXITCODE -ne 0) { throw '運用版の変更不能性検証に失敗しました。' }
                        $probePython = Join-Path $probeRoot 'runtime\Scripts\python.exe'
                        $probe = Invoke-UpdatePython $probePython $helper @('smoke', '--scratch', (Join-Path $taskRoot "$phase-probe"))
                        if ($probe.tool_schema_sha256 -ne $candidate.tool_schema_sha256) { throw 'インストール後のツール定義が準備時と一致しません。' }
                        if ($phase -eq 'switched') {
                            Invoke-UpdatePython $probePython $helper @('authority') | Out-Null
                            # Binding is part of verification: reject before committing if it fails.
                            $saved = Update-ServerScriptBinding $state $statePath $stateHash (Join-Path $install 'run-server.ps1')
                            if ($null -ne $saved) {
                                $stateBackup = $saved.BackupPath
                                $changedStateHash = $saved.Hash
                            }
                            $state = Read-TunnelState -StatePath $statePath
                            $rebound = Resolve-TunnelServerRuntime -ScriptRoot $sourceRoot -State $state
                            if (-not $rebound.Valid) { throw '更新後の接続設定の検証に失敗しました。' }
                            $binding = Test-TunnelProfileBinding -State $state -ConfigPath $Config -ServerScript $rebound.ServerScript `
                                -ProfileRoot (Join-Path $stateRoot 'tunnel-profiles') -StateRoot $stateRoot
                            if (-not $binding.Valid) { throw $binding.Message }
                        }
                        $accepted = $true
                    } catch { Write-Warning $_.Exception.Message }
                    Write-UpdateJson (Join-Path $taskRoot "$phase.decision.json") @{ accept = $accepted }
                }
                if ($phase -in @('installed', 'rolled_back', 'failed_before_switch', 'recovery_required')) { $finalStatus = $phase; break }
            }
            if ($child.HasExited) {
                # The child can publish its final status immediately after the ACK above.
                if (Test-Path -LiteralPath $statusPath) {
                    $last = (Get-Content -Raw -Encoding UTF8 -LiteralPath $statusPath | ConvertFrom-Json).status
                    if ($last -in @('installed', 'rolled_back', 'failed_before_switch', 'recovery_required')) {
                        $finalStatus = $last
                        break
                    }
                }
                throw "更新処理が終了しました。記録を確認してください: $taskRoot"
            }
            Start-Sleep -Milliseconds 500
        }
        if ($finalStatus -ne 'installed') { throw "更新は完了していません ($finalStatus)。記録: $taskRoot" }
        $installed = $true
        Write-Host "[5/5] 運用版の更新が完了しました。旧版: $($plan.backup_root)"
        Write-Host "更新記録: $taskRoot"
        if ($refresh) { Write-Host 'ツール定義が変わりました。起動後にChatGPT側の「更新する」を押してください。' }
        else { Write-Host 'ツール定義に変更はありません。実装の更新を反映しました。' }
        $mutex.ReleaseMutex(); $held = $false
        if (-not $NoRestart) {
            # The server must inherit this normal user, never the elevated installer token.
            $launchPath = (Join-Path $sourceRoot 'run-localmcp.ps1').Replace("'", "''")
            $launchConfig = $Config.Replace("'", "''")
            $launch = "Remove-Item Env:WLMCP_NO_PAUSE -ErrorAction SilentlyContinue; & '$launchPath' -Config '$launchConfig'"
            $launchEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($launch))
            Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $launchEncoded) -WindowStyle Hidden | Out-Null
            $ready = Wait-TunnelReady -HealthUrlFile $state.health_url_file -TimeoutSeconds 60
            $running = Get-TunnelProcessStatus -PidFile $state.pid_file -ClientPath $binding.ClientPath -ProfilePath $binding.ProfilePath
            if (-not $ready.Ready -or $running.Status -ne 'running') { throw '運用版は更新済みですが、正規のTunnelと接続準備を確認できません。run-localmcp.bat を起動して診断を確認してください。' }
            Write-Host 'Tunnelの接続準備が完了しました。'
        }
    } finally {
        if (-not $installed -and $stateBackup -and (Test-Path -LiteralPath $stateBackup)) {
            # Never restore an old binding while the new runtime remains installed.
            if ($finalStatus -eq 'rolled_back' -and
                (Get-UpdateHash (Join-Path $install 'run-server.ps1')) -eq $plan.old_server_sha256 -and
                (Get-UpdateHash $statePath) -eq $changedStateHash) {
                Restore-TunnelFileBackup -DestinationPath $statePath -BackupPath $stateBackup
            } else {
                Write-Warning '旧版への復元を確定できないため接続設定は保持します。更新記録を確認し、必要なら configure-localmcp.bat で運用版との対応を再設定してください。'
            }
        }
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

# Dot sourcing exposes pure helpers to tests without starting an update.
if ($MyInvocation.InvocationName -eq '.') { return }
try {
    if ($Elevated) {
        if (-not $PlanPath -or (Get-UpdateHash $PlanPath) -ne $PlanSha256) { throw 'Update plan changed.' }
        $plan = Get-Content -Raw -Encoding UTF8 -LiteralPath $PlanPath | ConvertFrom-Json
        Invoke-ElevatedUpdate $plan
    } else { Invoke-LocalMcpUpdate }
    exit 0
} catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 1
}
