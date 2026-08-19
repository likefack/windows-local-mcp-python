[CmdletBinding()]
param(
    [string]$CodexPath,

    [string]$OutputPath,

    [switch]$RunSandboxProbe
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "この診断はnative Windowsでのみ実行できます。"
}

function Resolve-CodexPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $root = Join-Path $env:LOCALAPPDATA "OpenAI\Codex\bin"
    $candidates = @(
        Get-ChildItem -LiteralPath $root -Filter "codex.exe" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                (Test-Path -LiteralPath (Join-Path $_.DirectoryName "codex-command-runner.exe")) -and
                (Test-Path -LiteralPath (Join-Path $_.DirectoryName "codex-windows-sandbox-setup.exe"))
            } |
            Sort-Object LastWriteTimeUtc -Descending
    )
    if ($candidates.Count -eq 0) {
        throw "installed Codex CLIを解決できません。-CodexPathで明示してください。"
    }
    return $candidates[0].FullName
}

function Get-FileSnapshot {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $item = Get-Item -LiteralPath $Path
    return [ordered]@{
        path = $item.FullName
        length = $item.Length
        last_write_time_utc = $item.LastWriteTimeUtc.ToString("o")
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    }
}

function Get-FirewallState {
    try {
        $rules = @(
            Get-NetFirewallRule -PolicyStore ActiveStore |
                Where-Object { $_.DisplayName -like "codex_sandbox_offline_*" }
        )
        $result = foreach ($rule in $rules) {
            $address = $rule | Get-NetFirewallAddressFilter
            $port = $rule | Get-NetFirewallPortFilter
            $security = $rule | Get-NetFirewallSecurityFilter
            [ordered]@{
                name = $rule.Name
                display_name = $rule.DisplayName
                enabled = [string]$rule.Enabled
                profile = [string]$rule.Profile
                direction = [string]$rule.Direction
                action = [string]$rule.Action
                status = [string]$rule.Status
                policy_store_source = [string]$rule.PolicyStoreSource
                protocol = [string]$port.Protocol
                remote_port = @($port.RemotePort)
                remote_address = @($address.RemoteAddress)
                local_user = [string]$security.LocalUser
            }
        }
        return [ordered]@{ status = "collected"; rules = @($result) }
    }
    catch {
        return [ordered]@{ status = "unavailable"; error = $_.Exception.Message; rules = @() }
    }
}

function Receive-TcpTokens {
    param([System.Net.Sockets.TcpListener]$Listener)

    $tokens = @()
    if ($null -eq $Listener) {
        return $tokens
    }
    while ($Listener.Pending()) {
        $client = $Listener.AcceptTcpClient()
        try {
            $client.ReceiveTimeout = 1000
            $reader = [System.IO.StreamReader]::new($client.GetStream(), [System.Text.Encoding]::UTF8)
            $tokens += $reader.ReadLine()
            $reader.Dispose()
        }
        finally {
            $client.Dispose()
        }
    }
    return $tokens
}

function Receive-UdpTokens {
    param(
        [System.Net.Sockets.UdpClient]$Client,
        [System.Net.IPAddress]$AnyAddress
    )

    $tokens = @()
    if ($null -eq $Client) {
        return $tokens
    }
    while ($Client.Available -gt 0) {
        $remote = [System.Net.IPEndPoint]::new($AnyAddress, 0)
        $bytes = $Client.Receive([ref]$remote)
        $tokens += [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    return $tokens
}

function New-ListenerSet {
    $set = [ordered]@{
        tcp4 = $null
        tcp6 = $null
        udp4 = $null
        udp6 = $null
        errors = @()
    }

    try {
        $set.tcp4 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $set.tcp4.Start(8)
        $set.udp4 = [System.Net.Sockets.UdpClient]::new(
            [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0)
        )
    }
    catch {
        $set.errors += "IPv4 listener: $($_.Exception.Message)"
    }

    if ([System.Net.Sockets.Socket]::OSSupportsIPv6) {
        try {
            $set.tcp6 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 0)
            $set.tcp6.Server.DualMode = $false
            $set.tcp6.Start(8)
        }
        catch {
            if ($null -ne $set.tcp6) {
                $set.tcp6.Stop()
                $set.tcp6 = $null
            }
            $set.errors += "IPv6 TCP listener: $($_.Exception.Message)"
        }

        try {
            # UdpClient(IPEndPoint) binds immediately. Windows can reject changing
            # IPV6_V6ONLY/DualMode after bind, so configure the socket first and bind last.
            $set.udp6 = [System.Net.Sockets.UdpClient]::new(
                [System.Net.Sockets.AddressFamily]::InterNetworkV6
            )
            $set.udp6.Client.DualMode = $false
            $set.udp6.Client.Bind(
                [System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Loopback, 0)
            )
        }
        catch {
            if ($null -ne $set.udp6) {
                $set.udp6.Dispose()
                $set.udp6 = $null
            }
            $set.errors += "IPv6 UDP listener: $($_.Exception.Message)"
        }
    }
    else {
        $set.errors += "IPv6 is not supported by this host"
    }
    return $set
}

function Stop-ListenerSet {
    param($Listeners)

    if ($null -ne $Listeners.tcp4) { $Listeners.tcp4.Stop() }
    if ($null -ne $Listeners.tcp6) { $Listeners.tcp6.Stop() }
    if ($null -ne $Listeners.udp4) { $Listeners.udp4.Dispose() }
    if ($null -ne $Listeners.udp6) { $Listeners.udp6.Dispose() }
}

$resolvedCodex = Resolve-CodexPath -ExplicitPath $CodexPath
$setupPath = Join-Path (Split-Path -Parent $resolvedCodex) "codex-windows-sandbox-setup.exe"
$runnerPath = Join-Path (Split-Path -Parent $resolvedCodex) "codex-command-runner.exe"
$markerPath = Join-Path $env:USERPROFILE ".codex\.sandbox\setup_marker.json"
$denyReadStatePath = Join-Path $env:USERPROFILE ".codex\.sandbox\deny_read_acl_state.json"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$childProbe = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "CodexLoopbackProbe.Child.ps1")).Path

if (-not $OutputPath) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $env:TEMP "codex-loopback-probe-$timestamp.json"
}

$offlineUser = Get-LocalUser -Name "CodexSandboxOffline" -ErrorAction Stop
$markerBefore = Get-FileSnapshot -Path $markerPath
$markerPayload = $null
if ($null -ne $markerBefore) {
    $markerPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $markerPath | ConvertFrom-Json
}

$report = [ordered]@{
    version = 1
    collected_at = (Get-Date).ToUniversalTime().ToString("o")
    host_identity = [ordered]@{
        name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        is_nested_sandbox = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -like "*\CodexSandbox*")
    }
    installed_backend = [ordered]@{
        codex = Get-FileSnapshot -Path $resolvedCodex
        command_runner = Get-FileSnapshot -Path $runnerPath
        setup_helper = Get-FileSnapshot -Path $setupPath
        authenticode = [string](Get-AuthenticodeSignature -LiteralPath $resolvedCodex).Status
    }
    sandbox_account = [ordered]@{
        name = $offlineUser.Name
        sid = $offlineUser.SID.Value
        enabled = $offlineUser.Enabled
        last_logon = if ($offlineUser.LastLogon) { $offlineUser.LastLogon.ToUniversalTime().ToString("o") } else { $null }
    }
    setup_state = [ordered]@{
        marker_before = $markerBefore
        marker_version = if ($null -ne $markerPayload) { $markerPayload.version } else { $null }
        proxy_ports = if ($null -ne $markerPayload) { @($markerPayload.proxy_ports) } else { @() }
        allow_local_binding = if ($null -ne $markerPayload) { $markerPayload.allow_local_binding } else { $null }
        deny_read_state = Get-FileSnapshot -Path $denyReadStatePath
    }
    firewall = Get-FirewallState
    sandbox_probe = [ordered]@{
        requested = [bool]$RunSandboxProbe
        executed = $false
        warning = "Codex Sandbox起動はinstalled backendがsetup refreshを判断する可能性があります。-RunSandboxProbeは明示実行時だけ使用します。"
    }
}

if ($RunSandboxProbe) {
    if ($report.host_identity.is_nested_sandbox) {
        throw "入れ子Sandboxからの実行はhost証拠にできないため中止しました。通常Windows userのPowerShellで実行してください。"
    }
    if ($null -eq $markerPayload -or $markerPayload.version -ne 5) {
        throw "setup marker version 5を確認できないため、setup refreshを避けて中止しました。"
    }
    if (@($markerPayload.proxy_ports).Count -ne 0 -or $markerPayload.allow_local_binding -ne $false) {
        throw "現在のproxy_ports/allow_local_bindingがprobeのoffline設定と一致しないため、setup refreshを避けて中止しました。"
    }

    $listeners = New-ListenerSet
    try {
        $tcp4Port = if ($null -ne $listeners.tcp4) { $listeners.tcp4.LocalEndpoint.Port } else { 0 }
        $tcp6Port = if ($null -ne $listeners.tcp6) { $listeners.tcp6.LocalEndpoint.Port } else { 0 }
        $udp4Port = if ($null -ne $listeners.udp4) { $listeners.udp4.Client.LocalEndPoint.Port } else { 0 }
        $udp6Port = if ($null -ne $listeners.udp6) { $listeners.udp6.Client.LocalEndPoint.Port } else { 0 }
        $powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

        $entries = @(
            [ordered]@{ path = [ordered]@{ type = "special"; value = [ordered]@{ kind = "minimal" } }; access = "read" },
            [ordered]@{ path = [ordered]@{ type = "path"; path = $workspace }; access = "read" },
            [ordered]@{ path = [ordered]@{ type = "path"; path = (Split-Path -Parent $powerShell) }; access = "read" }
        )
        $sandboxState = [ordered]@{
            permissionProfile = [ordered]@{
                type = "managed"
                file_system = [ordered]@{ type = "restricted"; entries = $entries; glob_scan_max_depth = 64 }
                network = "restricted"
            }
            codexLinuxSandboxExe = $null
            sandboxCwd = ([System.Uri]::new($workspace)).AbsoluteUri
            useLegacyLandlock = $false
        } | ConvertTo-Json -Depth 10 -Compress

        $sandboxConfig = 'windows.sandbox="elevated"'
        $sandboxStateArgument = $sandboxState
        $sandboxConfigArgument = $sandboxConfig
        if ($PSVersionTable.PSVersion.Major -le 5) {
            # Windows PowerShell 5.1はnative exeへ渡す際に埋め込みquoteを除去するため、
            # codex.exe側へliteral quoteとして届くよう、この呼び出しに限ってescapeする。
            $sandboxStateArgument = $sandboxStateArgument.Replace('"', '\"')
            $sandboxConfigArgument = $sandboxConfigArgument.Replace('"', '\"')
        }

        $arguments = @(
            "sandbox",
            "-c", $sandboxConfigArgument,
            "--sandbox-state-json", $sandboxStateArgument,
            "--sandbox-state-disable-network",
            "--",
            $powerShell,
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $childProbe,
            "-Stage", "parent",
            "-Tcp4Port", [string]$tcp4Port,
            "-Tcp6Port", [string]$tcp6Port,
            "-Udp4Port", [string]$udp4Port,
            "-Udp6Port", [string]$udp6Port
        )

        # markerと一致するoffline設定を維持するため、loopback proxyを示すambient値を
        # この診断processのCodex起動時だけ除外し、終了後に必ず復元する。
        $proxyKeys = @(
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "WS_PROXY", "WSS_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "ws_proxy", "wss_proxy",
            "CODEX_WINDOWS_SANDBOX_PROXY_PORTS", "CODEX_NETWORK_ALLOW_LOCAL_BINDING"
        )
        $savedEnvironment = @{}
        foreach ($key in $proxyKeys) {
            $savedEnvironment[$key] = [System.Environment]::GetEnvironmentVariable($key, "Process")
            [System.Environment]::SetEnvironmentVariable($key, $null, "Process")
        }

        try {
            $started = Get-Date
            $rawOutput = @(& $resolvedCodex @arguments 2>&1 | ForEach-Object { [string]$_ })
            $exitCode = $LASTEXITCODE
            $elapsed = ((Get-Date) - $started).TotalMilliseconds
        }
        finally {
            foreach ($key in $proxyKeys) {
                [System.Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key], "Process")
            }
        }

        Start-Sleep -Milliseconds 200
        $tokens = [ordered]@{
            tcp4 = @(Receive-TcpTokens -Listener $listeners.tcp4)
            tcp6 = @(Receive-TcpTokens -Listener $listeners.tcp6)
            udp4 = @(Receive-UdpTokens -Client $listeners.udp4 -AnyAddress ([System.Net.IPAddress]::Any))
            udp6 = @(Receive-UdpTokens -Client $listeners.udp6 -AnyAddress ([System.Net.IPAddress]::IPv6Any))
        }
        $stageResults = @()
        foreach ($line in $rawOutput) {
            if ($line.TrimStart().StartsWith("{")) {
                try {
                    $candidate = $line | ConvertFrom-Json
                    if ($candidate.stage -in @("parent", "child", "grandchild")) {
                        $stageResults += $candidate
                    }
                }
                catch {
                    # Codex側の非JSON診断行はraw_outputに保持し、stage結果には混ぜない。
                }
            }
        }

        $report.sandbox_probe = [ordered]@{
            requested = $true
            executed = $true
            exit_code = $exitCode
            elapsed_milliseconds = [math]::Round($elapsed, 3)
            listener_errors = @($listeners.errors)
            stages = @($stageResults)
            host_received_tokens = $tokens
            raw_output = @($rawOutput)
            interpretation = "TCPはsandbox側connectedとhost token受信、UDPはhost token受信を接続成功の証拠とする。UDP send成功だけで未受信の場合はunverified。"
        }
    }
    finally {
        Stop-ListenerSet -Listeners $listeners
    }
}

$report.setup_state["marker_after"] = Get-FileSnapshot -Path $markerPath
$report.setup_state["marker_changed"] = (
    $null -ne $report.setup_state.marker_before -and
    $null -ne $report.setup_state.marker_after -and
    $report.setup_state.marker_before.sha256 -ne $report.setup_state.marker_after.sha256
)

$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
}
$report | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 -LiteralPath $OutputPath
$report | ConvertTo-Json -Depth 12
Write-Host "診断結果: $OutputPath"
