[CmdletBinding()]
param(
    [string]$OutputDirectory,

    [string]$SandboxSid
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "この診断はnative Windowsでのみ実行できます。"
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "WFP filter列挙には管理者権限が必要です。管理者として起動したPowerShellで実行してください。"
}

if (-not $SandboxSid) {
    $SandboxSid = (Get-LocalUser -Name "CodexSandboxOffline" -ErrorAction Stop).SID.Value
}
if ($SandboxSid -notmatch '^S-1-[0-9-]+$') {
    throw "SandboxSidがSID形式ではありません。"
}

if (-not $OutputDirectory) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDirectory = Join-Path $env:TEMP "codex-wfp-state-$timestamp"
}
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null

$queries = @(
    [ordered]@{ name = "tcp4-loopback"; protocol = 6; address = "127.0.0.1" },
    [ordered]@{ name = "udp4-loopback"; protocol = 17; address = "127.0.0.1" },
    [ordered]@{ name = "tcp6-loopback"; protocol = 6; address = "::1" },
    [ordered]@{ name = "udp6-loopback"; protocol = 17; address = "::1" }
)

$files = @()
foreach ($query in $queries) {
    $filterPath = Join-Path $resolvedOutput ("filters-{0}.xml" -f $query.name)
    & netsh.exe wfp show filters (
        "file={0}" -f $filterPath
    ) (
        "protocol={0}" -f $query.protocol
    ) (
        "remoteaddr={0}" -f $query.address
    ) (
        "userid={0}" -f $SandboxSid
    ) "dir=OUT" "verbose=ON"
    if ($LASTEXITCODE -ne 0) {
        throw "netsh wfp show filters failed: $($query.name), exit=$LASTEXITCODE"
    }

    $eventPath = Join-Path $resolvedOutput ("netevents-{0}.xml" -f $query.name)
    & netsh.exe wfp show netevents (
        "file={0}" -f $eventPath
    ) (
        "protocol={0}" -f $query.protocol
    ) (
        "remoteaddr={0}" -f $query.address
    ) (
        "userid={0}" -f $SandboxSid
    ) "timewindow=600"
    $eventExitCode = $LASTEXITCODE

    $files += [ordered]@{
        query = $query
        filters = [ordered]@{
            path = $filterPath
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $filterPath).Hash
            length = (Get-Item -LiteralPath $filterPath).Length
        }
        netevents = if (Test-Path -LiteralPath $eventPath) {
            [ordered]@{
                path = $eventPath
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $eventPath).Hash
                length = (Get-Item -LiteralPath $eventPath).Length
                exit_code = $eventExitCode
            }
        } else {
            [ordered]@{ path = $eventPath; exit_code = $eventExitCode; unavailable = $true }
        }
    }
}

$firewallRules = @(
    Get-NetFirewallRule -PolicyStore ActiveStore |
        Where-Object { $_.DisplayName -like "codex_sandbox_offline_*" } |
        ForEach-Object {
            $address = $_ | Get-NetFirewallAddressFilter
            $port = $_ | Get-NetFirewallPortFilter
            $security = $_ | Get-NetFirewallSecurityFilter
            [ordered]@{
                name = $_.Name
                display_name = $_.DisplayName
                enabled = [string]$_.Enabled
                profile = [string]$_.Profile
                direction = [string]$_.Direction
                action = [string]$_.Action
                status = [string]$_.Status
                policy_store_source = [string]$_.PolicyStoreSource
                protocol = [string]$port.Protocol
                remote_port = @($port.RemotePort)
                remote_address = @($address.RemoteAddress)
                local_user = [string]$security.LocalUser
            }
        }
)

$profiles = @(
    Get-NetFirewallProfile | ForEach-Object {
        [ordered]@{
            name = $_.Name
            enabled = $_.Enabled
            default_inbound_action = [string]$_.DefaultInboundAction
            default_outbound_action = [string]$_.DefaultOutboundAction
            allow_local_firewall_rules = [string]$_.AllowLocalFirewallRules
        }
    }
)

$summary = [ordered]@{
    version = 1
    collected_at = (Get-Date).ToUniversalTime().ToString("o")
    collector = [ordered]@{ name = $identity.Name; sid = $identity.User.Value; elevated = $true }
    sandbox_sid = $SandboxSid
    note = "netsh wfp show filters/show netevents と Firewall ActiveStore の読み取りだけを実行し、規則・filter・監査設定は変更していない。"
    firewall_rules = $firewallRules
    firewall_profiles = $profiles
    wfp_queries = $files
}

$summaryPath = Join-Path $resolvedOutput "summary.json"
$summary | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -LiteralPath $summaryPath
$summary | ConvertTo-Json -Depth 10
Write-Host "WFP診断結果: $summaryPath"
