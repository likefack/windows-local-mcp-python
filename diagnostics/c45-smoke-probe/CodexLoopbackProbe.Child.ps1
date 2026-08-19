[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("parent", "child", "grandchild")]
    [string]$Stage,

    [Parameter(Mandatory = $true)]
    [int]$Tcp4Port,

    [Parameter(Mandatory = $true)]
    [int]$Tcp6Port,

    [Parameter(Mandatory = $true)]
    [int]$Udp4Port,

    [Parameter(Mandatory = $true)]
    [int]$Udp6Port
)

$ErrorActionPreference = "Stop"

function Test-TcpLoopback {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [System.Net.IPAddress]$Address,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    if ($Port -le 0) {
        return [ordered]@{ status = "unavailable"; detail = "host listener was not created" }
    }

    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait(2000)) {
            return [ordered]@{ status = "timeout"; detail = "connect did not complete in 2 seconds" }
        }
        if (-not $client.Connected) {
            return [ordered]@{ status = "error"; detail = "connect completed without a connection" }
        }

        $token = [System.Text.Encoding]::UTF8.GetBytes("$Stage|$Name`n")
        $stream = $client.GetStream()
        $stream.Write($token, 0, $token.Length)
        $stream.Flush()
        return [ordered]@{ status = "connected"; detail = "host listener accepted the connect path" }
    }
    catch {
        return [ordered]@{ status = "error"; detail = $_.Exception.Message }
    }
    finally {
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

function Test-UdpLoopback {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [System.Net.IPAddress]$Address,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    if ($Port -le 0) {
        return [ordered]@{ status = "unavailable"; detail = "host listener was not created" }
    }

    $client = $null
    try {
        $client = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
        $client.Connect($Address, $Port)
        $token = [System.Text.Encoding]::UTF8.GetBytes("$Stage|$Name")
        $sent = $client.Send($token, $token.Length)
        return [ordered]@{
            status = "sent"
            detail = "UDP send returned successfully; host receipt decides reachability"
            bytes = $sent
        }
    }
    catch {
        return [ordered]@{ status = "error"; detail = $_.Exception.Message }
    }
    finally {
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

function Get-IntegritySid {
    try {
        $lines = & "$env:SystemRoot\System32\whoami.exe" /groups /fo csv /nh 2>$null
        foreach ($line in $lines) {
            if ($line -match "S-1-16-[0-9]+") {
                return $Matches[0]
            }
        }
    }
    catch {
        return $null
    }
    return $null
}

function Invoke-CurrentStage {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = @($identity.Groups | ForEach-Object { $_.Value })
    return [ordered]@{
        stage = $Stage
        process_id = $PID
        user_name = $identity.Name
        user_sid = $identity.User.Value
        integrity_sid = Get-IntegritySid
        authentication_type = $identity.AuthenticationType
        impersonation_level = [string]$identity.ImpersonationLevel
        group_sids = $groups
        network = [ordered]@{
            tcp4 = Test-TcpLoopback -Name "tcp4" -Address ([System.Net.IPAddress]::Loopback) -Port $Tcp4Port
            tcp6 = Test-TcpLoopback -Name "tcp6" -Address ([System.Net.IPAddress]::IPv6Loopback) -Port $Tcp6Port
            udp4 = Test-UdpLoopback -Name "udp4" -Address ([System.Net.IPAddress]::Loopback) -Port $Udp4Port
            udp6 = Test-UdpLoopback -Name "udp6" -Address ([System.Net.IPAddress]::IPv6Loopback) -Port $Udp6Port
        }
    }
}

# 各世代が同じコードを実行し、出力を親へそのまま返すことで、世代ごとの
# security context と通信結果を独立して記録する。
Invoke-CurrentStage | ConvertTo-Json -Depth 8 -Compress

$powerShell = Join-Path $PSHOME "powershell.exe"
$commonArguments = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $PSCommandPath,
    "-Tcp4Port", [string]$Tcp4Port,
    "-Tcp6Port", [string]$Tcp6Port,
    "-Udp4Port", [string]$Udp4Port,
    "-Udp6Port", [string]$Udp6Port
)

if ($Stage -eq "parent") {
    & $powerShell @commonArguments -Stage "child"
    exit $LASTEXITCODE
}

if ($Stage -eq "child") {
    & $powerShell @commonArguments -Stage "grandchild"
    exit $LASTEXITCODE
}
