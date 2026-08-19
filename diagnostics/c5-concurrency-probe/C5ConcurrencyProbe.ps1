[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Label,

    [Parameter(Mandatory=$true)]
    [int]$HoldSeconds,

    [Parameter(Mandatory=$true)]
    [int]$Tcp4Port,

    [Parameter(Mandatory=$true)]
    [int]$Tcp6Port,

    [Parameter(Mandatory=$true)]
    [int]$Udp4Port,

    [Parameter(Mandatory=$true)]
    [int]$Udp6Port
)

$ErrorActionPreference = "Stop"

function Test-Tcp {
    param(
        [System.Net.IPAddress]$Address,
        [int]$Port
    )

    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new(
            $Address.AddressFamily
        )

        $task = $client.ConnectAsync($Address, $Port)

        if (-not $task.Wait(1000)) {
            return "timeout"
        }

        if ($client.Connected) {
            return "connected"
        }

        return "error"
    }
    catch {
        return "error"
    }
    finally {
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

function Send-Udp {
    param(
        [System.Net.IPAddress]$Address,
        [int]$Port
    )

    $client = $null
    try {
        $client = [System.Net.Sockets.UdpClient]::new(
            $Address.AddressFamily
        )

        $client.Connect($Address, $Port)

        $bytes = [System.Text.Encoding]::ASCII.GetBytes(
            "$Label|udp"
        )

        [void]$client.Send($bytes, $bytes.Length)
        return "sent"
    }
    catch {
        return "error"
    }
    finally {
        if ($null -ne $client) {
            $client.Dispose()
        }
    }
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$started = [DateTimeOffset]::UtcNow
$iteration = 0

while ($true) {
    $elapsed = (
        [DateTimeOffset]::UtcNow - $started
    ).TotalSeconds

    $record = [ordered]@{
        label = $Label
        iteration = $iteration
        elapsed_seconds = [Math]::Round($elapsed, 3)
        process_id = $PID
        user_name = $identity.Name
        user_sid = $identity.User.Value

        network = [ordered]@{
            tcp4 = Test-Tcp `
                -Address ([System.Net.IPAddress]::Loopback) `
                -Port $Tcp4Port

            tcp6 = Test-Tcp `
                -Address ([System.Net.IPAddress]::IPv6Loopback) `
                -Port $Tcp6Port

            udp4 = Send-Udp `
                -Address ([System.Net.IPAddress]::Loopback) `
                -Port $Udp4Port

            udp6 = Send-Udp `
                -Address ([System.Net.IPAddress]::IPv6Loopback) `
                -Port $Udp6Port
        }
    }

    $record | ConvertTo-Json -Depth 5 -Compress

    if ($elapsed -ge $HoldSeconds) {
        break
    }

    $iteration++
    Start-Sleep -Seconds 2
}
