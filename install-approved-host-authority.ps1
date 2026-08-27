[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),
    [string]$RuntimeUser = "$env:USERDOMAIN\$env:USERNAME",
    [string]$AuthorityStateRoot = (Join-Path $env:ProgramData "WindowsLocalMCP\ApprovedHostAuthority"),
    [switch]$Replace
)

$ErrorActionPreference = "Stop"
$ServiceName = "WindowsLocalMCPApprovedHost"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Approved Host authority installation must run from an elevated PowerShell session."
    }
}

function Resolve-AccountSid {
    param([Parameter(Mandatory = $true)][string]$Account)
    try {
        return [Security.Principal.NTAccount]::new($Account).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        throw "Could not resolve RuntimeUser to a Windows SID: $Account"
    }
}

function Assert-AuthorityStateRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $programData = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\', '/')
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if (-not $candidate.StartsWith(
        $programData + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "AuthorityStateRoot must be below ProgramData: $candidate"
    }
    return $candidate
}

function Invoke-Sc {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & "$env:SystemRoot\System32\sc.exe" @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code $LASTEXITCODE: $($Arguments -join ' ')"
    }
}

Assert-Administrator
$RuntimeSid = Resolve-AccountSid -Account $RuntimeUser
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\', '/')
$AuthorityStateRoot = Assert-AuthorityStateRoot -Path $AuthorityStateRoot
$AuthorityBase = Split-Path -Parent $AuthorityStateRoot
$RuntimePython = Join-Path $InstallRoot "runtime\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $RuntimePython -PathType Leaf)) {
    throw "Immutable Approved Host runtime Python was not found: $RuntimePython"
}

& $RuntimePython -I -B -c "import windows_local_mcp.approved_host_service_entry"
if ($LASTEXITCODE -ne 0) {
    throw "Approved Host authority service module is not importable from the immutable runtime."
}

$ActiveState = Join-Path $AuthorityStateRoot "active.json"
if (Test-Path -LiteralPath $ActiveState -PathType Leaf) {
    throw "Approved Host authority has active/recovery state. Perform explicit recovery before replacing or reinstalling the service: $ActiveState"
}

$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $ExistingService -and -not $Replace) {
    throw "Approved Host authority service already exists. Use -Replace only after verifying no active recovery state."
}

if (-not $PSCmdlet.ShouldProcess($ServiceName, "install LocalSystem Approved Host authority")) {
    return
}

New-Item -ItemType Directory -Path $AuthorityStateRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $AuthorityStateRoot "completed") -Force | Out-Null

# Protect the complete WLMCP ProgramData authority namespace. The runtime user intentionally
# receives no file-system access: all health/launch interaction goes through the authenticated
# named pipe, and only LocalSystem writes durable state or completion proofs.
& "$env:SystemRoot\System32\icacls.exe" $AuthorityBase /setowner "*S-1-5-18" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Setting authority state owner failed." }
& "$env:SystemRoot\System32\icacls.exe" $AuthorityBase /inheritance:r /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Removing authority state ACL inheritance failed." }
& "$env:SystemRoot\System32\icacls.exe" $AuthorityBase /grant:r `
    "*S-1-5-18:(OI)(CI)F" `
    "*S-1-5-32-544:(OI)(CI)F" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Applying authority state ACL failed." }

if ($null -ne $ExistingService) {
    if ($ExistingService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $ServiceName -Force
        (Get-Service -Name $ServiceName).WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(30)
        )
    }
    Invoke-Sc -Arguments @("delete", $ServiceName)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        throw "Timed out waiting for the previous Approved Host authority service to be deleted."
    }
}

$ServiceCommand = '"{0}" -I -B -m windows_local_mcp.approved_host_service_entry --runtime-sid "{1}" --state-root "{2}"' -f `
    $RuntimePython, $RuntimeSid, $AuthorityStateRoot
New-Service `
    -Name $ServiceName `
    -BinaryPathName $ServiceCommand `
    -DisplayName "Windows Local MCP Approved Host Authority" `
    -Description "LocalSystem security authority for Approved Host monitoring and durable postflight state." `
    -StartupType Automatic | Out-Null

# Runtime user may query the service PID so the client can authenticate the named-pipe server,
# but receives no start/stop/change-config/delete/WRITE_DAC/WRITE_OWNER rights.
$ServiceSddl = "D:P(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LC;;;$RuntimeSid)"
Invoke-Sc -Arguments @("sdset", $ServiceName, $ServiceSddl)
Invoke-Sc -Arguments @("failure", $ServiceName, "reset=", "0", "actions=", "restart/5000")
Invoke-Sc -Arguments @("failureflag", $ServiceName, "1")

Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus(
    [ServiceProcess.ServiceControllerStatus]::Running,
    [TimeSpan]::FromSeconds(30)
)

Write-Output "Approved Host authority installed and running."
Write-Output "Service: $ServiceName (LocalSystem)"
Write-Output "Runtime user: $RuntimeUser ($RuntimeSid)"
Write-Output "Durable state: $AuthorityStateRoot"
Write-Output "Run verify-approved-host-authority.ps1 from the normal non-elevated RuntimeUser session before enabling live Approved Host use."
