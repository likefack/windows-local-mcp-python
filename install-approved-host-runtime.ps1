[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$BasePython,

    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),

    [string]$RuntimeUser = "$env:USERDOMAIN\$env:USERNAME",

    [switch]$Replace
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Approved Host runtime installation must run from an elevated PowerShell session."
}

$SourceRoot = $PSScriptRoot
$BasePython = (Resolve-Path -LiteralPath $BasePython).Path
if (-not (Test-Path -LiteralPath $BasePython -PathType Leaf)) {
    throw "Base Python executable does not exist: $BasePython"
}

$runtimeAccount = [Security.Principal.NTAccount]::new($RuntimeUser)
try {
    $runtimeSid = $runtimeAccount.Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "Could not resolve RuntimeUser to a Windows SID: $RuntimeUser"
}

$BuildRoot = Join-Path $SourceRoot ".dev-tmp\approved-host-runtime"
$WheelRoot = Join-Path $BuildRoot "wheel"
$StagingRoot = "$InstallRoot.staging-$PID"

if ((Test-Path -LiteralPath $InstallRoot) -and -not $Replace) {
    throw "InstallRoot already exists. Use -Replace to replace it: $InstallRoot"
}
if (Test-Path -LiteralPath $StagingRoot) {
    Remove-Item -LiteralPath $StagingRoot -Recurse -Force
}
if (Test-Path -LiteralPath $BuildRoot) {
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $WheelRoot -Force | Out-Null

try {
    & $BasePython -I -B -m pip wheel --no-deps --wheel-dir $WheelRoot $SourceRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Building the WLMCP wheel failed."
    }

    $wheel = Get-ChildItem -LiteralPath $WheelRoot -Filter "windows_local_mcp-*.whl" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $wheel) {
        throw "The WLMCP wheel was not produced."
    }

    if (-not $PSCmdlet.ShouldProcess($InstallRoot, "install immutable Approved Host runtime")) {
        return
    }

    New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
    $RuntimeRoot = Join-Path $StagingRoot "runtime"
    & $BasePython -I -B -m venv $RuntimeRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Creating the production virtual environment failed."
    }

    $RuntimePython = Join-Path $RuntimeRoot "Scripts\python.exe"
    & $RuntimePython -I -B -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "Updating pip in the production runtime failed."
    }
    & $RuntimePython -I -B -m pip install $wheel.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "Installing the WLMCP wheel and dependencies failed."
    }

    Copy-Item -LiteralPath (Join-Path $SourceRoot "run-server.ps1") -Destination $StagingRoot
    Copy-Item -LiteralPath (Join-Path $SourceRoot "run-approvals.ps1") -Destination $StagingRoot
    Copy-Item -LiteralPath (Join-Path $SourceRoot "verify-approved-host-runtime.ps1") -Destination $StagingRoot
    Copy-Item -LiteralPath (Join-Path $SourceRoot "config.example.toml") -Destination $StagingRoot

    if ($Replace -and (Test-Path -LiteralPath $InstallRoot)) {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
    Move-Item -LiteralPath $StagingRoot -Destination $InstallRoot

    & icacls.exe $InstallRoot /setowner "*S-1-5-32-544" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Setting the Approved Host runtime owner failed."
    }
    & icacls.exe $InstallRoot /inheritance:r /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Removing inherited Approved Host runtime ACLs failed."
    }
    & icacls.exe $InstallRoot /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*$runtimeSid:(OI)(CI)RX" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Applying the Approved Host runtime ACL failed."
    }

    Write-Output "Approved Host runtime installed at: $InstallRoot"
    Write-Output "Runtime user: $RuntimeUser ($runtimeSid)"
    Write-Output "Base Python: $BasePython"
    Write-Output "Run verify-approved-host-runtime.ps1 from a normal non-elevated $RuntimeUser session before enabling Approved Host use."
} finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
