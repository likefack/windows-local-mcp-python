[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$BasePython,

    [string]$InstallRoot = (Join-Path $env:ProgramFiles "WindowsLocalMCP"),

    [string]$RuntimeUser = "$env:USERDOMAIN\$env:USERNAME",

    [switch]$Replace
)

$ErrorActionPreference = "Stop"
$AuthorityServiceName = "WindowsLocalMCPApprovedHost"
$AuthorityActiveState = Join-Path $env:ProgramData "WindowsLocalMCP\ApprovedHostAuthority\active.json"

function Assert-UnderProgramFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramW6432
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') } |
        Select-Object -Unique

    foreach ($root in $roots) {
        if ($candidate.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            return $candidate
        }
    }
    throw "$Label must be below a Windows Program Files directory: $candidate"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Approved Host runtime installation must run from an elevated PowerShell session."
}

$SourceRoot = $PSScriptRoot
$InstallRoot = Assert-UnderProgramFiles -Path $InstallRoot -Label "InstallRoot"
$BasePython = (Resolve-Path -LiteralPath $BasePython).Path
if (-not (Test-Path -LiteralPath $BasePython -PathType Leaf)) {
    throw "Base Python executable does not exist: $BasePython"
}
$BasePython = Assert-UnderProgramFiles -Path $BasePython -Label "BasePython"
$BasePrefix = ((& $BasePython -I -B -c "import sys; print(sys.base_prefix)") | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($BasePrefix)) {
    throw "Could not resolve sys.base_prefix from BasePython."
}
if (-not (Test-Path -LiteralPath $BasePrefix -PathType Container)) {
    throw "Base Python prefix does not exist: $BasePrefix"
}
$BasePrefix = Assert-UnderProgramFiles -Path $BasePrefix -Label "sys.base_prefix"

$runtimeAccount = [Security.Principal.NTAccount]::new($RuntimeUser)
try {
    $runtimeSid = $runtimeAccount.Translate([Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "Could not resolve RuntimeUser to a Windows SID: $RuntimeUser"
}

$BuildRoot = Join-Path $SourceRoot ".dev-tmp\approved-host-runtime"
$WheelRoot = Join-Path $BuildRoot "wheel"
$StagingRoot = "$InstallRoot.staging-$PID"
$existingAuthorityService = Get-Service -Name $AuthorityServiceName -ErrorAction SilentlyContinue
$restartAuthorityService = $false

if ((Test-Path -LiteralPath $InstallRoot) -and -not $Replace) {
    throw "InstallRoot already exists. Use -Replace to replace it: $InstallRoot"
}
if ($Replace -and $null -ne $existingAuthorityService) {
    if (Test-Path -LiteralPath $AuthorityActiveState -PathType Leaf) {
        throw "Approved Host authority has active/recovery state. Review and recover it before replacing the immutable runtime."
    }
    if ($existingAuthorityService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name $AuthorityServiceName
        (Get-Service -Name $AuthorityServiceName).WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(30)
        )
        $restartAuthorityService = $true
    }
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

    foreach ($script in @(
        "run-server.ps1",
        "run-approvals.ps1",
        "install-approved-host-authority.ps1",
        "recover-approved-host-authority.ps1",
        "verify-approved-host-runtime.ps1",
        "verify-approved-host-authority.ps1",
        "verify-approved-host-authority-abnormal.ps1"
    )) {
        Copy-Item -LiteralPath (Join-Path $SourceRoot $script) -Destination $StagingRoot
    }
    Copy-Item -LiteralPath (Join-Path $SourceRoot "config.example.toml") -Destination $StagingRoot

    # Build one protected ACL boundary at the install root, then make every descendant inherit
    # from that boundary. Recursively stripping inheritance after a recursive grant is unsafe:
    # a descendant grant may still be inherited and can disappear when /inheritance:r reaches
    # that object. The resulting tree must therefore have exactly one upstream ACL authority:
    # the protected staging root with SYSTEM/Admin full control and runtime-user read/execute.
    # Do not use /C for any security-critical ACL operation: one error aborts the installation.
    & icacls.exe $StagingRoot /setowner "*S-1-5-32-544" /T | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Setting the Approved Host runtime owner failed."
    }
    & icacls.exe $StagingRoot /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*${runtimeSid}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Applying the Approved Host runtime root ACL failed."
    }
    & icacls.exe $StagingRoot /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Protecting the Approved Host runtime root ACL failed."
    }
    $StagingChildren = Join-Path $StagingRoot "*"
    & icacls.exe $StagingChildren /reset /T | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Resetting Approved Host runtime descendants to the protected root ACL failed."
    }
    & icacls.exe $StagingRoot /verify /T | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Verifying the Approved Host runtime ACL tree failed."
    }

    if ($Replace -and (Test-Path -LiteralPath $InstallRoot)) {
        Remove-Item -LiteralPath $InstallRoot -Recurse -Force
    }
    Move-Item -LiteralPath $StagingRoot -Destination $InstallRoot

    if ($restartAuthorityService) {
        Start-Service -Name $AuthorityServiceName
        (Get-Service -Name $AuthorityServiceName).WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(30)
        )
    }

    Write-Output "Approved Host runtime installed at: $InstallRoot"
    Write-Output "Runtime user: $RuntimeUser ($runtimeSid)"
    Write-Output "Base Python: $BasePython"
    Write-Output "Base Python prefix: $BasePrefix"
    Write-Output "1. Run verify-approved-host-runtime.ps1 from normal non-elevated $RuntimeUser."
    if ($null -eq $existingAuthorityService) {
        Write-Output "2. Run install-approved-host-authority.ps1 from an elevated Administrator session."
    } else {
        Write-Output "2. Existing Approved Host authority service was preserved; re-run its installer with -Replace if service configuration changed."
    }
    Write-Output "3. Run verify-approved-host-authority.ps1 from normal non-elevated $RuntimeUser."
    Write-Output "4. Before claiming WLMCP-R2-001 fixed, run verify-approved-host-authority-abnormal.ps1 through Arm / KillAndRestart / Check."
} finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
