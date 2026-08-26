from __future__ import annotations

import os
from pathlib import Path

_BROKERED_PROCESS_DENIED = b"WLMCP_BROKERED_PROCESS=DENIED"
_BROKERED_PROCESS_REACHABLE = b"WLMCP_BROKERED_PROCESS=REACHABLE"


def brokered_process_probe_command(nonce: str) -> list[str]:
    """Return a non-spawning WMI probe for the exact Sandbox security context."""

    windows_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not windows_root:
        raise RuntimeError("Windows system root is unavailable")
    powershell = (
        Path(windows_root)
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    ).resolve(strict=True)
    probe_path = (
        Path(windows_root)
        / "System32"
        / f"__wlmcp_brokered_probe_{nonce}__"
        / "never.exe"
    )
    escaped_probe_path = str(probe_path).replace("'", "''")
    script = rf'''
$ErrorActionPreference = 'Stop'

function Stop-WithManagementError([System.Exception]$Exception) {{
    $current = $Exception
    while ($null -ne $current.InnerException) {{
        $current = $current.InnerException
    }}
    if ($current -is [System.Management.ManagementException]) {{
        [Console]::Out.WriteLine(("WLMCP_WMI_STATUS={{0}}" -f [int]$current.ErrorCode))
        if ($current.ErrorCode -eq [System.Management.ManagementStatus]::AccessDenied) {{
            [Console]::Out.WriteLine("WLMCP_BROKERED_PROCESS=DENIED")
            exit 0
        }}
    }}
    [Console]::Out.WriteLine("WLMCP_BROKERED_PROCESS=UNVERIFIED")
    [Console]::Out.WriteLine(("WLMCP_EXCEPTION_TYPE={{0}}" -f $current.GetType().FullName))
    exit 21
}}

try {{
    $scope = New-Object System.Management.ManagementScope("\\.\root\cimv2")
    $scope.Connect()
}}
catch {{
    Stop-WithManagementError $_.Exception
}}

try {{
    $mc = New-Object System.Management.ManagementClass(
        $scope,
        (New-Object System.Management.ManagementPath("Win32_Process")),
        $null
    )
    [object[]]$methodArgs = @(
        '{escaped_probe_path}',
        $null,
        $null,
        [uint32]0
    )
    $result = [int]$mc.InvokeMethod("Create", $methodArgs)
    [Console]::Out.WriteLine(("WLMCP_WMI_CREATE_RETURN={{0}}" -f $result))
    [Console]::Out.WriteLine(("WLMCP_WMI_CREATE_PID={{0}}" -f [uint32]$methodArgs[3]))
    if ($result -eq 2 -or $result -eq 3) {{
        [Console]::Out.WriteLine("WLMCP_BROKERED_PROCESS=DENIED")
        exit 0
    }}
    if ($result -eq 0 -or $result -eq 9) {{
        [Console]::Out.WriteLine("WLMCP_BROKERED_PROCESS=REACHABLE")
        exit 9
    }}
    [Console]::Out.WriteLine("WLMCP_BROKERED_PROCESS=UNVERIFIED")
    exit 21
}}
catch {{
    Stop-WithManagementError $_.Exception
}}
'''
    return [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]


def classify_brokered_process_probe(
    returncode: int | None, stdout: bytes
) -> tuple[bool | None, str]:
    """Classify only explicit WMI denial as safe; everything else fails closed."""

    if returncode == 0 and _BROKERED_PROCESS_DENIED in stdout:
        return True, "verified: brokered Win32_Process.Create is explicitly denied"
    if returncode == 9 and _BROKERED_PROCESS_REACHABLE in stdout:
        return False, "failed: brokered Win32_Process.Create reached process creation"
    return None, "unverified: brokered Win32_Process.Create denial was not established"
