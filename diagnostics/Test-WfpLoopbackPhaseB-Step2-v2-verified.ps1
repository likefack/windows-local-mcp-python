#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP Phase B - Step 1/2 precheck and dynamic WFP session test.

.DESCRIPTION
  This script performs the first two operational steps only:

    STEP 1
      - Verify runtime filter 70511 is AppContainerLoopback PERMIT.
      - Verify runtime filter 70512 is AppContainerLoopback PERMIT.
      - Verify both filters resolve to the same WFP sublayer.
      - Verify that sublayer weight is 7.
      - Verify the local user CodexSandboxOffline exists and is enabled.
      - Record its current SID.

    STEP 2
      - Open a WFP engine session with FWPM_SESSION_FLAG_DYNAMIC.
      - Keep the session open until the operator presses Enter.
      - Close the session.

  This script DOES NOT:
      - add a WFP sublayer
      - add a WFP filter
      - add/modify a Windows Firewall rule
      - modify the registry
      - start/stop/reconfigure services

  Therefore it does not change network filtering behavior.

  Output:
    <script-dir>\WFP-PhaseB-Step2-Results\<timestamp>\result.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [UInt64]$AppLoopbackV4FilterId = 70511,

    [Parameter(Mandatory = $false)]
    [UInt64]$AppLoopbackV6FilterId = 70512,

    [Parameter(Mandatory = $false)]
    [UInt16]$ExpectedAppIsolationWeight = 7,

    [Parameter(Mandatory = $false)]
    [string]$OutputBase = (Join-Path $PSScriptRoot 'WFP-PhaseB-Step2-Results')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not [Environment]::Is64BitProcess) {
    throw 'ERROR: Run this script from 64-bit Windows PowerShell.'
}

if (-not (Test-IsAdministrator)) {
    throw 'ERROR: Run this script from an Administrator PowerShell window.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputBase $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$resultPath = Join-Path $outputDir 'result.json'
$logPath = Join-Path $outputDir 'step2-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-StepLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

Write-StepLog 'Starting WLMCP Phase B Step 1/2.'
Write-StepLog ("Output directory: {0}" -f $outputDir)

$source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseBStep2
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;

    private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    private const uint FWP_ACTION_BLOCK = 0x00001001;
    private const uint FWP_ACTION_PERMIT = 0x00001002;

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_DISPLAY_DATA0
    {
        public IntPtr name;
        public IntPtr description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FWP_VALUE0
    {
        [FieldOffset(0)]
        public uint type;

        [FieldOffset(8)]
        public ulong inlineValue;

        [FieldOffset(8)]
        public IntPtr pointerValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterTypeOrCalloutKey;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FWPM_CONTEXT_UNION0
    {
        [FieldOffset(0)]
        public ulong rawContext;

        [FieldOffset(0)]
        public Guid providerContextKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public FWPM_CONTEXT_UNION0 context;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public IntPtr sid;
        public IntPtr username;

        [MarshalAs(UnmanagedType.Bool)]
        public bool kernelMode;
    }

    public sealed class FilterSnapshot
    {
        public ulong requested_filter_id { get; set; }
        public bool found { get; set; }
        public string error_hex { get; set; }
        public ulong runtime_filter_id { get; set; }
        public string filter_key { get; set; }
        public string name { get; set; }
        public string description { get; set; }
        public string layer_key { get; set; }
        public string sublayer_key { get; set; }
        public uint flags { get; set; }
        public string flags_hex { get; set; }
        public uint action_type { get; set; }
        public string action_type_hex { get; set; }
        public string action_name { get; set; }
        public uint condition_count { get; set; }
        public bool sublayer_found { get; set; }
        public string sublayer_error_hex { get; set; }
        public string sublayer_name { get; set; }
        public ushort sublayer_weight { get; set; }
    }

    public sealed class DynamicSessionHandle : IDisposable
    {
        private IntPtr _engineHandle;

        public string session_key { get; private set; }
        public uint flags { get; private set; }
        public string flags_hex { get; private set; }

        internal DynamicSessionHandle(IntPtr handle, Guid sessionKey)
        {
            _engineHandle = handle;
            session_key = sessionKey.ToString("B");
            flags = FWPM_SESSION_FLAG_DYNAMIC;
            flags_hex = "0x" + FWPM_SESSION_FLAG_DYNAMIC.ToString("X8");
        }

        public bool is_open
        {
            get { return _engineHandle != IntPtr.Zero; }
        }

        public void Dispose()
        {
            if (_engineHandle != IntPtr.Zero)
            {
                uint rc = FwpmEngineClose0(_engineHandle);
                _engineHandle = IntPtr.Zero;

                if (rc != ERROR_SUCCESS)
                {
                    throw new Win32Exception(
                        unchecked((int)rc),
                        "FwpmEngineClose0 failed: 0x" + rc.ToString("X8"));
                }
            }
        }
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(
        string serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterGetById0(
        IntPtr engineHandle,
        ulong id,
        out IntPtr filter);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerGetByKey0(
        IntPtr engineHandle,
        ref Guid key,
        out IntPtr subLayer);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);

    private static string PtrToStringUni(IntPtr p)
    {
        return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);
    }

    private static string ActionName(uint actionType)
    {
        if (actionType == FWP_ACTION_BLOCK) return "FWP_ACTION_BLOCK";
        if (actionType == FWP_ACTION_PERMIT) return "FWP_ACTION_PERMIT";
        return "OTHER";
    }

    private static IntPtr OpenReadEngine()
    {
        IntPtr engine;
        uint rc = FwpmEngineOpen0(
            null,
            RPC_C_AUTHN_WINNT,
            IntPtr.Zero,
            IntPtr.Zero,
            out engine);

        if (rc != ERROR_SUCCESS)
        {
            throw new Win32Exception(
                unchecked((int)rc),
                "FwpmEngineOpen0(read) failed: 0x" + rc.ToString("X8"));
        }

        return engine;
    }

    public static FilterSnapshot ReadFilter(ulong id)
    {
        IntPtr engine = IntPtr.Zero;
        IntPtr filterPtr = IntPtr.Zero;
        IntPtr subLayerPtr = IntPtr.Zero;

        try
        {
            engine = OpenReadEngine();

            uint rc = FwpmFilterGetById0(engine, id, out filterPtr);
            if (rc != ERROR_SUCCESS)
            {
                return new FilterSnapshot
                {
                    requested_filter_id = id,
                    found = false,
                    error_hex = "0x" + rc.ToString("X8")
                };
            }

            FWPM_FILTER0 f = Marshal.PtrToStructure<FWPM_FILTER0>(filterPtr);

            var result = new FilterSnapshot
            {
                requested_filter_id = id,
                found = true,
                error_hex = null,
                runtime_filter_id = f.filterId,
                filter_key = f.filterKey.ToString("B"),
                name = PtrToStringUni(f.displayData.name),
                description = PtrToStringUni(f.displayData.description),
                layer_key = f.layerKey.ToString("B"),
                sublayer_key = f.subLayerKey.ToString("B"),
                flags = f.flags,
                flags_hex = "0x" + f.flags.ToString("X8"),
                action_type = f.action.type,
                action_type_hex = "0x" + f.action.type.ToString("X8"),
                action_name = ActionName(f.action.type),
                condition_count = f.numFilterConditions
            };

            Guid subLayerKey = f.subLayerKey;
            rc = FwpmSubLayerGetByKey0(engine, ref subLayerKey, out subLayerPtr);

            if (rc == ERROR_SUCCESS)
            {
                FWPM_SUBLAYER0 s =
                    Marshal.PtrToStructure<FWPM_SUBLAYER0>(subLayerPtr);

                result.sublayer_found = true;
                result.sublayer_error_hex = null;
                result.sublayer_name = PtrToStringUni(s.displayData.name);
                result.sublayer_weight = s.weight;
            }
            else
            {
                result.sublayer_found = false;
                result.sublayer_error_hex = "0x" + rc.ToString("X8");
            }

            return result;
        }
        finally
        {
            if (subLayerPtr != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref subLayerPtr);
            }

            if (filterPtr != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref filterPtr);
            }

            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }
        }
    }

    public static DynamicSessionHandle OpenDynamicSession()
    {
        Guid sessionKey = Guid.NewGuid();

        FWPM_SESSION0 session = new FWPM_SESSION0();
        session.sessionKey = sessionKey;
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.txnWaitTimeoutInMSec = 0;
        session.processId = 0;
        session.sid = IntPtr.Zero;
        session.username = IntPtr.Zero;
        session.kernelMode = false;

        IntPtr sessionPtr = IntPtr.Zero;
        IntPtr engine = IntPtr.Zero;

        try
        {
            sessionPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWPM_SESSION0)));
            Marshal.StructureToPtr(session, sessionPtr, false);

            uint rc = FwpmEngineOpen0(
                null,
                RPC_C_AUTHN_WINNT,
                IntPtr.Zero,
                sessionPtr,
                out engine);

            if (rc != ERROR_SUCCESS)
            {
                throw new Win32Exception(
                    unchecked((int)rc),
                    "FwpmEngineOpen0(dynamic) failed: 0x" + rc.ToString("X8"));
            }

            IntPtr ownedHandle = engine;
            engine = IntPtr.Zero;
            return new DynamicSessionHandle(ownedHandle, sessionKey);
        }
        finally
        {
            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }

            if (sessionPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(sessionPtr);
            }
        }
    }
}
'@

if ($null -eq ('WfpPhaseBStep2' -as [type])) {
    Write-StepLog 'Compiling the WFP Step 1/2 helper.'
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
} else {
    Write-StepLog 'WfpPhaseBStep2 type is already loaded in this PowerShell process; reusing it.'
}

Write-StepLog ("Reading filter {0}." -f $AppLoopbackV4FilterId)
$v4 = [WfpPhaseBStep2]::ReadFilter($AppLoopbackV4FilterId)

Write-StepLog ("Reading filter {0}." -f $AppLoopbackV6FilterId)
$v6 = [WfpPhaseBStep2]::ReadFilter($AppLoopbackV6FilterId)

$precheckErrors = New-Object System.Collections.Generic.List[string]

foreach ($item in @(
    [pscustomobject]@{ label = 'V4'; filter = $v4; expected_id = $AppLoopbackV4FilterId },
    [pscustomobject]@{ label = 'V6'; filter = $v6; expected_id = $AppLoopbackV6FilterId }
)) {
    $f = $item.filter

    if (-not $f.found) {
        $precheckErrors.Add(("{0}: runtime filter {1} not found ({2})" -f $item.label, $item.expected_id, $f.error_hex))
        continue
    }

    if ($f.runtime_filter_id -ne $item.expected_id) {
        $precheckErrors.Add(("{0}: runtime filter ID mismatch" -f $item.label))
    }

    if ($f.name -ne 'AppContainerLoopback') {
        $precheckErrors.Add(("{0}: name is not AppContainerLoopback (actual: {1})" -f $item.label, $f.name))
    }

    if ($f.action_name -ne 'FWP_ACTION_PERMIT') {
        $precheckErrors.Add(("{0}: action is not FWP_ACTION_PERMIT (actual: {1})" -f $item.label, $f.action_name))
    }

    if (-not $f.sublayer_found) {
        $precheckErrors.Add(("{0}: sublayer could not be read ({1})" -f $item.label, $f.sublayer_error_hex))
    }

    if ($f.sublayer_found -and $f.sublayer_weight -ne $ExpectedAppIsolationWeight) {
        $precheckErrors.Add(("{0}: sublayer weight changed (expected {1}, actual {2})" -f $item.label, $ExpectedAppIsolationWeight, $f.sublayer_weight))
    }
}

if ($v4.found -and $v6.found -and
    -not [string]::IsNullOrWhiteSpace($v4.sublayer_key) -and
    -not [string]::IsNullOrWhiteSpace($v6.sublayer_key) -and
    $v4.sublayer_key -ne $v6.sublayer_key) {
    $precheckErrors.Add('V4 and V6 AppContainerLoopback filters are in different sublayers.')
}

$codexUser = $null
try {
    $u = Get-LocalUser -Name 'CodexSandboxOffline' -ErrorAction Stop
    $codexUser = [ordered]@{
        found = $true
        name = $u.Name
        sid = $u.SID.Value
        enabled = $u.Enabled
    }

    if (-not $u.Enabled) {
        $precheckErrors.Add('CodexSandboxOffline exists but is disabled.')
    }
} catch {
    $codexUser = [ordered]@{
        found = $false
        name = 'CodexSandboxOffline'
        sid = $null
        enabled = $null
        error = $_.Exception.Message
    }
    $precheckErrors.Add('CodexSandboxOffline local user could not be read.')
}

$precheckPassed = ($precheckErrors.Count -eq 0)

$result = [ordered]@{
    schema_version = 1
    started_at = (Get-Date).ToString('o')
    host = [ordered]@{
        computer_name = $env:COMPUTERNAME
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        process_id = $PID
        is_administrator = $true
        is_64_bit_process = [Environment]::Is64BitProcess
        codex_sandbox_offline = $codexUser
    }
    step1_precheck = [ordered]@{
        passed = $precheckPassed
        expected_app_isolation_weight = $ExpectedAppIsolationWeight
        errors = @($precheckErrors)
        filter_70511 = $v4
        filter_70512 = $v6
    }
    step2_dynamic_session = [ordered]@{
        attempted = $false
        opened = $false
        session_key = $null
        flags = $null
        flags_hex = $null
        held_until_operator_enter = $false
        closed = $false
        error = $null
    }
    policy_mutation = [ordered]@{
        wfp_sublayer_added = $false
        wfp_filter_added = $false
        windows_firewall_rule_changed = $false
        registry_changed = $false
        service_changed = $false
        expected_network_behavior_change = $false
    }
    output = [ordered]@{
        directory = $outputDir
        result_json = $resultPath
        log = $logPath
        artifact_hashes = $hashPath
    }
}

if (-not $precheckPassed) {
    Write-StepLog 'STEP 1 FAILED. No dynamic session will be opened.'
    foreach ($e in $precheckErrors) {
        Write-StepLog ("PRECHECK ERROR: {0}" -f $e)
    }

    $result.step2_dynamic_session.attempted = $false
    $result.finished_at = (Get-Date).ToString('o')
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $logLines | Set-Content -LiteralPath $logPath -Encoding UTF8

    throw ("STEP 1 PRECHECK FAILED. See: {0}" -f $resultPath)
}

Write-StepLog 'STEP 1 PASSED.'
Write-StepLog ("CodexSandboxOffline SID: {0}" -f $codexUser.sid)
Write-StepLog ("App Isolation sublayer weight: {0}" -f $v4.sublayer_weight)

$dynamicSession = $null
$step2Passed = $false
try {
    $result.step2_dynamic_session.attempted = $true

    Write-StepLog 'Opening dynamic WFP session.'
    $dynamicSession = [WfpPhaseBStep2]::OpenDynamicSession()

    $result.step2_dynamic_session.opened = $dynamicSession.is_open
    $result.step2_dynamic_session.session_key = $dynamicSession.session_key
    $result.step2_dynamic_session.flags = $dynamicSession.flags
    $result.step2_dynamic_session.flags_hex = $dynamicSession.flags_hex

    if (-not $dynamicSession.is_open) {
        throw 'Dynamic WFP session returned without an open engine handle.'
    }

    Write-StepLog ("STEP 2 OPENED. Session key: {0}" -f $dynamicSession.session_key)
    Write-StepLog ("Session flags: {0} (FWPM_SESSION_FLAG_DYNAMIC)" -f $dynamicSession.flags_hex)
    Write-Host ''
    Write-Host 'No WFP policy objects have been added.'
    Write-Host 'Network filtering behavior has not been changed.'
    Write-Host ''
    Write-Host 'Press Enter to close the dynamic session and finish STEP 2.'
    [void](Read-Host)

    $result.step2_dynamic_session.held_until_operator_enter = $true

    Write-StepLog 'Closing dynamic WFP session.'
    $dynamicSession.Dispose()
    $dynamicSession = $null
    $result.step2_dynamic_session.closed = $true
    $step2Passed = $true

    Write-StepLog 'STEP 2 PASSED. Dynamic WFP session opened and closed successfully.'
}
catch {
    $result.step2_dynamic_session.error = $_.Exception.Message
    Write-StepLog ("STEP 2 FAILED: {0}" -f $_.Exception.Message)
}
finally {
    if ($null -ne $dynamicSession) {
        try {
            $dynamicSession.Dispose()
            $dynamicSession = $null
            $result.step2_dynamic_session.closed = $true
            Write-StepLog 'Dynamic WFP session closed by finally cleanup.'
        } catch {
            if ([string]::IsNullOrWhiteSpace($result.step2_dynamic_session.error)) {
                $result.step2_dynamic_session.error = $_.Exception.Message
            }
            Write-StepLog ("WARNING: cleanup close failed: {0}" -f $_.Exception.Message)
        }
    }
}

$result.finished_at = (Get-Date).ToString('o')
$result |
    ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $resultPath -Encoding UTF8

$logLines |
    Set-Content -LiteralPath $logPath -Encoding UTF8

$hashes = @()
Get-ChildItem -LiteralPath $outputDir -File |
    Where-Object { $_.Name -ne 'artifact-sha256.json' } |
    ForEach-Object {
        $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        $hashes += [pscustomobject]@{
            file = $_.FullName
            sha256 = $h.Hash
            length = $_.Length
        }
    }

$hashes |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $hashPath -Encoding UTF8

Write-Host ''
Write-Host '============================================================'
Write-Host 'WLMCP Phase B STEP 1/2 - DONE'
Write-Host '============================================================'
Write-Host ("RESULT_DIR  = {0}" -f $outputDir)
Write-Host ("RESULT_JSON = {0}" -f $resultPath)
Write-Host 'STEP_1      = PASSED'
if ($step2Passed) {
    Write-Host 'STEP_2      = PASSED'
} else {
    Write-Host 'STEP_2      = FAILED'
}
Write-Host 'POLICY_MUTATION = false'

if (-not $step2Passed) {
    throw ("STEP 2 FAILED. See: {0}" -f $resultPath)
}
