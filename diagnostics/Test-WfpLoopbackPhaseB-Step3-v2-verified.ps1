#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP Phase B - Step 3 temporary WFP sublayer test (verified v2).

.DESCRIPTION
  This is a cautious Step 3 test.

  It performs:
    1. Re-check AppContainerLoopback V4/V6 runtime filters.
    2. Verify their expected ALE_AUTH_CONNECT layers.
    3. Verify both are PERMIT and share the same weight-7 sublayer.
    4. Verify CodexSandboxOffline exists and is enabled.
    5. Generate a unique temporary sublayer GUID and verify it is absent.
    6. Open a dynamic WFP session.
    7. Add ONE empty temporary sublayer with weight 8.
    8. Immediately record that the add succeeded.
    9. Read the sublayer back and verify key/name/weight/flags.
   10. Wait for operator Enter.
   11. Close the dynamic session.
   12. Verify the temporary sublayer is absent from a fresh session.
   13. If automatic cleanup is not observed, attempt deletion of ONLY the
       unique temporary sublayer GUID and report Step 3 as FAILED.

  This script temporarily adds ONE EMPTY WFP sublayer.
  It does NOT add any WFP filter and is not expected to change traffic.

  It does NOT:
    - add a WFP filter
    - add/modify a Windows Firewall rule
    - modify the registry
    - start/stop/reconfigure services
    - create a persistent WFP object

  Output:
    <script-dir>\WFP-PhaseB-Step3-v2-Results\<timestamp>\result.json
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
    [UInt16]$TemporarySubLayerWeight = 8,

    [Parameter(Mandatory = $false)]
    [string]$OutputBase = (Join-Path $PSScriptRoot 'WFP-PhaseB-Step3-v2-Results')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedV4LayerKey = '{c38d57d1-05a7-4c33-904f-7fbceee60e82}'
$ExpectedV6LayerKey = '{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}'
$NotFoundHex = '0x80320007'

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

if ($TemporarySubLayerWeight -le $ExpectedAppIsolationWeight) {
    throw 'ERROR: TemporarySubLayerWeight must be greater than ExpectedAppIsolationWeight.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputBase $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$resultPath = Join-Path $outputDir 'result.json'
$logPath = Join-Path $outputDir 'step3-v2-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-StepLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

Write-StepLog 'Starting WLMCP Phase B Step 3 verified v2.'
Write-StepLog ("Output directory: {0}" -f $outputDir)

$source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseBStep3V2
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;
    private const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;
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
        public string name { get; set; }
        public string description { get; set; }
        public string layer_key { get; set; }
        public string sublayer_key { get; set; }
        public uint action_type { get; set; }
        public string action_type_hex { get; set; }
        public string action_name { get; set; }
        public bool sublayer_found { get; set; }
        public string sublayer_error_hex { get; set; }
        public string sublayer_name { get; set; }
        public ushort sublayer_weight { get; set; }
    }

    public sealed class SubLayerSnapshot
    {
        public bool found { get; set; }
        public string error_hex { get; set; }
        public string key { get; set; }
        public string name { get; set; }
        public string description { get; set; }
        public uint flags { get; set; }
        public ushort weight { get; set; }
    }

    public sealed class DynamicSubLayerSession
    {
        private IntPtr _engineHandle;

        public string session_key { get; private set; }
        public uint session_flags { get; private set; }
        public string session_flags_hex { get; private set; }

        internal DynamicSubLayerSession(IntPtr handle, Guid sessionKey)
        {
            _engineHandle = handle;
            session_key = sessionKey.ToString("B");
            session_flags = FWPM_SESSION_FLAG_DYNAMIC;
            session_flags_hex = "0x" + FWPM_SESSION_FLAG_DYNAMIC.ToString("X8");
        }

        public bool is_open
        {
            get { return _engineHandle != IntPtr.Zero; }
        }

        public void AddSubLayer(
            Guid subLayerKey,
            string name,
            string description,
            ushort weight)
        {
            if (_engineHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Dynamic WFP session is closed.");
            }

            IntPtr namePtr = IntPtr.Zero;
            IntPtr descriptionPtr = IntPtr.Zero;

            try
            {
                namePtr = Marshal.StringToHGlobalUni(name);
                descriptionPtr = Marshal.StringToHGlobalUni(description);

                FWPM_SUBLAYER0 subLayer = new FWPM_SUBLAYER0();
                subLayer.subLayerKey = subLayerKey;
                subLayer.displayData.name = namePtr;
                subLayer.displayData.description = descriptionPtr;
                subLayer.flags = 0;
                subLayer.providerKey = IntPtr.Zero;
                subLayer.providerData.size = 0;
                subLayer.providerData.data = IntPtr.Zero;
                subLayer.weight = weight;

                uint rc = FwpmSubLayerAdd0(
                    _engineHandle,
                    ref subLayer,
                    IntPtr.Zero);

                if (rc != ERROR_SUCCESS)
                {
                    throw new Win32Exception(
                        unchecked((int)rc),
                        "FwpmSubLayerAdd0 failed: 0x" + rc.ToString("X8"));
                }
            }
            finally
            {
                if (descriptionPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(descriptionPtr);
                }

                if (namePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(namePtr);
                }
            }
        }

        public SubLayerSnapshot ReadSubLayer(Guid key)
        {
            if (_engineHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Dynamic WFP session is closed.");
            }

            return ReadSubLayerOnEngine(_engineHandle, key);
        }

        public uint DeleteSubLayer(Guid key)
        {
            if (_engineHandle == IntPtr.Zero)
            {
                return 0xFFFFFFFF;
            }

            Guid localKey = key;
            return FwpmSubLayerDeleteByKey0(_engineHandle, ref localKey);
        }

        public uint Close()
        {
            if (_engineHandle == IntPtr.Zero)
            {
                return ERROR_SUCCESS;
            }

            uint rc = FwpmEngineClose0(_engineHandle);

            if (rc == ERROR_SUCCESS)
            {
                _engineHandle = IntPtr.Zero;
            }

            return rc;
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
    private static extern uint FwpmSubLayerAdd0(
        IntPtr engineHandle,
        ref FWPM_SUBLAYER0 subLayer,
        IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDeleteByKey0(
        IntPtr engineHandle,
        ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);

    private static string PtrToStringUni(IntPtr p)
    {
        return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);
    }

    private static string ActionName(uint actionType)
    {
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

    private static SubLayerSnapshot ReadSubLayerOnEngine(
        IntPtr engine,
        Guid key)
    {
        IntPtr subLayerPtr = IntPtr.Zero;

        try
        {
            Guid lookupKey = key;

            uint rc = FwpmSubLayerGetByKey0(
                engine,
                ref lookupKey,
                out subLayerPtr);

            if (rc == FWP_E_SUBLAYER_NOT_FOUND)
            {
                return new SubLayerSnapshot
                {
                    found = false,
                    error_hex = "0x" + rc.ToString("X8"),
                    key = key.ToString("B")
                };
            }

            if (rc != ERROR_SUCCESS)
            {
                throw new Win32Exception(
                    unchecked((int)rc),
                    "FwpmSubLayerGetByKey0 failed: 0x" + rc.ToString("X8"));
            }

            FWPM_SUBLAYER0 actual =
                Marshal.PtrToStructure<FWPM_SUBLAYER0>(subLayerPtr);

            return new SubLayerSnapshot
            {
                found = true,
                error_hex = null,
                key = actual.subLayerKey.ToString("B"),
                name = PtrToStringUni(actual.displayData.name),
                description = PtrToStringUni(actual.displayData.description),
                flags = actual.flags,
                weight = actual.weight
            };
        }
        finally
        {
            if (subLayerPtr != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref subLayerPtr);
            }
        }
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

            FWPM_FILTER0 f =
                Marshal.PtrToStructure<FWPM_FILTER0>(filterPtr);

            FilterSnapshot result = new FilterSnapshot
            {
                requested_filter_id = id,
                found = true,
                error_hex = null,
                runtime_filter_id = f.filterId,
                name = PtrToStringUni(f.displayData.name),
                description = PtrToStringUni(f.displayData.description),
                layer_key = f.layerKey.ToString("B"),
                sublayer_key = f.subLayerKey.ToString("B"),
                action_type = f.action.type,
                action_type_hex = "0x" + f.action.type.ToString("X8"),
                action_name = ActionName(f.action.type)
            };

            Guid subLayerKey = f.subLayerKey;
            rc = FwpmSubLayerGetByKey0(
                engine,
                ref subLayerKey,
                out subLayerPtr);

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

    public static DynamicSubLayerSession OpenDynamicSession()
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
            sessionPtr =
                Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FWPM_SESSION0)));
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

            return new DynamicSubLayerSession(ownedHandle, sessionKey);
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

    public static SubLayerSnapshot ReadSubLayerFresh(Guid key)
    {
        IntPtr engine = IntPtr.Zero;

        try
        {
            engine = OpenReadEngine();
            return ReadSubLayerOnEngine(engine, key);
        }
        finally
        {
            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }
        }
    }

    public static uint DeleteSubLayerFresh(Guid key)
    {
        IntPtr engine = IntPtr.Zero;

        try
        {
            engine = OpenReadEngine();
            Guid localKey = key;
            return FwpmSubLayerDeleteByKey0(engine, ref localKey);
        }
        finally
        {
            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }
        }
    }
}
'@

if (-not ('WfpPhaseBStep3V2' -as [type])) {
    Write-StepLog 'Compiling the WFP Step 3 v2 helper.'
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
} else {
    Write-StepLog 'Reusing already loaded WFP Step 3 v2 helper type.'
}

Write-StepLog ("Reading filter {0}." -f $AppLoopbackV4FilterId)
$v4 = [WfpPhaseBStep3V2]::ReadFilter($AppLoopbackV4FilterId)

Write-StepLog ("Reading filter {0}." -f $AppLoopbackV6FilterId)
$v6 = [WfpPhaseBStep3V2]::ReadFilter($AppLoopbackV6FilterId)

$precheckErrors = New-Object System.Collections.Generic.List[string]

foreach ($item in @(
    [pscustomobject]@{
        label = 'V4'
        filter = $v4
        expected_id = $AppLoopbackV4FilterId
        expected_layer = $ExpectedV4LayerKey
    },
    [pscustomobject]@{
        label = 'V6'
        filter = $v6
        expected_id = $AppLoopbackV6FilterId
        expected_layer = $ExpectedV6LayerKey
    }
)) {
    $f = $item.filter

    if (-not $f.found) {
        $precheckErrors.Add(
            ("{0}: runtime filter {1} not found ({2})" -f
                $item.label,
                $item.expected_id,
                $f.error_hex))
        continue
    }

    if ($f.runtime_filter_id -ne $item.expected_id) {
        $precheckErrors.Add(
            ("{0}: runtime filter ID mismatch" -f $item.label))
    }

    if ($f.name -ne 'AppContainerLoopback') {
        $precheckErrors.Add(
            ("{0}: name mismatch (actual: {1})" -f
                $item.label,
                $f.name))
    }

    if ($f.action_name -ne 'FWP_ACTION_PERMIT') {
        $precheckErrors.Add(
            ("{0}: action mismatch (actual: {1})" -f
                $item.label,
                $f.action_name))
    }

    if ($f.layer_key -ne $item.expected_layer) {
        $precheckErrors.Add(
            ("{0}: layer mismatch (expected {1}, actual {2})" -f
                $item.label,
                $item.expected_layer,
                $f.layer_key))
    }

    if (-not $f.sublayer_found) {
        $precheckErrors.Add(
            ("{0}: sublayer could not be read ({1})" -f
                $item.label,
                $f.sublayer_error_hex))
    }

    if ($f.sublayer_found -and
        $f.sublayer_weight -ne $ExpectedAppIsolationWeight) {
        $precheckErrors.Add(
            ("{0}: sublayer weight changed (expected {1}, actual {2})" -f
                $item.label,
                $ExpectedAppIsolationWeight,
                $f.sublayer_weight))
    }
}

if ($v4.found -and
    $v6.found -and
    -not [string]::IsNullOrWhiteSpace($v4.sublayer_key) -and
    -not [string]::IsNullOrWhiteSpace($v6.sublayer_key) -and
    $v4.sublayer_key -ne $v6.sublayer_key) {
    $precheckErrors.Add(
        'V4 and V6 AppContainerLoopback filters are in different sublayers.')
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
        $precheckErrors.Add(
            'CodexSandboxOffline exists but is disabled.')
    }
} catch {
    $codexUser = [ordered]@{
        found = $false
        name = 'CodexSandboxOffline'
        sid = $null
        enabled = $null
        error = $_.Exception.Message
    }

    $precheckErrors.Add(
        'CodexSandboxOffline local user could not be read.')
}

$temporarySubLayerKey = [Guid]::NewGuid()
$temporarySubLayerName =
    'WLMCP_PhaseB_Temporary_Loopback_Block_Sublayer_v2'
$temporarySubLayerDescription =
    'Temporary Phase B Step 3 sublayer. No filters are added.'

$keyBefore =
    [WfpPhaseBStep3V2]::ReadSubLayerFresh($temporarySubLayerKey)

if ($keyBefore.found -or $keyBefore.error_hex -ne $NotFoundHex) {
    $precheckErrors.Add(
        'Generated temporary sublayer key was not proven absent before add.')
}

$precheckPassed = ($precheckErrors.Count -eq 0)

$result = [ordered]@{
    schema_version = 2
    started_at = (Get-Date).ToString('o')
    host = [ordered]@{
        computer_name = $env:COMPUTERNAME
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        process_id = $PID
        is_administrator = $true
        is_64_bit_process = [Environment]::Is64BitProcess
        codex_sandbox_offline = $codexUser
    }
    precheck = [ordered]@{
        passed = $precheckPassed
        expected_v4_layer_key = $ExpectedV4LayerKey
        expected_v6_layer_key = $ExpectedV6LayerKey
        expected_app_isolation_weight = $ExpectedAppIsolationWeight
        errors = @($precheckErrors)
        filter_70511 = $v4
        filter_70512 = $v6
        temporary_key_before_add = $keyBefore
    }
    step3 = [ordered]@{
        attempted = $false
        dynamic_session_opened = $false
        dynamic_session_key = $null
        dynamic_session_flags_hex = $null

        requested_key = $temporarySubLayerKey.ToString('B')
        requested_name = $temporarySubLayerName
        requested_weight = $TemporarySubLayerWeight

        add_attempted = $false
        add_succeeded = $false

        readback_attempted = $false
        readback_verified = $false
        observed_while_session_open = $null

        held_until_operator_enter = $false

        close_attempted = $false
        close_rc_hex = $null
        close_succeeded = $false

        same_session_emergency_delete_attempted = $false
        same_session_emergency_delete_rc_hex = $null

        cleanup_verified_absent = $false
        post_close_lookup = $null

        fresh_emergency_delete_attempted = $false
        fresh_emergency_delete_rc_hex = $null
        final_lookup = $null

        error = $null
        cleanup_warning = $null
    }
    policy_mutation = [ordered]@{
        temporary_wfp_sublayer_added = $false
        wfp_filter_added = $false
        windows_firewall_rule_changed = $false
        registry_changed = $false
        service_changed = $false
        persistent_wfp_object_created = $false
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
    Write-StepLog 'PRECHECK FAILED. No WFP object will be added.'

    foreach ($e in $precheckErrors) {
        Write-StepLog ("PRECHECK ERROR: {0}" -f $e)
    }

    $result.finished_at = (Get-Date).ToString('o')
    $result |
        ConvertTo-Json -Depth 16 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    $logLines |
        Set-Content -LiteralPath $logPath -Encoding UTF8

    throw ("PRECHECK FAILED. See: {0}" -f $resultPath)
}

Write-StepLog 'PRECHECK PASSED.'
Write-StepLog ("CodexSandboxOffline SID: {0}" -f $codexUser.sid)
Write-StepLog (
    ("App Isolation sublayer weight: {0}" -f
        $v4.sublayer_weight))
Write-StepLog (
    ("Temporary sublayer weight to test: {0}" -f
        $TemporarySubLayerWeight))

$dynamicSession = $null

try {
    $result.step3.attempted = $true

    Write-StepLog 'Opening dynamic WFP session.'
    $dynamicSession = [WfpPhaseBStep3V2]::OpenDynamicSession()

    $result.step3.dynamic_session_opened =
        $dynamicSession.is_open
    $result.step3.dynamic_session_key =
        $dynamicSession.session_key
    $result.step3.dynamic_session_flags_hex =
        $dynamicSession.session_flags_hex

    Write-StepLog (
        ("Dynamic session opened: {0}" -f
            $dynamicSession.session_key))

    $result.step3.add_attempted = $true

    Write-StepLog (
        ("Adding ONE EMPTY temporary sublayer: key={0}, weight={1}" -f
            $temporarySubLayerKey.ToString('B'),
            $TemporarySubLayerWeight))

    $dynamicSession.AddSubLayer(
        $temporarySubLayerKey,
        $temporarySubLayerName,
        $temporarySubLayerDescription,
        $TemporarySubLayerWeight)

    # Set this immediately after FwpmSubLayerAdd0 succeeds.
    $result.step3.add_succeeded = $true
    $result.policy_mutation.temporary_wfp_sublayer_added = $true

    Write-StepLog 'FwpmSubLayerAdd0 returned success.'

    $result.step3.readback_attempted = $true

    $observed =
        $dynamicSession.ReadSubLayer($temporarySubLayerKey)

    $result.step3.observed_while_session_open = $observed

    $verified =
        $observed.found -and
        $observed.key -eq $temporarySubLayerKey.ToString('B') -and
        $observed.name -eq $temporarySubLayerName -and
        $observed.weight -eq $TemporarySubLayerWeight -and
        $observed.flags -eq 0

    if (-not $verified) {
        throw 'Temporary sublayer read-back verification failed.'
    }

    $result.step3.readback_verified = $true
    Write-StepLog 'Temporary sublayer read-back verification PASSED.'

    Write-Host ''
    Write-Host 'STEP 3 temporary EMPTY sublayer is currently present.'
    Write-Host 'No WFP filters have been added.'
    Write-Host 'Network traffic behavior is not expected to change.'
    Write-Host ''
    Write-Host (
        "Temporary sublayer key: {0}" -f
            $temporarySubLayerKey.ToString('B'))
    Write-Host (
        "Temporary sublayer weight: {0}" -f
            $TemporarySubLayerWeight)
    Write-Host ''
    Write-Host 'Press Enter to close the dynamic session.'
    [void](Read-Host)

    $result.step3.held_until_operator_enter = $true
}
catch {
    $result.step3.error = $_.Exception.Message
    Write-StepLog ("STEP 3 ERROR: {0}" -f $_.Exception.Message)
}
finally {
    if ($null -ne $dynamicSession -and $dynamicSession.is_open) {
        try {
            $result.step3.close_attempted = $true
            Write-StepLog 'Closing dynamic WFP session.'

            $closeRc = $dynamicSession.Close()
            $result.step3.close_rc_hex =
                ('0x{0:X8}' -f $closeRc)

            if ($closeRc -eq 0) {
                $result.step3.close_succeeded = $true
                Write-StepLog 'Dynamic WFP session close PASSED.'
            } else {
                Write-StepLog (
                    ("WARNING: FwpmEngineClose0 returned {0}" -f
                        $result.step3.close_rc_hex))

                if ($result.step3.add_succeeded -and
                    $dynamicSession.is_open) {
                    $result.step3.same_session_emergency_delete_attempted =
                        $true

                    Write-StepLog (
                        'Attempting same-session emergency deletion of ONLY ' +
                        'the temporary sublayer GUID.')

                    $deleteRc =
                        $dynamicSession.DeleteSubLayer(
                            $temporarySubLayerKey)

                    $result.step3.same_session_emergency_delete_rc_hex =
                        ('0x{0:X8}' -f $deleteRc)

                    Write-StepLog (
                        ("Same-session emergency delete returned {0}" -f
                            $result.step3.same_session_emergency_delete_rc_hex))
                }

                if ($dynamicSession.is_open) {
                    Write-StepLog 'Retrying dynamic session close once.'
                    $retryCloseRc = $dynamicSession.Close()

                    if ($retryCloseRc -eq 0) {
                        $result.step3.close_succeeded = $true
                        $result.step3.close_rc_hex = '0x00000000'
                        Write-StepLog 'Retry close PASSED.'
                    } else {
                        $result.step3.cleanup_warning =
                            ("Dynamic session close could not be proven. " +
                             "Retry returned 0x{0:X8}. Close this PowerShell " +
                             "window after collecting the result." -f
                                $retryCloseRc)

                        Write-StepLog (
                            ("CRITICAL CLEANUP WARNING: {0}" -f
                                $result.step3.cleanup_warning))
                    }
                }
            }
        } catch {
            $result.step3.cleanup_warning =
                ("Exception while closing dynamic session: {0}. " +
                 "Close this PowerShell window after collecting the result." -f
                    $_.Exception.Message)

            Write-StepLog (
                ("CRITICAL CLEANUP WARNING: {0}" -f
                    $result.step3.cleanup_warning))
        }
    }
}

# Verify absence from a fresh session. Use a short bounded retry because this
# is a cleanup observation, not an unbounded wait.
if ($result.step3.add_succeeded) {
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $after =
                [WfpPhaseBStep3V2]::ReadSubLayerFresh(
                    $temporarySubLayerKey)

            $result.step3.post_close_lookup = $after

            if (-not $after.found -and
                $after.error_hex -eq $NotFoundHex) {
                $result.step3.cleanup_verified_absent = $true
                Write-StepLog (
                    'CLEANUP VERIFIED: temporary sublayer is absent.')
                break
            }
        } catch {
            Write-StepLog (
                ("Cleanup lookup attempt failed: {0}" -f
                    $_.Exception.Message))
        }

        Start-Sleep -Milliseconds 200
    }
}

# Belt-and-suspenders cleanup. This runs only if automatic cleanup was not
# observed and targets ONLY the unique GUID generated by this run.
if ($result.step3.add_succeeded -and
    -not $result.step3.cleanup_verified_absent) {

    try {
        $result.step3.fresh_emergency_delete_attempted = $true

        Write-StepLog (
            'Automatic cleanup was not verified. Attempting fresh-session ' +
            'deletion of ONLY the temporary sublayer GUID.')

        $freshDeleteRc =
            [WfpPhaseBStep3V2]::DeleteSubLayerFresh(
                $temporarySubLayerKey)

        $result.step3.fresh_emergency_delete_rc_hex =
            ('0x{0:X8}' -f $freshDeleteRc)

        Write-StepLog (
            ("Fresh-session emergency delete returned {0}" -f
                $result.step3.fresh_emergency_delete_rc_hex))
    } catch {
        Write-StepLog (
            ("Fresh-session emergency delete failed: {0}" -f
                $_.Exception.Message))
    }

    try {
        $finalLookup =
            [WfpPhaseBStep3V2]::ReadSubLayerFresh(
                $temporarySubLayerKey)

        $result.step3.final_lookup = $finalLookup

        if (-not $finalLookup.found -and
            $finalLookup.error_hex -eq $NotFoundHex) {
            $result.step3.cleanup_verified_absent = $true
            Write-StepLog (
                'FINAL CLEANUP VERIFIED: temporary sublayer is absent.')
        } else {
            $result.step3.cleanup_warning =
                'Temporary sublayer absence could not be verified.'
            Write-StepLog (
                'CRITICAL: temporary sublayer absence could not be verified.')
        }
    } catch {
        $result.step3.cleanup_warning =
            ("Final cleanup verification failed: {0}" -f
                $_.Exception.Message)
        Write-StepLog (
            ("CRITICAL: {0}" -f $result.step3.cleanup_warning))
    }
}

if ($result.step3.add_succeeded -and
    -not $result.step3.readback_verified -and
    [string]::IsNullOrWhiteSpace($result.step3.error)) {
    $result.step3.error =
        'Sublayer was added but read-back verification did not pass.'
}

if ($result.step3.add_succeeded -and
    -not $result.step3.cleanup_verified_absent -and
    [string]::IsNullOrWhiteSpace($result.step3.error)) {
    $result.step3.error =
        'Temporary sublayer cleanup could not be verified.'
}

$result.finished_at = (Get-Date).ToString('o')

$result |
    ConvertTo-Json -Depth 16 |
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
Write-Host 'WLMCP Phase B STEP 3 verified v2 - FINISHED'
Write-Host '============================================================'
Write-Host ("RESULT_DIR  = {0}" -f $outputDir)
Write-Host ("RESULT_JSON = {0}" -f $resultPath)
Write-Host (
    ("ADD_SUCCEEDED = {0}" -f
        $result.step3.add_succeeded))
Write-Host (
    ("READBACK_VERIFIED = {0}" -f
        $result.step3.readback_verified))
Write-Host (
    ("CLOSE_SUCCEEDED = {0}" -f
        $result.step3.close_succeeded))
Write-Host (
    ("CLEANUP_VERIFIED = {0}" -f
        $result.step3.cleanup_verified_absent))

$stepPassed =
    $result.precheck.passed -and
    $result.step3.add_succeeded -and
    $result.step3.readback_verified -and
    $result.step3.close_succeeded -and
    $result.step3.cleanup_verified_absent -and
    [string]::IsNullOrWhiteSpace($result.step3.error)

if ($stepPassed) {
    Write-Host 'STEP_3 = PASSED'
} else {
    Write-Host 'STEP_3 = FAILED_OR_INCONCLUSIVE'

    if (-not [string]::IsNullOrWhiteSpace($result.step3.error)) {
        Write-Host ("ERROR = {0}" -f $result.step3.error)
    }

    if (-not [string]::IsNullOrWhiteSpace(
            $result.step3.cleanup_warning)) {
        Write-Host (
            ("CLEANUP_WARNING = {0}" -f
                $result.step3.cleanup_warning))
    }
}
