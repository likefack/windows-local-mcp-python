#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP Phase B - Step 3 temporary WFP sublayer test.

.DESCRIPTION
  Performs:
    1. Re-runs the AppContainerLoopback precheck.
    2. Opens a dynamic WFP session.
    3. Adds ONE temporary WFP sublayer with weight 8.
    4. Reads the sublayer back and verifies its key/name/weight.
    5. Waits for operator Enter.
    6. Closes the dynamic WFP session.
    7. Opens a fresh read session and verifies the temporary sublayer is gone.

  This step DOES modify WFP policy temporarily by adding a sublayer.
  It DOES NOT add any WFP filter, so it is not expected to change network traffic.

  It does NOT:
    - add a WFP filter
    - add/modify a Windows Firewall rule
    - modify the registry
    - start/stop/reconfigure services
    - create a persistent WFP object

  Output:
    <script-dir>\WFP-PhaseB-Step3-Results\<timestamp>\result.json
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
    [string]$OutputBase = (Join-Path $PSScriptRoot 'WFP-PhaseB-Step3-Results')
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

if ($TemporarySubLayerWeight -le $ExpectedAppIsolationWeight) {
    throw 'ERROR: TemporarySubLayerWeight must be greater than ExpectedAppIsolationWeight.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputBase $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$resultPath = Join-Path $outputDir 'result.json'
$logPath = Join-Path $outputDir 'step3-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-StepLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

Write-StepLog 'Starting WLMCP Phase B Step 3.'
Write-StepLog ("Output directory: {0}" -f $outputDir)

$source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseBStep3V1
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

    public sealed class DynamicSubLayerSession : IDisposable
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

        public SubLayerSnapshot AddAndReadSubLayer(
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
            IntPtr subLayerPtr = IntPtr.Zero;

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

                Guid lookupKey = subLayerKey;
                rc = FwpmSubLayerGetByKey0(
                    _engineHandle,
                    ref lookupKey,
                    out subLayerPtr);

                if (rc != ERROR_SUCCESS)
                {
                    throw new Win32Exception(
                        unchecked((int)rc),
                        "FwpmSubLayerGetByKey0(after add) failed: 0x" +
                        rc.ToString("X8"));
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
    private static extern uint FwpmSubLayerAdd0(
        IntPtr engineHandle,
        ref FWPM_SUBLAYER0 subLayer,
        IntPtr sd);

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
        IntPtr subLayerPtr = IntPtr.Zero;

        try
        {
            engine = OpenReadEngine();
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
                    "FwpmSubLayerGetByKey0(fresh) failed: 0x" +
                    rc.ToString("X8"));
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

            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }
        }
    }
}
'@

if (-not ('WfpPhaseBStep3V1' -as [type])) {
    Write-StepLog 'Compiling the WFP Step 3 helper.'
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
} else {
    Write-StepLog 'Reusing already loaded WFP Step 3 helper type.'
}

Write-StepLog ("Reading filter {0}." -f $AppLoopbackV4FilterId)
$v4 = [WfpPhaseBStep3V1]::ReadFilter($AppLoopbackV4FilterId)

Write-StepLog ("Reading filter {0}." -f $AppLoopbackV6FilterId)
$v6 = [WfpPhaseBStep3V1]::ReadFilter($AppLoopbackV6FilterId)

$precheckErrors = New-Object System.Collections.Generic.List[string]

foreach ($item in @(
    [pscustomobject]@{
        label = 'V4'
        filter = $v4
        expected_id = $AppLoopbackV4FilterId
    },
    [pscustomobject]@{
        label = 'V6'
        filter = $v6
        expected_id = $AppLoopbackV6FilterId
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
        $precheckErrors.Add(("{0}: runtime filter ID mismatch" -f $item.label))
    }

    if ($f.name -ne 'AppContainerLoopback') {
        $precheckErrors.Add(
            ("{0}: name is not AppContainerLoopback (actual: {1})" -f
                $item.label,
                $f.name))
    }

    if ($f.action_name -ne 'FWP_ACTION_PERMIT') {
        $precheckErrors.Add(
            ("{0}: action is not FWP_ACTION_PERMIT (actual: {1})" -f
                $item.label,
                $f.action_name))
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

    $precheckErrors.Add(
        'CodexSandboxOffline local user could not be read.')
}

$precheckPassed = ($precheckErrors.Count -eq 0)

$temporarySubLayerKey = [Guid]::NewGuid()
$temporarySubLayerName = 'WLMCP_PhaseB_Temporary_Loopback_Block_Sublayer'
$temporarySubLayerDescription =
    'Temporary Phase B test sublayer. No filters are added in Step 3.'

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
    step3_temporary_sublayer = [ordered]@{
        attempted = $false
        dynamic_session_opened = $false
        dynamic_session_key = $null
        dynamic_session_flags_hex = $null
        requested_key = $temporarySubLayerKey.ToString('B')
        requested_name = $temporarySubLayerName
        requested_weight = $TemporarySubLayerWeight
        added = $false
        verified_while_session_open = $false
        observed_while_session_open = $null
        held_until_operator_enter = $false
        dynamic_session_closed = $false
        cleanup_verified_absent = $false
        post_close_lookup = $null
        error = $null
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
        ConvertTo-Json -Depth 14 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    $logLines |
        Set-Content -LiteralPath $logPath -Encoding UTF8

    throw ("PRECHECK FAILED. See: {0}" -f $resultPath)
}

Write-StepLog 'PRECHECK PASSED.'
Write-StepLog ("CodexSandboxOffline SID: {0}" -f $codexUser.sid)
Write-StepLog (
    ("App Isolation sublayer weight: {0}" -f $v4.sublayer_weight))
Write-StepLog (
    ("Temporary sublayer weight to test: {0}" -f $TemporarySubLayerWeight))

$dynamicSession = $null

try {
    $result.step3_temporary_sublayer.attempted = $true

    Write-StepLog 'Opening dynamic WFP session.'
    $dynamicSession = [WfpPhaseBStep3V1]::OpenDynamicSession()

    $result.step3_temporary_sublayer.dynamic_session_opened =
        $dynamicSession.is_open
    $result.step3_temporary_sublayer.dynamic_session_key =
        $dynamicSession.session_key
    $result.step3_temporary_sublayer.dynamic_session_flags_hex =
        $dynamicSession.session_flags_hex

    Write-StepLog (
        ("Dynamic session opened: {0}" -f $dynamicSession.session_key))

    Write-StepLog (
        ("Adding temporary sublayer: key={0}, weight={1}" -f
            $temporarySubLayerKey.ToString('B'),
            $TemporarySubLayerWeight))

    $observed = $dynamicSession.AddAndReadSubLayer(
        $temporarySubLayerKey,
        $temporarySubLayerName,
        $temporarySubLayerDescription,
        $TemporarySubLayerWeight)

    $result.step3_temporary_sublayer.added = $true
    $result.policy_mutation.temporary_wfp_sublayer_added = $true
    $result.step3_temporary_sublayer.observed_while_session_open = $observed

    $verified =
        $observed.found -and
        $observed.key -eq $temporarySubLayerKey.ToString('B') -and
        $observed.name -eq $temporarySubLayerName -and
        $observed.weight -eq $TemporarySubLayerWeight -and
        $observed.flags -eq 0

    if (-not $verified) {
        throw 'Temporary sublayer read-back verification failed.'
    }

    $result.step3_temporary_sublayer.verified_while_session_open = $true

    Write-StepLog 'Temporary sublayer read-back verification PASSED.'
    Write-Host ''
    Write-Host 'STEP 3 temporary sublayer is currently present.'
    Write-Host 'No WFP filters have been added.'
    Write-Host 'Network traffic behavior should be unchanged.'
    Write-Host ''
    Write-Host (
        "Temporary sublayer key: {0}" -f
            $temporarySubLayerKey.ToString('B'))
    Write-Host (
        "Temporary sublayer weight: {0}" -f
            $TemporarySubLayerWeight)
    Write-Host ''
    Write-Host 'Press Enter to close the dynamic session.'
    Write-Host 'The temporary sublayer should then be removed by BFE.'
    [void](Read-Host)

    $result.step3_temporary_sublayer.held_until_operator_enter = $true

    Write-StepLog 'Closing dynamic WFP session.'
    $dynamicSession.Dispose()
    $dynamicSession = $null
    $result.step3_temporary_sublayer.dynamic_session_closed = $true

    Write-StepLog 'Checking that the temporary sublayer was removed.'
    $after =
        [WfpPhaseBStep3V1]::ReadSubLayerFresh($temporarySubLayerKey)

    $result.step3_temporary_sublayer.post_close_lookup = $after

    if ($after.found) {
        throw 'CLEANUP FAILED: temporary sublayer still exists after session close.'
    }

    if ($after.error_hex -ne '0x80320007') {
        throw (
            "CLEANUP INCONCLUSIVE: expected FWP_E_SUBLAYER_NOT_FOUND " +
            "(0x80320007), actual " +
            $after.error_hex)
    }

    $result.step3_temporary_sublayer.cleanup_verified_absent = $true
    Write-StepLog 'CLEANUP VERIFIED: temporary sublayer is absent.'
    Write-StepLog 'STEP 3 PASSED.'
}
catch {
    $result.step3_temporary_sublayer.error = $_.Exception.Message
    Write-StepLog ("STEP 3 ERROR: {0}" -f $_.Exception.Message)
}
finally {
    if ($null -ne $dynamicSession) {
        try {
            Write-StepLog 'Closing dynamic WFP session in finally cleanup.'
            $dynamicSession.Dispose()
            $dynamicSession = $null
            $result.step3_temporary_sublayer.dynamic_session_closed = $true
            Write-StepLog 'Dynamic WFP session closed by finally cleanup.'
        } catch {
            Write-StepLog (
                ("WARNING: dynamic session cleanup close failed: {0}" -f
                    $_.Exception.Message))
        }
    }

    if ($result.step3_temporary_sublayer.added -and
        -not $result.step3_temporary_sublayer.cleanup_verified_absent) {
        try {
            Write-StepLog 'Running final post-close sublayer lookup.'
            $finalAfter =
                [WfpPhaseBStep3V1]::ReadSubLayerFresh($temporarySubLayerKey)
            $result.step3_temporary_sublayer.post_close_lookup = $finalAfter

            if (-not $finalAfter.found -and
                $finalAfter.error_hex -eq '0x80320007') {
                $result.step3_temporary_sublayer.cleanup_verified_absent =
                    $true
                Write-StepLog (
                    'Final cleanup verification PASSED: sublayer is absent.')
            } else {
                Write-StepLog (
                    'WARNING: final cleanup verification did not prove absence.')
            }
        } catch {
            Write-StepLog (
                ("WARNING: final cleanup verification failed: {0}" -f
                    $_.Exception.Message))
        }
    }
}

$result.finished_at = (Get-Date).ToString('o')

$result |
    ConvertTo-Json -Depth 14 |
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
Write-Host 'WLMCP Phase B STEP 3 - FINISHED'
Write-Host '============================================================'
Write-Host ("RESULT_DIR  = {0}" -f $outputDir)
Write-Host ("RESULT_JSON = {0}" -f $resultPath)
Write-Host (
    ("SUBLAYER_ADDED = {0}" -f
        $result.step3_temporary_sublayer.added))
Write-Host (
    ("READBACK_VERIFIED = {0}" -f
        $result.step3_temporary_sublayer.verified_while_session_open))
Write-Host (
    ("CLEANUP_VERIFIED = {0}" -f
        $result.step3_temporary_sublayer.cleanup_verified_absent))

if ([string]::IsNullOrWhiteSpace(
        $result.step3_temporary_sublayer.error)) {
    Write-Host 'STEP_3 = PASSED'
} else {
    Write-Host (
        ("STEP_3 = FAILED: {0}" -f
            $result.step3_temporary_sublayer.error))
}
