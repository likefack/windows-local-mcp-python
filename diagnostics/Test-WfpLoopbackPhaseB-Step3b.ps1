#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP Phase B - Step 3b sublayer-weight mapping diagnostic.

.DESCRIPTION
  This diagnostic investigates why a temporary sublayer requested with
  weight 8 was read back as weight 10.

  It does NOT add any WFP filter.

  It performs only these temporary WFP mutations:
    - for each requested weight in 8,9,10,11,256:
      * open a fresh dynamic WFP session
      * create ONE empty temporary sublayer with a unique GUID
      * read the sublayer back
      * close the dynamic session
      * verify the sublayer is gone
    - if automatic cleanup is not observed, delete ONLY that unique GUID

  It also enumerates the current WFP sublayer list before and after the
  trials. This is a small sublayer-only enumeration, not a full WFP state dump.

  It validates the x64 interop layout of FWPM_SUBLAYER0 before any mutation.

  Output:
    <script-dir>\WFP-PhaseB-Step3b-Results\<timestamp>\result.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [UInt16[]]$RequestedWeights = @(8, 9, 10, 11, 256),

    [Parameter(Mandatory = $false)]
    [string]$OutputBase = (Join-Path $PSScriptRoot 'WFP-PhaseB-Step3b-Results')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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

if ($RequestedWeights.Count -eq 0) {
    throw 'ERROR: RequestedWeights must contain at least one value.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputBase $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$resultPath = Join-Path $outputDir 'result.json'
$logPath = Join-Path $outputDir 'step3b-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-StepLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

Write-StepLog 'Starting WLMCP Phase B Step 3b.'
Write-StepLog ("Output directory: {0}" -f $outputDir)
Write-StepLog ("Requested weights: {0}" -f ($RequestedWeights -join ', '))

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseBStep3bV1
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;
    private const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

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

    public sealed class LayoutInfo
    {
        public int sublayer_size { get; set; }
        public long offset_subLayerKey { get; set; }
        public long offset_displayData { get; set; }
        public long offset_flags { get; set; }
        public long offset_providerKey { get; set; }
        public long offset_providerData { get; set; }
        public long offset_weight { get; set; }
        public int display_data_size { get; set; }
        public int byte_blob_size { get; set; }
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

    public sealed class DynamicSession
    {
        private IntPtr _engineHandle;

        public string session_key { get; private set; }
        public string flags_hex { get; private set; }

        internal DynamicSession(IntPtr engineHandle, Guid sessionKey)
        {
            _engineHandle = engineHandle;
            session_key = sessionKey.ToString("B");
            flags_hex = "0x" + FWPM_SESSION_FLAG_DYNAMIC.ToString("X8");
        }

        public bool is_open
        {
            get { return _engineHandle != IntPtr.Zero; }
        }

        public void AddSubLayer(
            Guid key,
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

                FWPM_SUBLAYER0 s = new FWPM_SUBLAYER0();
                s.subLayerKey = key;
                s.displayData.name = namePtr;
                s.displayData.description = descriptionPtr;
                s.flags = 0;
                s.providerKey = IntPtr.Zero;
                s.providerData.size = 0;
                s.providerData.data = IntPtr.Zero;
                s.weight = weight;

                uint rc = FwpmSubLayerAdd0(
                    _engineHandle,
                    ref s,
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
    private static extern uint FwpmSubLayerAdd0(
        IntPtr engineHandle,
        ref FWPM_SUBLAYER0 subLayer,
        IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDeleteByKey0(
        IntPtr engineHandle,
        ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerGetByKey0(
        IntPtr engineHandle,
        ref Guid key,
        out IntPtr subLayer);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerCreateEnumHandle0(
        IntPtr engineHandle,
        IntPtr enumTemplate,
        out IntPtr enumHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerEnum0(
        IntPtr engineHandle,
        IntPtr enumHandle,
        uint numEntriesRequested,
        out IntPtr entries,
        out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDestroyEnumHandle0(
        IntPtr engineHandle,
        IntPtr enumHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);

    private static string PtrToStringUni(IntPtr p)
    {
        return p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);
    }

    public static LayoutInfo GetLayoutInfo()
    {
        return new LayoutInfo
        {
            sublayer_size = Marshal.SizeOf(typeof(FWPM_SUBLAYER0)),
            offset_subLayerKey = Marshal.OffsetOf(typeof(FWPM_SUBLAYER0), "subLayerKey").ToInt64(),
            offset_displayData = Marshal.OffsetOf(typeof(FWPM_SUBLAYER0), "displayData").ToInt64(),
            offset_flags = Marshal.OffsetOf(typeof(FWPM_SUBLAYER0), "flags").ToInt64(),
            offset_providerKey = Marshal.OffsetOf(typeof(FWPM_SUBLAYER0), "providerKey").ToInt64(),
            offset_providerData = Marshal.OffsetOf(typeof(FWPM_SUBLAYER0), "providerData").ToInt64(),
            offset_weight = Marshal.OffsetOf(typeof(FWPM_SUBLAYER0), "weight").ToInt64(),
            display_data_size = Marshal.SizeOf(typeof(FWPM_DISPLAY_DATA0)),
            byte_blob_size = Marshal.SizeOf(typeof(FWP_BYTE_BLOB))
        };
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
        IntPtr p = IntPtr.Zero;

        try
        {
            Guid localKey = key;

            uint rc = FwpmSubLayerGetByKey0(
                engine,
                ref localKey,
                out p);

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

            FWPM_SUBLAYER0 s =
                Marshal.PtrToStructure<FWPM_SUBLAYER0>(p);

            return new SubLayerSnapshot
            {
                found = true,
                error_hex = null,
                key = s.subLayerKey.ToString("B"),
                name = PtrToStringUni(s.displayData.name),
                description = PtrToStringUni(s.displayData.description),
                flags = s.flags,
                weight = s.weight
            };
        }
        finally
        {
            if (p != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref p);
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

    public static DynamicSession OpenDynamicSession()
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

            return new DynamicSession(ownedHandle, sessionKey);
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

    public static SubLayerSnapshot[] EnumerateSubLayers()
    {
        IntPtr engine = IntPtr.Zero;
        IntPtr enumHandle = IntPtr.Zero;
        var output = new List<SubLayerSnapshot>();

        try
        {
            engine = OpenReadEngine();

            uint rc = FwpmSubLayerCreateEnumHandle0(
                engine,
                IntPtr.Zero,
                out enumHandle);

            if (rc != ERROR_SUCCESS)
            {
                throw new Win32Exception(
                    unchecked((int)rc),
                    "FwpmSubLayerCreateEnumHandle0 failed: 0x" +
                    rc.ToString("X8"));
            }

            while (true)
            {
                IntPtr entries = IntPtr.Zero;
                uint returned = 0;

                try
                {
                    rc = FwpmSubLayerEnum0(
                        engine,
                        enumHandle,
                        128,
                        out entries,
                        out returned);

                    if (rc != ERROR_SUCCESS)
                    {
                        throw new Win32Exception(
                            unchecked((int)rc),
                            "FwpmSubLayerEnum0 failed: 0x" +
                            rc.ToString("X8"));
                    }

                    for (uint i = 0; i < returned; i++)
                    {
                        IntPtr itemPtr =
                            Marshal.ReadIntPtr(
                                entries,
                                checked((int)(i * (uint)IntPtr.Size)));

                        if (itemPtr == IntPtr.Zero)
                        {
                            continue;
                        }

                        FWPM_SUBLAYER0 s =
                            Marshal.PtrToStructure<FWPM_SUBLAYER0>(itemPtr);

                        output.Add(
                            new SubLayerSnapshot
                            {
                                found = true,
                                error_hex = null,
                                key = s.subLayerKey.ToString("B"),
                                name = PtrToStringUni(s.displayData.name),
                                description = PtrToStringUni(s.displayData.description),
                                flags = s.flags,
                                weight = s.weight
                            });
                    }
                }
                finally
                {
                    if (entries != IntPtr.Zero)
                    {
                        FwpmFreeMemory0(ref entries);
                    }
                }

                if (returned < 128)
                {
                    break;
                }
            }

            return output.ToArray();
        }
        finally
        {
            if (enumHandle != IntPtr.Zero && engine != IntPtr.Zero)
            {
                FwpmSubLayerDestroyEnumHandle0(engine, enumHandle);
            }

            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }
        }
    }
}
'@

if (-not ('WfpPhaseBStep3bV1' -as [type])) {
    Write-StepLog 'Compiling the Step 3b helper.'
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
} else {
    Write-StepLog 'Reusing already loaded Step 3b helper type.'
}

$layout = [WfpPhaseBStep3bV1]::GetLayoutInfo()

$expectedLayout = [ordered]@{
    sublayer_size = 72
    offset_subLayerKey = 0
    offset_displayData = 16
    offset_flags = 32
    offset_providerKey = 40
    offset_providerData = 48
    offset_weight = 64
    display_data_size = 16
    byte_blob_size = 16
}

$layoutErrors = New-Object System.Collections.Generic.List[string]

foreach ($name in $expectedLayout.Keys) {
    if ([Int64]$layout.$name -ne [Int64]$expectedLayout[$name]) {
        $layoutErrors.Add(
            ("{0}: expected {1}, actual {2}" -f
                $name,
                $expectedLayout[$name],
                $layout.$name))
    }
}

if ($layoutErrors.Count -gt 0) {
    Write-StepLog 'INTEROP LAYOUT CHECK FAILED. No WFP mutation will occur.'

    foreach ($e in $layoutErrors) {
        Write-StepLog ("LAYOUT ERROR: {0}" -f $e)
    }

    $failed = [ordered]@{
        schema_version = 1
        started_at = (Get-Date).ToString('o')
        layout = $layout
        expected_layout = $expectedLayout
        layout_errors = @($layoutErrors)
        trials = @()
        mutation_performed = $false
        result = 'STOP_LAYOUT_MISMATCH'
        output = [ordered]@{
            directory = $outputDir
            result_json = $resultPath
            log = $logPath
            artifact_hashes = $hashPath
        }
        finished_at = (Get-Date).ToString('o')
    }

    $failed |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8

    $logLines |
        Set-Content -LiteralPath $logPath -Encoding UTF8

    throw ("Interop layout mismatch. See: {0}" -f $resultPath)
}

Write-StepLog 'Interop layout check PASSED.'

Write-StepLog 'Enumerating existing WFP sublayers before trials.'
$baseline = [WfpPhaseBStep3bV1]::EnumerateSubLayers() |
    Sort-Object -Property @{ Expression = { $_.weight }; Descending = $true },
                          @{ Expression = { $_.name }; Descending = $false }

Write-StepLog ("Baseline sublayer count: {0}" -f @($baseline).Count)

$nearbyBaseline = @(
    $baseline |
    Where-Object { $_.weight -ge 0 -and $_.weight -le 20 }
)

Write-StepLog (
    ("Existing sublayers with weight 0..20: {0}" -f
        @($nearbyBaseline).Count))

$trials = New-Object System.Collections.Generic.List[object]
$stopFurtherTrials = $false

foreach ($requestedWeight in $RequestedWeights) {
    if ($stopFurtherTrials) {
        break
    }

    $trialKey = [Guid]::NewGuid()
    $trialName =
        'WLMCP_PhaseB_Step3b_Weight_' + $requestedWeight.ToString()

    $trial = [ordered]@{
        requested_weight = [UInt16]$requestedWeight
        key = $trialKey.ToString('B')

        absent_before_add = $false
        before_lookup = $null

        dynamic_session_opened = $false
        dynamic_session_key = $null

        add_attempted = $false
        add_succeeded = $false

        readback_attempted = $false
        observed_weight = $null
        observed = $null

        close_attempted = $false
        close_rc_hex = $null
        close_succeeded = $false

        cleanup_verified_absent = $false
        post_close_lookup = $null

        emergency_delete_attempted = $false
        emergency_delete_rc_hex = $null
        final_lookup = $null

        trial_error = $null
    }

    Write-StepLog (
        ("Trial requested weight {0}: checking unique GUID absence." -f
            $requestedWeight))

    try {
        $before =
            [WfpPhaseBStep3bV1]::ReadSubLayerFresh($trialKey)

        $trial.before_lookup = $before

        if (-not $before.found -and
            $before.error_hex -eq $NotFoundHex) {
            $trial.absent_before_add = $true
        } else {
            throw 'Unique trial GUID was not proven absent before add.'
        }
    } catch {
        $trial.trial_error =
            ("Pre-add lookup failed: {0}" -f $_.Exception.Message)

        Write-StepLog (
            ("TRIAL ERROR: {0}" -f $trial.trial_error))

        $trials.Add([pscustomobject]$trial)
        $stopFurtherTrials = $true
        break
    }

    $session = $null

    try {
        $session =
            [WfpPhaseBStep3bV1]::OpenDynamicSession()

        $trial.dynamic_session_opened = $session.is_open
        $trial.dynamic_session_key = $session.session_key

        $trial.add_attempted = $true

        Write-StepLog (
            ("Adding empty temporary sublayer with requested weight {0}." -f
                $requestedWeight))

        $session.AddSubLayer(
            $trialKey,
            $trialName,
            'Temporary Step 3b weight mapping trial. No filters.',
            [UInt16]$requestedWeight)

        $trial.add_succeeded = $true

        $trial.readback_attempted = $true

        $observed =
            $session.ReadSubLayer($trialKey)

        $trial.observed = $observed

        if (-not $observed.found) {
            throw 'Read-back did not find the just-added sublayer.'
        }

        if ($observed.key -ne $trialKey.ToString('B')) {
            throw 'Read-back GUID mismatch.'
        }

        if ($observed.name -ne $trialName) {
            throw 'Read-back display name mismatch.'
        }

        if ($observed.flags -ne 0) {
            throw 'Read-back flags mismatch.'
        }

        $trial.observed_weight = [UInt16]$observed.weight

        Write-StepLog (
            ("Weight mapping observed: requested {0} -> observed {1}" -f
                $requestedWeight,
                $trial.observed_weight))
    } catch {
        $trial.trial_error = $_.Exception.Message

        Write-StepLog (
            ("TRIAL ERROR: {0}" -f $trial.trial_error))
    } finally {
        if ($null -ne $session -and $session.is_open) {
            $trial.close_attempted = $true

            try {
                $closeRc = $session.Close()
                $trial.close_rc_hex =
                    ('0x{0:X8}' -f $closeRc)

                if ($closeRc -eq 0) {
                    $trial.close_succeeded = $true
                } else {
                    Write-StepLog (
                        ("WARNING: session close returned {0}" -f
                            $trial.close_rc_hex))
                }
            } catch {
                Write-StepLog (
                    ("WARNING: session close threw: {0}" -f
                        $_.Exception.Message))
            }
        }
    }

    if ($trial.add_succeeded) {
        for ($i = 0; $i -lt 5; $i++) {
            try {
                $after =
                    [WfpPhaseBStep3bV1]::ReadSubLayerFresh(
                        $trialKey)

                $trial.post_close_lookup = $after

                if (-not $after.found -and
                    $after.error_hex -eq $NotFoundHex) {
                    $trial.cleanup_verified_absent = $true
                    break
                }
            } catch {
                Write-StepLog (
                    ("Cleanup lookup failed: {0}" -f
                        $_.Exception.Message))
            }

            Start-Sleep -Milliseconds 200
        }
    }

    if ($trial.add_succeeded -and
        -not $trial.cleanup_verified_absent) {

        $trial.emergency_delete_attempted = $true

        Write-StepLog (
            'Automatic cleanup was not verified. Deleting ONLY the unique ' +
            'trial sublayer GUID.')

        try {
            $deleteRc =
                [WfpPhaseBStep3bV1]::DeleteSubLayerFresh(
                    $trialKey)

            $trial.emergency_delete_rc_hex =
                ('0x{0:X8}' -f $deleteRc)
        } catch {
            Write-StepLog (
                ("Emergency delete failed: {0}" -f
                    $_.Exception.Message))
        }

        try {
            $final =
                [WfpPhaseBStep3bV1]::ReadSubLayerFresh(
                    $trialKey)

            $trial.final_lookup = $final

            if (-not $final.found -and
                $final.error_hex -eq $NotFoundHex) {
                $trial.cleanup_verified_absent = $true
            }
        } catch {
            Write-StepLog (
                ("Final cleanup lookup failed: {0}" -f
                    $_.Exception.Message))
        }
    }

    if (-not $trial.close_succeeded -or
        -not $trial.cleanup_verified_absent) {
        if ([string]::IsNullOrWhiteSpace($trial.trial_error)) {
            $trial.trial_error =
                'Session close or cleanup could not be verified.'
        }

        $stopFurtherTrials = $true
    }

    $trials.Add([pscustomobject]$trial)
}

Write-StepLog 'Enumerating WFP sublayers after trials.'
$afterAll = [WfpPhaseBStep3bV1]::EnumerateSubLayers() |
    Sort-Object -Property @{ Expression = { $_.weight }; Descending = $true },
                          @{ Expression = { $_.name }; Descending = $false }

$remainingTrialObjects = @(
    $afterAll |
    Where-Object {
        $_.name -like 'WLMCP_PhaseB_Step3b_Weight_*'
    }
)

$allTrialsClean = (
    @($trials).Count -gt 0 -and
    @($trials | Where-Object {
        -not $_.cleanup_verified_absent
    }).Count -eq 0 -and
    @($remainingTrialObjects).Count -eq 0
)

$allTrialsMeasured = (
    @($trials).Count -eq $RequestedWeights.Count -and
    @($trials | Where-Object {
        $null -eq $_.observed_weight
    }).Count -eq 0
)

$mapping = @(
    $trials |
    ForEach-Object {
        [pscustomobject]@{
            requested = $_.requested_weight
            observed = $_.observed_weight
            delta = if ($null -ne $_.observed_weight) {
                [Int32]$_.observed_weight - [Int32]$_.requested_weight
            } else {
                $null
            }
        }
    }
)

$classification = 'INCONCLUSIVE'

if ($allTrialsMeasured -and $allTrialsClean) {
    $allExact = (
        @($mapping | Where-Object {
            $_.requested -ne $_.observed
        }).Count -eq 0
    )

    $allSameDelta = $false
    if (@($mapping).Count -gt 0) {
        $uniqueDeltas = @(
            $mapping |
            Select-Object -ExpandProperty delta |
            Select-Object -Unique
        )
        $allSameDelta = ($uniqueDeltas.Count -eq 1)
    }

    if ($allExact) {
        $classification = 'EXACT_MAPPING'
    } elseif ($allSameDelta) {
        $classification = 'CONSTANT_OFFSET'
    } else {
        $classification = 'NONTRIVIAL_MAPPING'
    }
}

$result = [ordered]@{
    schema_version = 1
    started_at = (Get-Date).ToString('o')
    host = [ordered]@{
        computer_name = $env:COMPUTERNAME
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        process_id = $PID
        is_administrator = $true
        is_64_bit_process = [Environment]::Is64BitProcess
    }
    interop_layout = [ordered]@{
        observed = $layout
        expected = $expectedLayout
        passed = ($layoutErrors.Count -eq 0)
        errors = @($layoutErrors)
    }
    baseline = [ordered]@{
        sublayer_count = @($baseline).Count
        sublayers = @($baseline)
        weight_0_to_20 = @($nearbyBaseline)
    }
    requested_weights = @($RequestedWeights)
    trials = @($trials)
    mapping = $mapping
    classification = $classification
    all_trials_measured = $allTrialsMeasured
    cleanup = [ordered]@{
        all_trial_objects_absent = $allTrialsClean
        remaining_named_trial_objects = @($remainingTrialObjects)
        post_trial_sublayer_count = @($afterAll).Count
    }
    policy_mutation = [ordered]@{
        wfp_filters_added = $false
        temporary_empty_sublayers_added = $true
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
    finished_at = (Get-Date).ToString('o')
}

$result |
    ConvertTo-Json -Depth 18 |
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
Write-Host 'WLMCP Phase B STEP 3b - FINISHED'
Write-Host '============================================================'
Write-Host ("RESULT_DIR  = {0}" -f $outputDir)
Write-Host ("RESULT_JSON = {0}" -f $resultPath)
Write-Host ("CLASSIFICATION = {0}" -f $classification)
Write-Host ("ALL_TRIALS_MEASURED = {0}" -f $allTrialsMeasured)
Write-Host ("CLEANUP_VERIFIED = {0}" -f $allTrialsClean)
Write-Host ''
Write-Host 'WEIGHT MAPPING:'

foreach ($m in $mapping) {
    Write-Host (
        ("  requested {0} -> observed {1} (delta {2})" -f
            $m.requested,
            $m.observed,
            $m.delta))
}

if (-not $allTrialsClean) {
    Write-Host ''
    Write-Host 'WARNING: cleanup was not fully verified.'
    Write-Host 'Do not proceed to Step 4.'
}
