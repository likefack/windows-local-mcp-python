#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP/Codex localhost investigation - lightweight read-only WFP collector v2.

.DESCRIPTION
  Reads only a few WFP objects through the documented WFP management API.

  This version deliberately contains ASCII source text only so Windows PowerShell
  5.1 can parse it even if a file transfer removes the UTF-8 BOM.

  It does NOT:
    - call "netsh wfp show state"
    - enumerate the full WFP filter set
    - add/delete/modify WFP filters or sublayers
    - add/delete/modify Windows Firewall rules
    - modify registry data
    - start/stop/reconfigure services

  It DOES:
    - open the WFP engine for reading
    - fetch selected runtime filter IDs
    - fetch only the sublayers referenced by those selected filters
    - read the CodexSandboxOffline local-user SID
    - read basic Windows/BFE/MpsSvc metadata
    - write report files under this script directory

  Default output:
    <script-dir>\WFP-PhaseA-Results\<timestamp>\summary.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [UInt64[]]$FilterIds = @(70511, 70512, 74502, 75081),

    [Parameter(Mandatory = $false)]
    [string]$OutputBase = (Join-Path $PSScriptRoot 'WFP-PhaseA-Results')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not [Environment]::Is64BitProcess) {
    throw 'ERROR: Run this collector from 64-bit Windows PowerShell.'
}

if (-not (Test-IsAdministrator)) {
    throw 'ERROR: Run this collector from an Administrator PowerShell window.'
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputBase $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$summaryPath = Join-Path $outputDir 'summary.json'
$objectsPath = Join-Path $outputDir 'selected-wfp-objects.json'
$logPath = Join-Path $outputDir 'collector-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-CollectorLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

Write-CollectorLog 'Starting WFP Phase A Lite v2.'
Write-CollectorLog ("Output directory: {0}" -f $outputDir)

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseAReader
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;

    // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT from fwpmtypes.h.
    private const uint FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 0x00000008;

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

    // x64 representation of FWP_VALUE0:
    // UINT32 type at offset 0, union begins at offset 8.
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

    public sealed class SubLayerInfo
    {
        public bool found { get; set; }
        public string error_hex { get; set; }
        public string key { get; set; }
        public string name { get; set; }
        public string description { get; set; }
        public uint flags { get; set; }
        public string provider_key { get; set; }
        public ushort weight { get; set; }
    }

    public sealed class FilterInfo
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
        public bool clear_action_right_flag_present { get; set; }
        public uint action_type { get; set; }
        public string action_type_hex { get; set; }
        public string action_name { get; set; }
        public string weight { get; set; }
        public string effective_weight { get; set; }
        public uint condition_count { get; set; }
        public SubLayerInfo sublayer { get; set; }
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

    private static string PtrToGuidString(IntPtr p)
    {
        if (p == IntPtr.Zero) return null;
        return Marshal.PtrToStructure<Guid>(p).ToString("B");
    }

    private static string ActionName(uint actionType)
    {
        // The documented FWP_ACTION_* values combine a base value with action flags.
        // The low byte identifies BLOCK/PERMIT/CALLOUT/etc.
        uint baseType = actionType & 0x000000FF;
        switch (baseType)
        {
            case 1: return "FWP_ACTION_BLOCK";
            case 2: return "FWP_ACTION_PERMIT";
            case 3: return "FWP_ACTION_CALLOUT_TERMINATING";
            case 4: return "FWP_ACTION_CALLOUT_INSPECTION";
            case 5: return "FWP_ACTION_CALLOUT_UNKNOWN";
            case 6: return "FWP_ACTION_CONTINUE";
            case 7: return "FWP_ACTION_NONE";
            case 8: return "FWP_ACTION_NONE_NO_MATCH";
            default: return "UNKNOWN";
        }
    }

    private static string ValueToString(FWP_VALUE0 value)
    {
        // FWP_DATA_TYPE: 0 EMPTY, 1 UINT8, 2 UINT16, 3 UINT32, 4 UINT64.
        switch (value.type)
        {
            case 0:
                return "FWP_EMPTY";
            case 1:
                return ((byte)(value.inlineValue & 0xFF)).ToString();
            case 2:
                return ((ushort)(value.inlineValue & 0xFFFF)).ToString();
            case 3:
                return ((uint)(value.inlineValue & 0xFFFFFFFF)).ToString();
            case 4:
                if (value.pointerValue == IntPtr.Zero) return null;
                return unchecked((ulong)Marshal.ReadInt64(value.pointerValue)).ToString();
            default:
                return "FWP_DATA_TYPE_" + value.type.ToString();
        }
    }

    private static IntPtr OpenEngine()
    {
        IntPtr engine;
        uint rc = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out engine);
        if (rc != ERROR_SUCCESS)
        {
            throw new Win32Exception(
                unchecked((int)rc),
                "FwpmEngineOpen0 failed: 0x" + rc.ToString("X8"));
        }
        return engine;
    }

    private static SubLayerInfo GetSubLayer(IntPtr engine, Guid key)
    {
        IntPtr p = IntPtr.Zero;
        uint rc = FwpmSubLayerGetByKey0(engine, ref key, out p);

        if (rc != ERROR_SUCCESS)
        {
            return new SubLayerInfo
            {
                found = false,
                error_hex = "0x" + rc.ToString("X8"),
                key = key.ToString("B")
            };
        }

        try
        {
            FWPM_SUBLAYER0 s = Marshal.PtrToStructure<FWPM_SUBLAYER0>(p);
            return new SubLayerInfo
            {
                found = true,
                error_hex = null,
                key = s.subLayerKey.ToString("B"),
                name = PtrToStringUni(s.displayData.name),
                description = PtrToStringUni(s.displayData.description),
                flags = s.flags,
                provider_key = PtrToGuidString(s.providerKey),
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

    public static FilterInfo[] ReadSelected(ulong[] ids)
    {
        IntPtr engine = IntPtr.Zero;
        var output = new List<FilterInfo>();

        try
        {
            engine = OpenEngine();

            foreach (ulong id in ids)
            {
                IntPtr p = IntPtr.Zero;
                uint rc = FwpmFilterGetById0(engine, id, out p);

                if (rc != ERROR_SUCCESS)
                {
                    output.Add(new FilterInfo
                    {
                        requested_filter_id = id,
                        found = false,
                        error_hex = "0x" + rc.ToString("X8")
                    });
                    continue;
                }

                try
                {
                    FWPM_FILTER0 f = Marshal.PtrToStructure<FWPM_FILTER0>(p);

                    var info = new FilterInfo
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
                        clear_action_right_flag_present =
                            (f.flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) != 0,
                        action_type = f.action.type,
                        action_type_hex = "0x" + f.action.type.ToString("X8"),
                        action_name = ActionName(f.action.type),
                        weight = ValueToString(f.weight),
                        effective_weight = ValueToString(f.effectiveWeight),
                        condition_count = f.numFilterConditions
                    };

                    info.sublayer = GetSubLayer(engine, f.subLayerKey);
                    output.Add(info);
                }
                finally
                {
                    if (p != IntPtr.Zero)
                    {
                        FwpmFreeMemory0(ref p);
                    }
                }
            }

            return output.ToArray();
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

Write-CollectorLog 'Compiling the in-process WFP reader.'
Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop

Write-CollectorLog ("Reading only runtime filter IDs: {0}" -f ($FilterIds -join ', '))
$filters = [WfpPhaseAReader]::ReadSelected([UInt64[]]$FilterIds)

# Validate runtime IDs before using them as evidence.
$validated = @()

foreach ($f in @($filters)) {
    $role = 'unknown'
    $identityValid = $false
    $validationReason = $null

    if (-not $f.found) {
        $validationReason = 'runtime filter ID was not found'
    }
    elseif ($f.requested_filter_id -in @(70511, 70512)) {
        $role = 'appcontainer_loopback_permit'
        if ($f.runtime_filter_id -eq $f.requested_filter_id -and
            $f.name -eq 'AppContainerLoopback' -and
            $f.action_name -eq 'FWP_ACTION_PERMIT') {
            $identityValid = $true
            $validationReason = 'runtime ID, name, and action match expected AppContainerLoopback permit'
        } else {
            $validationReason = 'runtime ID exists but no longer matches expected AppContainerLoopback permit'
        }
    }
    elseif ($f.requested_filter_id -eq 74502) {
        $role = 'codex_firewall_block_candidate'
        if ($f.runtime_filter_id -eq $f.requested_filter_id -and
            $f.action_name -eq 'FWP_ACTION_BLOCK' -and
            -not [string]::IsNullOrWhiteSpace($f.name) -and
            $f.name -match 'codex.*loopback.*tcp|loopback.*tcp.*codex') {
            $identityValid = $true
            $validationReason = 'action and display name match expected Codex loopback TCP block'
        } else {
            $validationReason = 'runtime ID exists but no longer matches expected Codex loopback TCP block'
        }
    }
    elseif ($f.requested_filter_id -eq 75081) {
        $role = 'wlmcp_control_block_candidate'
        if ($f.runtime_filter_id -eq $f.requested_filter_id -and
            $f.action_name -eq 'FWP_ACTION_BLOCK' -and
            $f.name -eq 'WLMCP_DIAG_Block_All_TCP4_Loopback') {
            $identityValid = $true
            $validationReason = 'action and display name match expected WLMCP diagnostic block'
        } else {
            $validationReason = 'runtime ID exists but no longer matches expected WLMCP diagnostic block'
        }
    }

    $validated += [pscustomobject][ordered]@{
        requested_filter_id = $f.requested_filter_id
        role = $role
        found = $f.found
        identity_valid = $identityValid
        validation_reason = $validationReason
        error_hex = $f.error_hex
        runtime_filter_id = $f.runtime_filter_id
        filter_key = $f.filter_key
        name = $f.name
        description = $f.description
        layer_key = $f.layer_key
        sublayer_key = $f.sublayer_key
        flags = $f.flags
        flags_hex = $f.flags_hex
        clear_action_right_flag_present = $f.clear_action_right_flag_present
        action_type = $f.action_type
        action_type_hex = $f.action_type_hex
        action_name = $f.action_name
        weight = $f.weight
        effective_weight = $f.effective_weight
        condition_count = $f.condition_count
        sublayer = $f.sublayer
    }
}

$validated |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $objectsPath -Encoding UTF8

$appFilters = @(
    $validated |
    Where-Object {
        $_.identity_valid -and
        $_.role -eq 'appcontainer_loopback_permit' -and
        $null -ne $_.sublayer -and
        $_.sublayer.found
    }
)

$appSublayerKeys = @(
    $appFilters |
    ForEach-Object { $_.sublayer.key.ToLowerInvariant() } |
    Select-Object -Unique
)

$appSublayerWeights = @(
    $appFilters |
    ForEach-Object { [UInt16]$_.sublayer.weight } |
    Select-Object -Unique
)

$appIsolationSublayer = $null
$appIsolationWeight = $null

if ($appSublayerKeys.Count -eq 1 -and $appSublayerWeights.Count -eq 1) {
    $appIsolationSublayer = $appFilters[0].sublayer
    $appIsolationWeight = [UInt16]$appSublayerWeights[0]
}

$wfCandidates = @(
    $validated |
    Where-Object {
        $_.identity_valid -and
        $_.role -in @('codex_firewall_block_candidate', 'wlmcp_control_block_candidate') -and
        $null -ne $_.sublayer -and
        $_.sublayer.found
    }
)

$windowsFirewallSublayer = $null
if ($wfCandidates.Count -gt 0) {
    $windowsFirewallSublayer = $wfCandidates[0].sublayer
}

$canChooseStrictlyHigher = $null
$minimumHigherWeight = $null

if ($null -ne $appIsolationWeight) {
    $canChooseStrictlyHigher = ($appIsolationWeight -lt [UInt16]::MaxValue)
    if ($canChooseStrictlyHigher) {
        $minimumHigherWeight = [UInt32]$appIsolationWeight + 1
    }
}

if ($appFilters.Count -eq 0) {
    $phaseBGate = 'INCONCLUSIVE_APP_FILTER_ID_STALE_OR_MISSING'
    $gateExplanation = 'No validated AppContainerLoopback permit was found at runtime IDs 70511/70512.'
}
elseif ($appSublayerKeys.Count -ne 1 -or $appSublayerWeights.Count -ne 1) {
    $phaseBGate = 'INCONCLUSIVE_APP_FILTERS_DISAGREE'
    $gateExplanation = 'Validated AppContainerLoopback filters did not resolve to exactly one sublayer key and weight.'
}
elseif (-not $canChooseStrictlyHigher) {
    $phaseBGate = 'STOP_NO_HIGHER_SUBLAYER_WEIGHT'
    $gateExplanation = 'AppContainerLoopback sublayer weight is 65535, so no strictly higher UINT16 sublayer weight exists.'
}
else {
    $phaseBGate = 'CANDIDATE_ONLY'
    $gateExplanation = 'A strictly higher numeric sublayer weight exists. This does not prove a user-mode block will win WFP arbitration.'
}

$codexUser = $null
try {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $u = Get-LocalUser -Name 'CodexSandboxOffline' -ErrorAction Stop
        $codexUser = [ordered]@{
            name = $u.Name
            sid = $u.SID.Value
            enabled = $u.Enabled
        }
    }
} catch {
    $codexUser = [ordered]@{
        name = 'CodexSandboxOffline'
        sid = $null
        enabled = $null
        error = $_.Exception.Message
    }
}

$cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
$mpssvc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue

$scriptHash = $null
try {
    if (-not [string]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path) -and
        (Test-Path -LiteralPath $MyInvocation.MyCommand.Path)) {
        $scriptHash = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash
    }
} catch {}

$summary = [ordered]@{
    schema_version = 3
    collector = [ordered]@{
        name = 'Collect-WfpLoopbackPhaseA-Lite-v2.ps1'
        collected_at = (Get-Date).ToString('o')
        script_sha256 = $scriptHash
        is_administrator = $true
        is_64_bit_process = [Environment]::Is64BitProcess
        source_is_ascii_only = $true
        mutating_wfp_firewall_registry_service_operations_performed = $false
        full_wfp_state_dump_performed = $false
        full_wfp_filter_enumeration_performed = $false
        method = 'FwpmFilterGetById0 + FwpmSubLayerGetByKey0'
    }
    host = [ordered]@{
        computer_name = $env:COMPUTERNAME
        user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        windows_product_name = $cv.ProductName
        windows_display_version = $cv.DisplayVersion
        windows_current_build = $cv.CurrentBuild
        windows_ubr = $cv.UBR
        os_version = [Environment]::OSVersion.VersionString
        bfe_status = if ($null -ne $bfe) { $bfe.Status.ToString() } else { $null }
        mpssvc_status = if ($null -ne $mpssvc) { $mpssvc.Status.ToString() } else { $null }
        codex_sandbox_offline = $codexUser
    }
    phase_b_gate = [ordered]@{
        result = $phaseBGate
        explanation = $gateExplanation
        validated_appcontainer_loopback_filter_count = $appFilters.Count
        app_isolation_sublayer = $appIsolationSublayer
        app_isolation_weight = $appIsolationWeight
        windows_firewall_sublayer = $windowsFirewallSublayer
        can_choose_strictly_higher_numeric_weight = $canChooseStrictlyHigher
        minimum_strictly_higher_numeric_weight = $minimumHigherWeight
        uint16_max_sublayer_weight = [UInt16]::MaxValue
        automatic_authorization_to_run_blocking_experiment = $false
    }
    selected_wfp_objects = $validated
    limitations = @(
        'Runtime filter IDs can change after reboot or BFE policy refresh.',
        'This collector refuses to trust runtime IDs 70511/70512 unless their current name and action still match AppContainerLoopback PERMIT.',
        'This collector intentionally does not enumerate the full WFP filter set.',
        'Static FWPM policy data does not expose the live FWPS_RIGHT_ACTION_WRITE state carried during an individual classify operation.',
        'CANDIDATE_ONLY is not proof that a future user-mode hard block will override AppContainerLoopback.',
        'No live traffic test is performed.'
    )
    output = [ordered]@{
        directory = $outputDir
        summary_json = $summaryPath
        selected_wfp_objects_json = $objectsPath
        collector_log = $logPath
        artifact_hashes = $hashPath
    }
}

$summary |
    ConvertTo-Json -Depth 14 |
    Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-CollectorLog 'Read-only WFP collection completed.'
Write-CollectorLog 'No WFP/Firewall/registry/service mutation API was called.'
$logLines | Set-Content -LiteralPath $logPath -Encoding UTF8

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
Write-Host 'WLMCP WFP Phase A Lite v2 - DONE'
Write-Host '============================================================'
Write-Host ("RESULT_DIR   = {0}" -f $outputDir)
Write-Host ("SUMMARY_JSON = {0}" -f $summaryPath)
Write-Host ("OBJECTS_JSON = {0}" -f $objectsPath)
Write-Host ("PHASE_B_GATE = {0}" -f $phaseBGate)

if ($null -ne $appIsolationWeight) {
    Write-Host ("APP_ISOLATION_WEIGHT = {0}" -f $appIsolationWeight)
}

if ($null -ne $minimumHigherWeight) {
    Write-Host ("MINIMUM_HIGHER_WEIGHT = {0}" -f $minimumHigherWeight)
}

Write-Host 'READ_ONLY_WFP_POLICY = true'
