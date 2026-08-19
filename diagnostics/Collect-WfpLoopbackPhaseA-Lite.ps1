#requires -Version 5.1
<#
.SYNOPSIS
  Lightweight read-only WFP Phase A collector for WLMCP/Codex localhost investigation.

.DESCRIPTION
  Uses the Windows Filtering Platform management API directly.
  It does NOT call "netsh wfp show state" and does NOT dump the entire WFP policy.

  Reads only:
    - all WFP sublayers (normally a small set) and their weights
    - selected runtime filter IDs (default: 70511, 70512, 74502, 75081)
    - the sublayer associated with each selected filter
    - CodexSandboxOffline local-user SID
    - basic Windows/BFE/MpsSvc metadata

  It does NOT add, delete, or modify WFP filters, Firewall rules, registry entries,
  services, or persistent WFP objects.

  Output goes under:
    <this script folder>\WFP-PhaseA-Results\<timestamp>\

  Example:
    C:\dev\windows-local-mcp-python\diagnostics\WFP-PhaseA-Results\20260815-010203\
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
    throw '64-bit PowerShell is required for this collector.'
}

if (-not (Test-IsAdministrator)) {
    throw @"
Run this script from an Administrator PowerShell window.

This collector is read-only with respect to WFP/Firewall/registry/services.
Administrator mode is requested only so the WFP management API can be read
consistently on this host.
"@
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputBase $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$summaryPath = Join-Path $outputDir 'summary.json'
$sublayersPath = Join-Path $outputDir 'sublayers.json'
$filtersPath = Join-Path $outputDir 'selected-filters.json'
$logPath = Join-Path $outputDir 'collector-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-CollectorLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

Write-CollectorLog 'Starting lightweight read-only WFP collection.'
Write-CollectorLog ("Results will be written to: {0}" -f $outputDir)

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpLiteReader
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;
    private const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;

    // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT.
    // Kept as the documented bit used by FWPM_FILTER0.flags.
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

    // x64 layout only. This script explicitly requires a 64-bit PowerShell process.
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
        public ulong runtime_filter_id { get; set; }
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
    private static extern uint FwpmFilterGetById0(
        IntPtr engineHandle,
        ulong id,
        out IntPtr filter);

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
        // FWP_ACTION_TYPE includes action flags in the high bits.
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
        // FWP_DATA_TYPE:
        // 0 EMPTY, 1 UINT8, 2 UINT16, 3 UINT32, 4 UINT64.
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
            throw new Win32Exception(unchecked((int)rc),
                "FwpmEngineOpen0 failed: 0x" + rc.ToString("X8"));
        }
        return engine;
    }

    public static SubLayerInfo[] GetSubLayers()
    {
        IntPtr engine = IntPtr.Zero;
        IntPtr enumHandle = IntPtr.Zero;
        IntPtr entries = IntPtr.Zero;

        try
        {
            engine = OpenEngine();

            uint rc = FwpmSubLayerCreateEnumHandle0(engine, IntPtr.Zero, out enumHandle);
            if (rc != ERROR_SUCCESS)
            {
                throw new Win32Exception(unchecked((int)rc),
                    "FwpmSubLayerCreateEnumHandle0 failed: 0x" + rc.ToString("X8"));
            }

            // Sublayers are a small policy object set. Request a generously bounded page.
            uint returned;
            rc = FwpmSubLayerEnum0(engine, enumHandle, 4096, out entries, out returned);
            if (rc != ERROR_SUCCESS)
            {
                throw new Win32Exception(unchecked((int)rc),
                    "FwpmSubLayerEnum0 failed: 0x" + rc.ToString("X8"));
            }

            var list = new List<SubLayerInfo>((int)returned);

            for (uint i = 0; i < returned; i++)
            {
                IntPtr itemPtr = Marshal.ReadIntPtr(entries, checked((int)(i * (uint)IntPtr.Size)));
                if (itemPtr == IntPtr.Zero) continue;

                FWPM_SUBLAYER0 item = Marshal.PtrToStructure<FWPM_SUBLAYER0>(itemPtr);
                list.Add(new SubLayerInfo
                {
                    key = item.subLayerKey.ToString("B"),
                    name = PtrToStringUni(item.displayData.name),
                    description = PtrToStringUni(item.displayData.description),
                    flags = item.flags,
                    provider_key = PtrToGuidString(item.providerKey),
                    weight = item.weight
                });
            }

            return list.ToArray();
        }
        finally
        {
            if (entries != IntPtr.Zero)
            {
                FwpmFreeMemory0(ref entries);
            }

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

    public static FilterInfo[] GetFilters(ulong[] ids)
    {
        IntPtr engine = IntPtr.Zero;
        var output = new List<FilterInfo>();

        try
        {
            engine = OpenEngine();

            foreach (ulong id in ids)
            {
                IntPtr filterPtr = IntPtr.Zero;
                uint rc = FwpmFilterGetById0(engine, id, out filterPtr);

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
                    FWPM_FILTER0 f = Marshal.PtrToStructure<FWPM_FILTER0>(filterPtr);

                    output.Add(new FilterInfo
                    {
                        requested_filter_id = id,
                        found = true,
                        error_hex = null,
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
                        condition_count = f.numFilterConditions,
                        runtime_filter_id = f.filterId
                    });
                }
                finally
                {
                    if (filterPtr != IntPtr.Zero)
                    {
                        FwpmFreeMemory0(ref filterPtr);
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

Write-CollectorLog 'Compiling small in-process WFP reader.'
Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop

Write-CollectorLog 'Reading WFP sublayers directly from the management API.'
$sublayers = [WfpLiteReader]::GetSubLayers() |
    Sort-Object -Property @{ Expression = { $_.weight }; Descending = $true }, @{ Expression = { $_.name }; Descending = $false }

Write-CollectorLog ("Read {0} sublayers." -f @($sublayers).Count)

Write-CollectorLog ("Reading selected runtime filter IDs only: {0}" -f ($FilterIds -join ', '))
$filters = [WfpLiteReader]::GetFilters([UInt64[]]$FilterIds)

$filters |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $filtersPath -Encoding UTF8

$sublayers |
    ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $sublayersPath -Encoding UTF8

# Map known selected filters to their sublayer rows.
$sublayerByKey = @{}
foreach ($s in @($sublayers)) {
    if ($null -ne $s.key) {
        $sublayerByKey[$s.key.ToLowerInvariant()] = $s
    }
}

$filterWithSubLayer = @()
foreach ($f in @($filters)) {
    $row = [ordered]@{
        requested_filter_id = $f.requested_filter_id
        found = $f.found
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
        sublayer = $null
    }

    if ($f.found -and -not [string]::IsNullOrWhiteSpace($f.sublayer_key)) {
        $k = $f.sublayer_key.ToLowerInvariant()
        if ($sublayerByKey.ContainsKey($k)) {
            $row.sublayer = $sublayerByKey[$k]
        }
    }

    $filterWithSubLayer += [pscustomobject]$row
}

# Use 70511 first, then 70512, as the AppContainerLoopback evidence source.
$appLoopbackFilter = $filterWithSubLayer |
    Where-Object { $_.found -and $_.requested_filter_id -in @(70511, 70512) } |
    Select-Object -First 1

$appIsolationWeight = $null
$appIsolationSublayer = $null
if ($null -ne $appLoopbackFilter -and $null -ne $appLoopbackFilter.sublayer) {
    $appIsolationSublayer = $appLoopbackFilter.sublayer
    $appIsolationWeight = [UInt16]$appIsolationSublayer.weight
}

$firewallFilter = $filterWithSubLayer |
    Where-Object { $_.found -and $_.requested_filter_id -eq 74502 } |
    Select-Object -First 1

$windowsFirewallSublayer = $null
if ($null -ne $firewallFilter -and $null -ne $firewallFilter.sublayer) {
    $windowsFirewallSublayer = $firewallFilter.sublayer
}

$canChooseStrictlyHigher = $null
$minimumHigherWeight = $null
if ($null -ne $appIsolationWeight) {
    $canChooseStrictlyHigher = ($appIsolationWeight -lt [UInt16]::MaxValue)
    if ($canChooseStrictlyHigher) {
        $minimumHigherWeight = [UInt32]$appIsolationWeight + 1
    }
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

$phaseBGate = if ($null -eq $appIsolationWeight) {
    'INCONCLUSIVE'
} elseif (-not $canChooseStrictlyHigher) {
    'STOP_NO_HIGHER_SUBLAYER_WEIGHT'
} else {
    'CANDIDATE_ONLY'
}

$gateExplanation = switch ($phaseBGate) {
    'INCONCLUSIVE' {
        'Filter 70511/70512 was not resolved to a sublayer weight in this run. Do not proceed to a blocking experiment from this result alone.'
    }
    'STOP_NO_HIGHER_SUBLAYER_WEIGHT' {
        'The AppContainerLoopback sublayer is already at UINT16_MAX (65535). A custom sublayer cannot be assigned a strictly higher numeric weight.'
    }
    default {
        'A strictly higher numeric sublayer weight exists. This is only a prerequisite for the proposed blocking experiment; it does not prove the custom block will win WFP arbitration.'
    }
}

$summary = [ordered]@{
    schema_version = 2
    collector = [ordered]@{
        name = 'Collect-WfpLoopbackPhaseA-Lite.ps1'
        collected_at = (Get-Date).ToString('o')
        is_administrator = $true
        is_64_bit_process = [Environment]::Is64BitProcess
        mutating_wfp_firewall_registry_service_operations_performed = $false
        full_wfp_state_dump_performed = $false
        method = 'Direct read-only WFP management API calls'
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
        appcontainer_loopback_filter_used = if ($null -ne $appLoopbackFilter) { $appLoopbackFilter.requested_filter_id } else { $null }
        app_isolation_sublayer = $appIsolationSublayer
        app_isolation_weight = $appIsolationWeight
        windows_firewall_sublayer_from_filter_74502 = $windowsFirewallSublayer
        can_choose_strictly_higher_numeric_weight = $canChooseStrictlyHigher
        minimum_strictly_higher_numeric_weight = $minimumHigherWeight
        uint16_max_sublayer_weight = [UInt16]::MaxValue
        automatic_authorization_to_run_blocking_experiment = $false
    }
    selected_filters = $filterWithSubLayer
    counts = [ordered]@{
        sublayers_read = @($sublayers).Count
        selected_filter_ids_requested = @($FilterIds).Count
        selected_filters_found = @($filterWithSubLayer | Where-Object { $_.found }).Count
    }
    limitations = @(
        'Runtime filter IDs such as 70511/70512 can change after reboot or policy refresh.',
        'This collector reads selected filters by runtime ID; it intentionally does not enumerate the full WFP filter set.',
        'Static FWPM policy data does not reveal the live FWPS_RIGHT_ACTION_WRITE state carried during an individual classify operation.',
        'CANDIDATE_ONLY means only that a numerically higher sublayer weight exists; it is not proof that a user-mode hard block will override the observed AppContainerLoopback permit.',
        'No traffic test is performed by this collector.'
    )
    output = [ordered]@{
        directory = $outputDir
        summary_json = $summaryPath
        sublayers_json = $sublayersPath
        selected_filters_json = $filtersPath
        collector_log = $logPath
        artifact_hashes = $hashPath
    }
}

$summary |
    ConvertTo-Json -Depth 14 |
    Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-CollectorLog 'WFP reads completed.'
Write-CollectorLog 'No WFP/Firewall/registry/service mutation was performed.'
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
Write-Host ' WLMCP WFP Phase A Lite - DONE'
Write-Host '============================================================'
Write-Host ''
Write-Host '結果フォルダ:'
Write-Host ("  {0}" -f $outputDir)
Write-Host ''
Write-Host 'まず私に見せるファイル:'
Write-Host ("  {0}" -f $summaryPath)
Write-Host ''
Write-Host '補助ファイル:'
Write-Host ("  {0}" -f $sublayersPath)
Write-Host ("  {0}" -f $filtersPath)
Write-Host ''
Write-Host ("PHASE_B_GATE = {0}" -f $phaseBGate)

if ($null -ne $appIsolationWeight) {
    Write-Host ("APP_ISOLATION_WEIGHT = {0}" -f $appIsolationWeight)
}

if ($null -ne $minimumHigherWeight) {
    Write-Host ("MINIMUM_HIGHER_WEIGHT = {0}" -f $minimumHigherWeight)
}

Write-Host ''
Write-Host 'この実行ではWFP/Firewallルールを追加・削除・変更していません。'
