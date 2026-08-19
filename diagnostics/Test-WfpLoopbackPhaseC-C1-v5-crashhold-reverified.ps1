#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP Phase C - C1 static WFP lifetime experiment.

.DESCRIPTION
  This script has three modes:

    Install
      Creates one STATIC (non-dynamic, non-persistent) WFP sublayer and
      exactly two BLOCK filters for CodexSandboxOffline loopback.
      The WFP engine session is then closed. The script verifies from a fresh
      WFP session that the objects still exist after the creating session ends.

    CrashHold
      Creates the same STATIC WFP objects, writes state.json, and intentionally
      keeps the creator process and WFP session alive. Kill this process from a
      second Administrator PowerShell with Stop-Process -Force. A forced process
      kill bypasses the script cleanup path; Verify can then test whether the
      static objects survived abrupt creator termination.

    Verify
      Reads the exact objects recorded in a C1 state.json file from a new WFP
      session and verifies that they still match the expected identity.

    Cleanup
      Deletes ONLY the exact filter GUIDs and sublayer GUID recorded in the
      supplied C1 state.json file, then verifies that all three are absent.

  IMPORTANT:
    - Install intentionally leaves the static WFP objects active after exit.
    - Cleanup must be run after the traffic experiment.
    - Static WFP objects are not persistent across BFE stop/system shutdown.
    - No Windows Firewall rule, registry value, service, provider, callout,
      driver, or FWPM_*_FLAG_PERSISTENT object is created.

  C1A first validates normal creator-session exit. A separate forced-crash
  variant will be used only after C1A passes.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-WfpLoopbackPhaseC-C1.ps1 -Mode Install

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-WfpLoopbackPhaseC-C1.ps1 -Mode Verify -StatePath C:\...\state.json

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-WfpLoopbackPhaseC-C1.ps1 -Mode Cleanup -StatePath C:\...\state.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'CrashHold', 'Verify', 'Cleanup')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$StatePath,

    [Parameter(Mandatory = $false)]
    [UInt64]$AppLoopbackV4FilterId = 70511,

    [Parameter(Mandatory = $false)]
    [UInt64]$AppLoopbackV6FilterId = 70512,

    [Parameter(Mandatory = $false)]
    [UInt16]$RequestedSubLayerWeight = 10,

    [Parameter(Mandatory = $false)]
    [string]$OutputBase = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptFilePath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($ScriptFilePath)) {
    throw 'Could not resolve the current script file path.'
}
$ScriptDirectory = Split-Path -Parent $ScriptFilePath
if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) {
    throw 'Could not resolve the current script directory.'
}
if ([string]::IsNullOrWhiteSpace($OutputBase)) {
    $OutputBase = Join-Path -Path $ScriptDirectory -ChildPath 'WFP-PhaseC-C1-Results'
}

$ExpectedV4LayerKey = '{c38d57d1-05a7-4c33-904f-7fbceee60e82}'
$ExpectedV6LayerKey = '{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}'
$ExpectedAppIsolationSubLayerKey = '{ffe221c3-92a8-4564-a59f-dafb70756020}'
$ExpectedFlagsConditionKey = '{632ce23b-5167-435c-86d7-e903684aa80c}'
$FilterNotFoundHex = '0x80320003'
$SubLayerNotFoundHex = '0x80320007'
$StateSchema = 1
$StateKind = 'wlmcp-phase-c-c1-static-wfp'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Save-Json {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string]$Path
    )
    $Object | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Require-State {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ("State file not found: {0}" -f $Path)
    }

    $state = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    if ($state.schema_version -ne $StateSchema -or $state.kind -ne $StateKind) {
        throw 'Refusing unknown or incompatible C1 state file.'
    }

    foreach ($name in @(
        'sublayer_key',
        'v4_filter_key',
        'v6_filter_key',
        'v4_filter_id',
        'v6_filter_id',
        'target_sid',
        'observed_sublayer_weight'
    )) {
        if ($null -eq $state.$name -or [string]::IsNullOrWhiteSpace([string]$state.$name)) {
            throw ("C1 state is missing required field: {0}" -f $name)
        }
    }

    return $state
}

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}
if (-not (Test-IsAdministrator)) {
    throw 'Run this script from an Administrator PowerShell.'
}

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseCStepC1V1
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;

    private const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    private const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;

    private const uint FWP_EMPTY = 0;
    private const uint FWP_UINT32 = 3;
    private const uint FWP_SECURITY_DESCRIPTOR_TYPE = 14;

    private const uint FWP_MATCH_EQUAL = 0;
    private const uint FWP_MATCH_FLAGS_ALL_SET = 6;

    private const uint FWP_ACTION_BLOCK = 0x00001001;
    private const uint FWP_ACTION_PERMIT = 0x00001002;

    private const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

    private const uint SDDL_REVISION_1 = 1;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;

    private static readonly Guid LayerAleAuthConnectV4 =
        new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    private static readonly Guid LayerAleAuthConnectV6 =
        new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    private static readonly Guid ConditionFlags =
        new Guid("632ce23b-5167-435c-86d7-e903684aa80c");

    private static readonly Guid ConditionAleUserId =
        new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");

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
        public byte uint8;

        [FieldOffset(8)]
        public ushort uint16;

        [FieldOffset(8)]
        public uint uint32;

        [FieldOffset(8)]
        public IntPtr pointerValue;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FWP_CONDITION_VALUE0
    {
        [FieldOffset(0)]
        public uint type;

        [FieldOffset(8)]
        public byte uint8;

        [FieldOffset(8)]
        public ushort uint16;

        [FieldOffset(8)]
        public uint uint32;

        [FieldOffset(8)]
        public IntPtr pointerValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
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

    public sealed class LayoutInfo
    {
        public int display_data_size { get; set; }
        public int byte_blob_size { get; set; }
        public int sublayer_size { get; set; }
        public int value_size { get; set; }
        public int condition_value_size { get; set; }
        public int filter_condition_size { get; set; }
        public int action_size { get; set; }
        public int filter_size { get; set; }

        public long sublayer_weight_offset { get; set; }

        public long condition_field_key_offset { get; set; }
        public long condition_match_type_offset { get; set; }
        public long condition_value_offset { get; set; }

        public long filter_flags_offset { get; set; }
        public long filter_layer_offset { get; set; }
        public long filter_sublayer_offset { get; set; }
        public long filter_weight_offset { get; set; }
        public long filter_condition_count_offset { get; set; }
        public long filter_condition_ptr_offset { get; set; }
        public long filter_action_offset { get; set; }
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

    public sealed class FilterConditionSnapshot
    {
        public string field_key { get; set; }
        public string field_name { get; set; }
        public uint match_type { get; set; }
        public uint value_type { get; set; }
        public uint uint32_value { get; set; }
        public string normalized_dacl_sddl { get; set; }
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

        public uint flags { get; set; }
        public string flags_hex { get; set; }

        public string layer_key { get; set; }
        public string sublayer_key { get; set; }

        public bool sublayer_found { get; set; }
        public string sublayer_error_hex { get; set; }
        public string sublayer_name { get; set; }
        public ushort sublayer_weight { get; set; }

        public uint action_type { get; set; }
        public string action_type_hex { get; set; }
        public string action_name { get; set; }

        public uint condition_count { get; set; }
        public FilterConditionSnapshot[] conditions { get; set; }
    }

    public sealed class AddFiltersResult
    {
        public string expected_normalized_dacl_sddl { get; set; }
        public string v4_filter_key { get; set; }
        public string v6_filter_key { get; set; }
        public ulong v4_filter_id { get; set; }
        public ulong v6_filter_id { get; set; }
    }

    public sealed class StaticSession
    {
        private IntPtr _engineHandle;

        public string session_key { get; private set; }
        public string flags_hex { get; private set; }

        internal StaticSession(IntPtr engineHandle, Guid sessionKey)
        {
            _engineHandle = engineHandle;
            session_key = sessionKey.ToString("B");
            flags_hex = "0x00000000";
        }

        public bool is_open
        {
            get { return _engineHandle != IntPtr.Zero; }
        }

        public void AddSubLayerTransaction(
            Guid key,
            string name,
            string description,
            ushort requestedWeight)
        {
            EnsureOpen();

            bool txn = false;
            IntPtr namePtr = IntPtr.Zero;
            IntPtr descriptionPtr = IntPtr.Zero;

            try
            {
                uint rc = FwpmTransactionBegin0(_engineHandle, 0);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmTransactionBegin0(sublayer)", rc);
                }

                txn = true;

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
                s.weight = requestedWeight;

                rc = FwpmSubLayerAdd0(
                    _engineHandle,
                    ref s,
                    IntPtr.Zero);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmSubLayerAdd0", rc);
                }

                rc = FwpmTransactionCommit0(_engineHandle);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmTransactionCommit0(sublayer)", rc);
                }

                txn = false;
            }
            finally
            {
                if (txn)
                {
                    FwpmTransactionAbort0(_engineHandle);
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

        public SubLayerSnapshot ReadSubLayer(Guid key)
        {
            EnsureOpen();
            return ReadSubLayerOnEngine(_engineHandle, key);
        }

        public AddFiltersResult AddBlockFiltersTransaction(
            Guid subLayerKey,
            Guid v4FilterKey,
            Guid v6FilterKey,
            string targetSid)
        {
            EnsureOpen();

            bool txn = false;

            IntPtr sd = IntPtr.Zero;
            IntPtr sdBlobPtr = IntPtr.Zero;
            IntPtr conditionsPtr = IntPtr.Zero;

            IntPtr v4NamePtr = IntPtr.Zero;
            IntPtr v4DescriptionPtr = IntPtr.Zero;
            IntPtr v6NamePtr = IntPtr.Zero;
            IntPtr v6DescriptionPtr = IntPtr.Zero;

            try
            {
                string sddl =
                    "D:(A;;0x1;;;" + targetSid + ")";

                uint sdSizeIgnored = 0;

                bool converted =
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl,
                        SDDL_REVISION_1,
                        out sd,
                        out sdSizeIgnored);

                if (!converted)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "ConvertStringSecurityDescriptorToSecurityDescriptorW failed.");
                }

                uint sdLength = GetSecurityDescriptorLength(sd);

                if (sdLength == 0)
                {
                    throw new InvalidOperationException(
                        "GetSecurityDescriptorLength returned zero.");
                }

                string normalizedExpected =
                    SecurityDescriptorToDaclSddl(sd);

                FWP_BYTE_BLOB sdBlob = new FWP_BYTE_BLOB();
                sdBlob.size = sdLength;
                sdBlob.data = sd;

                sdBlobPtr =
                    Marshal.AllocHGlobal(
                        Marshal.SizeOf(typeof(FWP_BYTE_BLOB)));

                Marshal.StructureToPtr(sdBlob, sdBlobPtr, false);

                int conditionSize =
                    Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));

                conditionsPtr =
                    Marshal.AllocHGlobal(conditionSize * 2);

                FWPM_FILTER_CONDITION0 userCondition =
                    new FWPM_FILTER_CONDITION0();

                userCondition.fieldKey = ConditionAleUserId;
                userCondition.matchType = FWP_MATCH_EQUAL;
                userCondition.conditionValue.type =
                    FWP_SECURITY_DESCRIPTOR_TYPE;
                userCondition.conditionValue.pointerValue = sdBlobPtr;

                Marshal.StructureToPtr(
                    userCondition,
                    conditionsPtr,
                    false);

                FWPM_FILTER_CONDITION0 loopbackCondition =
                    new FWPM_FILTER_CONDITION0();

                loopbackCondition.fieldKey = ConditionFlags;
                loopbackCondition.matchType = FWP_MATCH_FLAGS_ALL_SET;
                loopbackCondition.conditionValue.type = FWP_UINT32;
                loopbackCondition.conditionValue.uint32 =
                    FWP_CONDITION_FLAG_IS_LOOPBACK;

                Marshal.StructureToPtr(
                    loopbackCondition,
                    IntPtr.Add(conditionsPtr, conditionSize),
                    false);

                v4NamePtr =
                    Marshal.StringToHGlobalUni(
                        "WLMCP_PhaseB_Temporary_Codex_Loopback_Block_V4");

                v4DescriptionPtr =
                    Marshal.StringToHGlobalUni(
                        "Temporary Step 4 block: CodexSandboxOffline loopback V4.");

                v6NamePtr =
                    Marshal.StringToHGlobalUni(
                        "WLMCP_PhaseB_Temporary_Codex_Loopback_Block_V6");

                v6DescriptionPtr =
                    Marshal.StringToHGlobalUni(
                        "Temporary Step 4 block: CodexSandboxOffline loopback V6.");

                FWPM_FILTER0 v4 = BuildBlockFilter(
                    v4FilterKey,
                    v4NamePtr,
                    v4DescriptionPtr,
                    LayerAleAuthConnectV4,
                    subLayerKey,
                    conditionsPtr);

                FWPM_FILTER0 v6 = BuildBlockFilter(
                    v6FilterKey,
                    v6NamePtr,
                    v6DescriptionPtr,
                    LayerAleAuthConnectV6,
                    subLayerKey,
                    conditionsPtr);

                uint rc = FwpmTransactionBegin0(_engineHandle, 0);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmTransactionBegin0(filters)", rc);
                }

                txn = true;

                ulong v4Id = 0;
                ulong v6Id = 0;

                rc = FwpmFilterAdd0(
                    _engineHandle,
                    ref v4,
                    IntPtr.Zero,
                    out v4Id);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmFilterAdd0(V4)", rc);
                }

                rc = FwpmFilterAdd0(
                    _engineHandle,
                    ref v6,
                    IntPtr.Zero,
                    out v6Id);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmFilterAdd0(V6)", rc);
                }

                rc = FwpmTransactionCommit0(_engineHandle);

                if (rc != ERROR_SUCCESS)
                {
                    ThrowWfp("FwpmTransactionCommit0(filters)", rc);
                }

                txn = false;

                return new AddFiltersResult
                {
                    expected_normalized_dacl_sddl = normalizedExpected,
                    v4_filter_key = v4FilterKey.ToString("B"),
                    v6_filter_key = v6FilterKey.ToString("B"),
                    v4_filter_id = v4Id,
                    v6_filter_id = v6Id
                };
            }
            finally
            {
                if (txn)
                {
                    FwpmTransactionAbort0(_engineHandle);
                }

                if (v6DescriptionPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(v6DescriptionPtr);
                }

                if (v6NamePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(v6NamePtr);
                }

                if (v4DescriptionPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(v4DescriptionPtr);
                }

                if (v4NamePtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(v4NamePtr);
                }

                if (conditionsPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(conditionsPtr);
                }

                if (sdBlobPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(sdBlobPtr);
                }

                if (sd != IntPtr.Zero)
                {
                    LocalFree(sd);
                }
            }
        }

        public FilterSnapshot ReadFilter(ulong id)
        {
            EnsureOpen();
            return ReadFilterOnEngine(_engineHandle, id);
        }

        public uint DeleteFilterByKey(Guid key)
        {
            if (_engineHandle == IntPtr.Zero)
            {
                return 0xFFFFFFFF;
            }

            Guid localKey = key;
            return FwpmFilterDeleteByKey0(
                _engineHandle,
                ref localKey);
        }

        public uint DeleteSubLayerByKey(Guid key)
        {
            if (_engineHandle == IntPtr.Zero)
            {
                return 0xFFFFFFFF;
            }

            Guid localKey = key;
            return FwpmSubLayerDeleteByKey0(
                _engineHandle,
                ref localKey);
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

        private void EnsureOpen()
        {
            if (_engineHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "Dynamic WFP session is closed.");
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
    private static extern uint FwpmEngineClose0(
        IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionBegin0(
        IntPtr engineHandle,
        uint flags);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionCommit0(
        IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmTransactionAbort0(
        IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(
        IntPtr engineHandle,
        ref FWPM_SUBLAYER0 subLayer,
        IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerGetByKey0(
        IntPtr engineHandle,
        ref Guid key,
        out IntPtr subLayer);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDeleteByKey0(
        IntPtr engineHandle,
        ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(
        IntPtr engineHandle,
        ref FWPM_FILTER0 filter,
        IntPtr sd,
        out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterGetById0(
        IntPtr engineHandle,
        ulong id,
        out IntPtr filter);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteByKey0(
        IntPtr engineHandle,
        ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(
        ref IntPtr p);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string stringSecurityDescriptor,
            uint stringSDRevision,
            out IntPtr securityDescriptor,
            out uint securityDescriptorSize);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(
        IntPtr pSecurityDescriptor);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr securityDescriptor,
            uint requestedStringSDRevision,
            uint securityInformation,
            out IntPtr stringSecurityDescriptor,
            out uint stringSecurityDescriptorLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(
        IntPtr hMem);

    public static LayoutInfo GetLayoutInfo()
    {
        return new LayoutInfo
        {
            display_data_size =
                Marshal.SizeOf(typeof(FWPM_DISPLAY_DATA0)),
            byte_blob_size =
                Marshal.SizeOf(typeof(FWP_BYTE_BLOB)),
            sublayer_size =
                Marshal.SizeOf(typeof(FWPM_SUBLAYER0)),
            value_size =
                Marshal.SizeOf(typeof(FWP_VALUE0)),
            condition_value_size =
                Marshal.SizeOf(typeof(FWP_CONDITION_VALUE0)),
            filter_condition_size =
                Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0)),
            action_size =
                Marshal.SizeOf(typeof(FWPM_ACTION0)),
            filter_size =
                Marshal.SizeOf(typeof(FWPM_FILTER0)),

            sublayer_weight_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_SUBLAYER0),
                    "weight").ToInt64(),

            condition_field_key_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER_CONDITION0),
                    "fieldKey").ToInt64(),
            condition_match_type_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER_CONDITION0),
                    "matchType").ToInt64(),
            condition_value_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER_CONDITION0),
                    "conditionValue").ToInt64(),

            filter_flags_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "flags").ToInt64(),
            filter_layer_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "layerKey").ToInt64(),
            filter_sublayer_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "subLayerKey").ToInt64(),
            filter_weight_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "weight").ToInt64(),
            filter_condition_count_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "numFilterConditions").ToInt64(),
            filter_condition_ptr_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "filterCondition").ToInt64(),
            filter_action_offset =
                Marshal.OffsetOf(
                    typeof(FWPM_FILTER0),
                    "action").ToInt64()
        };
    }

    public static StaticSession OpenStaticSession()
    {
        Guid sessionKey = Guid.NewGuid();
        IntPtr engine = IntPtr.Zero;

        uint rc = FwpmEngineOpen0(
            null,
            RPC_C_AUTHN_WINNT,
            IntPtr.Zero,
            IntPtr.Zero,
            out engine);

        if (rc != ERROR_SUCCESS)
        {
            ThrowWfp("FwpmEngineOpen0(static)", rc);
        }

        IntPtr ownedHandle = engine;
        engine = IntPtr.Zero;

        return new StaticSession(
            ownedHandle,
            sessionKey);
    }

    public static SubLayerSnapshot ReadSubLayerFresh(
        Guid key)
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

    public static FilterSnapshot ReadFilterFresh(
        ulong id)
    {
        IntPtr engine = IntPtr.Zero;

        try
        {
            engine = OpenReadEngine();
            return ReadFilterOnEngine(engine, id);
        }
        finally
        {
            if (engine != IntPtr.Zero)
            {
                FwpmEngineClose0(engine);
            }
        }
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
            ThrowWfp("FwpmEngineOpen0(read)", rc);
        }

        return engine;
    }

    private static FWPM_FILTER0 BuildBlockFilter(
        Guid filterKey,
        IntPtr namePtr,
        IntPtr descriptionPtr,
        Guid layerKey,
        Guid subLayerKey,
        IntPtr conditionsPtr)
    {
        FWPM_FILTER0 f = new FWPM_FILTER0();

        f.filterKey = filterKey;
        f.displayData.name = namePtr;
        f.displayData.description = descriptionPtr;

        f.flags = 0;
        f.providerKey = IntPtr.Zero;
        f.providerData.size = 0;
        f.providerData.data = IntPtr.Zero;

        f.layerKey = layerKey;
        f.subLayerKey = subLayerKey;

        f.weight.type = FWP_EMPTY;

        f.numFilterConditions = 2;
        f.filterCondition = conditionsPtr;

        f.action.type = FWP_ACTION_BLOCK;
        f.action.filterTypeOrCalloutKey = Guid.Empty;

        f.context.rawContext = 0;
        f.reserved = IntPtr.Zero;

        return f;
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
                ThrowWfp("FwpmSubLayerGetByKey0", rc);
            }

            FWPM_SUBLAYER0 s =
                Marshal.PtrToStructure<FWPM_SUBLAYER0>(p);

            return new SubLayerSnapshot
            {
                found = true,
                error_hex = null,
                key = s.subLayerKey.ToString("B"),
                name = PtrToStringUni(s.displayData.name),
                description =
                    PtrToStringUni(s.displayData.description),
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

    private static FilterSnapshot ReadFilterOnEngine(
        IntPtr engine,
        ulong id)
    {
        IntPtr p = IntPtr.Zero;

        try
        {
            uint rc = FwpmFilterGetById0(
                engine,
                id,
                out p);

            if (rc == FWP_E_FILTER_NOT_FOUND)
            {
                return new FilterSnapshot
                {
                    requested_filter_id = id,
                    found = false,
                    error_hex =
                        "0x" + rc.ToString("X8"),
                    conditions =
                        new FilterConditionSnapshot[0]
                };
            }

            if (rc != ERROR_SUCCESS)
            {
                ThrowWfp("FwpmFilterGetById0", rc);
            }

            FWPM_FILTER0 f =
                Marshal.PtrToStructure<FWPM_FILTER0>(p);

            List<FilterConditionSnapshot> conditionList =
                new List<FilterConditionSnapshot>();

            int conditionSize =
                Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));

            for (uint i = 0; i < f.numFilterConditions; i++)
            {
                IntPtr conditionPtr =
                    IntPtr.Add(
                        f.filterCondition,
                        checked((int)(i * (uint)conditionSize)));

                FWPM_FILTER_CONDITION0 c =
                    Marshal.PtrToStructure<FWPM_FILTER_CONDITION0>(
                        conditionPtr);

                FilterConditionSnapshot cs =
                    new FilterConditionSnapshot();

                cs.field_key = c.fieldKey.ToString("B");
                cs.field_name = ConditionName(c.fieldKey);
                cs.match_type = c.matchType;
                cs.value_type = c.conditionValue.type;
                cs.uint32_value = c.conditionValue.uint32;

                if (c.fieldKey == ConditionAleUserId &&
                    c.conditionValue.type ==
                        FWP_SECURITY_DESCRIPTOR_TYPE &&
                    c.conditionValue.pointerValue != IntPtr.Zero)
                {
                    FWP_BYTE_BLOB blob =
                        Marshal.PtrToStructure<FWP_BYTE_BLOB>(
                            c.conditionValue.pointerValue);

                    if (blob.data != IntPtr.Zero &&
                        blob.size > 0)
                    {
                        cs.normalized_dacl_sddl =
                            SecurityDescriptorToDaclSddl(
                                blob.data);
                    }
                }

                conditionList.Add(cs);
            }

            SubLayerSnapshot parentSubLayer =
                ReadSubLayerOnEngine(
                    engine,
                    f.subLayerKey);

            return new FilterSnapshot
            {
                requested_filter_id = id,
                found = true,
                error_hex = null,

                runtime_filter_id = f.filterId,
                filter_key = f.filterKey.ToString("B"),
                name = PtrToStringUni(f.displayData.name),
                description =
                    PtrToStringUni(f.displayData.description),

                flags = f.flags,
                flags_hex =
                    "0x" + f.flags.ToString("X8"),

                layer_key = f.layerKey.ToString("B"),
                sublayer_key =
                    f.subLayerKey.ToString("B"),

                sublayer_found = parentSubLayer.found,
                sublayer_error_hex = parentSubLayer.error_hex,
                sublayer_name = parentSubLayer.name,
                sublayer_weight = parentSubLayer.weight,

                action_type = f.action.type,
                action_type_hex =
                    "0x" + f.action.type.ToString("X8"),
                action_name =
                    ActionName(f.action.type),

                condition_count =
                    f.numFilterConditions,
                conditions =
                    conditionList.ToArray()
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

    private static string SecurityDescriptorToDaclSddl(
        IntPtr sd)
    {
        IntPtr stringSd = IntPtr.Zero;
        uint lengthIgnored = 0;

        try
        {
            bool ok =
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    out stringSd,
                    out lengthIgnored);

            if (!ok)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "ConvertSecurityDescriptorToStringSecurityDescriptorW failed.");
            }

            return Marshal.PtrToStringUni(stringSd);
        }
        finally
        {
            if (stringSd != IntPtr.Zero)
            {
                LocalFree(stringSd);
            }
        }
    }

    private static string ConditionName(Guid key)
    {
        if (key == ConditionAleUserId)
        {
            return "FWPM_CONDITION_ALE_USER_ID";
        }

        if (key == ConditionFlags)
        {
            return "FWPM_CONDITION_FLAGS";
        }

        return "OTHER";
    }

    private static string ActionName(uint actionType)
    {
        if (actionType == FWP_ACTION_BLOCK)
        {
            return "FWP_ACTION_BLOCK";
        }

        if (actionType == FWP_ACTION_PERMIT)
        {
            return "FWP_ACTION_PERMIT";
        }

        return "OTHER";
    }

    private static string PtrToStringUni(IntPtr p)
    {
        if (p == IntPtr.Zero)
        {
            return null;
        }

        return Marshal.PtrToStringUni(p);
    }

    private static void ThrowWfp(
        string operation,
        uint rc)
    {
        throw new Win32Exception(
            unchecked((int)rc),
            operation + " failed: 0x" + rc.ToString("X8"));
    }
}
'@

if (-not ('WfpPhaseCStepC1V1' -as [type])) {
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}

$layout = [WfpPhaseCStepC1V1]::GetLayoutInfo()
$expectedLayout = [ordered]@{
    display_data_size = 16
    byte_blob_size = 16
    sublayer_size = 72
    value_size = 16
    condition_value_size = 16
    filter_condition_size = 40
    action_size = 20
    filter_size = 200
    sublayer_weight_offset = 64
    condition_field_key_offset = 0
    condition_match_type_offset = 16
    condition_value_offset = 24
    filter_flags_offset = 32
    filter_layer_offset = 64
    filter_sublayer_offset = 80
    filter_weight_offset = 96
    filter_condition_count_offset = 112
    filter_condition_ptr_offset = 120
    filter_action_offset = 128
}
foreach ($name in $expectedLayout.Keys) {
    if ([Int64]$layout.$name -ne [Int64]$expectedLayout[$name]) {
        throw ("Interop layout mismatch: {0}, expected={1}, actual={2}" -f
            $name, $expectedLayout[$name], $layout.$name)
    }
}

function Test-ReferenceFilter {
    param(
        [Parameter(Mandatory = $true)] $Filter,
        [Parameter(Mandatory = $true)] [UInt64]$ExpectedId,
        [Parameter(Mandatory = $true)] [string]$ExpectedLayer,
        [Parameter(Mandatory = $true)] [string]$Label
    )

    if (-not $Filter.found) { throw ("{0}: reference filter not found." -f $Label) }
    if ($Filter.runtime_filter_id -ne $ExpectedId) { throw ("{0}: runtime ID mismatch." -f $Label) }
    if ($Filter.name -ne 'AppContainerLoopback') { throw ("{0}: name mismatch." -f $Label) }
    if ($Filter.action_name -ne 'FWP_ACTION_PERMIT') { throw ("{0}: action mismatch." -f $Label) }
    if ($Filter.layer_key -ne $ExpectedLayer) { throw ("{0}: layer mismatch." -f $Label) }
    if (-not $Filter.sublayer_found) { throw ("{0}: parent sublayer unavailable." -f $Label) }
    if ($Filter.sublayer_key -ne $ExpectedAppIsolationSubLayerKey) {
        throw ("{0}: App Isolation sublayer key mismatch." -f $Label)
    }
    if ($Filter.condition_count -ne 1) { throw ("{0}: expected one condition." -f $Label) }

    $conditions = @($Filter.conditions)
    if ($conditions.Count -ne 1) { throw ("{0}: condition array mismatch." -f $Label) }
    $c = $conditions[0]
    if ($c.field_key -ne $ExpectedFlagsConditionKey -or
        $c.match_type -ne 6 -or
        $c.value_type -ne 3 -or
        $c.uint32_value -ne 1) {
        throw ("{0}: loopback condition identity mismatch." -f $Label)
    }
}

function Test-InstalledFilter {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] [string]$ExpectedFilterKey,
        [Parameter(Mandatory = $true)] [string]$ExpectedLayerKey,
        [Parameter(Mandatory = $true)] [string]$ExpectedSubLayerKey,
        [Parameter(Mandatory = $true)] [string]$ExpectedDaclSddl
    )

    if (-not $Snapshot.found) { return $false }
    if ($Snapshot.filter_key -ne $ExpectedFilterKey) { return $false }
    if ($Snapshot.layer_key -ne $ExpectedLayerKey) { return $false }
    if ($Snapshot.sublayer_key -ne $ExpectedSubLayerKey) { return $false }
    if ($Snapshot.flags -ne 0) { return $false }
    if ($Snapshot.action_name -ne 'FWP_ACTION_BLOCK') { return $false }
    if ($Snapshot.action_type_hex -ne '0x00001001') { return $false }
    if ($Snapshot.condition_count -ne 2) { return $false }

    $conditions = @($Snapshot.conditions)
    if ($conditions.Count -ne 2) { return $false }

    $user = @($conditions | Where-Object { $_.field_name -eq 'FWPM_CONDITION_ALE_USER_ID' })
    $flags = @($conditions | Where-Object { $_.field_name -eq 'FWPM_CONDITION_FLAGS' })
    if ($user.Count -ne 1 -or $flags.Count -ne 1) { return $false }

    $uc = $user[0]
    $fc = $flags[0]
    if ($uc.match_type -ne 0 -or $uc.value_type -ne 14) { return $false }
    if ($uc.normalized_dacl_sddl -ne $ExpectedDaclSddl) { return $false }
    if ($fc.match_type -ne 6 -or $fc.value_type -ne 3 -or $fc.uint32_value -ne 1) {
        return $false
    }
    return $true
}

function Verify-FromState {
    param([Parameter(Mandatory = $true)] $State)

    $sub = [WfpPhaseCStepC1V1]::ReadSubLayerFresh([Guid]$State.sublayer_key)
    $v4 = [WfpPhaseCStepC1V1]::ReadFilterFresh([UInt64]$State.v4_filter_id)
    $v6 = [WfpPhaseCStepC1V1]::ReadFilterFresh([UInt64]$State.v6_filter_id)

    $subOk = (
        $sub.found -and
        $sub.key -eq [string]$State.sublayer_key -and
        $sub.flags -eq 0 -and
        [UInt16]$sub.weight -eq [UInt16]$State.observed_sublayer_weight -and
        [UInt16]$sub.weight -gt [UInt16]$State.app_isolation_weight
    )

    $v4Ok = Test-InstalledFilter `
        -Snapshot $v4 `
        -ExpectedFilterKey ([string]$State.v4_filter_key) `
        -ExpectedLayerKey $ExpectedV4LayerKey `
        -ExpectedSubLayerKey ([string]$State.sublayer_key) `
        -ExpectedDaclSddl ([string]$State.expected_normalized_dacl_sddl)

    $v6Ok = Test-InstalledFilter `
        -Snapshot $v6 `
        -ExpectedFilterKey ([string]$State.v6_filter_key) `
        -ExpectedLayerKey $ExpectedV6LayerKey `
        -ExpectedSubLayerKey ([string]$State.sublayer_key) `
        -ExpectedDaclSddl ([string]$State.expected_normalized_dacl_sddl)

    return [pscustomobject]@{
        sublayer = $sub
        v4 = $v4
        v6 = $v6
        sublayer_verified = $subOk
        v4_verified = $v4Ok
        v6_verified = $v6Ok
        all_verified = ($subOk -and $v4Ok -and $v6Ok)
    }
}

if ($Mode -in @('Install', 'CrashHold')) {
    if (-not [string]::IsNullOrWhiteSpace($StatePath)) {
        throw 'Do not supply -StatePath in Install or CrashHold mode.'
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outputDir = Join-Path $OutputBase $timestamp
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    $stateFile = Join-Path $outputDir 'state.json'
    $resultFile = Join-Path $outputDir 'install-result.json'

    $v4Ref = [WfpPhaseCStepC1V1]::ReadFilterFresh($AppLoopbackV4FilterId)
    $v6Ref = [WfpPhaseCStepC1V1]::ReadFilterFresh($AppLoopbackV6FilterId)
    Test-ReferenceFilter $v4Ref $AppLoopbackV4FilterId $ExpectedV4LayerKey 'V4'
    Test-ReferenceFilter $v6Ref $AppLoopbackV6FilterId $ExpectedV6LayerKey 'V6'

    if ($v4Ref.sublayer_key -ne $v6Ref.sublayer_key -or
        $v4Ref.sublayer_weight -ne $v6Ref.sublayer_weight) {
        throw 'V4/V6 reference filters do not share the same App Isolation sublayer identity.'
    }

    $u = Get-LocalUser -Name 'CodexSandboxOffline' -ErrorAction Stop
    if (-not $u.Enabled) { throw 'CodexSandboxOffline is disabled.' }
    $targetSid = $u.SID.Value
    $operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($targetSid -eq $operatorSid) { throw 'Operator SID equals CodexSandboxOffline SID.' }

    $subKey = [Guid]::NewGuid()
    $v4Key = [Guid]::NewGuid()
    $v6Key = [Guid]::NewGuid()

    $preexisting = [WfpPhaseCStepC1V1]::ReadSubLayerFresh($subKey)
    if ($preexisting.found) { throw 'Generated sublayer GUID unexpectedly already exists.' }

    $scriptHash = (Get-FileHash -LiteralPath $ScriptFilePath -Algorithm SHA256).Hash
    $state = [ordered]@{
        schema_version = $StateSchema
        kind = $StateKind
        created_at = (Get-Date).ToString('o')
        status = 'prepared'
        script_sha256 = $scriptHash
        target_account = 'CodexSandboxOffline'
        target_sid = $targetSid
        operator_sid = $operatorSid
        reference_v4_filter_id = $AppLoopbackV4FilterId
        reference_v6_filter_id = $AppLoopbackV6FilterId
        app_isolation_sublayer_key = $v4Ref.sublayer_key
        app_isolation_weight = [UInt16]$v4Ref.sublayer_weight
        requested_sublayer_weight = $RequestedSubLayerWeight
        observed_sublayer_weight = $null
        sublayer_key = $subKey.ToString('B')
        v4_filter_key = $v4Key.ToString('B')
        v6_filter_key = $v6Key.ToString('B')
        v4_filter_id = $null
        v6_filter_id = $null
        expected_normalized_dacl_sddl = $null
        static_nonpersistent = $true
        dynamic_session = $false
        persistent_flag = $false
        output_dir = $outputDir
    }
    Save-Json $state $stateFile

    $session = $null
    $committed = $false
    try {
        $session = [WfpPhaseCStepC1V1]::OpenStaticSession()

        $session.AddSubLayerTransaction(
            $subKey,
            'WLMCP_PhaseC_C1_Static_Codex_Loopback_Block',
            'Phase C C1 static non-persistent lifetime experiment.',
            $RequestedSubLayerWeight
        )

        $sub = $session.ReadSubLayer($subKey)
        if (-not $sub.found -or [UInt16]$sub.weight -le [UInt16]$v4Ref.sublayer_weight) {
            throw 'C1 sublayer was not assigned above App Isolation.'
        }

        $added = $session.AddBlockFiltersTransaction(
            $subKey,
            $v4Key,
            $v6Key,
            $targetSid
        )
        $committed = $true

        $v4Now = $session.ReadFilter($added.v4_filter_id)
        $v6Now = $session.ReadFilter($added.v6_filter_id)
        $v4Ok = Test-InstalledFilter `
            -Snapshot $v4Now `
            -ExpectedFilterKey ($v4Key.ToString('B')) `
            -ExpectedLayerKey $ExpectedV4LayerKey `
            -ExpectedSubLayerKey ($subKey.ToString('B')) `
            -ExpectedDaclSddl $added.expected_normalized_dacl_sddl

        $v6Ok = Test-InstalledFilter `
            -Snapshot $v6Now `
            -ExpectedFilterKey ($v6Key.ToString('B')) `
            -ExpectedLayerKey $ExpectedV6LayerKey `
            -ExpectedSubLayerKey ($subKey.ToString('B')) `
            -ExpectedDaclSddl $added.expected_normalized_dacl_sddl
        if (-not $v4Ok -or -not $v6Ok) { throw 'C1 filter read-back verification failed before session close.' }

        $state.status = 'installed_before_creator_session_close'
        $state.observed_sublayer_weight = [UInt16]$sub.weight
        $state.v4_filter_id = [UInt64]$added.v4_filter_id
        $state.v6_filter_id = [UInt64]$added.v6_filter_id
        $state.expected_normalized_dacl_sddl = $added.expected_normalized_dacl_sddl
        if ($Mode -eq 'CrashHold') {
            $state.status = 'crash_hold_active'
            $state | Add-Member -NotePropertyName 'holder_pid' -NotePropertyValue $PID -Force
            Save-Json $state $stateFile

            $result = [ordered]@{
                passed = $true
                mode = 'CrashHold'
                ready_for_forced_kill = $true
                holder_pid = $PID
                state_path = $stateFile
                state = $state
            }
            Save-Json $result $resultFile

            Write-Host ''
            Write-Host '============================================================'
            Write-Host 'C1 CRASH HOLD READY'
            Write-Host '============================================================'
            Write-Host 'READY_FOR_FORCED_KILL = True'
            Write-Host ("HOLDER_PID = {0}" -f $PID)
            Write-Host ("SUBLAYER_WEIGHT = {0}" -f $state.observed_sublayer_weight)
            Write-Host ("APP_ISOLATION_WEIGHT = {0}" -f $state.app_isolation_weight)
            Write-Host ("V4_FILTER_ID = {0}" -f $state.v4_filter_id)
            Write-Host ("V6_FILTER_ID = {0}" -f $state.v6_filter_id)
            Write-Host ("STATE_PATH = {0}" -f $stateFile)
            Write-Host ''
            Write-Host 'Leave this window running.'
            Write-Host 'From a SECOND Administrator PowerShell, use Stop-Process -Id HOLDER_PID -Force.'
            Write-Host 'Do not press Ctrl+C and do not close this window normally for the crash test.'

            try {
                while ($true) {
                    Start-Sleep -Seconds 1
                }
            }
            finally {
                # Normal script termination is NOT the crash path. If this finally runs,
                # remove only this experiment's exact objects so Ctrl+C/normal closure
                # does not intentionally leave stale policy behind.
                try { [void]$session.DeleteFilterByKey($v4Key) } catch {}
                try { [void]$session.DeleteFilterByKey($v6Key) } catch {}
                try { [void]$session.DeleteSubLayerByKey($subKey) } catch {}
                try { [void]$session.Close() } catch {}
            }
        }

        Save-Json $state $stateFile

        $closeRc = $session.Close()
        if ($closeRc -ne 0) { throw ("Static creator session close failed: 0x{0:X8}" -f $closeRc) }

        $after = Verify-FromState $state
        if (-not $after.all_verified) {
            throw 'Static WFP objects did not survive creator-session close or failed identity verification.'
        }

        $state.status = 'static_lifetime_confirmed_after_creator_session_close'
        $state.creator_session_closed_at = (Get-Date).ToString('o')
        Save-Json $state $stateFile

        $result = [ordered]@{
            passed = $true
            mode = 'Install'
            static_lifetime_confirmed = $true
            state_path = $stateFile
            state = $state
            post_close_verification = $after
        }
        Save-Json $result $resultFile

        Write-Host ''
        Write-Host '============================================================'
        Write-Host 'C1 INSTALL PASSED'
        Write-Host '============================================================'
        Write-Host 'STATIC_LIFETIME_AFTER_SESSION_CLOSE = True'
        Write-Host ("SUBLAYER_WEIGHT = {0}" -f $state.observed_sublayer_weight)
        Write-Host ("APP_ISOLATION_WEIGHT = {0}" -f $state.app_isolation_weight)
        Write-Host ("V4_FILTER_ID = {0}" -f $state.v4_filter_id)
        Write-Host ("V6_FILTER_ID = {0}" -f $state.v6_filter_id)
        Write-Host ("STATE_PATH = {0}" -f $stateFile)
        Write-Host ''
        Write-Host 'IMPORTANT: The BLOCK remains active after this command exits.'
        Write-Host 'Do not reboot or stop BFE. Run C1 Verify next, then traffic tests.'
    }
    catch {
        $cleanupSession = $null
        try {
            if ($null -ne $session -and $session.is_open) {
                $cleanupSession = $session
            } elseif ($committed) {
                $cleanupSession = [WfpPhaseCStepC1V1]::OpenStaticSession()
            }

            if ($null -ne $cleanupSession) {
                try { [void]$cleanupSession.DeleteFilterByKey($v4Key) } catch {}
                try { [void]$cleanupSession.DeleteFilterByKey($v6Key) } catch {}
                try { [void]$cleanupSession.DeleteSubLayerByKey($subKey) } catch {}
                try { [void]$cleanupSession.Close() } catch {}
            }
        } catch {
        }

        if ($committed) {
            $postErrorSub = [WfpPhaseCStepC1V1]::ReadSubLayerFresh($subKey)
            $postErrorV4 = $null
            $postErrorV6 = $null

            if ($null -ne $state.v4_filter_id) {
                $postErrorV4 = [WfpPhaseCStepC1V1]::ReadFilterFresh([UInt64]$state.v4_filter_id)
            }
            if ($null -ne $state.v6_filter_id) {
                $postErrorV6 = [WfpPhaseCStepC1V1]::ReadFilterFresh([UInt64]$state.v6_filter_id)
            }

            $residue = $postErrorSub.found
            if ($null -ne $postErrorV4 -and $postErrorV4.found) { $residue = $true }
            if ($null -ne $postErrorV6 -and $postErrorV6.found) { $residue = $true }

            if ($residue) {
                Write-Host ''
                Write-Host 'CRITICAL: Exact C1 objects may remain after an Install error.'
                Write-Host ("STATE_PATH = {0}" -f $stateFile)
                Write-Host 'Run Cleanup with this exact state file immediately.'
            }
        }
        throw
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($StatePath)) {
    throw '-StatePath is required in Verify and Cleanup modes.'
}

$resolvedStatePath = (Resolve-Path -LiteralPath $StatePath).Path
$state = Require-State $resolvedStatePath

if ($Mode -eq 'Verify') {
    $verification = Verify-FromState $state
    $resultFile = Join-Path ([IO.Path]::GetDirectoryName($resolvedStatePath)) 'verify-result.json'
    Save-Json ([ordered]@{
        passed = [bool]$verification.all_verified
        mode = 'Verify'
        verified_at = (Get-Date).ToString('o')
        state_path = $resolvedStatePath
        verification = $verification
    }) $resultFile

    Write-Host ''
    Write-Host '============================================================'
    Write-Host 'C1 VERIFY'
    Write-Host '============================================================'
    Write-Host ("SUBLAYER_VERIFIED = {0}" -f $verification.sublayer_verified)
    Write-Host ("V4_FILTER_VERIFIED = {0}" -f $verification.v4_verified)
    Write-Host ("V6_FILTER_VERIFIED = {0}" -f $verification.v6_verified)
    Write-Host ("STATIC_OBJECTS_PRESENT = {0}" -f $verification.all_verified)
    if (-not $verification.all_verified) { exit 2 }
    exit 0
}

if ($Mode -eq 'Cleanup') {
    $before = Verify-FromState $state

    # Refuse broad cleanup. We only delete the exact GUIDs in this state file.
    if ($before.v4.found -and $before.v4.filter_key -ne [string]$state.v4_filter_key) {
        throw 'V4 runtime ID now points to an unexpected filter key. Refusing deletion.'
    }
    if ($before.v6.found -and $before.v6.filter_key -ne [string]$state.v6_filter_key) {
        throw 'V6 runtime ID now points to an unexpected filter key. Refusing deletion.'
    }
    if ($before.sublayer.found -and $before.sublayer.key -ne [string]$state.sublayer_key) {
        throw 'Sublayer identity mismatch. Refusing deletion.'
    }

    $session = [WfpPhaseCStepC1V1]::OpenStaticSession()
    $delete = [ordered]@{}
    try {
        $delete.v4_rc_hex = ('0x{0:X8}' -f $session.DeleteFilterByKey([Guid]$state.v4_filter_key))
        $delete.v6_rc_hex = ('0x{0:X8}' -f $session.DeleteFilterByKey([Guid]$state.v6_filter_key))
        $delete.sublayer_rc_hex = ('0x{0:X8}' -f $session.DeleteSubLayerByKey([Guid]$state.sublayer_key))
        $closeRc = $session.Close()
        $delete.session_close_rc_hex = ('0x{0:X8}' -f $closeRc)
        if ($closeRc -ne 0) { throw 'Cleanup WFP session close failed.' }
    }
    finally {
        if ($session.is_open) { try { [void]$session.Close() } catch {} }
    }

    $postSub = [WfpPhaseCStepC1V1]::ReadSubLayerFresh([Guid]$state.sublayer_key)
    $postV4 = [WfpPhaseCStepC1V1]::ReadFilterFresh([UInt64]$state.v4_filter_id)
    $postV6 = [WfpPhaseCStepC1V1]::ReadFilterFresh([UInt64]$state.v6_filter_id)

    $v4Absent = (-not $postV4.found -and $postV4.error_hex -eq $FilterNotFoundHex)
    $v6Absent = (-not $postV6.found -and $postV6.error_hex -eq $FilterNotFoundHex)
    $subAbsent = (-not $postSub.found -and $postSub.error_hex -eq $SubLayerNotFoundHex)
    $allAbsent = ($v4Absent -and $v6Absent -and $subAbsent)

    $state.status = if ($allAbsent) { 'cleaned' } else { 'cleanup_incomplete' }
    $cleanedAt = (Get-Date).ToString('o')
    if ($state.PSObject.Properties.Name -contains 'cleaned_at') {
        $state.cleaned_at = $cleanedAt
    } else {
        $state | Add-Member -NotePropertyName 'cleaned_at' -NotePropertyValue $cleanedAt
    }
    Save-Json $state $resolvedStatePath

    $resultFile = Join-Path ([IO.Path]::GetDirectoryName($resolvedStatePath)) 'cleanup-result.json'
    Save-Json ([ordered]@{
        passed = $allAbsent
        mode = 'Cleanup'
        state_path = $resolvedStatePath
        delete_calls = $delete
        v4_absent = $v4Absent
        v6_absent = $v6Absent
        sublayer_absent = $subAbsent
        post_v4 = $postV4
        post_v6 = $postV6
        post_sublayer = $postSub
    }) $resultFile

    Write-Host ''
    Write-Host '============================================================'
    Write-Host 'C1 CLEANUP'
    Write-Host '============================================================'
    Write-Host ("V4_CLEANUP_VERIFIED = {0}" -f $v4Absent)
    Write-Host ("V6_CLEANUP_VERIFIED = {0}" -f $v6Absent)
    Write-Host ("SUBLAYER_CLEANUP_VERIFIED = {0}" -f $subAbsent)
    Write-Host ("ALL_CLEANUP_VERIFIED = {0}" -f $allAbsent)

    if (-not $allAbsent) {
        Write-Host ''
        Write-Host 'CRITICAL: C1 cleanup is incomplete.'
        Write-Host ("STATE_PATH = {0}" -f $resolvedStatePath)
        exit 3
    }
    exit 0
}
