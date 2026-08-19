#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP Phase B - Step 4 temporary CodexSandboxOffline loopback block.

.DESCRIPTION
  IMPORTANT: This is the first Phase B step that intentionally changes
  network filtering behavior while the script is running.

  The script:
    1. Re-checks runtime filters 70511/70512 as AppContainerLoopback PERMIT
       at ALE_AUTH_CONNECT V4/V6 and reads the App Isolation sublayer weight.
    2. Verifies CodexSandboxOffline exists and is enabled, and obtains its
       current SID.
    3. Verifies the current operator SID is different from CodexSandboxOffline.
    4. Opens a dynamic WFP session.
    5. Adds ONE empty temporary sublayer with requested weight 10.
    6. Reads it back and requires observed weight > App Isolation weight.
    7. In ONE transaction adds exactly two temporary BLOCK filters:
         - ALE_AUTH_CONNECT_V4
         - ALE_AUTH_CONNECT_V6
       Conditions on each filter:
         - FWPM_CONDITION_ALE_USER_ID == CodexSandboxOffline
         - FWPM_CONDITION_FLAGS has FWP_CONDITION_FLAG_IS_LOOPBACK (0x1)
    8. Reads both filters back and verifies layer, sublayer, BLOCK action,
       zero filter flags, exactly two conditions, target SID DACL, and
       loopback flag.
    9. Writes an active result and waits for operator Enter.
   10. On Enter, closes the dynamic session and verifies both filters and
       the temporary sublayer are gone.

  No Windows Firewall rule, registry value, service, driver, provider, or
  persistent WFP object is created.

  While READY_FOR_STEP5 is shown, localhost connection attempts made by
  CodexSandboxOffline are expected to be blocked. Leave this PowerShell
  window open for the Step 5 traffic test.

  Output:
    <script-dir>\WFP-PhaseB-Step4-Results\<timestamp>\result.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [UInt64]$AppLoopbackV4FilterId = 70511,

    [Parameter(Mandatory = $false)]
    [UInt64]$AppLoopbackV6FilterId = 70512,

    [Parameter(Mandatory = $false)]
    [UInt16]$RequestedTemporarySubLayerWeight = 10,

    [Parameter(Mandatory = $false)]
    [string]$OutputBase = (Join-Path $PSScriptRoot 'WFP-PhaseB-Step4-Results')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedV4LayerKey = '{c38d57d1-05a7-4c33-904f-7fbceee60e82}'
$ExpectedV6LayerKey = '{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}'
$FilterNotFoundHex = '0x80320003'
$SubLayerNotFoundHex = '0x80320007'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Save-CurrentResult {
    param(
        [Parameter(Mandatory = $true)]
        $Object,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Object |
        ConvertTo-Json -Depth 20 |
        Set-Content -LiteralPath $Path -Encoding UTF8
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
$logPath = Join-Path $outputDir 'step4-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$logLines = New-Object System.Collections.Generic.List[string]
function Write-StepLog {
    param([string]$Message)

    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $logLines.Add($line)
    Write-Host $line
}

function Flush-StepLog {
    $logLines | Set-Content -LiteralPath $logPath -Encoding UTF8
}

Write-StepLog 'Starting WLMCP Phase B Step 4.'
Write-StepLog ("Output directory: {0}" -f $outputDir)

$source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WfpPhaseBStep4V1
{
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint ERROR_SUCCESS = 0;

    private const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    private const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;

    private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

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
                Marshal.AllocHGlobal(
                    Marshal.SizeOf(typeof(FWPM_SESSION0)));

            Marshal.StructureToPtr(
                session,
                sessionPtr,
                false);

            uint rc = FwpmEngineOpen0(
                null,
                RPC_C_AUTHN_WINNT,
                IntPtr.Zero,
                sessionPtr,
                out engine);

            if (rc != ERROR_SUCCESS)
            {
                ThrowWfp("FwpmEngineOpen0(dynamic)", rc);
            }

            IntPtr ownedHandle = engine;
            engine = IntPtr.Zero;

            return new DynamicSession(
                ownedHandle,
                sessionKey);
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

if (-not ('WfpPhaseBStep4V1' -as [type])) {
    Write-StepLog 'Compiling the Step 4 helper.'
    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
} else {
    Write-StepLog 'Reusing already loaded Step 4 helper type.'
}

$layout = [WfpPhaseBStep4V1]::GetLayoutInfo()

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

    Flush-StepLog
    throw 'Interop layout mismatch. Step 4 stopped before WFP mutation.'
}

Write-StepLog 'Interop layout check PASSED.'

# Read the known runtime AppContainerLoopback filters with this Step 4
# helper itself. This keeps the script self-contained and safe to run from
# a fresh Administrator PowerShell process.
Write-StepLog ("Reading AppContainerLoopback filter {0}." -f $AppLoopbackV4FilterId)
$v4Reference = [WfpPhaseBStep4V1]::ReadFilterFresh($AppLoopbackV4FilterId)

Write-StepLog ("Reading AppContainerLoopback filter {0}." -f $AppLoopbackV6FilterId)
$v6Reference = [WfpPhaseBStep4V1]::ReadFilterFresh($AppLoopbackV6FilterId)

$precheckErrors = New-Object System.Collections.Generic.List[string]

foreach ($item in @(
    [pscustomobject]@{
        label = 'V4'
        filter = $v4Reference
        expected_id = $AppLoopbackV4FilterId
        expected_layer = $ExpectedV4LayerKey
    },
    [pscustomobject]@{
        label = 'V6'
        filter = $v6Reference
        expected_id = $AppLoopbackV6FilterId
        expected_layer = $ExpectedV6LayerKey
    }
)) {
    $f = $item.filter

    if (-not $f.found) {
        $precheckErrors.Add(
            ("{0}: reference filter not found." -f $item.label))
        continue
    }

    if ($f.runtime_filter_id -ne $item.expected_id) {
        $precheckErrors.Add(
            ("{0}: runtime filter ID mismatch." -f $item.label))
    }

    if ($f.name -ne 'AppContainerLoopback') {
        $precheckErrors.Add(
            ("{0}: name mismatch: {1}" -f $item.label, $f.name))
    }

    if ($f.action_name -ne 'FWP_ACTION_PERMIT') {
        $precheckErrors.Add(
            ("{0}: action mismatch: {1}" -f
                $item.label,
                $f.action_name))
    }

    if ($f.layer_key -ne $item.expected_layer) {
        $precheckErrors.Add(
            ("{0}: layer mismatch: {1}" -f
                $item.label,
                $f.layer_key))
    }

    if (-not $f.sublayer_found) {
        $precheckErrors.Add(
            ("{0}: App Isolation sublayer not readable." -f $item.label))
    }
}

if ($v4Reference.found -and
    $v6Reference.found -and
    $v4Reference.sublayer_key -ne $v6Reference.sublayer_key) {
    $precheckErrors.Add(
        'V4/V6 AppContainerLoopback filters are not in the same sublayer.')
}

if ($v4Reference.sublayer_found -and
    $v6Reference.sublayer_found -and
    $v4Reference.sublayer_weight -ne $v6Reference.sublayer_weight) {
    $precheckErrors.Add(
        'V4/V6 App Isolation sublayer weights differ.')
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

$operatorSid =
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

if ($codexUser.found -and $operatorSid -eq $codexUser.sid) {
    $precheckErrors.Add(
        'Current operator SID equals CodexSandboxOffline SID. Refusing Step 4.')
}

$appIsolationWeight = $null
$appIsolationSubLayerKey = $null

if ($v4Reference.sublayer_found) {
    $appIsolationWeight = [UInt16]$v4Reference.sublayer_weight
    $appIsolationSubLayerKey = $v4Reference.sublayer_key
}

if ($null -eq $appIsolationWeight) {
    $precheckErrors.Add(
        'App Isolation sublayer weight was not obtained.')
}

$precheckPassed = ($precheckErrors.Count -eq 0)

$temporarySubLayerKey = [Guid]::NewGuid()
$v4FilterKey = [Guid]::NewGuid()
$v6FilterKey = [Guid]::NewGuid()

$temporarySubLayerName =
    'WLMCP_PhaseB_Temporary_Codex_Loopback_Block_Sublayer'
$temporarySubLayerDescription =
    'Temporary Step 4 sublayer for CodexSandboxOffline loopback block.'

$result = [ordered]@{
    schema_version = 1
    started_at = (Get-Date).ToString('o')

    host = [ordered]@{
        computer_name = $env:COMPUTERNAME
        operator = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        operator_sid = $operatorSid
        process_id = $PID
        is_administrator = $true
        is_64_bit_process = [Environment]::Is64BitProcess
        codex_sandbox_offline = $codexUser
    }

    interop_layout = [ordered]@{
        passed = ($layoutErrors.Count -eq 0)
        observed = $layout
        expected = $expectedLayout
        errors = @($layoutErrors)
    }

    precheck = [ordered]@{
        passed = $precheckPassed
        errors = @($precheckErrors)
        app_isolation_sublayer_key = $appIsolationSubLayerKey
        app_isolation_weight = $appIsolationWeight
        reference_filter_v4 = $v4Reference
        reference_filter_v6 = $v6Reference
    }

    temporary_sublayer = [ordered]@{
        key = $temporarySubLayerKey.ToString('B')
        requested_weight = $RequestedTemporarySubLayerWeight
        add_succeeded = $false
        observed = $null
        verified_higher_than_app_isolation = $false
    }

    temporary_filters = [ordered]@{
        transaction_committed = $false

        expected_target_sid = if ($codexUser.found) {
            $codexUser.sid
        } else {
            $null
        }

        expected_loopback_flag = 1
        expected_user_match_type = 0
        expected_flags_match_type = 6
        expected_user_value_type = 14
        expected_flags_value_type = 3

        expected_normalized_dacl_sddl = $null

        v4_filter_key = $v4FilterKey.ToString('B')
        v6_filter_key = $v6FilterKey.ToString('B')

        v4_filter_id = $null
        v6_filter_id = $null

        v4_readback = $null
        v6_readback = $null

        v4_verified = $false
        v6_verified = $false
    }

    active = [ordered]@{
        ready_for_step5 = $false
        filters_active = $false
        waiting_for_operator_enter = $false
    }

    cleanup = [ordered]@{
        close_attempted = $false
        close_rc_hex = $null
        close_succeeded = $false

        emergency_delete_attempted = $false
        emergency_delete_results = @()

        v4_filter_absent = $false
        v6_filter_absent = $false
        sublayer_absent = $false

        v4_post_close = $null
        v6_post_close = $null
        sublayer_post_close = $null
    }

    policy_mutation = [ordered]@{
        temporary_wfp_sublayer_added = $false
        temporary_wfp_filters_added = $false
        windows_firewall_rule_changed = $false
        registry_changed = $false
        service_changed = $false
        provider_added = $false
        driver_added = $false
        persistent_wfp_object_created = $false
        expected_network_behavior_change_while_active =
            'Block CodexSandboxOffline loopback outbound connect/first datagram at ALE_AUTH_CONNECT V4/V6.'
    }

    error = $null

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

    $result.error = 'Step 4 precheck failed.'
    $result.finished_at = (Get-Date).ToString('o')

    Save-CurrentResult -Object $result -Path $resultPath
    Flush-StepLog

    throw ("STEP 4 PRECHECK FAILED. See: {0}" -f $resultPath)
}

Write-StepLog 'PRECHECK PASSED.'
Write-StepLog (
    ("CodexSandboxOffline SID: {0}" -f $codexUser.sid))
Write-StepLog (
    ("Operator SID: {0}" -f $operatorSid))
Write-StepLog (
    ("App Isolation sublayer weight: {0}" -f $appIsolationWeight))

$dynamicSession = $null
$filtersCommitted = $false

try {
    Write-StepLog 'Opening dynamic WFP session.'
    $dynamicSession = [WfpPhaseBStep4V1]::OpenDynamicSession()

    Write-StepLog (
        ("Dynamic session opened: {0}" -f $dynamicSession.session_key))

    Write-StepLog (
        ("Adding empty temporary sublayer, requested weight {0}." -f
            $RequestedTemporarySubLayerWeight))

    $dynamicSession.AddSubLayerTransaction(
        $temporarySubLayerKey,
        $temporarySubLayerName,
        $temporarySubLayerDescription,
        $RequestedTemporarySubLayerWeight)

    $result.temporary_sublayer.add_succeeded = $true
    $result.policy_mutation.temporary_wfp_sublayer_added = $true

    $observedSubLayer =
        $dynamicSession.ReadSubLayer($temporarySubLayerKey)

    $result.temporary_sublayer.observed = $observedSubLayer

    if (-not $observedSubLayer.found) {
        throw 'Temporary sublayer was not found after commit.'
    }

    if ($observedSubLayer.key -ne $temporarySubLayerKey.ToString('B')) {
        throw 'Temporary sublayer key mismatch.'
    }

    if ($observedSubLayer.flags -ne 0) {
        throw 'Temporary sublayer flags are not zero.'
    }

    if ([UInt16]$observedSubLayer.weight -le [UInt16]$appIsolationWeight) {
        throw (
            "Temporary sublayer priority is not above App Isolation. " +
            "Observed={0}, AppIsolation={1}" -f
                $observedSubLayer.weight,
                $appIsolationWeight)
    }

    $result.temporary_sublayer.verified_higher_than_app_isolation = $true

    Write-StepLog (
        ("Temporary sublayer observed weight: {0}; App Isolation: {1}." -f
            $observedSubLayer.weight,
            $appIsolationWeight))

    Write-StepLog (
        'Adding V4 and V6 BLOCK filters atomically.')

    $addResult =
        $dynamicSession.AddBlockFiltersTransaction(
            $temporarySubLayerKey,
            $v4FilterKey,
            $v6FilterKey,
            $codexUser.sid)

    $filtersCommitted = $true
    $result.temporary_filters.transaction_committed = $true
    $result.policy_mutation.temporary_wfp_filters_added = $true

    $result.temporary_filters.expected_normalized_dacl_sddl =
        $addResult.expected_normalized_dacl_sddl
    $result.temporary_filters.v4_filter_id =
        $addResult.v4_filter_id
    $result.temporary_filters.v6_filter_id =
        $addResult.v6_filter_id

    Write-StepLog (
        ("V4 filter runtime ID: {0}" -f $addResult.v4_filter_id))
    Write-StepLog (
        ("V6 filter runtime ID: {0}" -f $addResult.v6_filter_id))

    $v4Readback =
        $dynamicSession.ReadFilter($addResult.v4_filter_id)

    $v6Readback =
        $dynamicSession.ReadFilter($addResult.v6_filter_id)

    $result.temporary_filters.v4_readback = $v4Readback
    $result.temporary_filters.v6_readback = $v6Readback

    function Test-Step4FilterReadback {
        param(
            [Parameter(Mandatory = $true)]
            $Snapshot,

            [Parameter(Mandatory = $true)]
            [string]$ExpectedFilterKey,

            [Parameter(Mandatory = $true)]
            [string]$ExpectedLayerKey,

            [Parameter(Mandatory = $true)]
            [string]$ExpectedSubLayerKey,

            [Parameter(Mandatory = $true)]
            [string]$ExpectedDaclSddl
        )

        if (-not $Snapshot.found) {
            return $false
        }

        if ($Snapshot.filter_key -ne $ExpectedFilterKey) {
            return $false
        }

        if ($Snapshot.layer_key -ne $ExpectedLayerKey) {
            return $false
        }

        if ($Snapshot.sublayer_key -ne $ExpectedSubLayerKey) {
            return $false
        }

        if ($Snapshot.flags -ne 0) {
            return $false
        }

        if ($Snapshot.action_name -ne 'FWP_ACTION_BLOCK') {
            return $false
        }

        if ($Snapshot.action_type_hex -ne '0x00001001') {
            return $false
        }

        if ($Snapshot.condition_count -ne 2) {
            return $false
        }

        $conditions = @($Snapshot.conditions)

        if ($conditions.Count -ne 2) {
            return $false
        }

        $userCondition = @(
            $conditions |
            Where-Object {
                $_.field_name -eq 'FWPM_CONDITION_ALE_USER_ID'
            }
        )

        $flagsCondition = @(
            $conditions |
            Where-Object {
                $_.field_name -eq 'FWPM_CONDITION_FLAGS'
            }
        )

        if ($userCondition.Count -ne 1) {
            return $false
        }

        if ($flagsCondition.Count -ne 1) {
            return $false
        }

        $uc = $userCondition[0]
        $fc = $flagsCondition[0]

        if ($uc.match_type -ne 0) {
            return $false
        }

        if ($uc.value_type -ne 14) {
            return $false
        }

        if ($uc.normalized_dacl_sddl -ne $ExpectedDaclSddl) {
            return $false
        }

        if ($fc.match_type -ne 6) {
            return $false
        }

        if ($fc.value_type -ne 3) {
            return $false
        }

        if ($fc.uint32_value -ne 1) {
            return $false
        }

        return $true
    }

    $v4Verified =
        Test-Step4FilterReadback `
            -Snapshot $v4Readback `
            -ExpectedFilterKey $v4FilterKey.ToString('B') `
            -ExpectedLayerKey $ExpectedV4LayerKey `
            -ExpectedSubLayerKey $temporarySubLayerKey.ToString('B') `
            -ExpectedDaclSddl $addResult.expected_normalized_dacl_sddl

    $v6Verified =
        Test-Step4FilterReadback `
            -Snapshot $v6Readback `
            -ExpectedFilterKey $v6FilterKey.ToString('B') `
            -ExpectedLayerKey $ExpectedV6LayerKey `
            -ExpectedSubLayerKey $temporarySubLayerKey.ToString('B') `
            -ExpectedDaclSddl $addResult.expected_normalized_dacl_sddl

    $result.temporary_filters.v4_verified = $v4Verified
    $result.temporary_filters.v6_verified = $v6Verified

    if (-not $v4Verified -or -not $v6Verified) {
        throw (
            'BLOCK filter read-back verification failed. ' +
            'The temporary policy will be removed immediately.')
    }

    $result.active.ready_for_step5 = $true
    $result.active.filters_active = $true
    $result.active.waiting_for_operator_enter = $true

    Save-CurrentResult -Object $result -Path $resultPath
    Flush-StepLog

    Write-StepLog 'STATIC READ-BACK VERIFICATION PASSED.'
    Write-Host ''
    Write-Host '============================================================'
    Write-Host 'READY_FOR_STEP5 = True'
    Write-Host '============================================================'
    Write-Host (
        "TEMP_SUBLAYER_WEIGHT = {0}" -f
            $observedSubLayer.weight)
    Write-Host (
        "APP_ISOLATION_WEIGHT = {0}" -f
            $appIsolationWeight)
    Write-Host (
        "V4_FILTER_ID = {0}" -f
            $addResult.v4_filter_id)
    Write-Host (
        "V6_FILTER_ID = {0}" -f
            $addResult.v6_filter_id)
    Write-Host (
        "TARGET_SID = {0}" -f
            $codexUser.sid)
    Write-Host ''
    Write-Host 'DO NOT press Enter yet if you are proceeding to Step 5.'
    Write-Host 'Leave this Administrator PowerShell window open.'
    Write-Host 'Run the localhost traffic test from a second PowerShell window.'
    Write-Host ''
    Write-Host 'Press Enter only when you want to remove the temporary policy.'
    [void](Read-Host)

    $result.active.waiting_for_operator_enter = $false
}
catch {
    $result.error = $_.Exception.Message
    Write-StepLog ("STEP 4 ERROR: {0}" -f $_.Exception.Message)

    if ($null -ne $dynamicSession -and $dynamicSession.is_open) {
        $result.cleanup.emergency_delete_attempted = $true

        $deleteResults = New-Object System.Collections.Generic.List[object]

        foreach ($target in @(
            [pscustomobject]@{
                type = 'filter'
                key = $v4FilterKey
                label = 'V4 filter'
            },
            [pscustomobject]@{
                type = 'filter'
                key = $v6FilterKey
                label = 'V6 filter'
            },
            [pscustomobject]@{
                type = 'sublayer'
                key = $temporarySubLayerKey
                label = 'temporary sublayer'
            }
        )) {
            try {
                if ($target.type -eq 'filter') {
                    $rc =
                        $dynamicSession.DeleteFilterByKey(
                            $target.key)
                } else {
                    $rc =
                        $dynamicSession.DeleteSubLayerByKey(
                            $target.key)
                }

                $deleteResults.Add(
                    [pscustomobject]@{
                        label = $target.label
                        rc_hex = ('0x{0:X8}' -f $rc)
                    })
            } catch {
                $deleteResults.Add(
                    [pscustomobject]@{
                        label = $target.label
                        error = $_.Exception.Message
                    })
            }
        }

        $result.cleanup.emergency_delete_results =
            $deleteResults.ToArray()
    }
}
finally {
    $result.active.filters_active = $false
    $result.active.ready_for_step5 = $false
    $result.active.waiting_for_operator_enter = $false

    if ($null -ne $dynamicSession -and $dynamicSession.is_open) {
        $result.cleanup.close_attempted = $true
        Write-StepLog 'Closing dynamic WFP session.'

        try {
            $closeRc = $dynamicSession.Close()

            $result.cleanup.close_rc_hex =
                ('0x{0:X8}' -f $closeRc)

            if ($closeRc -eq 0) {
                $result.cleanup.close_succeeded = $true
                Write-StepLog 'Dynamic WFP session close PASSED.'
            } else {
                Write-StepLog (
                    ("WARNING: dynamic session close returned {0}" -f
                        $result.cleanup.close_rc_hex))

                if ($dynamicSession.is_open) {
                    $result.cleanup.emergency_delete_attempted = $true
                    Write-StepLog (
                        'Close did not succeed. Removing ONLY this run''s ' +
                        'two filter GUIDs and temporary sublayer GUID.')

                    $fallbackDeletes =
                        New-Object System.Collections.Generic.List[object]

                    foreach ($target in @(
                        [pscustomobject]@{
                            type = 'filter'
                            key = $v4FilterKey
                            label = 'V4 filter after close failure'
                        },
                        [pscustomobject]@{
                            type = 'filter'
                            key = $v6FilterKey
                            label = 'V6 filter after close failure'
                        },
                        [pscustomobject]@{
                            type = 'sublayer'
                            key = $temporarySubLayerKey
                            label = 'temporary sublayer after close failure'
                        }
                    )) {
                        try {
                            if ($target.type -eq 'filter') {
                                $deleteRc =
                                    $dynamicSession.DeleteFilterByKey(
                                        $target.key)
                            } else {
                                $deleteRc =
                                    $dynamicSession.DeleteSubLayerByKey(
                                        $target.key)
                            }

                            $fallbackDeletes.Add(
                                [pscustomobject]@{
                                    label = $target.label
                                    rc_hex = ('0x{0:X8}' -f $deleteRc)
                                })
                        } catch {
                            $fallbackDeletes.Add(
                                [pscustomobject]@{
                                    label = $target.label
                                    error = $_.Exception.Message
                                })
                        }
                    }

                    $result.cleanup.emergency_delete_results =
                        $fallbackDeletes.ToArray()

                    Write-StepLog 'Retrying dynamic session close once.'
                    $retryRc = $dynamicSession.Close()

                    $result.cleanup.close_rc_hex =
                        ('0x{0:X8}' -f $retryRc)

                    if ($retryRc -eq 0) {
                        $result.cleanup.close_succeeded = $true
                        Write-StepLog 'Retry dynamic session close PASSED.'
                    } else {
                        Write-StepLog (
                            ("CRITICAL: retry dynamic session close returned 0x{0:X8}" -f
                                $retryRc))
                    }
                }
            }
        } catch {
            Write-StepLog (
                ("WARNING: dynamic session close threw: {0}" -f
                    $_.Exception.Message))

            if ($dynamicSession.is_open) {
                $result.cleanup.emergency_delete_attempted = $true

                try {
                    [void]$dynamicSession.DeleteFilterByKey($v4FilterKey)
                } catch {
                }

                try {
                    [void]$dynamicSession.DeleteFilterByKey($v6FilterKey)
                } catch {
                }

                try {
                    [void]$dynamicSession.DeleteSubLayerByKey(
                        $temporarySubLayerKey)
                } catch {
                }

                try {
                    $retryRc = $dynamicSession.Close()
                    $result.cleanup.close_rc_hex =
                        ('0x{0:X8}' -f $retryRc)

                    if ($retryRc -eq 0) {
                        $result.cleanup.close_succeeded = $true
                        Write-StepLog (
                            'Emergency cleanup and retry close PASSED.')
                    }
                } catch {
                    Write-StepLog (
                        ("CRITICAL: emergency cleanup retry failed: {0}" -f
                            $_.Exception.Message))
                }
            }
        }
    }
}

if ($filtersCommitted) {
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $postV4 =
                [WfpPhaseBStep4V1]::ReadFilterFresh(
                    [UInt64]$result.temporary_filters.v4_filter_id)

            $postV6 =
                [WfpPhaseBStep4V1]::ReadFilterFresh(
                    [UInt64]$result.temporary_filters.v6_filter_id)

            $postSubLayer =
                [WfpPhaseBStep4V1]::ReadSubLayerFresh(
                    $temporarySubLayerKey)

            $result.cleanup.v4_post_close = $postV4
            $result.cleanup.v6_post_close = $postV6
            $result.cleanup.sublayer_post_close = $postSubLayer

            $result.cleanup.v4_filter_absent =
                (-not $postV4.found -and
                 $postV4.error_hex -eq $FilterNotFoundHex)

            $result.cleanup.v6_filter_absent =
                (-not $postV6.found -and
                 $postV6.error_hex -eq $FilterNotFoundHex)

            $result.cleanup.sublayer_absent =
                (-not $postSubLayer.found -and
                 $postSubLayer.error_hex -eq $SubLayerNotFoundHex)

            if ($result.cleanup.v4_filter_absent -and
                $result.cleanup.v6_filter_absent -and
                $result.cleanup.sublayer_absent) {
                break
            }
        } catch {
            Write-StepLog (
                ("Post-close cleanup lookup failed: {0}" -f
                    $_.Exception.Message))
        }

        Start-Sleep -Milliseconds 200
    }
} elseif ($result.temporary_sublayer.add_succeeded) {
    try {
        $postSubLayer =
            [WfpPhaseBStep4V1]::ReadSubLayerFresh(
                $temporarySubLayerKey)

        $result.cleanup.sublayer_post_close = $postSubLayer
        $result.cleanup.sublayer_absent =
            (-not $postSubLayer.found -and
             $postSubLayer.error_hex -eq $SubLayerNotFoundHex)
    } catch {
        Write-StepLog (
            ("Post-close sublayer lookup failed: {0}" -f
                $_.Exception.Message))
    }
}

if ($filtersCommitted -and
    $result.cleanup.v4_filter_absent -and
    $result.cleanup.v6_filter_absent -and
    $result.cleanup.sublayer_absent) {
    Write-StepLog 'CLEANUP VERIFIED: V4/V6 filters and sublayer are absent.'
}

$result.finished_at = (Get-Date).ToString('o')

Save-CurrentResult -Object $result -Path $resultPath
Flush-StepLog

$hashes = @()

Get-ChildItem -LiteralPath $outputDir -File |
    Where-Object { $_.Name -ne 'artifact-sha256.json' } |
    ForEach-Object {
        $h =
            Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256

        $hashes +=
            [pscustomobject]@{
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
Write-Host 'WLMCP Phase B STEP 4 - FINISHED'
Write-Host '============================================================'
Write-Host ("RESULT_DIR  = {0}" -f $outputDir)
Write-Host ("RESULT_JSON = {0}" -f $resultPath)
Write-Host (
    ("SUBLAYER_HIGHER_THAN_APP_ISOLATION = {0}" -f
        $result.temporary_sublayer.verified_higher_than_app_isolation))
Write-Host (
    ("V4_STATIC_VERIFIED = {0}" -f
        $result.temporary_filters.v4_verified))
Write-Host (
    ("V6_STATIC_VERIFIED = {0}" -f
        $result.temporary_filters.v6_verified))
Write-Host (
    ("SESSION_CLOSE_SUCCEEDED = {0}" -f
        $result.cleanup.close_succeeded))
Write-Host (
    ("V4_CLEANUP_VERIFIED = {0}" -f
        $result.cleanup.v4_filter_absent))
Write-Host (
    ("V6_CLEANUP_VERIFIED = {0}" -f
        $result.cleanup.v6_filter_absent))
Write-Host (
    ("SUBLAYER_CLEANUP_VERIFIED = {0}" -f
        $result.cleanup.sublayer_absent))

if (-not [string]::IsNullOrWhiteSpace($result.error)) {
    Write-Host ("STEP_4_ERROR = {0}" -f $result.error)
}
