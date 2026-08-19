#requires -Version 5.1
<#
.SYNOPSIS
  WLMCP / Codex Windows Sandbox localhost issue - Phase A read-only WFP collector.

.DESCRIPTION
  Reads current Windows Filtering Platform state and extracts:
    - FWPM_SUBLAYER_MPSSVC_APP_ISOLATION sublayer weight
    - FWPM_SUBLAYER_MPSSVC_WF sublayer weight
    - Filter 70511 / 70512 static policy details, when present
    - Top sublayer weights for context
    - Current CodexSandboxOffline SID, when available
    - Basic Windows/BFE/MpsSvc metadata

  It does NOT add/delete/modify WFP filters or sublayers, Windows Firewall rules,
  registry values, or services. The only changes are report files in OutputRoot.

  Important limitation:
  A static WFP snapshot can show filter flags such as
  FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, but cannot directly reveal the runtime
  FWPS_RIGHT_ACTION_WRITE state carried during a specific classify operation.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = $env:TEMP
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NodeText {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string]$XPath
    )
    $n = $Node.SelectSingleNode($XPath)
    if ($null -eq $n) { return $null }
    return $n.InnerText.Trim()
}

function Convert-TextToUInt64 {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    if ($t -match '^0[xX]([0-9A-Fa-f]+)$') { return [Convert]::ToUInt64($Matches[1], 16) }
    if ($t -match '^\d+$') { return [UInt64]$t }
    return $null
}

function Get-NumericValueFromNode {
    param([Parameter(Mandatory = $true)]$Node)
    foreach ($name in @('uint8','uint16','uint32','uint64','value')) {
        $leaf = $Node.SelectSingleNode(".//*[local-name()='$name']")
        if ($null -ne $leaf) {
            $v = Convert-TextToUInt64 $leaf.InnerText
            if ($null -ne $v) { return $v }
        }
    }
    return Convert-TextToUInt64 $Node.InnerText
}

function Get-DisplayName {
    param([Parameter(Mandatory = $true)]$Node)
    return Get-NodeText $Node "./*[local-name()='displayData']/*[local-name()='name']"
}

function Get-SublayerObject {
    param([Parameter(Mandatory = $true)]$Node)
    $weightNode = $Node.SelectSingleNode("./*[local-name()='weight']")
    $weightValue = $null
    $weightXml = $null
    if ($null -ne $weightNode) {
        $weightValue = Get-NumericValueFromNode $weightNode
        $weightXml = $weightNode.OuterXml
    }
    [pscustomobject]@{
        key          = Get-NodeText $Node "./*[local-name()='subLayerKey']"
        name         = Get-DisplayName $Node
        description  = Get-NodeText $Node "./*[local-name()='displayData']/*[local-name()='description']"
        flags        = Get-NodeText $Node "./*[local-name()='flags']"
        provider_key = Get-NodeText $Node "./*[local-name()='providerKey']"
        weight       = $weightValue
        weight_xml   = $weightXml
    }
}

function Get-FilterObject {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string]$RequestedId
    )
    $weightNode = $Node.SelectSingleNode("./*[local-name()='weight']")
    $effectiveWeightNode = $Node.SelectSingleNode("./*[local-name()='effectiveWeight']")
    $flagsNode = $Node.SelectSingleNode("./*[local-name()='flags']")
    $conditionsNode = $Node.SelectSingleNode("./*[local-name()='filterCondition']")
    $flagsText = $null
    $flagsXml = $null
    if ($null -ne $flagsNode) {
        $flagsText = $flagsNode.InnerText.Trim()
        $flagsXml = $flagsNode.OuterXml
    }
    $actionNode = $Node.SelectSingleNode("./*[local-name()='action']")
    $actionType = $null
    $actionXml = $null
    if ($null -ne $actionNode) {
        $actionType = Get-NodeText $actionNode "./*[local-name()='type']"
        if ([string]::IsNullOrWhiteSpace($actionType)) { $actionType = $actionNode.InnerText.Trim() }
        $actionXml = $actionNode.OuterXml
    }
    [pscustomobject]@{
        requested_filter_id = $RequestedId
        filter_id           = Get-NodeText $Node "./*[local-name()='filterId']"
        filter_key          = Get-NodeText $Node "./*[local-name()='filterKey']"
        name                = Get-DisplayName $Node
        description         = Get-NodeText $Node "./*[local-name()='displayData']/*[local-name()='description']"
        flags_text          = $flagsText
        flags_xml           = $flagsXml
        clear_action_right_flag_present = (($null -ne $flagsText -and $flagsText -match 'CLEAR_ACTION_RIGHT') -or ($null -ne $flagsXml -and $flagsXml -match 'CLEAR_ACTION_RIGHT'))
        provider_key        = Get-NodeText $Node "./*[local-name()='providerKey']"
        layer_key           = Get-NodeText $Node "./*[local-name()='layerKey']"
        sublayer_key        = Get-NodeText $Node "./*[local-name()='subLayerKey']"
        provider_context_key = Get-NodeText $Node "./*[local-name()='providerContextKey']"
        weight              = if ($null -ne $weightNode) { Get-NumericValueFromNode $weightNode } else { $null }
        weight_xml          = if ($null -ne $weightNode) { $weightNode.OuterXml } else { $null }
        effective_weight    = if ($null -ne $effectiveWeightNode) { Get-NumericValueFromNode $effectiveWeightNode } else { $null }
        effective_weight_xml = if ($null -ne $effectiveWeightNode) { $effectiveWeightNode.OuterXml } else { $null }
        action_type         = $actionType
        action_xml          = $actionXml
        condition_count     = Get-NodeText $Node "./*[local-name()='numFilterConditions']"
        conditions_xml      = if ($null -ne $conditionsNode) { $conditionsNode.OuterXml } else { $null }
        static_snapshot_limitation = 'Runtime FWPS_RIGHT_ACTION_WRITE during classify is not observable from this static policy snapshot.'
    }
}

function Find-FilterNodeById {
    param(
        [Parameter(Mandatory = $true)][xml]$Xml,
        [Parameter(Mandatory = $true)][string]$Id
    )
    $node = $Xml.SelectSingleNode("//*[local-name()='filter'][.//*[local-name()='filterId' and normalize-space(.)='$Id']]")
    if ($null -ne $node) { return $node }
    $idNode = $Xml.SelectSingleNode("//*[local-name()='filterId' and normalize-space(.)='$Id']")
    while ($null -ne $idNode) {
        if ($idNode.LocalName -eq 'filter') { return $idNode }
        $idNode = $idNode.ParentNode
    }
    return $null
}

if (-not (Test-IsAdministrator)) {
    throw @"
This collector must be run from an Administrator PowerShell window.

It is read-only with respect to WFP/Firewall/registry/services, but the WFP state
query may require elevated access.

Right-click PowerShell -> Run as administrator, then run this script again.
"@
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outputDir = Join-Path $OutputRoot "WLMCP-WFP-PhaseA-$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$statePath = Join-Path $outputDir 'wfpstate.xml'
$summaryPath = Join-Path $outputDir 'summary.json'
$filter70511Path = Join-Path $outputDir 'filter-70511.xml'
$filter70512Path = Join-Path $outputDir 'filter-70512.xml'
$sublayersPath = Join-Path $outputDir 'sublayers-top.json'
$transcriptPath = Join-Path $outputDir 'collector-log.txt'
$hashPath = Join-Path $outputDir 'artifact-sha256.json'

$log = New-Object System.Collections.Generic.List[string]
function Add-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $log.Add($line)
    Write-Host $line
}

Add-Log 'Starting read-only WFP Phase A collection.'
Add-Log "Output directory: $outputDir"

$netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
if (-not (Test-Path -LiteralPath $netsh)) { throw "netsh.exe was not found at: $netsh" }

Add-Log 'Running: netsh wfp show state'
& $netsh wfp show state "file=$statePath"
if ($LASTEXITCODE -ne 0) { throw "netsh wfp show state failed with exit code $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $statePath)) { throw "Expected WFP state file was not created: $statePath" }
if ((Get-Item -LiteralPath $statePath).Length -le 0) { throw "WFP state file is empty: $statePath" }

Add-Log 'Loading WFP XML.'
$xmlText = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8
[xml]$wfp = $xmlText

$sublayerNodes = $wfp.SelectNodes("//*[local-name()='subLayer']")
$sublayers = @()
foreach ($node in $sublayerNodes) {
    $key = Get-NodeText $node "./*[local-name()='subLayerKey']"
    $weightNode = $node.SelectSingleNode("./*[local-name()='weight']")
    if ($null -ne $key -and $null -ne $weightNode) { $sublayers += Get-SublayerObject $node }
}
$sublayers = @($sublayers | Group-Object key | ForEach-Object { $_.Group | Select-Object -First 1 })

$appIsolation = $sublayers | Where-Object { $_.key -eq 'FWPM_SUBLAYER_MPSSVC_APP_ISOLATION' } | Select-Object -First 1
$windowsFirewall = $sublayers | Where-Object { $_.key -eq 'FWPM_SUBLAYER_MPSSVC_WF' } | Select-Object -First 1

if ($null -eq $appIsolation) {
    $candidate = $wfp.SelectSingleNode("//*[local-name()='subLayer'][.//*[contains(normalize-space(.),'MPSSVC_APP_ISOLATION')]]")
    if ($null -ne $candidate) { $appIsolation = Get-SublayerObject $candidate }
}
if ($null -eq $windowsFirewall) {
    $candidate = $wfp.SelectSingleNode("//*[local-name()='subLayer'][.//*[contains(normalize-space(.),'MPSSVC_WF')]]")
    if ($null -ne $candidate) { $windowsFirewall = Get-SublayerObject $candidate }
}

$topSublayers = @($sublayers | Where-Object { $null -ne $_.weight } | Sort-Object -Property @{Expression='weight'; Descending=$true}, @{Expression='key'; Descending=$false} | Select-Object -First 30)
$topSublayers | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $sublayersPath -Encoding UTF8

$filterObjects = @()
foreach ($id in @('70511','70512')) {
    $node = Find-FilterNodeById -Xml $wfp -Id $id
    if ($null -eq $node) {
        Add-Log "Filter $id was not found in the current WFP state."
        $filterObjects += [pscustomobject]@{
            requested_filter_id = $id
            found = $false
            note = 'Filter IDs are runtime-generated and may differ after reboot/BFE policy changes. AppContainerLoopback is also searched by name.'
        }
        continue
    }
    $obj = Get-FilterObject -Node $node -RequestedId $id
    $obj | Add-Member -NotePropertyName found -NotePropertyValue $true
    $filterObjects += $obj
    $filterOut = if ($id -eq '70511') { $filter70511Path } else { $filter70512Path }
    $node.OuterXml | Set-Content -LiteralPath $filterOut -Encoding UTF8
    Add-Log "Captured filter $id."
}

$appContainerLoopbackNodes = $wfp.SelectNodes("//*[local-name()='filter'][.//*[local-name()='name' and contains(normalize-space(.),'AppContainerLoopback')]]")
$appContainerLoopbackFilters = @()
foreach ($node in $appContainerLoopbackNodes) {
    $id = Get-NodeText $node "./*[local-name()='filterId']"
    if ([string]::IsNullOrWhiteSpace($id)) { $id = 'unknown' }
    $appContainerLoopbackFilters += Get-FilterObject -Node $node -RequestedId $id
}

$codexSandboxOffline = $null
try {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $u = Get-LocalUser -Name 'CodexSandboxOffline' -ErrorAction Stop
        $codexSandboxOffline = [pscustomobject]@{ name = $u.Name; sid = $u.SID.Value; enabled = $u.Enabled }
    }
} catch {
    $codexSandboxOffline = [pscustomobject]@{ name = 'CodexSandboxOffline'; sid = $null; enabled = $null; error = $_.Exception.Message }
}

$cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
$mpssvc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue

$appWeight = if ($null -ne $appIsolation) { $appIsolation.weight } else { $null }
$wfWeight = if ($null -ne $windowsFirewall) { $windowsFirewall.weight } else { $null }
$canStrictlyPrecede = $null
$candidateMinimumWeight = $null
if ($null -ne $appWeight) {
    $canStrictlyPrecede = ([UInt64]$appWeight -lt 65535)
    if ($canStrictlyPrecede) { $candidateMinimumWeight = ([UInt64]$appWeight + 1) }
}

$scriptHash = $null
try {
    if (-not [string]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path) -and (Test-Path -LiteralPath $MyInvocation.MyCommand.Path)) {
        $scriptHash = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash
    }
} catch {}

$summary = [ordered]@{
    schema_version = 1
    collector = [ordered]@{
        name = 'Collect-WfpLoopbackPhaseA.ps1'
        collected_at = (Get-Date).ToString('o')
        script_sha256 = $scriptHash
        is_administrator = $true
        mutating_wfp_firewall_registry_service_operations_performed = $false
        filesystem_changes = @("Created report directory: $outputDir", 'Created report files only')
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
        codex_sandbox_offline = $codexSandboxOffline
    }
    target_sublayers = [ordered]@{ app_isolation = $appIsolation; windows_firewall = $windowsFirewall }
    phase_b_gate = [ordered]@{
        app_isolation_weight_found = ($null -ne $appWeight)
        windows_firewall_weight_found = ($null -ne $wfWeight)
        app_isolation_weight = $appWeight
        windows_firewall_weight = $wfWeight
        uint16_max_sublayer_weight = 65535
        can_choose_strictly_higher_numeric_weight_than_app_isolation = $canStrictlyPrecede
        minimum_strictly_higher_numeric_weight = $candidateMinimumWeight
        runtime_action_right_observable_from_static_snapshot = $false
        automatic_phase_b_authorization = $false
        interpretation = if ($null -eq $appWeight) {
            'INCONCLUSIVE: App Isolation sublayer weight was not parsed. Review raw wfpstate.xml before any Phase B experiment.'
        } elseif (-not $canStrictlyPrecede) {
            'STOP: App Isolation is already at UINT16_MAX, so a strictly higher custom sublayer weight cannot be chosen.'
        } else {
            'CANDIDATE ONLY: A numerically higher sublayer weight exists. This does NOT prove a user-mode hard block will beat 70511/70512; arbitration/action-right semantics still require review and a controlled experiment.'
        }
    }
    requested_filters = $filterObjects
    appcontainer_loopback_filters_found_by_name = $appContainerLoopbackFilters
    files = [ordered]@{
        output_directory = $outputDir
        summary_json = $summaryPath
        wfp_state_xml = $statePath
        filter_70511_xml = if (Test-Path -LiteralPath $filter70511Path) { $filter70511Path } else { $null }
        filter_70512_xml = if (Test-Path -LiteralPath $filter70512Path) { $filter70512Path } else { $null }
        top_sublayers_json = $sublayersPath
        collector_log = $transcriptPath
    }
    limitations = @(
        'Filter IDs such as 70511/70512 are runtime IDs and can change; AppContainerLoopback is also searched by display name.',
        'Static FWPM filter state can expose filter flags and policy metadata, but not runtime FWPS_RIGHT_ACTION_WRITE during a particular classify.',
        'A numerically higher sublayer weight is only a prerequisite for the proposed Phase B experiment, not proof that the filter will win arbitration.',
        'This collector performs no live traffic classification test.'
    )
}

$summary | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

$hashes = @()
Get-ChildItem -LiteralPath $outputDir -File | Where-Object { $_.Name -ne 'artifact-sha256.json' } | ForEach-Object {
    $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
    $hashes += [pscustomobject]@{ file = $_.FullName; sha256 = $h.Hash; length = $_.Length }
}
$hashes | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $hashPath -Encoding UTF8

Add-Log 'Collection complete.'
Add-Log 'No WFP/Firewall/registry/service mutation commands were executed.'
$log | Set-Content -LiteralPath $transcriptPath -Encoding UTF8

Write-Host ''
Write-Host '===== WLMCP WFP Phase A Collector Result ====='
Write-Host ("OUTPUT_DIR      = {0}" -f $outputDir)
Write-Host ("SUMMARY_JSON    = {0}" -f $summaryPath)
Write-Host ("WFP_STATE_XML   = {0}" -f $statePath)
Write-Host ("TOP_SUBLAYERS   = {0}" -f $sublayersPath)
Write-Host ("ARTIFACT_HASHES = {0}" -f $hashPath)
Write-Host ''
if ($null -ne $appWeight) { Write-Host ("APP_ISOLATION_WEIGHT = {0}" -f $appWeight) } else { Write-Warning 'APP_ISOLATION_WEIGHT could not be parsed. Do not proceed to Phase B based on this run alone.' }
if ($null -ne $wfWeight) { Write-Host ("WINDOWS_FIREWALL_WEIGHT = {0}" -f $wfWeight) }
if ($null -eq $appWeight) { Write-Host 'PHASE_B_GATE = INCONCLUSIVE' }
elseif (-not $canStrictlyPrecede) { Write-Host 'PHASE_B_GATE = STOP (no strictly higher UINT16 weight exists)' }
else { Write-Host 'PHASE_B_GATE = CANDIDATE_ONLY (manual review required; do not auto-run Phase B)' }
