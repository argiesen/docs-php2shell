#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Uses Microsoft Defender for Cloud data to find PHP on Azure VMs, VM scale sets, and
    Azure Arc machines, and to assess PHP2Shell exposure (CVE-2026-109618 / CVE-2026-109619).

.DESCRIPTION
    All data comes from Azure Resource Graph, so nothing runs on the machines.

      - Machines:            resources (virtualMachines, virtualMachineScaleSets, hybridCompute/machines)
      - Defender plan:       securityresources, microsoft.security/pricings (VirtualMachines)
      - Software inventory:  securityresources, microsoft.security/softwareinventories
                             (Defender Vulnerability Management, Defender for Servers)
      - CVE findings:        securityresources, assessments/subassessments mentioning either CVE

    Every machine is reported. Machines with no software inventory are marked as a coverage gap,
    because "no PHP found" is meaningless without inventory.

    Fixed upstream PHP releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Branches 8.1 and older are EOL.

.PARAMETER PhpOnly
    Omit machines with inventory and no PHP. Coverage-gap machines are still reported.

.EXAMPLE
    ./Find-Php2ShellVms.ps1
    ./Find-Php2ShellVms.ps1 -PhpOnly
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [switch]$PhpOnly,
    [string]$SoftwarePattern = 'php',
    [string]$OutputPath = (Join-Path $HOME ('php2shell-vms-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date)))
)

$ErrorActionPreference = 'Stop'
$Fixed = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }
$rows  = [System.Collections.Generic.List[object]]::new()

#region Helpers
function Invoke-Arg {
    param([string]$Query)
    $out  = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $p = @{ Query = $Query; First = 1000 }
        if ($SubscriptionId) { $p.Subscription = $SubscriptionId } else { $p.UseTenantScope = $true }
        if ($skip) { $p.SkipToken = $skip }
        $r = Search-AzGraph @p
        if ($r.Data) { $out.AddRange([object[]]$r.Data) }
        $skip = $r.SkipToken
    } while ($skip)
    , $out
}

# Normalizes a Defender child resource ID to the machine it belongs to.
# Scale set instance IDs roll up to the scale set.
function Get-MachineKey {
    param([string]$Id)
    $k = $Id.ToLowerInvariant()
    $i = $k.IndexOf('/providers/microsoft.security/')
    if ($i -gt 0) { $k = $k.Substring(0, $i) }
    if ($k -match '^(.+/virtualmachinescalesets/[^/]+)/virtualmachines/') { $k = $Matches[1] }
    $k
}

function Get-VersionAssessment {
    param([string]$Software, [string]$Version)
    if ($Software -notmatch '^php$|^php[0-9.]*(-|$)|php_') {
        return "PHP-related software ($Software). Confirm the PHP runtime version on this machine."
    }
    if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') { return "PHP detected, unparsed version '$Version'. Review manually." }
    $mm  = "$($Matches[1]).$($Matches[2])"
    $cur = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
    $note = ' If PHP came from distro packages, confirm the package revision; distros backport fixes without changing the upstream version.'
    if (-not $Fixed.ContainsKey($mm)) { return "VULNERABLE: EOL branch $Version. No upstream fix.$note" }
    if ($cur -ge [version]$Fixed[$mm]) { return "Patched: $Version meets $($Fixed[$mm])." }
    "VULNERABLE: $Version is below $($Fixed[$mm]).$note"
}
#endregion

#region Data collection
$subNames = @{}
Get-AzSubscription -WarningAction SilentlyContinue | ForEach-Object { $subNames[$_.Id] = $_.Name }

Write-Host 'Reading machines...' -ForegroundColor Cyan
$machines = Invoke-Arg @'
resources
| where type in~ ('microsoft.compute/virtualmachines',
                  'microsoft.compute/virtualmachinescalesets',
                  'microsoft.hybridcompute/machines')
| project id = tolower(id), name, type, resourceGroup, subscriptionId,
    os = coalesce(tostring(properties.storageProfile.osDisk.osType),
                  tostring(properties.virtualMachineProfile.storageProfile.osDisk.osType),
                  tostring(properties.osType)),
    power = coalesce(tostring(properties.extended.instanceView.powerState.code),
                     tostring(properties.status))
'@

Write-Host 'Reading Defender for Servers plan status...' -ForegroundColor Cyan
$plans = @{}
Invoke-Arg @'
securityresources
| where type =~ 'microsoft.security/pricings' and name =~ 'VirtualMachines'
| project subscriptionId, tier = tostring(properties.pricingTier), subPlan = tostring(properties.subPlan)
'@ | ForEach-Object {
    $plans[$_.subscriptionId] = if ($_.tier -eq 'Standard') { "Servers $($_.subPlan)".Trim() } else { 'Off' }
}

Write-Host 'Reading Defender software inventory...' -ForegroundColor Cyan
$inventoried = [System.Collections.Generic.HashSet[string]]::new()
Invoke-Arg @'
securityresources
| where type =~ 'microsoft.security/softwareinventories'
| extend lid = tolower(id)
| project machine = substring(lid, 0, indexof(lid, '/providers/microsoft.security/'))
| distinct machine
'@ | ForEach-Object { [void]$inventoried.Add((Get-MachineKey $_.machine)) }

$software = Invoke-Arg @"
securityresources
| where type =~ 'microsoft.security/softwareinventories'
| where tostring(properties.softwareName) matches regex @'(?i)$SoftwarePattern'
| project id, vendor = tostring(properties.vendor),
    software = tostring(properties.softwareName),
    version  = tostring(properties.version)
"@

Write-Host 'Reading Defender CVE findings...' -ForegroundColor Cyan
$findings = Invoke-Arg @'
securityresources
| where type =~ 'microsoft.security/assessments/subassessments'
| where tostring(properties) contains 'CVE-2026-109618' or tostring(properties) contains 'CVE-2026-109619'
| project id, resourceId = tostring(properties.resourceDetails.id),
    cve    = extract(@'(CVE-2026-10961[89])', 1, tostring(properties)),
    status = tostring(properties.status.code)
'@
#endregion

#region Join
$swByMachine = @{}
foreach ($s in $software) {
    $key = Get-MachineKey $s.id
    if (-not $swByMachine.ContainsKey($key)) { $swByMachine[$key] = [System.Collections.Generic.List[object]]::new() }
    $swByMachine[$key].Add($s)
}

$cveByMachine = @{}
foreach ($f in $findings) {
    $key = Get-MachineKey ($f.resourceId ? $f.resourceId : $f.id)
    $cveByMachine[$key] = (@($cveByMachine[$key], "$($f.cve) ($($f.status))") | Where-Object { $_ }) -join '; '
}

foreach ($m in $machines) {
    $base = [ordered]@{
        Subscription = $subNames[$m.subscriptionId] ?? $m.subscriptionId
        ResourceGroup = $m.resourceGroup
        Machine      = $m.name
        Type         = switch -Regex ($m.type) { 'scalesets' { 'VM scale set' } 'hybridcompute' { 'Arc machine' } default { 'VM' } }
        OS           = $m.os
        PowerState   = ($m.power -replace '^PowerState/', '')
        DefenderPlan = $plans[$m.subscriptionId] ?? 'Unknown'
        Inventory    = if ($inventoried.Contains($m.id)) { 'Yes' } else { 'No' }
        Software     = $null
        Version      = $null
        CveFinding   = $cveByMachine[$m.id]
        Assessment   = $null
        ResourceId   = $m.id
    }

    $sw = $swByMachine[$m.id]
    if ($sw) {
        foreach ($s in $sw) {
            $h = [ordered]@{}; foreach ($k in $base.Keys) { $h[$k] = $base[$k] }
            $h.Software   = $s.software
            $h.Version    = $s.version
            $h.Assessment = Get-VersionAssessment $s.software $s.version
            if ($h.CveFinding) { $h.Assessment = "VULNERABLE (Defender finding). $($h.Assessment)" }
            $rows.Add([pscustomobject]$h)
        }
        continue
    }

    if ($base.CveFinding) {
        $base.Assessment = 'VULNERABLE (Defender finding). PHP not matched in inventory; review the finding.'
    }
    elseif ($base.Inventory -eq 'No') {
        $base.Assessment = 'COVERAGE GAP: no Defender software inventory. PHP status unknown.'
    }
    elseif ($PhpOnly) { continue }
    else { $base.Assessment = 'No PHP in Defender inventory.' }

    $rows.Add([pscustomobject]$base)
}
#endregion

#region Output
$sorted = $rows | Sort-Object `
    @{ Expression = { switch -Regex ($_.Assessment) { '^VULNERABLE' { 0 } '^PHP' { 1 } '^COVERAGE' { 2 } '^Patched' { 3 } default { 4 } } } },
    Subscription, Machine

$sorted | Export-Csv -Path $OutputPath -NoTypeInformation

$sorted | Where-Object { $_.Software -or $_.CveFinding } |
    Format-Table Subscription, Machine, Type, OS, Software, Version, CveFinding, Assessment -AutoSize -Wrap

Write-Host 'Coverage' -ForegroundColor Cyan
$total   = $machines.Count
$covered = ($machines | Where-Object { $inventoried.Contains($_.id) }).Count
$phpHits = ($rows | Where-Object Software | Select-Object -ExpandProperty ResourceId -Unique).Count
[pscustomobject]@{
    Machines             = $total
    WithInventory        = $covered
    WithoutInventory     = $total - $covered
    MachinesWithPhp      = $phpHits
    DefenderCveFindings  = $findings.Count
} | Format-List

$machines | Group-Object { $plans[$_.subscriptionId] ?? 'Unknown' } |
    Select-Object @{ n = 'DefenderPlan'; e = { $_.Name } }, Count | Format-Table -AutoSize

if (-not $findings.Count) {
    Write-Host 'No Defender findings reference either CVE yet. Treat this as unknown until Defender Vulnerability Management adds them.' -ForegroundColor Yellow
}
Write-Host "CSV written to $OutputPath" -ForegroundColor Green
#endregion
