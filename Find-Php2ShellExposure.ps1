#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Inventories Azure PHP workloads for PHP2Shell exposure (CVE-2026-109618 / CVE-2026-109619).

.DESCRIPTION
    Uses Azure Resource Graph to enumerate every subscription the signed-in identity can read,
    then reads ARM configuration for each App Service site and slot.

    Covered:
      - App Service and Function Apps (sites and slots): built-in Linux PHP stack, Windows PHP
        handler, custom containers (DOCKER/COMPOSE/Windows), and sidecar (sitecontainers) apps
      - Azure Container Apps and Container Apps Jobs
      - Azure Container Instances

    Not covered (counts are printed at the end): AKS workloads, VMs, VM scale sets.

    Fixed upstream PHP releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Branches 8.1 and older are EOL.

    Container images are classified by image name only. An image without "php" in its name can
    still contain PHP, so "Unknown" rows need image inspection or a vulnerability scan.

.PARAMETER SubscriptionId
    Limit the scan to specific subscriptions. Default is all subscriptions in the tenant.

.PARAMETER PhpOnly
    Suppress container rows whose image name gives no PHP signal.

.PARAMETER WebApiVersion
    Microsoft.Web API version. Default is the newest non-preview version the provider reports.

.EXAMPLE
    ./Find-Php2ShellExposure.ps1
    ./Find-Php2ShellExposure.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -PhpOnly
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [switch]$PhpOnly,
    [string]$WebApiVersion,
    [string]$PhpImagePattern = 'php|wordpress|drupal|magento|laravel|symfony|moodle|nextcloud|joomla|mediawiki|matomo|prestashop|opencart|phpbb',
    [string]$OutputPath = (Join-Path $HOME ('php2shell-inventory-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date)))
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

function Get-Arm {
    param([string]$Path)
    $r = Invoke-AzRestMethod -Method GET -Path $Path
    if ($r.StatusCode -ne 200) { Write-Warning "GET $Path returned $($r.StatusCode)"; return $null }
    $r.Content | ConvertFrom-Json -Depth 20
}

# Property name is matched loosely so the script works whether the RP surfaces the setting
# on the site object or in siteConfig, and regardless of exact casing.
function Find-ReleaseChannel {
    param($Obj)
    if (-not $Obj) { return $null }
    $hit = $Obj.PSObject.Properties | Where-Object { $_.Name -match 'release.?channel' } | Select-Object -First 1
    if ($hit -and $hit.Value) { return [string]$hit.Value }
    if ($Obj.PSObject.Properties['siteConfig'] -and $Obj.siteConfig) { return Find-ReleaseChannel $Obj.siteConfig }
    $null
}

function Get-BuiltInAssessment {
    param([string]$Version, [string]$Channel)
    $mm = (($Version -split '\.')[0..1]) -join '.'
    if (-not $Fixed.ContainsKey($mm)) {
        return "EOL branch ($Version). No upstream fix. Change the stack to PHP 8.3 or later."
    }
    $msg = "Platform-managed. Vulnerable until App Service rolls PHP $($Fixed[$mm]) or later to this app's channel. Verify with 'php -v' over SSH."
    switch -Regex ($Channel) {
        'Extended' { "HIGH: Extended channel lags Standard. $msg" }
        'Latest'   { "Latest channel receives patches first. $msg" }
        default    { $msg }
    }
}

function Get-ContainerAssessment {
    param([string]$Image)
    if ($Image -match 'mcr\.microsoft\.com/appsvc/wordpress') {
        'LIKELY PHP. Microsoft WordPress on App Service image. Confirm Microsoft has published a fixed tag and that the app has pulled it.'
    }
    elseif ($Image -match $PhpImagePattern) {
        'LIKELY PHP (image name). Customer-owned image. Rebuild on a fixed PHP base and redeploy.'
    }
    else {
        'Unknown. Image name gives no PHP signal. Inspect the image or check container vulnerability findings.'
    }
}

function Add-Row {
    param([System.Collections.IDictionary]$Base, [hashtable]$Set)
    $h = [ordered]@{}
    foreach ($k in $Base.Keys) { $h[$k] = $Base[$k] }
    foreach ($k in $Set.Keys)  { $h[$k] = $Set[$k] }
    $script:rows.Add([pscustomobject]$h)
}

function Test-Skip {
    param([string]$Image)
    $PhpOnly -and $Image -notmatch $PhpImagePattern
}
#endregion

#region Setup
if (-not (Get-AzContext)) { Connect-AzAccount -UseDeviceAuthentication | Out-Null }

if (-not $WebApiVersion) {
    $WebApiVersion = (Get-AzResourceProvider -ProviderNamespace Microsoft.Web).ResourceTypes |
        Where-Object ResourceTypeName -eq 'sites' |
        ForEach-Object ApiVersions |
        Where-Object { $_ -notmatch 'preview' } |
        Sort-Object -Descending -Unique |
        Select-Object -First 1
}
Write-Host "Microsoft.Web API version: $WebApiVersion" -ForegroundColor Cyan

$subNames = @{}
Get-AzSubscription -WarningAction SilentlyContinue | ForEach-Object { $subNames[$_.Id] = $_.Name }
#endregion

#region App Service sites and slots
$sites = Invoke-Arg @'
resources
| where type in~ ('microsoft.web/sites', 'microsoft.web/sites/slots')
| where kind !contains 'workflowapp'
| project id, name, type, kind, resourceGroup, subscriptionId, properties
'@
Write-Host "App Service sites and slots found: $($sites.Count)" -ForegroundColor Cyan

$i = 0
foreach ($s in $sites) {
    $i++
    Write-Progress -Activity 'Reading App Service configuration' -Status $s.name -PercentComplete (100 * $i / $sites.Count)

    $cfgDoc = Get-Arm "$($s.id)/config/web?api-version=$WebApiVersion"
    if (-not $cfgDoc) { continue }
    $cfg = $cfgDoc.properties
    $p   = $s.properties

    $linuxFx = [string]$cfg.linuxFxVersion
    $winFx   = [string]$cfg.windowsFxVersion
    $siteIsLinux = [bool]$p.reserved -or $s.kind -match 'linux'

    $restricted = $cfg.ipSecurityRestrictionsDefaultAction -eq 'Deny' -or
        [bool]($cfg.ipSecurityRestrictions | Where-Object { $_.action -eq 'Allow' -and $_.ipAddress -ne 'Any' })
    $access = if ($p.publicNetworkAccess -eq 'Disabled') { 'Disabled' }
              elseif ($restricted) { 'Restricted' }
              else { 'Open' }

    $base = [ordered]@{
        Subscription   = $subNames[$s.subscriptionId] ?? $s.subscriptionId
        ResourceGroup  = $s.resourceGroup
        Name           = $s.name
        Service        = if ($s.type -match 'slots') { 'App Service slot' } else { 'App Service' }
        Kind           = $s.kind
        OS             = if ($siteIsLinux) { 'Linux' } else { 'Windows' }
        Hosting        = $null
        PhpStack       = $null
        Image          = $null
        ReleaseChannel = $null
        PublicAccess   = $access
        State          = $p.state
        Assessment     = $null
        ResourceId     = $s.id
    }

    if ($linuxFx -match '^PHP\|(.+)$') {
        $ver  = $Matches[1]
        $chan = (Find-ReleaseChannel $p) ?? (Find-ReleaseChannel $cfg)
        if (-not $chan) {
            $siteDoc = Get-Arm "$($s.id)?api-version=$WebApiVersion"
            if ($siteDoc) { $chan = Find-ReleaseChannel $siteDoc.properties }
        }
        $chan = $chan ?? 'Not returned (default is Standard)'
        Add-Row $base @{
            Hosting        = 'Built-in PHP'
            PhpStack       = $ver
            ReleaseChannel = $chan
            Assessment     = Get-BuiltInAssessment $ver $chan
        }
    }
    elseif ($linuxFx -match '^(DOCKER|COMPOSE)\|(.+)$') {
        $fxKind = $Matches[1]; $fxVal = $Matches[2]
        $images = if ($fxKind -eq 'COMPOSE') {
            try {
                $yaml = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($fxVal))
                [regex]::Matches($yaml, '(?m)^\s*image:\s*["'']?([^"''\s]+)') | ForEach-Object { $_.Groups[1].Value }
            } catch { 'COMPOSE (could not decode)' }
        } else { $fxVal }
        foreach ($img in $images) {
            if (Test-Skip $img) { continue }
            Add-Row $base @{
                Hosting        = "Custom container ($fxKind)"
                Image          = $img
                ReleaseChannel = 'N/A (customer image)'
                Assessment     = Get-ContainerAssessment $img
            }
        }
    }
    elseif ($linuxFx -eq 'SITECONTAINERS') {
        $scDoc = Get-Arm "$($s.id)/sitecontainers?api-version=$WebApiVersion"
        foreach ($c in $scDoc.value) {
            $img = [string]$c.properties.image
            if (Test-Skip $img) { continue }
            $role = if ($c.properties.isMain) { 'main' } else { 'sidecar' }
            Add-Row $base @{
                Hosting        = "Custom container (sitecontainers, $role)"
                Image          = $img
                ReleaseChannel = 'N/A (customer image)'
                Assessment     = Get-ContainerAssessment $img
            }
        }
    }
    elseif ($winFx -match '^DOCKER\|(.+)$') {
        $img = $Matches[1]
        if (-not (Test-Skip $img)) {
            Add-Row $base @{
                Hosting        = 'Custom container (Windows)'
                Image          = $img
                ReleaseChannel = 'N/A (customer image)'
                Assessment     = Get-ContainerAssessment $img
            }
        }
    }
    elseif (-not $siteIsLinux -and [string]$cfg.phpVersion -match '^\d') {
        Add-Row $base @{
            Hosting        = 'Windows PHP handler'
            PhpStack       = $cfg.phpVersion
            ReleaseChannel = 'N/A (Linux only)'
            Assessment     = "PHP $($cfg.phpVersion) handler is enabled on a Windows app. Windows PHP is not a supported App Service stack and receives no fix. Set PHP to Off if unused; migrate to Linux if used."
        }
    }
}
Write-Progress -Activity 'Reading App Service configuration' -Completed
#endregion

#region Container Apps and Jobs
$aca = Invoke-Arg @'
resources
| where type in~ ('microsoft.app/containerapps', 'microsoft.app/jobs')
| mv-expand c = properties.template.containers
| project id, name, type, resourceGroup, subscriptionId,
    image    = tostring(c.image),
    hasIngress = isnotnull(properties.configuration.ingress),
    external = tobool(properties.configuration.ingress.external),
    state    = tostring(properties.runningStatus)
'@
foreach ($a in $aca) {
    if (Test-Skip $a.image) { continue }
    $access = if ($a.type -match 'jobs') { 'No ingress (job)' }
              elseif (-not $a.hasIngress) { 'No ingress' }
              elseif ($a.external) { 'External ingress' }
              else { 'Internal ingress' }
    $rows.Add([pscustomobject][ordered]@{
        Subscription   = $subNames[$a.subscriptionId] ?? $a.subscriptionId
        ResourceGroup  = $a.resourceGroup
        Name           = $a.name
        Service        = if ($a.type -match 'jobs') { 'Container Apps job' } else { 'Container App' }
        Kind           = $null
        OS             = 'Linux'
        Hosting        = 'Custom container'
        PhpStack       = $null
        Image          = $a.image
        ReleaseChannel = 'N/A (customer image)'
        PublicAccess   = $access
        State          = $a.state
        Assessment     = Get-ContainerAssessment $a.image
        ResourceId     = $a.id
    })
}
#endregion

#region Container Instances
$aci = Invoke-Arg @'
resources
| where type =~ 'microsoft.containerinstance/containergroups'
| mv-expand c = properties.containers
| project id, name, resourceGroup, subscriptionId,
    image  = tostring(c.properties.image),
    ipType = tostring(properties.ipAddress.type),
    osType = tostring(properties.osType),
    state  = tostring(properties.instanceView.state)
'@
foreach ($c in $aci) {
    if (Test-Skip $c.image) { continue }
    $rows.Add([pscustomobject][ordered]@{
        Subscription   = $subNames[$c.subscriptionId] ?? $c.subscriptionId
        ResourceGroup  = $c.resourceGroup
        Name           = $c.name
        Service        = 'Container Instances'
        Kind           = $null
        OS             = $c.osType
        Hosting        = 'Custom container'
        PhpStack       = $null
        Image          = $c.image
        ReleaseChannel = 'N/A (customer image)'
        PublicAccess   = if ($c.ipType) { "$($c.ipType) IP" } else { 'No IP' }
        State          = $c.state
        Assessment     = Get-ContainerAssessment $c.image
        ResourceId     = $c.id
    })
}
#endregion

#region Output
$sorted = $rows | Sort-Object @{ Expression = { $_.Assessment -match '^(HIGH|EOL|LIKELY)' }; Descending = $true }, Subscription, Name
$sorted | Export-Csv -Path $OutputPath -NoTypeInformation

$sorted | Format-Table Subscription, Name, Service, Hosting, PhpStack, Image, ReleaseChannel, PublicAccess -AutoSize -Wrap

Write-Host ''
Write-Host 'Summary' -ForegroundColor Cyan
$rows | Group-Object Hosting | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize

$notScanned = Invoke-Arg @'
resources
| where type in~ ('microsoft.containerservice/managedclusters',
                  'microsoft.compute/virtualmachines',
                  'microsoft.compute/virtualmachinescalesets')
| summarize Count = count() by Type = type
'@
if ($notScanned.Count) {
    Write-Host 'Not scanned by this script (check with Defender for Cloud vulnerability findings or in-guest tooling):' -ForegroundColor Yellow
    $notScanned | Format-Table Type, Count -AutoSize
}

Write-Host "CSV written to $OutputPath" -ForegroundColor Green
#endregion
