#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.ResourceGraph
<#
.SYNOPSIS
    Inventories AKS workloads for PHP2Shell exposure (CVE-2026-109618 / CVE-2026-109619).

.DESCRIPTION
    Enumerates AKS clusters with Azure Resource Graph, then reads pods, services, and ingresses
    from each cluster with kubectl. One row is produced per workload + container + image,
    not per pod replica.

    Detection layers:
      1. Image name heuristic (always).
      2. Optional in-container probe (-ProbePhp): runs a read-only shell command in one running
         pod per workload to report the PHP version and, on Debian/Ubuntu images, the distro
         package version. Requires pods/exec rights and a shell in the image.
      3. Defender for Cloud container vulnerability findings that reference either CVE.

    Exposure is derived from LoadBalancer and NodePort services and Ingress backends that select
    the pod. Gateway API routes and service mesh gateways are not evaluated.

    Fixed upstream PHP releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Branches 8.1 and older are EOL.

.PARAMETER ProbePhp
    Exec into one running pod per workload to read the PHP version.

.PARAMETER CommandInvokeFallback
    If direct kubectl access fails (for example, a private API server), retry the read with
    'az aks command invoke'. This creates a short-lived pod in the aks-command namespace.
    The PHP probe does not run in this mode.

.PARAMETER IncludeSystemNamespaces
    Include kube-system and other platform namespaces.

.EXAMPLE
    ./Find-Php2ShellAks.ps1
    ./Find-Php2ShellAks.ps1 -ProbePhp -CommandInvokeFallback
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [switch]$ProbePhp,
    [switch]$CommandInvokeFallback,
    [switch]$IncludeSystemNamespaces,
    [string]$PhpImagePattern = 'php|wordpress|drupal|magento|laravel|symfony|moodle|nextcloud|joomla|mediawiki|matomo|prestashop|opencart|phpbb',
    [string]$OutputPath = (Join-Path $HOME ('php2shell-aks-{0:yyyyMMdd-HHmm}.csv' -f (Get-Date)))
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$Fixed    = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }
$SystemNs = @('kube-system', 'kube-public', 'kube-node-lease', 'gatekeeper-system', 'calico-system',
              'tigera-operator', 'aks-command', 'aks-istio-system', 'app-routing-system')

# Prints "<php version or NOPHP>|<debian package=version list>"
$ProbeScript = 'v=$(php -r "echo PHP_VERSION;" 2>/dev/null); [ -z "$v" ] && v=$(php-fpm -v 2>/dev/null | head -n1 | cut -d" " -f2); [ -z "$v" ] && v="$PHP_VERSION"; p=$(dpkg-query -W -f="\${Package}=\${Version} " "php*-common" 2>/dev/null); echo "${v:-NOPHP}|$p"'

$rows          = [System.Collections.Generic.List[object]]::new()
$clusterStatus = [System.Collections.Generic.List[object]]::new()

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

function Invoke-Kubectl {
    param([string]$Kubeconfig, [string[]]$KubectlArgs)
    $errFile = [IO.Path]::GetTempFileName()
    try {
        $out = & kubectl --kubeconfig $Kubeconfig --request-timeout=30s @KubectlArgs 2> $errFile
        if ($LASTEXITCODE -ne 0) { throw ((Get-Content $errFile -Raw) ?? "kubectl exit $LASTEXITCODE") }
        $out -join "`n"
    }
    finally { Remove-Item $errFile -ErrorAction SilentlyContinue }
}

function Invoke-AksCommand {
    param($Cluster, [string]$Command)
    $raw = az aks command invoke -g $Cluster.resourceGroup -n $Cluster.name --subscription $Cluster.subscriptionId `
        --command $Command -o json --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'az aks command invoke failed' }
    $r = ($raw | Out-String) | ConvertFrom-Json
    if ($r.exitCode -ne 0) { throw "command invoke exit $($r.exitCode): $($r.logs)" }
    $r.logs
}

function Test-Selects {
    param($Svc, $Pod)
    $sel = $Svc.spec.selector
    $lbl = $Pod.metadata.labels
    if (-not $sel -or -not $lbl) { return $false }
    foreach ($k in $sel.PSObject.Properties) {
        if ($lbl.($k.Name) -ne $k.Value) { return $false }
    }
    $true
}

function Get-Exposure {
    param($Pod, $Services, [hashtable]$IngressBackends)
    $ns   = $Pod.metadata.namespace
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($svc in $Services) {
        if ($svc.metadata.namespace -ne $ns -or -not (Test-Selects $svc $Pod)) { continue }
        $name = $svc.metadata.name
        switch ($svc.spec.type) {
            'LoadBalancer' {
                $internal = $svc.metadata.annotations.'service.beta.kubernetes.io/azure-load-balancer-internal' -eq 'true'
                $hits.Add($(if ($internal) { "Internal LB:$name" } else { "Public LB:$name" }))
            }
            'NodePort' { $hits.Add("NodePort:$name") }
        }
        if ($IngressBackends.ContainsKey("$ns/$name")) { $hits.Add("Ingress:$name") }
    }
    if ($hits.Count) { ($hits | Select-Object -Unique) -join '; ' } else { 'No LB/NodePort/Ingress found' }
}

function Get-NameAssessment {
    param([string]$Image)
    if ($Image -match $PhpImagePattern) { 'LIKELY PHP (image name). Rebuild on a fixed PHP base and redeploy.' }
    else { 'Unknown. Image name gives no PHP signal.' }
}

function Get-ProbeAssessment {
    param([string]$Raw)
    $ver, $pkg = $Raw.Trim() -split '\|', 2
    $pkg = $pkg.Trim()
    if ($ver -eq 'NOPHP') { return 'No PHP found in container.' }
    if ($ver -notmatch '^(\d+)\.(\d+)\.(\d+)') { return "PHP detected, unparsed version '$ver'. Review manually." }
    $mm  = "$($Matches[1]).$($Matches[2])"
    $cur = [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])"
    $a = if (-not $Fixed.ContainsKey($mm)) { "VULNERABLE: EOL branch $ver. No upstream fix." }
         elseif ($cur -ge [version]$Fixed[$mm]) { "Patched: $ver meets $($Fixed[$mm])." }
         else { "VULNERABLE: $ver is below $($Fixed[$mm])." }
    if ($pkg) {
        $a += " Distro package: $pkg. Distros backport fixes without changing the upstream version, so confirm the package revision against the vendor advisory."
    }
    $a
}
#endregion

#region Clusters
$subNames = @{}
Get-AzSubscription -WarningAction SilentlyContinue | ForEach-Object { $subNames[$_.Id] = $_.Name }

$clusters = Invoke-Arg @'
resources
| where type =~ 'microsoft.containerservice/managedclusters'
| project id, name, resourceGroup, subscriptionId,
    power     = tostring(properties.powerState.code),
    isPrivate = tobool(properties.apiServerAccessProfile.enablePrivateCluster),
    aad       = isnotnull(properties.aadProfile)
'@
Write-Host "AKS clusters found: $($clusters.Count)" -ForegroundColor Cyan

foreach ($k in $clusters) {
    $subName = $subNames[$k.subscriptionId] ?? $k.subscriptionId
    Write-Host "Scanning $($k.name)..." -ForegroundColor Cyan

    if ($k.power -eq 'Stopped') {
        $clusterStatus.Add([pscustomobject]@{ Cluster = $k.name; Mode = '-'; Result = 'Skipped: cluster stopped' })
        continue
    }

    $mode = $null; $json = $null; $directError = $null
    $kc = Join-Path ([IO.Path]::GetTempPath()) "kc-$([guid]::NewGuid()).yaml"
    try {
        try {
            az aks get-credentials -g $k.resourceGroup -n $k.name --subscription $k.subscriptionId `
                --file $kc --overwrite-existing --only-show-errors 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'get-credentials failed (needs Cluster User role)' }
            if ($k.aad) { kubelogin convert-kubeconfig -l azurecli --kubeconfig $kc 2>$null | Out-Null }
            $json = Invoke-Kubectl $kc @('get', 'pods,services,ingresses.networking.k8s.io', '-A', '-o', 'json')
            $mode = 'kubectl'
        }
        catch {
            $directError = ($_.Exception.Message -split "`n")[0]
            if ($CommandInvokeFallback) {
                try {
                    $json = Invoke-AksCommand $k 'kubectl get pods,services,ingresses.networking.k8s.io -A -o json'
                    $mode = 'command invoke'
                }
                catch { $directError += " | fallback: $(($_.Exception.Message -split "`n")[0])" }
            }
        }

        if (-not $mode) {
            $hint = if ($k.isPrivate -and -not $CommandInvokeFallback) { ' (private cluster: rerun with -CommandInvokeFallback)' } else { '' }
            $clusterStatus.Add([pscustomobject]@{ Cluster = $k.name; Mode = '-'; Result = "FAILED: $directError$hint" })
            continue
        }

        $items = ($json | ConvertFrom-Json -Depth 64).items
        $pods  = $items | Where-Object kind -eq 'Pod'
        $svcs  = $items | Where-Object kind -eq 'Service'
        $ings  = $items | Where-Object kind -eq 'Ingress'

        $ingressBackends = @{}
        foreach ($ing in $ings) {
            $ns = $ing.metadata.namespace
            $names = @($ing.spec.defaultBackend.service.name) +
                     @($ing.spec.rules | ForEach-Object { $_.http.paths } | ForEach-Object { $_.backend.service.name })
            foreach ($n in ($names | Where-Object { $_ })) { $ingressBackends["$ns/$n"] = $true }
        }

        # Group pod containers into workloads
        $groups = [ordered]@{}
        foreach ($pod in $pods) {
            $ns = $pod.metadata.namespace
            if (-not $IncludeSystemNamespaces -and $ns -in $SystemNs) { continue }

            $owner = $pod.metadata.ownerReferences | Select-Object -First 1
            $wl = if (-not $owner) { "Pod/$($pod.metadata.name)" }
                  elseif ($owner.kind -eq 'ReplicaSet') { "Deployment/$($owner.name -replace '-[a-z0-9]{6,10}$', '')" }
                  else { "$($owner.kind)/$($owner.name)" }

            $exposure = Get-Exposure $pod $svcs $ingressBackends
            $statuses = @($pod.status.containerStatuses; $pod.status.initContainerStatuses) | Where-Object { $_ }
            $specs    = @(
                $pod.spec.containers     | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ C = $_; Init = $false } }
                $pod.spec.initContainers | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ C = $_; Init = $true } }
            )

            foreach ($s in $specs) {
                $key = "$ns|$wl|$($s.C.name)|$($s.C.image)"
                if (-not $groups.Contains($key)) {
                    $groups[$key] = [pscustomobject]@{
                        Namespace = $ns; Workload = $wl; Container = $s.C.name; Init = $s.Init
                        Image     = $s.C.image
                        Digest    = ($statuses | Where-Object name -eq $s.C.name | Select-Object -First 1).imageID
                        Exposure  = $exposure
                        Running   = [System.Collections.Generic.List[string]]::new()
                        PodCount  = 0
                    }
                }
                $g = $groups[$key]
                $g.PodCount++
                if ($pod.status.phase -eq 'Running') { $g.Running.Add($pod.metadata.name) }
            }
        }

        foreach ($g in $groups.Values) {
            $php = 'Not probed'
            $assessment = Get-NameAssessment $g.Image

            if ($ProbePhp -and $mode -eq 'kubectl' -and -not $g.Init -and $g.Running.Count) {
                try {
                    $raw = Invoke-Kubectl $kc @('exec', '-n', $g.Namespace, $g.Running[0], '-c', $g.Container, '--', 'sh', '-c', $ProbeScript)
                    $php = ($raw.Trim() -split '\|')[0]
                    $assessment = Get-ProbeAssessment $raw
                }
                catch {
                    $php = 'Probe failed'
                    $assessment += ' Probe failed (no shell in image, or no exec rights).'
                }
            }

            $rows.Add([pscustomobject][ordered]@{
                Subscription = $subName
                Cluster      = $k.name
                Namespace    = $g.Namespace
                Workload     = $g.Workload
                Container    = if ($g.Init) { "$($g.Container) (init)" } else { $g.Container }
                Pods         = $g.PodCount
                Image        = $g.Image
                ImageDigest  = $g.Digest
                Exposure     = $g.Exposure
                PhpDetected  = $php
                Assessment   = $assessment
            })
        }

        $clusterStatus.Add([pscustomobject]@{ Cluster = $k.name; Mode = $mode; Result = "OK: $($groups.Count) workload containers" })
    }
    finally { Remove-Item $kc -ErrorAction SilentlyContinue }
}
#endregion

#region Output
$sorted = $rows | Sort-Object `
    @{ Expression = { if ($_.Assessment -match '^VULNERABLE') { 0 } elseif ($_.Assessment -match '^LIKELY') { 1 } elseif ($_.PhpDetected -match '^\d') { 2 } else { 3 } } },
    @{ Expression = { $_.Exposure -match 'Public LB|Ingress|NodePort' }; Descending = $true },
    Cluster, Namespace, Workload

$sorted | Export-Csv -Path $OutputPath -NoTypeInformation
$sorted | Where-Object { $_.Assessment -notmatch '^No PHP' } |
    Format-Table Cluster, Namespace, Workload, Container, Image, Exposure, PhpDetected -AutoSize -Wrap

Write-Host 'Cluster coverage' -ForegroundColor Cyan
$clusterStatus | Format-Table Cluster, Mode, Result -AutoSize -Wrap

Write-Host 'Defender for Cloud container findings referencing either CVE' -ForegroundColor Cyan
$defender = Invoke-Arg @'
securityresources
| where type =~ 'microsoft.security/assessments/subassessments'
| where tostring(properties) contains 'CVE-2026-109618' or tostring(properties) contains 'CVE-2026-109619'
| project resourceId = tostring(properties.resourceDetails.id),
    finding = tostring(properties.id),
    status  = tostring(properties.status.code),
    detail  = tostring(properties.displayName)
'@
if ($defender.Count) { $defender | Format-Table -AutoSize -Wrap }
else { Write-Host 'None yet. Defender may not have ingested these CVEs, or Defender for Containers is not enabled.' -ForegroundColor Yellow }

Write-Host "CSV written to $OutputPath" -ForegroundColor Green
#endregion
