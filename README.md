# docs-php2shell

Scripts and hunting queries for finding Azure workloads exposed to **PHP2Shell**
(CVE-2026-109618 / CVE-2026-109619) and for looking for signs of exploitation in
Azure Front Door logs.

| File | What it covers |
| --- | --- |
| [`Find-Php2ShellExposure.ps1`](Find-Php2ShellExposure.ps1) | App Service and Function Apps (sites and slots), Container Apps and Container Apps jobs, Container Instances |
| [`Find-Php2ShellAks.ps1`](Find-Php2ShellAks.ps1) | AKS workloads (pods, services, ingresses) |
| [`Find-Php2ShellVms.ps1`](Find-Php2ShellVms.ps1) | VMs, VM scale sets and Azure Arc machines, using Defender for Cloud data |
| [`php2shell-afd-hunting.kql`](php2shell-afd-hunting.kql) | Log Analytics hunting queries for Front Door access and WAF logs, plus an App Service origin-bypass check |

## Fixed versions

The scripts treat these upstream PHP releases as fixed:

| Branch | Fixed in |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

PHP 8.1 and older are end of life and get no upstream fix. Linux distributions
often backport fixes without changing the upstream version number, so for
distro-packaged PHP, check the package revision against the vendor advisory.

## Prerequisites

- PowerShell 7 or later
- `Az.Accounts` and `Az.ResourceGraph` modules
- An Azure sign-in with Reader access to the subscriptions you want to scan
  (`Connect-AzAccount`). `Find-Php2ShellExposure.ps1` prompts for device-code
  sign-in if there is no context; the other scripts expect you to be signed in already.
- For `Find-Php2ShellAks.ps1` only: Azure CLI (`az`, signed in), `kubectl`,
  `kubelogin` for Entra ID-enabled clusters, and the **Azure Kubernetes Service
  Cluster User** role (plus Kubernetes read rights) on each cluster.

```powershell
Install-Module Az.Accounts, Az.ResourceGraph -Scope CurrentUser
Connect-AzAccount
```

Every script scans all subscriptions the signed-in identity can read unless you
pass `-SubscriptionId`, and writes a timestamped CSV to your home directory
unless you pass `-OutputPath`.

## Find-Php2ShellExposure.ps1

Inventories PaaS PHP workloads. Uses Azure Resource Graph to find resources,
then reads each App Service site's ARM configuration.

```powershell
./Find-Php2ShellExposure.ps1
./Find-Php2ShellExposure.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -PhpOnly
```

| Parameter | Description |
| --- | --- |
| `-SubscriptionId` | Limit the scan to specific subscriptions |
| `-PhpOnly` | Drop container rows whose image name gives no PHP signal |
| `-WebApiVersion` | Microsoft.Web API version (default: newest non-preview) |
| `-PhpImagePattern` | Regex used to flag container images as likely PHP |
| `-OutputPath` | CSV path (default `~/php2shell-inventory-<timestamp>.csv`) |

What it reports:

- **Built-in Linux PHP stack**: the PHP version and release channel. These are
  platform-managed, so the app stays vulnerable until App Service rolls out a
  fixed build to its channel. The Extended channel is flagged as higher risk
  because it lags Standard. Confirm with `php -v` over SSH.
- **Windows PHP handler**: not a supported stack and gets no fix. Turn PHP off if
  unused, or move to Linux.
- **Custom containers** (single container, Compose, sitecontainers/sidecars,
  Windows containers, Container Apps, Container Instances): classified by image
  name only. Rows marked `Unknown` need image inspection or a vulnerability scan.
- Public network access for each resource (Open, Restricted, Disabled, or ingress type).

At the end it prints counts of AKS clusters, VMs and scale sets, which this
script does not scan; use the two scripts below for those.

## Find-Php2ShellAks.ps1

Finds AKS clusters with Resource Graph, then reads pods, services and ingresses
from each with `kubectl`. Produces one row per workload, container and image
(not per replica), with exposure derived from LoadBalancer and NodePort services
and Ingress backends.

```powershell
./Find-Php2ShellAks.ps1
./Find-Php2ShellAks.ps1 -ProbePhp -CommandInvokeFallback
```

| Parameter | Description |
| --- | --- |
| `-ProbePhp` | Exec a read-only shell command in one running pod per workload to read the PHP version and, on Debian/Ubuntu images, the `php*-common` package version. Needs `pods/exec` rights and a shell in the image |
| `-CommandInvokeFallback` | If direct `kubectl` access fails (for example a private API server), retry with `az aks command invoke`. This creates a short-lived pod in the `aks-command` namespace. The PHP probe does not run in this mode |
| `-IncludeSystemNamespaces` | Include `kube-system` and other platform namespaces |
| `-PhpImagePattern` | Regex used to flag container images as likely PHP |
| `-OutputPath` | CSV path (default `~/php2shell-aks-<timestamp>.csv`) |

Stopped clusters are skipped. The script also lists any Defender for Cloud
container findings that reference either CVE. Gateway API routes and service
mesh gateways are not evaluated for exposure.

## Find-Php2ShellVms.ps1

Finds PHP on VMs, VM scale sets and Arc machines using only Azure Resource
Graph and Defender for Cloud data, so nothing runs on the machines. It joins:

- Defender for Servers plan status per subscription
- Defender software inventory (Defender Vulnerability Management)
- Defender CVE findings that mention either CVE

```powershell
./Find-Php2ShellVms.ps1
./Find-Php2ShellVms.ps1 -PhpOnly
```

| Parameter | Description |
| --- | --- |
| `-SubscriptionId` | Limit the scan to specific subscriptions |
| `-PhpOnly` | Omit machines that have inventory and no PHP. Coverage-gap machines are still reported |
| `-SoftwarePattern` | Regex matched against inventory software names (default `php`) |
| `-OutputPath` | CSV path (default `~/php2shell-vms-<timestamp>.csv`) |

Every machine is reported. Machines with no Defender software inventory are
marked **COVERAGE GAP**, because "no PHP found" means nothing without inventory.
Scale set instances roll up to their scale set.

## php2shell-afd-hunting.kql

Hunting queries for Azure Front Door logs in Log Analytics (`AzureDiagnostics`,
categories `FrontDoorAccessLog` and `FrontDoorWebApplicationFirewallLog`).
Each block is self-contained: put the cursor in a block and select **Run**.
The default lookback is 14 days.

| Query | Looks for |
| --- | --- |
| Q1 | Known PHP2Shell tooling: scanner/PoC user agents, probe paths, early source IPs |
| Q2 | WAF matches on exploit content, joined to the access log to show whether the request reached the origin |
| Q3 | CVE-2026-109618 "arm then fire" pattern: a large POST returning 500, then a POST returning 502/503/504 from the same client within 10 minutes |
| Q4 | Bursts of more than 3 large POSTs from one client to one host within 2 minutes |
| Q5 | POST 5xx trend per host (timechart), to spot spikes from October 21, 2026 onward |
| Q6 | Possible web shell use: `.php` requests with a command-style query parameter |
| Q7 | `phpinfo`-style recon probes, and any that returned 200 |
| Q8 | Full timeline across access and WAF logs for suspect IPs (edit the `Suspects` list) |
| Origin bypass | `AppServiceHTTPLogs` check for traffic that reached App Service directly, skipping Front Door |

IOC IPs and user agents change easily: treat hits as confirmed and misses as
inconclusive. Tune `ArmMinBytes` in Q3 and the size threshold in Q4 to your
apps' normal upload sizes.

## Limitations

- Container images are classified by name unless you probe them. An image
  without `php` in its name can still contain PHP.
- Built-in App Service PHP versions are reported as configured, not as the
  patch level actually running.
- Defender CVE findings only appear once Defender Vulnerability Management has
  ingested these CVEs; until then, treat "no findings" as unknown.
