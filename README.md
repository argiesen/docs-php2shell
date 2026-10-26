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

PHP 7.4, 8.0 and 8.1 get no official release. The PHP security team published
minimal source backports, and distributions and LTS vendors (Debian, Ubuntu,
RHEL-family) ship backported packages. The official Docker `php` images for 8.1
and older are not fixed. PHP 7.3 and older have no fix.

Distributions backport fixes without changing the upstream version number, so
for distro-packaged PHP, check the package changelog for the CVE:

```bash
zgrep CVE-2026-109618 /usr/share/doc/php*-common/changelog.Debian.gz
```

```bash
rpm -q --changelog php-common | grep CVE-2026-109618
```

### Status as of 2026-10-26

- **Exploitation:** in the wild. AWS saw attempts on 2026-10-17, before
  disclosure. Most observed traffic targets CVE-2026-109619 through the session
  upload-progress path. Not yet in CISA KEV as of 2026-10-22.
- **App Service on Linux:** patched built-in PHP images are live on the
  **Latest** and **Standard** release channels (2026-10-21). **Extended** is
  patched last; Microsoft advises moving those apps to Standard or Latest.
- **App Service on Windows:** built-in PHP runtimes are end of life and no patch
  is planned. Move to Linux or bring your own runtime.
- **Custom containers:** host patching does not reach PHP inside an image.
  Rebuild on a fixed base and redeploy.
- **Related:** on 2026-10-23 PHP published an informational advisory for a
  separate upload-progress issue, CVE-2026-115560, fixed in the next regular
  release. It only applies when an app switches `session.serialize_handler` at runtime.

## Interim mitigations

Upgrading is the only complete fix. These reduce exposure while you patch.

**PHP configuration** (from PHP's advisory). Set these where they load before
request parsing (php.ini, FPM pool with `php_admin_*`, or server config, not
`ini_set()` or `.user.ini`), then restart every worker:

```ini
session.upload_progress.enabled = 0   ; CVE-2026-109619
fatal_error_backtraces = 0            ; CVE-2026-109619, PHP 8.5 only
memory_limit = -1                     ; CVE-2026-109618; pair with container/cgroup memory limits
post_max_size = 8M                    ; or 32M if uploads are needed
```

Don't use `RLIMIT_AS` or `RLIMIT_DATA`.

**Azure WAF** (from Microsoft's Azure Network Security blog):

- **Front Door:** enable managed rule **99006001** (group
  `MS-ThreatIntel-Response-CVEs`, DRS 2.0–2.2, disabled by default, rollout
  completes around 2026-10-28). It strips malicious session data from
  responses, takes effect only with the rule action set to anomaly-score Block,
  and writes **no WAF log entries**. Add the custom rules
  `BlockPhpSessionUploadProgress`, `PhpFormNesting20` and `PhpMultipartNesting20`
  (start the nesting rules in Log mode), and a `RequestBody` size rule set to the
  smallest limit your app needs.
- **Application Gateway v2:** same custom rules, plus a rewrite rule that deletes
  a `Set-Cookie` header matching the malicious `PHPSESSID` pattern. Set the WAF
  maximum request body size as low as your app allows. A managed rule is coming later.
- **Application Gateway for Containers:** custom rules only for now.

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

- **Built-in Linux PHP stack**: the PHP version and release channel. Apps on
  Latest or Standard are on a channel that has the patched image. Apps on
  Extended are flagged **HIGH**. Either way, confirm with `php -v` over SSH,
  since App Service only exposes major.minor in configuration.
- **Windows PHP handler**: end of life and gets no fix. Turn PHP off if unused,
  or move to Linux.
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
| `-ProbePhp` | Exec a read-only shell command in one running pod per workload. Reads the PHP version, the `php*-common` package version on Debian/Ubuntu, whether the dpkg or rpm changelog mentions either CVE (a distro backport), and the CLI value of `session.upload_progress.enabled` (the `CliIni` column). Needs `pods/exec` rights and a shell in the image |
| `-CommandInvokeFallback` | If direct `kubectl` access fails (for example a private API server), retry with `az aks command invoke`. This creates a short-lived pod in the `aks-command` namespace. The PHP probe does not run in this mode |
| `-IncludeSystemNamespaces` | Include `kube-system` and other platform namespaces |
| `-PhpImagePattern` | Regex used to flag container images as likely PHP |
| `-OutputPath` | CSV path (default `~/php2shell-aks-<timestamp>.csv`) |

`CliIni` shows what the PHP CLI sees. FPM pool overrides (`php_admin_value`)
and Debian/Ubuntu's separate CLI `php.ini` can differ from the web SAPI, so
confirm mitigations in the web server or pool config. Slim images often
strip `/usr/share/doc`, so a missing changelog match doesn't prove there's no
backport.

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
Scale set instances roll up to their scale set. PHP 7.4–8.1 is reported as
**VULNERABLE unless backported**, with the changelog check to run on the machine.

Defender for Cloud doesn't yet confirm coverage of these CVEs. For machines
onboarded to Defender for Endpoint, also check `DeviceTvmSoftwareVulnerabilities`
in Defender XDR advanced hunting.

## php2shell-afd-hunting.kql

Hunting queries for Azure Front Door logs in Log Analytics (`AzureDiagnostics`,
categories `FrontDoorAccessLog` and `FrontDoorWebApplicationFirewallLog`).
Each block is self-contained: put the cursor in a block and select **Run**.
Every query looks back to 2026-10-15, just before the earliest known
exploitation (2026-10-17).

| Query | Looks for |
| --- | --- |
| Q1 | Known PHP2Shell tooling: scanner/PoC user agents (including UAs carrying a PHP payload), probe paths, and published source IPs from VulnCheck, AWS and LevelBlue |
| Q2 | WAF matches on exploit content or Microsoft's PHP2Shell custom rules, joined to the access log to show whether the request reached the origin |
| Q3 | CVE-2026-109618 "arm then fire" pattern: a large POST returning 500, then a POST returning 502/503/504 from the same client within 10 minutes |
| Q4 | Bursts of more than 3 POSTs of 50 KB or more from one client to one host within 2 minutes |
| Q5 | POST 5xx trend per host (timechart), to spot spikes from October 17, 2026 onward |
| Q6 | Possible web shell use: `.php` requests with a command-style query parameter |
| Q7 | `phpinfo`-style recon probes, and any that returned 200 |
| Q8 | CVE-2026-109619 heap grooming: 20 or more small POSTs to `/` or `/index.php` from one client in 10 minutes |
| Q9 | Full timeline across access and WAF logs for suspect IPs (edit the `Suspects` list) |
| Origin bypass | `AppServiceHTTPLogs` check for traffic that reached App Service directly, skipping Front Door |

Some published IPs are shared anonymization infrastructure, so validate hits
against the request shape before acting. Misses are inconclusive, and a
successful exploit can return 200, so status-code queries (Q3, Q5) can miss it.
Reported payloads range from about 60 KB to about 60 MB; tune `ArmMinBytes` in
Q3, the size threshold in Q4 and `MinPosts` in Q8 to your apps' normal traffic.
Front Door managed rule 99006001 writes no WAF logs, so it never appears in Q2.

## Limitations

- Container images are classified by name unless you probe them. An image
  without `php` in its name can still contain PHP.
- Built-in App Service PHP versions are reported as configured, not as the
  patch level actually running.
- Defender CVE findings only appear once Defender Vulnerability Management has
  ingested these CVEs; until then, treat "no findings" as unknown.

## Sources

Reviewed 2026-10-26.

- [PHP news archive: 2026 security releases and mitigations](https://www.php.net/archive/2026.php)
- [Microsoft: upgrade guidance and Azure WAF mitigations](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623)
- [Microsoft: Azure WAF custom rules for PHP2Shell mitigation](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684)
- [Azure App Service: patched images on Latest and Standard](https://x.com/AzAppService/status/2112993469421719585)
- [AWS: PHP2Shell exploitation prior to public disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [VulnCheck: PHP2Shell vulnerabilities](https://www.vulncheck.com/blog/php2shell-vulnerabilities)
- [F5 Labs: PHP2Shell exploitation attempts observed](https://www.f5.com/labs/articles/php2shell-exploitation-attempts-observed)
- [Datadog Security Labs: detection, analysis, and remediation](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Sansec: PHP2Shell](https://sansec.io/research/php2shell)
- [watchTowr: PHP2Shell FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
