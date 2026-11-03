---
title: "Bait n' Switch: Windows RDP Honeypot Report"
author: "<First Last>"
date: "<date>"
---

# 1. Setup

**Goal:** a deliberately vulnerable Windows VM exposed to the internet over RDP, with telemetry in Microsoft Sentinel.

| Component | Value |
|---|---|
| VM | `HR-FILE-SRV-01`, Windows Server 2022 Datacenter Azure Edition, `Standard_D2s_v6`, `<region>` |
| Exposure | NSG `Allow-RDP-Any`: TCP 3389, source Any |
| Credentials | 28-character random password (Terraform `random_password`) |
| Telemetry | Azure Monitor Agent; DCR "All Security Events" → `SecurityEvent`; DCR Sysmon/PowerShell/Firewall/TaskScheduler → `Event` |
| SIEM | Log Analytics `law-soc-honeypot` + Microsoft Sentinel |
| IaC | Terraform (azurerm 4.x), run from macOS |
| Observation period | `<from … to …>` (`<N>` hours) |

> Screenshot: Data connectors → Windows Security Events via AMA (connected)

# 2. Smoke test

Three failed RDP logons from `<my IP>` → 4625 in Sentinel after `<N>` min → incident
"Honeypot - RDP Brute Force" → status **Open**, assigned to **<me>**.

> Screenshot: result of `SecurityEvent | where EventID == 4625`
> Screenshot: incident Open + assigned

# 3. Statistics

| Metric | Value |
|---|---|
| Total failed logons (4625, own IPs excluded) | `<…>` |
| Unique IPs | `<…>` |
| Unique usernames | `<…>` |
| Time from deployment to first attack | `<…>` |
| Countries | `<…>` |
| Top country | `<…>` (`<…>` attempts, `<…>`%) |
| Successful third-party logons | `<0>` |

**Top 5 countries:** `<…>`

**Top 10 usernames:** `<administrator, admin, user, …>`

**Top 5 IPs** (with ASN / AbuseIPDB reputation): `<…>`

**Observations:** `<time-of-day patterns, password spraying (one IP, many accounts) vs. guessing one account,
distributed attacks from one subnet, hosting providers and VPS>`

KQL: `kql/02-attack-statistics.kql`, `kql/03-geoip.kql`, `kql/04-usernames-and-timeline.kql`.

> Screenshots: workbook (map, top countries, top usernames), incident queue, investigation graph

# 4. The classmate attack

**Ground truth** (classmate's list / `ground-truth.csv`):

| # | Time (UTC) | Action |
|---|---|---|
| 1 | | |

**Reconstruction** (`kql/05-attack-timeline.kql`):

| Time (UTC) | Source | Event ID | What it shows | Found? |
|---|---|---|---|---|
| | Security | 4624 (type 10) | Logon of `<user>` from `<IP>` | ✅ |
| | Sysmon | 1 | `whoami /all`, `net user`, … | |
| | Security | 4720 / 4732 | `svc_backup` created and added to Administrators | |
| | Security / Sysmon | 4950 / 1 | `netsh advfirewall set allprofiles state off` | |
| | PowerShell / Sysmon | 4104 / 3 / 11 | `Invoke-WebRequest` → `update.txt` | |
| | Security / Sysmon | 4698 / 1 | `schtasks /create … /ru SYSTEM` | |

**Key queries:** `<2–3 queries that found the most>`

**What was missed and why:** `<…>`

# 5. Innovations

- All infrastructure in Terraform: reproducible deployment and `terraform destroy` after the project.
- Sysmon with the SwiftOnSecurity config; a separate DCR for Sysmon, PowerShell 4103/4104, Firewall, TaskScheduler, RDP sessions.
- Extended auditing: command line in 4688, scheduled tasks 4698, firewall 4946–4950, 1 GB Security log.
- Three custom analytics rules (Brute Force; Success after failures; Persistence/Defense evasion) with entity mapping and MITRE.
- Workbook "Honeypot Dashboard": attack map, top countries, usernames and IPs, timeline, successful logons.
- `<T-Pot, if done>`

# 6. Hardening: no longer a lamb to the slaughter

**Network, most important:**

1. Take 3389 off the internet: remove the `Allow-RDP-Any` rule and the public IP.
   Use **Azure Bastion** or **Just-In-Time VM access** (Defender for Cloud), which opens the port
   temporarily and only for the requester's IP.
2. If RDP must stay reachable: restrict the source to specific IPs, or use RD Gateway or a VPN (P2S/WireGuard).

**Identity:**

3. Entra ID login (AADLoginForWindows) with MFA and Conditional Access instead of a local password.
4. Account lockout policy, e.g. 5 attempts / 15 minutes (`net accounts /lockoutthreshold:5`).
   Right now brute force is unlimited.
5. Non-default admin name, Windows LAPS for local password rotation, separate non-admin accounts for daily work.
6. NLA enforced (on by default), no blank or weak passwords.

**Host:**

7. Microsoft Defender for Endpoint / Defender for Servers, ASR rules, automatic updates (Azure Update Manager).
8. Windows Firewall enforced by policy (GPO); a profile change raises an alert.
9. Minimization: remove unused roles and services, AppLocker / WDAC.

**Monitoring (keep):**

10. Sysmon + AMA + Sentinel with this project's rules, plus a playbook
    (Logic App: on Brute Force, add the IP to an NSG deny rule).

# 7. Conclusions

`<what was surprising, time to first attack, lessons learned>`
