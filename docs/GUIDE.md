# Bait n' Switch: step-by-step guide

Data flow:

```
Internet bots / attacker ──RDP 3389──▶ HR-FILE-SRV-01 (Standard_D2s_v6, Windows Server 2022)
                                         │  Security log, Sysmon, PowerShell, Firewall, TaskScheduler
                                         ▼
                                Azure Monitor Agent (AMA)
                                 ├─ dcr-security-events-all  ──▶ SecurityEvent
                                 └─ dcr-forensics-events     ──▶ Event
                                         ▼
                          Log Analytics law-soc-honeypot + Microsoft Sentinel
                          (3 analytics rules, workbook "Honeypot Dashboard")
```

All commands run on macOS from the repository root. Sentinel itself is used in the Microsoft Defender
portal (https://security.microsoft.com); the Azure portal pages for Sentinel now redirect there.

---

## Phase 1. Deploying the bait

```bash
az login
```

```bash
az account set --subscription "<SUBSCRIPTION_ID>"
```

Check that Dsv6 is available in the region:

```bash
az vm list-skus --location westeurope --size Standard_D2s_v6 --output table
```

If `Restrictions` shows `NotAvailableForSubscription, type: Location`, the size is not available in the
region: pick another one (`germanywestcentral`, `northeurope`, `swedencentral`) and set it in
`terraform.tfvars`. If it shows `type: Zone`, only the listed zones are blocked: set an open zone in `vm_zone`.

```bash
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
```

```bash
terraform -chdir=infra/terraform init
```

```bash
terraform -chdir=infra/terraform apply
```

The apply takes about 10–15 minutes: VM, AMA, then Run Command executes `Enable-AuditPolicy.ps1` and
`Install-Sysmon.ps1` on the VM.

Copy the VM password to the clipboard:

```bash
terraform -chdir=infra/terraform output -raw admin_password | pbcopy
```

Open the VM in Windows App (App Store), windowed at 1920×1080:

```bash
printf 'full address:s:%s\nusername:s:%s\nscreen mode id:i:1\ndesktopwidth:i:1920\ndesktopheight:i:1080\nsmart sizing:i:1\n' "$(terraform -chdir=infra/terraform output -raw vm_public_ip)" "$(terraform -chdir=infra/terraform output -raw admin_username)" > /tmp/honeypot.rdp && open /tmp/honeypot.rdp
```

### What Terraform creates

| Brief item | Resource |
|---|---|
| Sentinel workspace | `azurerm_log_analytics_workspace` + `azurerm_sentinel_log_analytics_workspace_onboarding` |
| 1. Windows VM with an "interesting" name | `azurerm_windows_virtual_machine` `HR-FILE-SRV-01`, `Standard_D2s_v6`, NVMe, Trusted Launch |
| 2. NSG 3389 ← Any | `azurerm_network_security_group`, rule `Allow-RDP-Any` (`source_address_prefix = "*"`) |
| 3. Strong credentials | 28-character `random_password` (stored only in the state, see below) |
| 4. Telemetry link (AMA + DCR "All Security Events") | `AzureMonitorWindowsAgent` + `dcr-security-events-all` (XPath `Security!*` and AppLocker, exactly like the "All Security Events" preset) |
| Extra for phases 4–5 | `dcr-forensics-events`: Sysmon, PowerShell 4103/4104, Firewall, TaskScheduler, RDP sessions, Defender → `Event` table |
| Phases 2–4: incidents | 3 scheduled analytics rules (`sentinel.tf`) |
| Phase 5: dashboard | Workbook "Honeypot Dashboard" from `sentinel/honeypot-workbook.json` |

### Manual steps in the portal

1. **Defender portal → Microsoft Sentinel → Content management → Content hub → "Windows Security Events" → Install.**
   If the workspace is not the primary one, select `law-soc-honeypot` in the workspace picker first.
   If Microsoft Sentinel is missing from the menu: Setup & configuration → Settings → Microsoft Sentinel →
   Workspaces → connect `law-soc-honeypot`.
2. **Microsoft Sentinel → Configuration → Data connectors → "Windows Security Events via AMA".** It shows as
   connected once the first events arrive; the DCR `dcr-security-events-all` is already there.
   **Do not create a second DCR in the connector wizard**, or every event is ingested twice
   (double cost and doubled statistics).

### Password and state

The password is stored in plain text in `terraform.tfstate`. The state stays local and is in `.gitignore`.
Never commit it; for phase 4 share only the username and password.

---

## Phase 2. Smoke test

1. Find your public IP: `curl -s https://ifconfig.me`. Put it into `MyIPs` in the KQL files and into the
   workbook parameter "Exclude my IPs".
2. In Windows App, try to log on to the VM 3 times with a wrong password.
3. After 2–10 minutes run [`kql/01-smoke-test.kql`](../kql/01-smoke-test.kql) or the query from the brief:
   ```kql
   SecurityEvent
   | where EventID == 4625
   ```
   With NLA (the default) a failed RDP logon is logged with `LogonType = 3`, not 10.
4. **Incident check.** The rule "Honeypot - RDP Brute Force (failed logons from single IP)" fires at
   ≥ `brute_force_threshold` (3) attempts from one IP within an hour and runs every 5 minutes. The incident
   appears in Defender → Cases (search "Honeypot") after about 5–15 minutes.
   Open it → **Manage case** → status **Open** (the In Progress group, the equivalent of "Active") →
   assign it to yourself → **Save**.
5. After the smoke test, optionally raise the threshold: `brute_force_threshold = 15` in
   `infra/terraform/terraform.tfvars`, then `terraform -chdir=infra/terraform apply`.

---

## Phase 3. The stakeout

- Bots usually find an open 3389 within hours. Check for third-party failed logons. In zsh, avoid `!`
  inside double quotes (history expansion), so use `not(... in ...)`:
  ```bash
  az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where EventID == 4625 and not(IpAddress in ('-', '', '<my-ip>')) | summarize Attempts=count(), Users=make_set(TargetUserName, 20) by IpAddress | extend Country=tostring(geo_info_from_ip_address(IpAddress).country)" --output table
  ```
- **Geo-IP:** [`kql/03-geoip.kql`](../kql/03-geoip.kql) uses the built-in `geo_info_from_ip_address()`.
  Cross-check attacker IPs on AbuseIPDB / ipinfo.io / VirusTotal (ASN and reputation).
- **Investigation graph:** open the incident in Defender → Cases; the incident graph shows which accounts
  and hosts are linked to the IP. Password spraying (one IP, many accounts) has its own block in
  [`kql/04-usernames-and-timeline.kql`](../kql/04-usernames-and-timeline.kql).
- **Login attempt detection:** the rule "Honeypot - Successful logon after failed attempts" (High) catches
  the key scenario: brute force followed by a successful logon.

---

## Phase 4. Peer-to-peer attack and forensics

**Before the attack**, make sure Sysmon reaches Sentinel:

```kql
Event | where Source == "Microsoft-Windows-Sysmon" | take 10
```

1. Give the classmate the IP, username and password (in person only).
2. They log on and perform the actions by hand or with
   [`scripts/classmate/Simulate-Attack.ps1`](../scripts/classmate/Simulate-Attack.ps1):
   recon, local user `svc_backup` added to Administrators, firewall disabled, file downloaded with
   `Invoke-WebRequest`, scheduled task at system start. The script writes `C:\Users\Public\ground-truth.csv`
   as the reference for verification.
3. **Reconstruction:** [`kql/05-attack-timeline.kql`](../kql/05-attack-timeline.kql) builds a single timeline
   from SecurityEvent and Sysmon. Focused queries are in [`kql/06-sysmon-and-powershell.kql`](../kql/06-sysmon-and-powershell.kql).

| Action | Where it shows up |
|---|---|
| RDP logon | 4624 LogonType 10 (preceded by 3 with NLA), 4672 (admin privileges), `TerminalServices-LocalSessionManager` 21/25 |
| Commands | Sysmon 1, 4688 with `CommandLine` |
| New user | 4720 (created), 4722 (enabled), 4724 (password), 4732 (added to Administrators) |
| Firewall off | 4950, Firewall channel 2003, Sysmon 1 `netsh advfirewall set allprofiles state off` |
| Download via PowerShell | 4104 (script block), Sysmon 3 (`powershell.exe` → 443), 22 (DNS), 11 (file `update.txt`) |
| Scheduled task | 4698 (task XML in `EventData`), Sysmon 1 `schtasks.exe /create`, TaskScheduler 106 |

Cmdlets such as `New-LocalUser` and `Invoke-WebRequest` run inside the existing `powershell.exe` and create
no process, so Sysmon 1 does not show them; PowerShell 4104 does.

4. **Verification:** compare the timeline with `ground-truth.csv` or the classmate's list. Typical gaps:
   GUI actions (only visible as `mmc.exe`, `lusrmgr.msc`, `wf.msc` starting), events filtered by the
   SwiftOnSecurity config, ingestion delay.
5. **Right after:** run [`scripts/classmate/Cleanup-Simulation.ps1`](../scripts/classmate/Cleanup-Simulation.ps1)
   and reset the password (Azure portal → VM → Help → Reset password).

---

## Phase 5. Improvements

| Idea | How |
|---|---|
| Sysmon (SwiftOnSecurity) | Installed by Terraform (`bootstrap_vm = true`). Manually: `scripts/vm/Install-Sysmon.ps1` |
| Dashboard | Defender → Microsoft Sentinel → Threat management → Workbooks → My workbooks → **Honeypot Dashboard** (map, top countries, usernames and IPs, timeline, successful logons) |
| Detections | 3 analytics rules in `sentinel.tf`, MITRE T1110 / T1078 / T1136 / T1053 / T1562; they alert only on events ingested since the previous run |
| RDP session recording (optional) | `install_session_recorder = true` → `terraform -chdir=infra/terraform apply`. ffmpeg records 2 fps into `C:\ProgramData\SessionRec\videos\*.mkv` at every logon. Recordings use the client resolution, so use a 1920×1080 session |
| T-Pot | A separate Linux VM (Ubuntu 24.04, ≥ 8 vCPU / 16 GB, e.g. `Standard_D4s_v6`), NSG as per the tpotce docs; compare its logs with the RDP honeypot |

---

## Phase 6. Report

Template: [`report/report-template.md`](../report/report-template.md). Screenshots worth taking: the connector
page (connected), the incident queue and one incident set to Open and assigned, the investigation graph,
the 4625 query result, the workbook map, the attack timeline. Redact your own IP and the tenant ID in the
browser address bar before sharing.

---

## Cleanup

```bash
terraform -chdir=infra/terraform destroy
```
