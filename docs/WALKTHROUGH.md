# Walkthrough log

Commands run on macOS, always from the repository root, with their CLI output.

## Phase 1: Deploying the bait

### 1. Create terraform.tfvars

```
❯ cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
```

### 2. terraform init

```
❯ terraform -chdir=infra/terraform init
...
Terraform has been successfully initialized!
```

Providers installed from the committed lock file (azurerm 4.81.0, random 3.9.1).

### 3. terraform plan

```
❯ terraform -chdir=infra/terraform plan -out=tfplan
...
Plan: 23 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + admin_password        = (sensitive value)
  + admin_username        = "hrsvcadmin"
  + rdp_url               = (known after apply)
  + vm_public_ip          = (known after apply)
  + workspace_customer_id = (known after apply)
  + workspace_id          = (known after apply)

Saved the plan to: tfplan
```

### 4. terraform apply

```
❯ terraform -chdir=infra/terraform apply -replace=azurerm_windows_virtual_machine.honeypot
...
Plan: 7 to add, 0 to change, 3 to destroy.
...
Apply complete! Resources: 7 added, 0 changed, 3 destroyed.

Outputs:

admin_password = <sensitive>
admin_username = "hrsvcadmin"
rdp_url = "rdp://full%20address=s:20.71.88.9:3389&username=s:hrsvcadmin"
vm_public_ip = "20.71.88.9"
workspace_customer_id = "<workspace-guid>"
workspace_id = "/subscriptions/<subscription-id>/resourceGroups/rg-honeypot/providers/Microsoft.OperationalInsights/workspaces/law-soc-honeypot"
```

### 5. Drift check

```
❯ terraform -chdir=infra/terraform plan
...
No changes. Your infrastructure matches the configuration.
```

### 6. Install "Windows Security Events" from Content hub

Azure portal: Microsoft Sentinel → `law-soc-honeypot` → Content management → Content hub shows:

```
This page has been moved to the Defender portal for the optimal, unified SecOps experience
```

Content hub now lives in the Defender portal: https://security.microsoft.com →
Microsoft Sentinel → Content management → Content hub → "Windows Security Events" → Install.

Defender portal → Setup & configuration → Settings → Microsoft Sentinel → Workspaces:

| Name | Status | Resource group |
|---|---|---|
| sentinel-lab-main-ws (Primary) | Connected | sentinel-lab-main |
| law-soc-honeypot | Connected | rg-honeypot |

The honeypot workspace is connected but not primary. Sentinel pages in Defender default to the primary
workspace, so `law-soc-honeypot` has to be selected in the workspace picker before installing content.

Content hub → workspace picker → `law-soc-honeypot` (1 of 3 selected) → "Windows Security Events" → Install. Installed.

### 7. Data connector status

Microsoft Sentinel → Configuration → Data connectors (Workspace: law-soc-honeypot):
3 connectors, 2 connected. "Windows Security Events via AMA" is connected, served by the
Terraform-created `dcr-security-events-all`. No second DCR was created in the connector wizard.

### 8. Events arrive in the workspace

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | summarize Events=count() by EventID | top 10 by Events" --output table
EventID    Events    TableName
---------  --------  -------------
4688       270       PrimaryResult
4689       220       PrimaryResult
4662       66        PrimaryResult
4674       60        PrimaryResult
4673       45        PrimaryResult
4702       36        PrimaryResult
5379       24        PrimaryResult
4624       18        PrimaryResult
4627       18        PrimaryResult
4672       18        PrimaryResult
```

The Security log reaches `SecurityEvent`. 4688/4689 (process creation/termination) and 4702
(scheduled task updated) are present, so `Enable-AuditPolicy.ps1` took effect.

**Phase 1 complete.**

## Phase 2: Smoke test

### 1. Failed RDP logons from the Mac

```
❯ printf 'full address:s:%s\nusername:s:%s\n' "$(terraform -chdir=infra/terraform output -raw vm_public_ip)" "$(terraform -chdir=infra/terraform output -raw admin_username)" > /tmp/honeypot.rdp && open /tmp/honeypot.rdp
```

Windows App: 5 logon attempts with a wrong password.

### 2. Failed logons in Sentinel (Event ID 4625)

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(1h) | project TimeGenerated, TargetUserName, IpAddress, LogonType | sort by TimeGenerated desc" --output table
IpAddress      LogonType    TableName      TargetUserName    TimeGenerated
-------------  -----------  -------------  ----------------  ----------------------------
<my-ip>        3            PrimaryResult  hrsvcadmin        2026-11-03T16:36:48.9877177Z
<my-ip>        3            PrimaryResult  hrsvcadmin        2026-11-03T16:36:41.4566416Z
<my-ip>        3            PrimaryResult  hrsvcadmin        2026-11-03T16:36:38.9942705Z
<my-ip>        3            PrimaryResult  hrsvcadmin        2026-11-03T16:36:35.4187131Z
<my-ip>        3            PrimaryResult  hrsvcadmin        2026-11-03T16:36:28.0338692Z
```

### 3. Brute Force incident

Defender portal → Cases → search "Honeypot":

| Case ID | Name | Severity | Status |
|---|---|---|---|
| 1824 | Honeypot - RDP Brute Force (failed logons from single IP) | Medium | New |

Manage case → Select status: **Open** (In Progress group) → assigned to myself → Save.
Incident graph: `<my-ip>` → `HR-FILE-SRV-01` → `hrsvcadmin`.

## Phase 3: The stakeout

### 1. First third-party failed logons

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where EventID == 4625 and not(IpAddress in ('-', '', '<my-ip>')) | summarize Attempts=count(), Users=make_set(TargetUserName, 10), First=min(TimeGenerated), Last=max(TimeGenerated) by IpAddress | extend Country=tostring(geo_info_from_ip_address(IpAddress).country)" --output table
Attempts    Country    First                         IpAddress       Last                          TableName      Users
----------  ---------  ----------------------------  --------------  ----------------------------  -------------  -----------------
7           Germany    2026-11-03T20:00:01.0053459Z  87.106.147.134  2026-11-03T20:30:00.5864563Z  PrimaryResult  ["Administrator"]
```

First attempt about 4 hours after deployment. 7 attempts in 30 minutes (roughly every 5 minutes),
only `Administrator`: a slow brute force that stays under typical lockout thresholds.

### 2. Geo-IP and reputation: 87.106.147.134

AbuseIPDB (https://www.abuseipdb.com/check/87.106.147.134):

| Field | Value |
|---|---|
| Abuse confidence score | 100% (Critical) |
| Reports | 514 from 107 distinct reporters, first reported 2026-02-26, latest minutes ago |
| ISP / ASN | IONOS SE, AS8560 |
| Usage type | Data Center / Web Hosting / Transit |
| Location | Berlin, Germany |
| Most common categories | Brute-Force 289, Hacking 163, SSH 71, Port Scan 52, Web App Attack 13 |

Other honeypots reported the same IP for RDP brute force within the same hour: a hosted server
running an internet-wide RDP scanning campaign, not a targeted attack.

### 3. Incident triage and investigation graph

Defender portal → Cases → Case 1870 "Honeypot - RDP Brute Force (failed logons from single IP)":
4 alerts grouped into one incident by the IP entity. Manage case → Open, assigned to myself.

Incident graph: `87.106.147.134` → `HR-FILE-SRV-01`. The IP targeted a single account
(`Administrator`), so this is password guessing against one account, not password spraying.

## Phase 4: Simulated breach and forensics

No classmate was available, so I played the attacker myself: RDP logon with the real credentials,
then the four actions from the brief, typed by hand in an elevated PowerShell.

### 1. Ground truth

| Time (UTC) | Action |
|---|---|
| 20:50:53 | Elevated PowerShell after RDP logon as `hrsvcadmin` |
| 20:51:23 | Recon: `whoami /all; net user; ipconfig /all` |
| 20:52:23 | `New-LocalUser svc_backup`, `Add-LocalGroupMember Administrators` |
| 20:52:49 | `netsh advfirewall set allprofiles state off` |
| 20:53:16 | `Invoke-WebRequest … -OutFile C:\Users\Public\Downloads\update.txt` |
| 20:53:42 | `schtasks /create /tn MicrosoftEdgeUpdateCheck … /sc onstart /ru SYSTEM` |
| 20:54:20 | `logoff` |

### 2. Logon (4624)

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where TimeGenerated between (datetime(2026-11-03 20:45) .. datetime(2026-11-03 21:10)) | where EventID in (4624, 4634, 4647) and TargetUserName =~ 'hrsvcadmin' and LogonType in (2, 3, 7, 10) | project TimeGenerated, EventID, LogonType, IpAddress | sort by TimeGenerated asc" --output table
EventID    IpAddress      LogonType    TableName      TimeGenerated
---------  -------------  -----------  -------------  ----------------------------
4624       <my-ip>        3            PrimaryResult  2026-11-03T20:49:06.5286794Z
4624       <my-ip>        10           PrimaryResult  2026-11-03T20:49:07.7821706Z
```

LogonType 3 is the NLA pre-authentication, LogonType 10 the interactive RDP session.

### 3. Account changes (4720, 4722, 4724, 4732, 4738)

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where TimeGenerated between (datetime(2026-11-03 20:45) .. datetime(2026-11-03 21:10)) | where EventID in (4720, 4722, 4724, 4732, 4738) | extend Actor=extract('SubjectUserName\">([^<]+)', 1, EventData) | project TimeGenerated, EventID, Activity, Actor, TargetUserName | sort by TimeGenerated asc" --output table
Activity                                                      Actor       EventID    TableName      TargetUserName    TimeGenerated
------------------------------------------------------------  ----------  ---------  -------------  ----------------  ----------------------------
4720 - A user account was created.                            hrsvcadmin  4720       PrimaryResult  svc_backup        2026-11-03T20:52:22.997304Z
4722 - A user account was enabled.                            hrsvcadmin  4722       PrimaryResult  svc_backup        2026-11-03T20:52:22.9999669Z
4738 - A user account was changed.                            hrsvcadmin  4738       PrimaryResult  svc_backup        2026-11-03T20:52:23.000007Z
4738 - A user account was changed.                            hrsvcadmin  4738       PrimaryResult  svc_backup        2026-11-03T20:52:23.0161147Z
4724 - An attempt was made to reset an account's password.    hrsvcadmin  4724       PrimaryResult  svc_backup        2026-11-03T20:52:23.016124Z
4732 - A member was added to a security-enabled local group.  hrsvcadmin  4732       PrimaryResult  Administrators    2026-11-03T20:52:23.0409787Z
```

### 4. Firewall disabled (4950)

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where TimeGenerated between (datetime(2026-11-03 20:45) .. datetime(2026-11-03 21:10)) | where EventID == 4950 | extend Profile=extract('ProfileChanged\">([^<]+)', 1, EventData), Setting=extract('SettingType\">([^<]+)', 1, EventData), Value=extract('SettingValue\">([^<]+)', 1, EventData) | project TimeGenerated, Profile, Setting, Value | sort by TimeGenerated asc" --output table
Profile    Setting                           TableName      TimeGenerated                 Value
---------  --------------------------------  -------------  ----------------------------  -------
(null)     Enable Windows Defender Firewall  PrimaryResult  2026-11-03T20:52:49.1794211Z  No
(null)     Enable Windows Defender Firewall  PrimaryResult  2026-11-03T20:52:49.1810686Z  No
(null)     Enable Windows Defender Firewall  PrimaryResult  2026-11-03T20:52:49.2166376Z  No
```

One event per firewall profile. 4950 carries no actor; Sysmon attributes it.

### 5. Process creation (Sysmon Event ID 1)

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "Event | where TimeGenerated between (datetime(2026-11-03 20:45) .. datetime(2026-11-03 21:10)) | where Source == 'Microsoft-Windows-Sysmon' and EventID == 1 | extend User=extract('Name=\"User\">([^<]+)', 1, EventData), CommandLine=extract('Name=\"CommandLine\">([^<]+)', 1, EventData) | where User has 'hrsvcadmin' | project TimeGenerated, CommandLine | sort by TimeGenerated asc" --output table
```

Relevant rows (logon noise from Explorer, Edge and Server Manager omitted):

| Time (UTC) | CommandLine |
|---|---|
| 20:49:27 | `ffmpeg.exe … -f gdigrab … C:\ProgramData\SessionRec\videos\hrsvcadmin_20261103-204925_%%03d.mkv` |
| 20:50:50 | `powershell.exe` |
| 20:51:23 | `whoami.exe /all` |
| 20:51:23 | `net.exe user` / `net1 user` |
| 20:51:23 | `ipconfig.exe /all` |
| 20:52:49 | `netsh.exe advfirewall set allprofiles state off` |
| 20:53:42 | `schtasks.exe /create /tn MicrosoftEdgeUpdateCheck /tr "cmd.exe /c whoami > C:\Users\Public\persist.txt" /sc onstart /ru SYSTEM /rl HIGHEST /f` |
| 20:54:20 | `logoff.exe` |

`New-LocalUser` and `Invoke-WebRequest` are cmdlets inside the running `powershell.exe`, so they
create no process and do not appear here.

### 6. PowerShell script blocks (4104)

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "Event | where TimeGenerated between (datetime(2026-11-03 20:45) .. datetime(2026-11-03 21:10)) | where Source == 'Microsoft-Windows-PowerShell' and EventID == 4104 | extend Script=extract('Name=\"ScriptBlockText\">([^<]+)', 1, EventData) | where Script has_any ('Invoke-WebRequest', 'New-LocalUser') | project TimeGenerated, Script | sort by TimeGenerated asc" --output table
```

| Time (UTC) | ScriptBlockText |
|---|---|
| 20:52:22 | `New-LocalUser -Name 'svc_backup' … ; Add-LocalGroupMember -Group 'Administrators' -Member 'svc_backup'` |
| 20:53:16 | `Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/README.md' -OutFile 'C:\Users\Public\Downloads\update.txt'` |

### 7. Detection

The tuned rule raised Case 1879 "Honeypot - User created / firewall changed / scheduled task created"
(High) for the attack. Manage case → Open, assigned to myself.

### 8. Verification

| Action | Found in |
|---|---|
| RDP logon | 4624 (LogonType 3 → 10) |
| Recon | Sysmon 1 |
| User created, added to Administrators | 4720, 4722, 4724, 4732 + PowerShell 4104 |
| Firewall disabled | 4950 + Sysmon 1 (`netsh`) |
| File downloaded via PowerShell | PowerShell 4104 |
| Scheduled task for persistence | Sysmon 1 (`schtasks`) |
| Logoff | Sysmon 1 (`logoff.exe`) |

All seven actions were found; nothing was missed.

### 9. Cleanup

```
PS C:\Users\hrsvcadmin> netsh advfirewall set allprofiles state on; Remove-LocalUser -Name 'svc_backup'; schtasks.exe /delete /tn 'MicrosoftEdgeUpdateCheck' /f; Remove-Item 'C:\Users\Public\Downloads\update.txt', 'C:\Users\Public\persist.txt' -ErrorAction SilentlyContinue; 'cleanup done'
Ok.

SUCCESS: The scheduled task "MicrosoftEdgeUpdateCheck" was successfully deleted.
cleanup done
```

## Phase 5: Improvements

### 1. Sysmon events in Sentinel

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "Event | where Source == 'Microsoft-Windows-Sysmon' | summarize Events=count() by EventID | sort by Events desc" --output table
EventID    Events    TableName
---------  --------  -------------
13         990       PrimaryResult
11         190       PrimaryResult
1          90        PrimaryResult
22         12        PrimaryResult
3          10        PrimaryResult
12         4         PrimaryResult
```

### 2. Tune the persistence / defense evasion rule

The rule "Honeypot - User created / firewall changed / scheduled task created" raised a false positive
right after deployment. The events behind it:

```
❯ az monitor log-analytics query --workspace "$(terraform -chdir=infra/terraform output -raw workspace_customer_id)" --analytics-query "SecurityEvent | where EventID in (4698, 4946, 4948) | extend Actor=extract('SubjectUserName\">([^<]+)', 1, EventData), Name=coalesce(extract('TaskName\">([^<]+)', 1, EventData), extract('RuleName\">([^<]+)', 1, EventData)) | project TimeGenerated, EventID, Actor, Name | sort by TimeGenerated asc" --output table
Actor            EventID    Name                                                                 TableName      TimeGenerated
---------------  ---------  -------------------------------------------------------------------  -------------  ----------------------------
HR-FILE-SRV-01$  4698       \Microsoft\Windows\UpdateOrchestrator\Schedule Work                  PrimaryResult  2026-11-03T16:08:12.4077208Z
HR-FILE-SRV-01$  4698       \Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work          PrimaryResult  2026-11-03T16:08:12.4210889Z
HR-FILE-SRV-01$  4698       \Microsoft\Windows\UpdateOrchestrator\Schedule Maintenance Work      PrimaryResult  2026-11-03T16:08:12.4600347Z
                 4948       Inbound service restriction rule for WinDefend                       PrimaryResult  2026-11-03T16:08:33.1838307Z
                 4948       Outbound service restriction rule for WinDefend                      PrimaryResult  2026-11-03T16:08:33.1944785Z
                 4946       Inbound service restriction rule for WinDefend                       PrimaryResult  2026-11-03T16:08:33.1969335Z
                 4946       Outbound service restriction rule for WinDefend                      PrimaryResult  2026-11-03T16:08:33.1982729Z
                 4948       WinDefend Outbound for TCP                                           PrimaryResult  2026-11-03T16:08:33.1986305Z
                 4946       WinDefend Outbound for TCP                                           PrimaryResult  2026-11-03T16:08:33.2018144Z
HR-FILE-SRV-01$  4698       \Microsoft\Windows\Defrag\ScheduledDefrag                            PrimaryResult  2026-11-03T16:13:42.6751449Z
HR-FILE-SRV-01$  4698       \Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan  PrimaryResult  2026-11-03T16:18:44.0078891Z
```

All of it is built-in Windows activity: tasks created by the machine account and Microsoft Defender's
firewall rules. The rule now reads the actor from `EventData` (the `SubjectUserName` column is empty)
and excludes the machine account, `\Microsoft\Windows\` tasks and `WinDefend` firewall rules.
The tuned query returns no rows on the same data.

```
❯ terraform -chdir=infra/terraform apply
...
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.
```

Case 1816 (the false positive) → Manage case → Closed, classified as False positive.

### 3. Honeypot Dashboard workbook

Defender portal → Microsoft Sentinel → Threat management → Workbooks → My workbooks →
Honeypot Dashboard → View saved workbook. All tiles render. The "Exclude my IPs" parameter
is set to my own IP so only third-party attempts are shown.
