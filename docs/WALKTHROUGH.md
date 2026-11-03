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
