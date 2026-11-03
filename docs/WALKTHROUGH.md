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
