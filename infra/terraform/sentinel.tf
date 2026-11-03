locals {
  sentinel_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
}

# Phase 2/3: brute-force detection. Threshold 3 so the manual smoke test fires.
resource "azurerm_sentinel_alert_rule_scheduled" "rdp_brute_force" {
  name                       = "honeypot-rdp-brute-force"
  log_analytics_workspace_id = local.sentinel_workspace_id
  display_name               = "Honeypot - RDP Brute Force (failed logons from single IP)"
  description                = "Multiple 4625 failed logons from one source IP against the honeypot."
  severity                   = "Medium"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1110"]

  query = <<-KQL
    SecurityEvent
    | where EventID == 4625
    | where isnotempty(IpAddress) and IpAddress !in ("-", "127.0.0.1", "::1")
    | summarize FailedAttempts = count(),
                TargetAccounts = make_set(TargetUserName, 25),
                AccountCount   = dcount(TargetUserName),
                StartTime      = min(TimeGenerated),
                EndTime        = max(TimeGenerated)
            by IpAddress, Computer
    | where FailedAttempts >= ${var.brute_force_threshold}
    | extend TopAccount = tostring(TargetAccounts[0])
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IpAddress"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "TopAccount"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "Selected"
      by_entities             = ["IP"]
    }
  }
}

# A failed-then-successful logon from the same IP: the alert that matters most on a honeypot.
resource "azurerm_sentinel_alert_rule_scheduled" "success_after_failures" {
  name                       = "honeypot-logon-success-after-failures"
  log_analytics_workspace_id = local.sentinel_workspace_id
  display_name               = "Honeypot - Successful logon after failed attempts"
  description                = "4624 (network/RDP) from an IP that previously produced 4625 events."
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["InitialAccess", "CredentialAccess"]
  techniques                 = ["T1078", "T1110"]

  query = <<-KQL
    let Failed = SecurityEvent
      | where EventID == 4625 and isnotempty(IpAddress) and IpAddress != "-"
      | summarize FailedAttempts = count() by IpAddress;
    SecurityEvent
    | where EventID == 4624 and LogonType in (3, 10)
    | where isnotempty(IpAddress) and IpAddress !in ("-", "127.0.0.1", "::1")
    | join kind=inner Failed on IpAddress
    | project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType, FailedAttempts
  KQL

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IpAddress"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "TargetUserName"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "Selected"
      by_entities             = ["IP", "Account"]
    }
  }
}

# Phase 4: post-compromise activity typical for the classmate exercise.
resource "azurerm_sentinel_alert_rule_scheduled" "persistence_and_defense_evasion" {
  name                       = "honeypot-persistence-defense-evasion"
  log_analytics_workspace_id = local.sentinel_workspace_id
  display_name               = "Honeypot - User created / firewall changed / scheduled task created"
  description                = "4720 user created, 4732 added to local group, 4698 scheduled task, 4946-4950 firewall changes, 1102 log cleared."
  severity                   = "High"
  enabled                    = true
  query_frequency            = "PT5M"
  query_period               = "PT10M"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1136", "T1053", "T1562"]

  query = <<-KQL
    SecurityEvent
    | where EventID in (4720, 4732, 4698, 4946, 4947, 4948, 4950, 1102)
    // The SubjectUserName column is empty for these events via AMA; read it from EventData.
    | extend Actor = coalesce(extract('SubjectUserName">([^<]+)', 1, EventData), "n/a"),
             Name  = coalesce(extract('TaskName">([^<]+)', 1, EventData), extract('RuleName">([^<]+)', 1, EventData))
    // Noise seen on a fresh VM: built-in tasks created by the machine account (SYSTEM)
    // and Microsoft Defender's service-hardening firewall rules.
    | where not(Actor endswith "$")
    | where not(EventID == 4698 and Name startswith @"\Microsoft\Windows\")
    | where not(EventID in (4946, 4947, 4948) and Name has "WinDefend")
    | project TimeGenerated, Computer, EventID, Activity, Actor, Name, TargetUserName
  KQL

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "Computer"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Actor"
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
    }
  }
}

# Phase 5: Honeypot Dashboard workbook, shown under Sentinel -> Workbooks -> My workbooks.
resource "random_uuid" "workbook" {}

resource "azurerm_application_insights_workbook" "honeypot" {
  name                = random_uuid.workbook.result
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  display_name        = "Honeypot Dashboard"
  category            = "sentinel"
  source_id           = lower(azurerm_log_analytics_workspace.this.id)
  data_json           = file("${path.module}/../../sentinel/honeypot-workbook.json")
  tags                = var.tags

  # "created-on" is stamped on every resource by Azure (most likely a tenant policy), not by
  # this code. Ignore only that key; all other tags are still compared.
  lifecycle {
    ignore_changes = [tags["created-on"]]
  }
}
