locals {
  scripts_dir = "${path.module}/../../scripts/vm"
}

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------------------
# Log Analytics + Microsoft Sentinel
# ---------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "this" {
  name                = var.workspace_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.workspace_retention_days
  tags                = var.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id = azurerm_log_analytics_workspace.this.id
}

# ---------------------------------------------------------------------------
# Network: VNet, public IP, NSG with RDP open to Any
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "this" {
  name                = "vnet-hr-files"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = ["10.20.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "servers" {
  name                 = "snet-servers"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.20.1.0/24"]
}

resource "azurerm_public_ip" "vm" {
  name                = "pip-${lower(var.vm_name)}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_security_group" "vm" {
  name                = "nsg-${lower(var.vm_name)}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  # Phase 1 "Open the Gates": intentionally exposed. This is the vulnerability under study.
  security_rule {
    name                       = "Allow-RDP-Any"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.rdp_source_address_prefix
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${lower(var.vm_name)}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.servers.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_network_interface_security_group_association" "vm" {
  network_interface_id      = azurerm_network_interface.vm.id
  network_security_group_id = azurerm_network_security_group.vm.id
}

# ---------------------------------------------------------------------------
# VM (strong random password: we want logs, not a real compromise)
# ---------------------------------------------------------------------------
resource "random_password" "admin" {
  length           = 28
  special          = true
  override_special = "!#%*-_=+?"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_windows_virtual_machine" "honeypot" {
  name                  = var.vm_name
  computer_name         = var.vm_name
  location              = azurerm_resource_group.this.location
  resource_group_name   = azurerm_resource_group.this.name
  size                  = var.vm_size
  admin_username        = var.admin_username
  admin_password        = random_password.admin.result
  network_interface_ids = [azurerm_network_interface.vm.id]

  # Dsv6 sizes only expose NVMe disk controllers and require a Gen2 image.
  disk_controller_type = "NVMe"
  secure_boot_enabled  = true
  vtpm_enabled         = true

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  # Gen2, NVMe-capable image.
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  # Azure Monitor Agent authenticates with the system-assigned identity.
  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.honeypot.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = var.tags
}

# ---------------------------------------------------------------------------
# Data Collection Rules
# ---------------------------------------------------------------------------

# Same XPath set the "Windows Security Events via AMA" connector uses for "All Security Events".
# Lands in the SecurityEvent table.
resource "azurerm_monitor_data_collection_rule" "security_events" {
  name                = "dcr-security-events-all"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  kind                = "Windows"
  tags                = var.tags

  destinations {
    log_analytics {
      name                  = "sentinel"
      workspace_resource_id = azurerm_log_analytics_workspace.this.id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["sentinel"]
  }

  data_sources {
    windows_event_log {
      name    = "all-security-events"
      streams = ["Microsoft-SecurityEvent"]
      x_path_queries = [
        "Security!*",
        "Microsoft-Windows-AppLocker/EXE and DLL!*",
        "Microsoft-Windows-AppLocker/MSI and Script!*",
      ]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.this]
}

# Sysmon, PowerShell, firewall, task scheduler, RDP session logs. Lands in the Event table.
resource "azurerm_monitor_data_collection_rule" "forensics_events" {
  name                = "dcr-forensics-events"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  kind                = "Windows"
  tags                = var.tags

  destinations {
    log_analytics {
      name                  = "sentinel"
      workspace_resource_id = azurerm_log_analytics_workspace.this.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["sentinel"]
  }

  data_sources {
    windows_event_log {
      name    = "forensics-channels"
      streams = ["Microsoft-Event"]
      x_path_queries = [
        "Microsoft-Windows-Sysmon/Operational!*",
        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4103 or EventID=4104)]]",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall!*",
        "Microsoft-Windows-TaskScheduler/Operational!*",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational!*",
        "Microsoft-Windows-Windows Defender/Operational!*",
        "System!*[System[(EventID=7045 or EventID=7040)]]",
      ]
    }
  }
}

resource "azurerm_monitor_data_collection_rule_association" "security_events" {
  name                    = "dcra-security-events"
  target_resource_id      = azurerm_windows_virtual_machine.honeypot.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.security_events.id
  depends_on              = [azurerm_virtual_machine_extension.ama]
}

resource "azurerm_monitor_data_collection_rule_association" "forensics_events" {
  name                    = "dcra-forensics-events"
  target_resource_id      = azurerm_windows_virtual_machine.honeypot.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.forensics_events.id
  depends_on              = [azurerm_virtual_machine_extension.ama]
}

# ---------------------------------------------------------------------------
# In-guest bootstrap via Run Command (runs as SYSTEM). Chained to avoid parallel run commands.
# ---------------------------------------------------------------------------
resource "azurerm_virtual_machine_run_command" "audit_policy" {
  count              = var.bootstrap_vm ? 1 : 0
  name               = "enable-audit-policy"
  location           = azurerm_resource_group.this.location
  virtual_machine_id = azurerm_windows_virtual_machine.honeypot.id

  source {
    script = file("${local.scripts_dir}/Enable-AuditPolicy.ps1")
  }

  depends_on = [azurerm_virtual_machine_extension.ama]
}

resource "azurerm_virtual_machine_run_command" "sysmon" {
  count              = var.bootstrap_vm ? 1 : 0
  name               = "install-sysmon"
  location           = azurerm_resource_group.this.location
  virtual_machine_id = azurerm_windows_virtual_machine.honeypot.id

  source {
    script = file("${local.scripts_dir}/Install-Sysmon.ps1")
  }

  depends_on = [azurerm_virtual_machine_run_command.audit_policy]
}

resource "azurerm_virtual_machine_run_command" "session_recorder" {
  count              = var.bootstrap_vm && var.install_session_recorder ? 1 : 0
  name               = "install-session-recorder"
  location           = azurerm_resource_group.this.location
  virtual_machine_id = azurerm_windows_virtual_machine.honeypot.id

  source {
    script = file("${local.scripts_dir}/Install-SessionRecorder.ps1")
  }

  depends_on = [azurerm_virtual_machine_run_command.sysmon]
}
