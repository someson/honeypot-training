variable "subscription_id" {
  description = "Azure subscription ID. Leave null to use ARM_SUBSCRIPTION_ID / az CLI default."
  type        = string
  default     = null
}

variable "location" {
  description = "Azure region. Check Dsv6 availability: az vm list-skus -l <region> --size Standard_D2s_v6 -o table"
  type        = string
  default     = "westeurope"
}

variable "resource_group_name" {
  type    = string
  default = "rg-honeypot"
}

variable "workspace_name" {
  type    = string
  default = "law-soc-honeypot"
}

variable "workspace_retention_days" {
  type    = number
  default = 30
}

variable "vm_name" {
  description = "VM name and Windows computer name (max 15 chars). Should sound interesting, not like a honeypot."
  type        = string
  default     = "HR-FILE-SRV-01"

  validation {
    condition     = length(var.vm_name) <= 15
    error_message = "Windows computer name must be at most 15 characters."
  }
}

variable "vm_zone" {
  description = "Availability zone for the VM. Dsv6 in westeurope is restricted to zone 1 for some subscriptions (see az vm list-skus). null = regional (no zone)."
  type        = string
  default     = "1"
}

variable "vm_size" {
  description = "Dsv6 is NVMe-only and needs a Gen2 image; both are handled in main.tf."
  type        = string
  default     = "Standard_D2s_v6"
}

variable "admin_username" {
  description = "Local admin. Azure rejects trivial names (admin, administrator, user, test, ...)."
  type        = string
  default     = "hrsvcadmin"
}

variable "rdp_source_address_prefix" {
  description = "Source allowed to reach 3389. '*' = Any (the honeypot setup). Set to 'x.x.x.x/32' for hardening."
  type        = string
  default     = "*"
}

variable "bootstrap_vm" {
  description = "Run Enable-AuditPolicy.ps1 and Install-Sysmon.ps1 on the VM via Run Command."
  type        = bool
  default     = true
}

variable "install_session_recorder" {
  description = "Also run Install-SessionRecorder.ps1 (ffmpeg screen recording at logon)."
  type        = bool
  default     = false
}

variable "brute_force_threshold" {
  description = "Failed logons from one IP within the query period to raise an alert. 3 suits the smoke test."
  type        = number
  default     = 3
}

variable "tags" {
  type = map(string)
  default = {
    project = "bait-n-switch"
    purpose = "honeypot-training"
  }
}
