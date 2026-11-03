output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "admin_username" {
  value = var.admin_username
}

output "admin_password" {
  description = "terraform output -raw admin_password"
  value       = random_password.admin.result
  sensitive   = true
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.this.id
}

output "workspace_customer_id" {
  description = "Workspace GUID (for Log Analytics API / az monitor log-analytics query)."
  value       = azurerm_log_analytics_workspace.this.workspace_id
}
