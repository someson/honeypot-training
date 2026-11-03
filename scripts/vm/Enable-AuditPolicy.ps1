<#
.SYNOPSIS
  Turns on the Windows auditing a honeypot needs for forensics.
  Run as Administrator (Terraform runs it as SYSTEM via Run Command).

  Without this, the "All Security Events" connector has little to collect:
  4688 has no command line, 4698 (scheduled task) and 4946-4950 (firewall) are not logged at all.
#>
$ErrorActionPreference = 'Stop'

# Create a registry key only if it is missing. New-Item -Force on an EXISTING key
# deletes and recreates it (with its whole subtree), so it must never run on existing keys.
function Ensure-RegistryKey([string]$Path) {
    if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

# Subcategory -> what it gives us in SecurityEvent
$subcategories = [ordered]@{
    'Logon'                          = '4624/4625 logon success/failure'
    'Logoff'                         = '4634/4647'
    'Special Logon'                  = '4672 admin logon'
    'Other Logon/Logoff Events'      = '4778/4779 RDP reconnect/disconnect'
    'Account Lockout'                = '4740'
    'Credential Validation'          = '4776 NTLM'
    'User Account Management'        = '4720/4722/4724/4726/4738'
    'Security Group Management'      = '4732 added to local group'
    'Process Creation'               = '4688'
    'Process Termination'            = '4689'
    'Other Object Access Events'     = '4698-4702 scheduled tasks'
    'MPSSVC Rule-Level Policy Change'= '4946-4950 firewall rules/settings'
    'Audit Policy Change'            = '4719'
    'Security System Extension'      = '4697 service installed'
    'Security State Change'          = '4608/4616'
}

foreach ($name in $subcategories.Keys) {
    & auditpol.exe /set /subcategory:"$name" /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol failed for '$name' (localized OS?)" }
    else { Write-Output ("[+] {0,-32} {1}" -f $name, $subcategories[$name]) }
}

# Make subcategory settings win over legacy category policy.
Ensure-RegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord

# Command line in 4688.
$audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Ensure-RegistryKey $audit
Set-ItemProperty -Path $audit -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
Write-Output '[+] Command line included in 4688'

# PowerShell Script Block Logging (4104) and Module Logging (4103).
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Ensure-RegistryKey "$ps\ScriptBlockLogging"
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
Ensure-RegistryKey "$ps\ModuleLogging\ModuleNames"
Set-ItemProperty -Path "$ps\ModuleLogging" -Name 'EnableModuleLogging' -Value 1 -Type DWord
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String
Write-Output '[+] PowerShell script block + module logging'

# Task Scheduler operational log is disabled by default.
& wevtutil.exe sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true
# Bigger Security log so a weekend of brute force does not overwrite the classmate session (1 GB).
& wevtutil.exe sl Security /ms:1073741824
Write-Output '[+] TaskScheduler/Operational enabled, Security log = 1 GB'

& auditpol.exe /get /category:* | Select-String -Pattern 'Logon|Process Creation|Other Object|MPSSVC|User Account'
