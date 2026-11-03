<#
.SYNOPSIS
  Reverts everything Simulate-Attack.ps1 (or the manual equivalent) changed.
  The VM is exposed to the internet - run this right after Phase 4.
#>
#Requires -RunAsAdministrator
param(
    [string]$NewUser  = 'svc_backup',
    [string]$TaskName = 'MicrosoftEdgeUpdateCheck'
)
$ErrorActionPreference = 'Continue'

netsh advfirewall set allprofiles state on | Out-Null
Write-Host '[+] Firewall enabled on all profiles'

if (Get-LocalUser -Name $NewUser -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $NewUser
    Write-Host "[+] User $NewUser removed"
}

schtasks.exe /delete /tn $TaskName /f 2>$null | Out-Null
Write-Host "[+] Task $TaskName removed"

Remove-Item 'C:\Users\Public\Downloads\update.txt', 'C:\Users\Public\persist.txt' -ErrorAction SilentlyContinue
Write-Host '[+] Dropped files removed (ground-truth.csv kept for the report)'
Write-Host '[!] Now change the password of the account you gave your classmate.'
