<#
.SYNOPSIS
  Phase 4: "suspicious" post-logon actions for the classmate (attacker) to run on the honeypot.
  Run in an elevated PowerShell after logging in via RDP.

  Every step is written to C:\Users\Public\ground-truth.csv with a UTC timestamp,
  so the defender can compare their KQL timeline with what actually happened (Phase 4, step 4).

  Doing the steps by hand (GUI / cmd) is even better practice - this script is the fallback.
  Undo everything with Cleanup-Simulation.ps1.
#>
#Requires -RunAsAdministrator
param(
    [string]$NewUser  = 'svc_backup',
    [string]$TaskName = 'MicrosoftEdgeUpdateCheck',
    [string]$DownloadUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/README.md'
)
$ErrorActionPreference = 'Stop'
$log = 'C:\Users\Public\ground-truth.csv'

function Step([string]$Name, [scriptblock]$Action) {
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "[$ts UTC] $Name" -ForegroundColor Yellow
    & $Action
    [pscustomobject]@{ TimeUtc = $ts; Action = $Name } | Export-Csv -Path $log -Append -NoTypeInformation
    Start-Sleep -Seconds 20   # spread steps out so they are easy to tell apart on the timeline
}

Step 'Recon: whoami /all, net user, ipconfig, systeminfo' {
    whoami /all | Out-Null; net user | Out-Null; ipconfig /all | Out-Null; systeminfo | Out-Null
}

Step "Create local user $NewUser and add to Administrators" {
    # Random strong password: this VM is on the internet, the account must not be guessable.
    $pw = -join ((48..57) + (65..90) + (97..122) + @(33, 35, 37) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
    New-LocalUser -Name $NewUser -Password (ConvertTo-SecureString $pw -AsPlainText -Force) `
        -Description 'Backup service account' -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group 'Administrators' -Member $NewUser
}

Step 'Disable Windows Firewall (all profiles) via netsh' {
    netsh advfirewall set allprofiles state off | Out-Null
}

Step "Download file via PowerShell from $DownloadUrl" {
    Invoke-WebRequest -UseBasicParsing -Uri $DownloadUrl -OutFile 'C:\Users\Public\Downloads\update.txt'
}

Step "Create scheduled task $TaskName (persistence, SYSTEM, at startup)" {
    schtasks.exe /create /tn $TaskName /tr 'cmd.exe /c whoami > C:\Users\Public\persist.txt' `
        /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null
}

Write-Host "`nDone. Ground truth: $log" -ForegroundColor Green
Import-Csv $log | Format-Table -AutoSize
