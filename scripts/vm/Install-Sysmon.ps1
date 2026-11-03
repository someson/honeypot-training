<#
.SYNOPSIS
  Installs Sysinternals Sysmon with the SwiftOnSecurity config (or updates the config if already installed).
  Events go to Microsoft-Windows-Sysmon/Operational -> collected by dcr-forensics-events -> Event table.
#>
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

$dir    = 'C:\ProgramData\Sysmon'
$config = Join-Path $dir 'sysmonconfig.xml'
New-Item -ItemType Directory -Path $dir -Force | Out-Null

Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$dir\Sysmon.zip"
Expand-Archive -Path "$dir\Sysmon.zip" -DestinationPath $dir -Force
Invoke-WebRequest -UseBasicParsing `
    -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' `
    -OutFile $config

$exe = Join-Path $dir 'Sysmon64.exe'
$sig = Get-AuthenticodeSignature $exe
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw "Sysmon64.exe signature check failed: $($sig.Status) $($sig.SignerCertificate.Subject)"
}

if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    & $exe -c $config
    Write-Output '[+] Sysmon already installed, config updated'
} else {
    & $exe -accepteula -i $config
    Write-Output '[+] Sysmon installed'
}

Get-Service Sysmon64 | Format-Table Name, Status, StartType
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
    Format-Table TimeCreated, Id, Message -AutoSize -Wrap
