<#
.SYNOPSIS
  Lightweight RDP session screen recording: ffmpeg (gdigrab) starts at every interactive logon.

  - Scheduled task "\Microsoft\Windows\SessionTelemetry\Recorder", trigger AtLogOn (any user),
    principal BUILTIN\Users -> runs inside the logging-on user's session, so it sees their desktop.
  - 2 fps, x264 ultrafast, 5-minute Matroska segments (.mkv stays playable if the process is killed).
  - Output: C:\ProgramData\SessionRec\videos\<user>_<timestamp>_NNN.mkv
  - A daily task removes recordings older than $RetentionDays days.

  Limitation: an attacker with admin rights can find and delete the recordings.
  For tamper resistance, ship segments off-box (e.g. azcopy to Blob Storage).
#>
param(
    [int]$Fps = 2,
    [int]$SegmentSeconds = 300,
    [int]$RetentionDays = 7
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

$root   = 'C:\ProgramData\SessionRec'
$bin    = Join-Path $root 'bin'
$videos = Join-Path $root 'videos'
New-Item -ItemType Directory -Path $bin, $videos -Force | Out-Null

# --- ffmpeg (gyan.dev release essentials build) ---
if (-not (Test-Path "$bin\ffmpeg.exe")) {
    $zip = Join-Path $env:TEMP 'ffmpeg.zip'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip' -OutFile $zip
    $extract = Join-Path $env:TEMP 'ffmpeg-extract'
    Expand-Archive -Path $zip -DestinationPath $extract -Force
    Get-ChildItem $extract -Recurse -Filter ffmpeg.exe | Select-Object -First 1 | Copy-Item -Destination $bin
    Remove-Item $zip, $extract -Recurse -Force
}

# --- ACL: users may create/write recordings but not list or delete them ---
& icacls.exe $videos /inheritance:r `
    /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' `
    /grant:r 'BUILTIN\Users:(CI)(WD,AD,S)' 'BUILTIN\Users:(OI)(IO)(R,W)' | Out-Null

# --- recorder script executed in the user's session ---
$recorder = @"
`$stamp = '{0}_{1}' -f `$env:USERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')
& '$bin\ffmpeg.exe' -hide_banner -loglevel error -nostdin ``
    -f gdigrab -framerate $Fps -draw_mouse 1 -i desktop ``
    -vf 'scale=trunc(iw/2)*2:trunc(ih/2)*2' ``
    -c:v libx264 -preset ultrafast -crf 32 -pix_fmt yuv420p ``
    -f segment -segment_time $SegmentSeconds -segment_format matroska -reset_timestamps 1 ``
    "$videos\`${stamp}_%03d.mkv"
"@
Set-Content -Path "$bin\rec.ps1" -Value $recorder -Encoding UTF8

# --- scheduled tasks ---
$taskPath = '\Microsoft\Windows\SessionTelemetry\'

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$bin\rec.ps1`""
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
Register-ScheduledTask -TaskPath $taskPath -TaskName 'Recorder' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

$cleanup = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    "-NoProfile -NonInteractive -Command `"Get-ChildItem '$videos' -Filter *.mkv | " +
    "Where-Object LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) | Remove-Item -Force`"")
Register-ScheduledTask -TaskPath $taskPath -TaskName 'RecorderCleanup' -Action $cleanup `
    -Trigger (New-ScheduledTaskTrigger -Daily -At 4am) -User 'SYSTEM' -RunLevel Highest -Force | Out-Null

Write-Output "[+] Session recorder installed. Recordings: $videos"
Write-Output '    Test: log off and RDP in again, then check the folder after ~1 minute.'
