<#
.SYNOPSIS
  Quick Windows Security log summary (last X hours) and export to CSV.

.DESCRIPTION
  Collects common Windows Security Event IDs (logons, failed logons, account changes, etc.),
  summarizes counts, and exports both raw events and a summary.

.NOTES
  Run PowerShell as Administrator for best results.
#>

param(
  [int]$HoursBack = 24,
  [string]$OutDir = ".\output"
)

# Common Security Event IDs to start with (you can expand this later)
$EventIds = @(
  4624, # Successful logon
  4625, # Failed logon
  4634, # Logoff
  4648, # Logon with explicit credentials
  4672, # Special privileges assigned
  4720, # User account created
  4722, # User account enabled
  4723, # Attempt to change password
  4724, # Attempt to reset password
  4725, # User account disabled
  4726, # User account deleted
  4732, # Member added to local group
  4733  # Member removed from local group
)

# Ensure output folder exists
if (-not (Test-Path $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

$StartTime = (Get-Date).AddHours(-$HoursBack)

Write-Host "Collecting Security events since: $StartTime" -ForegroundColor Cyan

# Pull events
$events = Get-WinEvent -FilterHashtable @{
  LogName   = "Security"
  Id        = $EventIds
  StartTime = $StartTime
} -ErrorAction SilentlyContinue

# Build a simple raw export (time, id, message)
$raw = $events | Select-Object `
  TimeCreated,
  Id,
  ProviderName,
  MachineName,
  Message

# Summary counts
$summary = $events |
  Group-Object Id |
  Sort-Object Count -Descending |
  Select-Object @{Name="EventId";Expression={$_.Name}}, Count

# Add a little “top failed usernames” view for 4625
$failedLogons = $events | Where-Object { $_.Id -eq 4625 }

function Get-EventDataValue {
  param([System.Diagnostics.Eventing.Reader.EventRecord]$Event, [string]$FieldName)

  try {
    $xml = [xml]$Event.ToXml()
    $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName } | Select-Object -First 1
    return $node.'#text'
  } catch {
    return $null
  }
}

$topFailedUsers = @()
if ($failedLogons.Count -gt 0) {
  $topFailedUsers =
    $failedLogons |
    ForEach-Object {
      [pscustomobject]@{
        TimeCreated = $_.TimeCreated
        TargetUser  = (Get-EventDataValue -Event $_ -FieldName "TargetUserName")
        IpAddress   = (Get-EventDataValue -Event $_ -FieldName "IpAddress")
        LogonType   = (Get-EventDataValue -Event $_ -FieldName "LogonType")
      }
    } |
    Where-Object { $_.TargetUser -and $_.TargetUser -ne "-" } |
    Group-Object TargetUser |
    Sort-Object Count -Descending |
    Select-Object -First 10 Name, Count
}

# Write files
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$rawPath = Join-Path $OutDir "security_events_raw_$timestamp.csv"
$summaryPath = Join-Path $OutDir "security_events_summary_$timestamp.csv"
$failedUsersPath = Join-Path $OutDir "security_failed_top_users_$timestamp.csv"

$raw | Export-Csv -NoTypeInformation -Path $rawPath
$summary | Export-Csv -NoTypeInformation -Path $summaryPath

if ($topFailedUsers.Count -gt 0) {
  $topFailedUsers | Export-Csv -NoTypeInformation -Path $failedUsersPath
}

Write-Host "Done." -ForegroundColor Green
Write-Host "Raw events:     $rawPath"
Write-Host "Summary:        $summaryPath"
if ($topFailedUsers.Count -gt 0) {
  Write-Host "Top failed users: $failedUsersPath"
} else {
  Write-Host "Top failed users: (none found)"
}
