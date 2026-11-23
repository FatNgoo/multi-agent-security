# Run on the same Windows lab endpoint/account after Invoke-LabScenario.ps1.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$CaseDirectory)
$ErrorActionPreference = 'Stop'
$CaseDirectory = (Resolve-Path -LiteralPath $CaseDirectory).Path
$manifest = Get-Content -LiteralPath (Join-Path $CaseDirectory 'scenario.json') -Raw | ConvertFrom-Json
$start = [DateTimeOffset]::Parse($manifest.start_utc)
$end = [DateTimeOffset]::Parse($manifest.end_utc)
$output = Join-Path $CaseDirectory 'sysmon'
if (Test-Path -LiteralPath $output) { throw 'Export directory exists. Keep the previous evidence; use another output/case.' }
# Allow Sysmon delivery to catch up; event timestamps remain constrained to the case window.
Start-Sleep -Seconds 15
$channel = 'Microsoft-Windows-Sysmon/Operational'
$events = @(Get-WinEvent -FilterHashtable @{
    LogName = $channel; Id = @(1, 3, 11, 12, 13, 14, 22)
    StartTime = $start.LocalDateTime; EndTime = $end.LocalDateTime
} -ErrorAction Stop | Sort-Object TimeCreated, RecordId)
if (-not $events.Count) { throw 'No Sysmon events in this window. Check collection and clock before exporting.' }
New-Item -ItemType Directory -Path $output | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
$from = $start.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
$until = $end.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
$query = "*[System[TimeCreated[@SystemTime >= '$from' and @SystemTime <= '$until']]]"
& wevtutil.exe epl $channel (Join-Path $output 'sysmon-original.evtx') "/q:$query" /ow:false
if ($LASTEXITCODE -ne 0) { throw 'EVTX export failed. Check permission to read the Sysmon channel.' }
$part = 1
$builder = New-Object System.Text.StringBuilder
[void]$builder.AppendLine('<Events>')
$size = 20
foreach ($event in $events) {
    $xml = $event.ToXml()
    $eventSize = $utf8.GetByteCount($xml) + 2
    if ($eventSize -gt 4000000) { throw 'Single event exceeds upload chunk limit; preserve EVTX and inspect manually.' }
    if ($size + $eventSize -gt 4000000) {
        [void]$builder.AppendLine('</Events>')
        [System.IO.File]::WriteAllText((Join-Path $output ('sysmon-{0:D3}.xml' -f $part)), $builder.ToString(), $utf8)
        $part++
        [void]$builder.Clear()
        [void]$builder.AppendLine('<Events>')
        $size = 20
    }
    [void]$builder.AppendLine($xml)
    $size += $eventSize
}
[void]$builder.AppendLine('</Events>')
[System.IO.File]::WriteAllText((Join-Path $output ('sysmon-{0:D3}.xml' -f $part)), $builder.ToString(), $utf8)
$summary = [ordered]@{
    case_id = $manifest.case_id; start_utc = $manifest.start_utc; end_utc = $manifest.end_utc
    computer_names = @($events | Select-Object -ExpandProperty MachineName -Unique)
    event_count = $events.Count; xml_parts = $part
    event_ids = @($events | Group-Object Id | Select-Object Name, Count)
    first_record_id = $events[0].RecordId; last_record_id = $events[-1].RecordId
    note = 'EVTX retains all event IDs in the time window; upload XML retains IDs 1,3,11,12,13,14,22.'
}
[System.IO.File]::WriteAllText((Join-Path $output 'collection.json'), ($summary | ConvertTo-Json -Depth 5), $utf8)
Get-ChildItem -LiteralPath $output -File | Get-FileHash -Algorithm SHA256 |
    Select-Object Path, Hash | Export-Csv -LiteralPath (Join-Path $output 'sha256.csv') -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($events.Count) events in $part XML part(s): $output"
Write-Host 'Upload sysmon-*.xml, not the .evtx file. Preserve both originals and hashes.'
