# Run on the Windows LAB endpoint, not on the analyst workstation.
[CmdletBinding()]
param(
    [ValidateSet('Combined', 'PersistenceOnly', 'PeriodicOnly', 'Jitter')]
    [string]$Scenario = 'Combined',
    [string]$ServerIp = '192.168.56.20',
    [ValidateRange(1, 65535)][int]$Port = 80,
    [ValidateRange(6, 30)][int]$Count = 12,
    [ValidateRange(5, 60)][int]$IntervalSeconds = 15,
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string]$CaseId = ('case-' + (Get-Date -Format 'yyyyMMdd-HHmmss')),
    [string]$OutputRoot = 'C:\SecurityLab\cases'
)
$ErrorActionPreference = 'Stop'
$address = [System.Net.IPAddress]::Parse($ServerIp)
$octets = $address.GetAddressBytes()
if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
    -not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
          ($octets[0] -eq 192 -and $octets[1] -eq 168))) {
    throw 'Use the private IPv4 address of your lab HTTP server.'
}
$caseDirectory = Join-Path $OutputRoot $CaseId
if (Test-Path -LiteralPath $caseDirectory) { throw 'Case directory already exists; choose another CaseId.' }
New-Item -ItemType Directory -Path $caseDirectory -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$valueName = 'SecurityLabMarker'
$writePersistence = $Scenario -in @('Combined', 'PersistenceOnly')
$sendNetwork = $Scenario -ne 'PersistenceOnly'
$start = [DateTime]::UtcNow
$requests = @()
$registryCommand = $null
$failure = $null
try {
    if ($writePersistence) {
        New-Item -Path $runKey -Force | Out-Null
        if (Get-ItemProperty -LiteralPath $runKey -Name $valueName -ErrorAction SilentlyContinue) {
            throw 'SecurityLabMarker already exists. Review and remove the previous lab marker first.'
        }
        # Only writes a timestamp marker at the next logon. Never starts a network client.
        $markerPath = Join-Path $caseDirectory 'logon-marker.txt'
        if ($markerPath.Contains('"') -or $markerPath.Contains('%') -or $markerPath.Contains('&')) {
            throw 'Use a simple output path without quote, percent or ampersand characters.'
        }
        $registryCommand = 'cmd.exe /d /c echo SECURITY_LAB_LOGON %DATE% %TIME%>>"' + $markerPath + '"'
        if ($registryCommand.Length -gt 260) { throw 'Autorun command is too long.' }
        New-ItemProperty -LiteralPath $runKey -Name $valueName -PropertyType String -Value $registryCommand | Out-Null
        Write-Host 'Created HKCU Run value SecurityLabMarker (marker only).'
    }
    if ($sendNetwork) {
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $next = 0.0
        $jitterIntervals = @(5, 30, 7, 45, 9, 20, 50, 6, 35, 11, 40)
        for ($index = 0; $index -lt $Count; $index++) {
            $delay = $next - $clock.Elapsed.TotalSeconds
            if ($delay -gt 0) { Start-Sleep -Milliseconds ([int]($delay * 1000)) }
            $sent = [DateTime]::UtcNow
            $client = New-Object System.Net.Sockets.TcpClient
            $status = $null
            $requestError = $null
            try {
                $task = $client.ConnectAsync($ServerIp, $Port)
                if (-not $task.Wait(3000)) { throw 'Connect timeout' }
                $stream = $client.GetStream()
                $stream.ReadTimeout = 3000
                $stream.WriteTimeout = 3000
                $payload = "GET /heartbeat.txt?case=$CaseId&seq=$index HTTP/1.1`r`nHost: ${ServerIp}:$Port`r`nUser-Agent: SecurityLab-Benign/1.0`r`nConnection: close`r`n`r`n"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
                $stream.Write($bytes, 0, $bytes.Length)
                $buffer = New-Object byte[] 1024
                $received = $stream.Read($buffer, 0, $buffer.Length)
                $status = ([System.Text.Encoding]::ASCII.GetString($buffer, 0, $received) -split "`r`n")[0]
                if ($status -notmatch '^HTTP/1\.[01] 200\b') { throw "Unexpected response: $status" }
            } catch {
                $requestError = $_.Exception.Message
            } finally {
                $client.Dispose()
            }
            $requests += [pscustomobject]@{ sequence = $index; utc = $sent.ToString('o'); status = $status; error = $requestError }
            Write-Host ("{0:o} seq={1} {2} {3}" -f $sent, $index, $status, $requestError)
            # Separate TCP connection per request; same PowerShell process writes the registry.
            $next += $(if ($Scenario -eq 'Jitter') { $jitterIntervals[$index % $jitterIntervals.Count] } else { $IntervalSeconds })
        }
    }
} catch {
    $failure = $_.Exception.Message
    throw
} finally {
    $end = [DateTime]::UtcNow
    $manifest = [ordered]@{
        case_id = $CaseId; scenario = $Scenario; host_hint = $env:COMPUTERNAME; process_id = $PID
        server_ip = $ServerIp; server_port = $Port; requested_connections = $(if ($sendNetwork) { $Count } else { 0 })
        interval_seconds = $IntervalSeconds; start_utc = $start.AddSeconds(-2).ToString('o')
        end_utc = $end.AddSeconds(3).ToString('o'); run_value_name = $(if ($writePersistence) { $valueName } else { $null })
        run_command = $registryCommand; failure = $failure; requests = $requests
        data_origin = 'real endpoint and network activity; benign controlled simulation'
    }
    [System.IO.File]::WriteAllText((Join-Path $caseDirectory 'scenario.json'), ($manifest | ConvertTo-Json -Depth 6), $utf8)
    Write-Host "Case saved: $caseDirectory"
    if ($writePersistence) { Write-Host 'Review/remove SecurityLabMarker after collection. It is not removed automatically.' }
}
if (@($requests | Where-Object { $_.error }).Count -gt 0) {
    throw 'One or more requests failed. Inspect scenario.json before treating this run as a successful capture.'
}
