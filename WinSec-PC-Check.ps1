#Requires -Version 5.1
<#
Windows 10/11, Windows Server; Windows PowerShell 5.1.
Run examples:
  .\WinSec-PC-Check.ps1 -Demo
  .\WinSec-PC-Check.ps1 -LookbackMinutes 60
  .\WinSec-PC-Check.ps1 -LookbackMinutes 1440 -Threshold 10 -WindowMinutes 5
Read-only: no firewall, policy, account, antivirus or scheduled-task changes.
One-shot collector, NOT a continuous monitor or comprehensive CVE scanner.
Run live collection from an elevated Windows PowerShell for Security access.
Reports contain account names/IPs. Store locally and redact before sharing.
No events != no attacks: audit configuration and retention determine visibility.
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [ValidateRange(1,10080)][int]$LookbackMinutes = 60,
    [ValidateRange(1,1440)][int]$WindowMinutes = 5,
    [ValidateRange(2,10000)][int]$Threshold = 10,
    [ValidateRange(100,100000)][int]$MaxEvents = 10000,
    [string]$OutputRoot = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Resolve script-relative output only after parameter binding.
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $baseDirectory = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($baseDirectory) -and $MyInvocation.MyCommand.Path) {
        $baseDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    if ([string]::IsNullOrWhiteSpace($baseDirectory)) {
        $baseDirectory = (Get-Location).Path
    }
    $OutputRoot = Join-Path -Path $baseDirectory -ChildPath 'WinSec-Reports'
}
if (-not $Demo -and $env:OS -ne 'Windows_NT') { throw 'Live mode requires Windows.' }
$now = Get-Date
$start = $now.AddMinutes(-$LookbackMinutes)
$run = Join-Path $OutputRoot ($now.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$null = New-Item -ItemType Directory -Path $run -Force
$collection = New-Object 'System.Collections.Generic.List[object]'
$raw = New-Object 'System.Collections.Generic.List[string]'
function Get-Field($Data, [string]$Name) {
    if ($Data.ContainsKey($Name)) { return [string]$Data[$Name] }
    return ''
}
function Read-Events([string]$Log, [int[]]$Ids) {
    try {
        $items = @(Get-WinEvent -FilterHashtable @{LogName=$Log;Id=$Ids;StartTime=$start;EndTime=$now} -MaxEvents $MaxEvents -ErrorAction Stop)
        $status = 'Collected'
        if ($items.Count -ge $MaxEvents) { $status = 'PossiblyTruncated' }
        $collection.Add([pscustomobject]@{Log=$Log;Status=$status;Count=$items.Count;Detail='Newest events returned; investigate truncation before conclusions.'})
        foreach ($item in $items) {
            $xmlText = $item.ToXml()
            $raw.Add($xmlText)
            [xml]$xml = $xmlText
            $data = @{}
            foreach ($node in @($xml.Event.EventData.Data)) {
                if ($null -ne $node -and $node.HasAttribute('Name')) { $data[$node.GetAttribute('Name')] = $node.InnerText }
            }
            [pscustomobject]@{Time=$item.TimeCreated;Id=$item.Id;RecordId=$item.RecordId;Log=$Log;Data=$data}
        }
    } catch {
        $status = 'Unavailable'
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $status = 'NoMatchingEvents' }
        $collection.Add([pscustomobject]@{Log=$Log;Status=$status;Count=0;Detail=$_.Exception.Message})
    }
}
$events = @()
$checks = @()
if ($Demo) {
    # Synthetic documentation IP only; no login attempts, malware or network traffic.
    $events = @(1..12 | ForEach-Object {
        [pscustomobject]@{Time=$now.AddSeconds(-180 + $_ * 10);Id=4625;RecordId=$_;Log='DEMO';Data=@{IpAddress='192.0.2.10';TargetUserName='demo-user';TargetDomainName='DEMO';LogonType='10';Status='0xC000006D';SubStatus='0xC000006A'}}
    })
    $collection.Add([pscustomobject]@{Log='DEMO';Status='Synthetic';Count=$events.Count;Detail='Sample only; not evidence from this PC.'})
    $checks = @([pscustomobject]@{Check='Mode';Value='DEMO - synthetic data only'})
} else {
    $events = @(Read-Events 'Security' @(4625,4624))
    $events += @(Read-Events 'Microsoft-Windows-Windows Defender/Operational' @(1116,1117,1118,1119,5001))
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $checks += [pscustomobject]@{Check='Defender';Value=($mp | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,QuickScanEndTime | ConvertTo-Json -Compress)}
    } catch { $checks += [pscustomobject]@{Check='Defender';Value=('Unknown: ' + $_.Exception.Message)} }
    try {
        $checks += @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{Check=('Firewall/' + $_.Name);Value=[string]$_.Enabled} })
    } catch { $checks += [pscustomobject]@{Check='Firewall';Value=('Unknown: ' + $_.Exception.Message)} }
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $checks += [pscustomobject]@{Check='OS';Value=($os.Caption + '; Build ' + $os.BuildNumber)}
    } catch { $checks += [pscustomobject]@{Check='OS';Value=('Unknown: ' + $_.Exception.Message)} }
    # Export audit policy in the OS language. No policy changes.
    try {
        $policy = & auditpol.exe /get /category:* 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($policy -join "`n") }
        $policy | Out-File (Join-Path $run 'audit-policy.txt') -Encoding utf8
    } catch { $checks += [pscustomobject]@{Check='AuditPolicy';Value=('Unknown: ' + $_.Exception.Message)} }
}
$failed = @($events | Where-Object Id -eq 4625 | ForEach-Object {
    [pscustomobject]@{Time=$_.Time;RecordId=$_.RecordId;IP=(Get-Field $_.Data 'IpAddress');User=(Get-Field $_.Data 'TargetUserName');Domain=(Get-Field $_.Data 'TargetDomainName');LogonType=(Get-Field $_.Data 'LogonType');Status=(Get-Field $_.Data 'Status');SubStatus=(Get-Field $_.Data 'SubStatus')}
})
$alerts = @()
# Sliding time window, one peak alert per source IP. Unknown/local sources excluded.
foreach ($group in @($failed | Where-Object { $_.IP -and $_.IP -notin @('-','127.0.0.1','::1','0.0.0.0','::') } | Group-Object IP)) {
    $sorted = @($group.Group | Sort-Object Time)
    $left=0; $peak=0; $peakLeft=0; $peakRight=0
    for ($right=0; $right -lt $sorted.Count; $right++) {
        while (($sorted[$right].Time - $sorted[$left].Time).TotalMinutes -gt $WindowMinutes) { $left++ }
        $count = $right - $left + 1
        if ($count -gt $peak) { $peak=$count; $peakLeft=$left; $peakRight=$right }
    }
    if ($peak -ge $Threshold) {
        $slice = @($sorted[$peakLeft..$peakRight])
        $alerts += [pscustomobject]@{Type='SuspectedBruteForce';IP=$group.Name;Count=$peak;WindowMinutes=$WindowMinutes;First=$sorted[$peakLeft].Time;Last=$sorted[$peakRight].Time;Users=(@($slice.User | Sort-Object -Unique) -join ', ');Action='Review only; no blocking';Confidence='Heuristic; stale credentials can also cause failures'}
    }
}
$malware = @($events | Where-Object { $_.Id -in @(1116,1117,1118,1119,5001) } | ForEach-Object {
    [pscustomobject]@{Time=$_.Time;EventId=$_.Id;RecordId=$_.RecordId;Details=$_.Data;Assessment='Review event fields; event 1117 alone does not prove remediation.'}
})
$successes = @($events | Where-Object Id -eq 4624 | ForEach-Object {
    [pscustomobject]@{Time=$_.Time;RecordId=$_.RecordId;IP=(Get-Field $_.Data 'IpAddress');User=(Get-Field $_.Data 'TargetUserName');LogonType=(Get-Field $_.Data 'LogonType')}
})
$report = [ordered]@{
    Version='1.0';Mode=$(if ($Demo) {'DEMO'} else {'LIVE'});Computer=$env:COMPUTERNAME
    Generated=$now.ToString('o');Start=$start.ToString('o');End=$now.ToString('o')
    Limitations=@('Read-only snapshot; not a comprehensive vulnerability scan.','No matching events is not proof of safety. Check audit-policy.txt and collection status.','Per-log maximum applies to all requested event IDs combined; busy success logs may crowd out failures.','Source IP may be absent, proxied or shared; never auto-block based solely on this report.','Raw XML is a collected subset, not a full EVTX export. No Defender events may mean another antivirus is installed.')
    Collection=@($collection.ToArray());Checks=$checks;Alerts=$alerts;FailedLogons=$failed;SuccessfulLogons=$successes;DefenderEvents=$malware
}
$report | ConvertTo-Json -Depth 12 | Out-File (Join-Path $run 'report.json') -Encoding utf8
$failed | Export-Csv (Join-Path $run 'failed-logons.csv') -NoTypeInformation -Encoding utf8
if ($raw.Count -gt 0) { ('<Events>' + ($raw -join "`n") + '</Events>') | Out-File (Join-Path $run 'events.xml') -Encoding utf8 }
# Encode JSON before embedding in HTML: event data cannot execute markup/scripts.
$encoded = [System.Net.WebUtility]::HtmlEncode(($report | ConvertTo-Json -Depth 12))
$html = @"
<!doctype html><html lang="en"><meta charset="utf-8"><title>WinSec PC Check</title>
<style>body{font:15px system-ui;margin:32px;background:#f5f7fa;color:#172235}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:20px;border-radius:12px}h1{color:#123963}</style>
<h1>WinSec PC Check - $($report.Mode)</h1><p>Alerts: $($alerts.Count) | Failed logons: $($failed.Count) | Defender events: $($malware.Count)</p>
<p>Read-only snapshot. Review collection status before drawing conclusions. DEMO results are synthetic.</p><pre>$encoded</pre></html>
"@
$html | Out-File (Join-Path $run 'report.html') -Encoding utf8
# Materialize both file enumeration and hashes BEFORE opening the output CSV.
# Exclude the manifest itself, including when a directory is reused.
$hashInputs = @(Get-ChildItem -LiteralPath $run -File | Where-Object { $_.Name -ne 'sha256.csv' })
$hashResults = @($hashInputs | Get-FileHash -Algorithm SHA256 | Select-Object Hash,Path)
$hashResults | Export-Csv (Join-Path $run 'sha256.csv') -NoTypeInformation -Encoding utf8
Write-Host ('Report: ' + (Join-Path $run 'report.html'))
Write-Host ('Mode: {0}; suspected brute-force sources: {1}; Defender events: {2}' -f $report.Mode,$alerts.Count,$malware.Count)
if ($Demo -and $Threshold -eq 10 -and $WindowMinutes -eq 5 -and $alerts.Count -ne 1) { throw 'Demo self-check failed: expected one alert.' }
