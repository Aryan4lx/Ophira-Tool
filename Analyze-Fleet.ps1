<#
Analyze-Fleet.ps1 - merge IR-Triage case packages into one fleet view
Point it at a folder containing IRCASE_*.zip files (or extracted case folders).
Produces fleet_report.csv (every finding) + fleet_summary.txt + console overview,
and detects the same indicator/binary appearing on MULTIPLE hosts (outbreak signal).
Optional: -Hayabusa <path to hayabusa.exe> runs a Sigma timeline across ALL hosts' evtx.
Usage:
  .\Analyze-Fleet.ps1 -Path .\collections
  .\Analyze-Fleet.ps1 -Path .\collections -Hayabusa C:\Tools\hayabusa.exe
#>

[CmdletBinding()]
param(
    [string]$Path = '.',
    [string]$Hayabusa = '',
    [string]$OutFolder = ''
)

$ErrorActionPreference = 'Continue'
if (-not $OutFolder) { $OutFolder = $Path }
$sources = @()
$sources += Get-ChildItem $Path -Filter 'IRCASE_*.zip' -File -ErrorAction SilentlyContinue
foreach ($d in (Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^IRCASE_' })) {
    if ((Test-Path (Join-Path $d.FullName 'case.json')) -and -not ($sources | Where-Object { $_.BaseName -eq $d.Name })) { $sources += $d }
}
if (-not $sources) { Write-Host "No IRCASE_* packages found in $Path" -ForegroundColor Red; exit 1 }

$findings = @()
$hosts = @()
$evtxDirs = @()

foreach ($src in $sources) {
    $tmp = $null
    $dir = $src.FullName
    if ($src -is [System.IO.FileInfo]) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($src.FullName, $tmp)
            $dir = $tmp
        } catch { Write-Host "cannot extract $($src.Name): $($_.Exception.Message)" -ForegroundColor Red; continue }
    }
    $host_ = $src.Name -replace '^IRCASE_', '' -replace '_\d{8}_\d{6}.*$', ''
    $caseJson = Join-Path $dir 'case.json'
    $meta = $null
    if (Test-Path $caseJson) { try { $meta = Get-Content $caseJson -Raw | ConvertFrom-Json } catch { } }
    if ($meta -and $meta.Computer) { $host_ = $meta.Computer }
    $hosts += [pscustomobject]@{
        Host = $host_; Source = $src.Name; CaseID = $meta.CaseID
        Collected = $meta.StartedUTC; Admin = $meta.AdminElevated; Sysmon = $meta.SysmonPresent
    }

    $csvDir = Join-Path $dir 'csv'
    if (Test-Path $csvDir) {
        $map = @{
            'flash_process_scored.csv'         = 'ProcAnomaly'
            'flash_ioc_hits.csv'               = 'IOC-HIT'
            'flash_public_connections.csv'     = 'PublicConn'
            'scheduled_tasks_flagged.csv'      = 'TaskFlagged'
            'services_flagged.csv'             = 'ServiceFlagged'
            'security_bruteforce_candidates.csv' = 'BruteForce'
            'defender_threats.csv'             = 'AVDetection'
            'system_new_services.csv'          = 'NewService'
        }
        foreach ($k in $map.Keys) {
            $f = Join-Path $csvDir $k
            if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) {
                try {
                    $rows = Import-Csv $f
                    foreach ($r in @($rows)) {
                        $detail = ''
                        if ($r.PSObject.Properties['Name']) { $detail += "$($r.Name) " }
                        if ($r.PSObject.Properties['Path']) { $detail += "$($r.Path) " }
                        if ($r.PSObject.Properties['Indicator']) { $detail += "[$($r.Indicator)] $($r.Where)" }
                        if ($r.PSObject.Properties['SourceIp']) { $detail += "$($r.SourceIp) ($($r.FailedLogons) failures)" }
                        if ($r.PSObject.Properties['ThreatName']) { $detail += "$($r.ThreatName) $($r.Resources)" }
                        if ($r.PSObject.Properties['RemoteAddress']) { $detail += "$($r.RemoteAddress):$($r.RemotePort) <- $($r.ProcessPath)" }
                        if ($r.PSObject.Properties['Service']) { $detail += "$($r.Service) $($r.Binary)" }
                        if ($r.PSObject.Properties['Verdict']) { $detail = "[$($r.Verdict) $($r.Score)] " + $detail + " {$($r.Evidence)}" }
                        if (-not $detail) { $detail = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' }
                        $findings += [pscustomobject]@{ Host = $host_; Type = $map[$k]; Detail = $detail.Trim(); Source = $k }
                    }
                } catch { }
            }
        }
    }
    $e = Join-Path $dir 'raw\evtx'
    if (Test-Path $e) { $evtxDirs += $e }
    if ($tmp) { } # keep temp for possible hayabusa pass, cleaned at end
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  FLEET ANALYSIS - $($hosts.Count) hosts, $($findings.Count) findings" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

$byType = $findings | Group-Object Type | Sort-Object Count -Descending
Write-Host "`n  Findings by type:" -ForegroundColor White
foreach ($g in $byType) { Write-Host ("    {0,-14} {1}" -f $g.Name, $g.Count) }

$highRisk = @($findings | Where-Object { $_.Type -in @('IOC-HIT', 'AVDetection') })
if ($highRisk.Count) {
    Write-Host "`n  *** HIGH-PRIORITY (IOC hits / AV detections) ***" -ForegroundColor Red
    $highRisk | Group-Object Host | ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor Red }
}

$crossHost = @()
foreach ($g in ($findings | Where-Object { $_.Type -in @('ProcAnomaly', 'IOC-HIT', 'TaskFlagged', 'ServiceFlagged') } | Group-Object { ($_.Detail -split ' ')[0] })) {
    $hs = @($g.Group | Select-Object -ExpandProperty Host -Unique)
    if ($hs.Count -gt 1) { $crossHost += [pscustomobject]@{ Indicator = $g.Name; Hosts = ($hs -join ', '); HostCount = $hs.Count } }
}
if ($crossHost.Count) {
    Write-Host "`n  SAME INDICATOR ON MULTIPLE HOSTS (outbreak signal):" -ForegroundColor Magenta
    $crossHost | Sort-Object HostCount -Descending | Select-Object -First 20 | ForEach-Object {
        Write-Host ("    {0,-45} {1} hosts: {2}" -f $_.Indicator, $_.HostCount, $_.Hosts) -ForegroundColor Magenta
    }
}

$hayOut = $null
if ($Hayabusa -and (Test-Path $Hayabusa) -and $evtxDirs.Count -gt 0) {
    Write-Host "`n  Running hayabusa fleet timeline over $($evtxDirs.Count) hosts' evtx..." -ForegroundColor Cyan
    $merged = Join-Path ([IO.Path]::GetTempPath()) 'fleet_merged_evtx'
    if (Test-Path $merged) { Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $merged -Force | Out-Null
    $i = 0
    foreach ($e in $evtxDirs) {
        $i++
        Get-ChildItem $e -Filter '*.evtx' -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $merged ("{0}_{1}" -f $i, $_.Name)) -Force
        }
    }
    $hayOut = Join-Path $OutFolder 'fleet_hayabusa_timeline.csv'
    & $Hayabusa csv-timeline -d "$merged" -o "$hayOut" -q -w 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    if (Test-Path $hayOut) {
        $n = @(Get-Content $hayOut | Select-Object -Skip 1).Count
        Write-Host "    hayabusa: $n detections -> $hayOut" -ForegroundColor Yellow
    }
    Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue
}

$reportCsv = Join-Path $OutFolder 'fleet_report.csv'
$findings | Sort-Object Host, Type | Export-Csv -LiteralPath $reportCsv -NoTypeInformation -Encoding UTF8
$summaryTxt = Join-Path $OutFolder 'fleet_summary.txt'
$lines = @()
$lines += "IR-Triage fleet analysis - $(Get-Date -Format u)"
$lines += "Hosts: $($hosts.Count)  Findings: $($findings.Count)"
$lines += ""
$lines += "HOSTS:"
foreach ($h in $hosts) { $lines += "  $($h.Host)  collected=$($h.Collected) admin=$($h.Admin) sysmon=$($h.Sysmon) src=$($h.Source)" }
$lines += ""
$lines += "HIGH PRIORITY:"
if ($highRisk.Count) { foreach ($f in $highRisk) { $lines += "  $($f.Host) $($f.Type) $($f.Detail)" } } else { $lines += "  none" }
$lines += ""
$lines += "CROSS-HOST INDICATORS:"
if ($crossHost.Count) { foreach ($c in $crossHost) { $lines += "  $($c.Indicator) -> $($c.Hosts)" } } else { $lines += "  none" }
$lines | Set-Content -LiteralPath $summaryTxt -Encoding UTF8

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  fleet_report.csv  : $reportCsv" -ForegroundColor Green
Write-Host "  fleet_summary.txt : $summaryTxt" -ForegroundColor Green
if ($hayOut) { Write-Host "  hayabusa timeline : $hayOut" -ForegroundColor Green }
Write-Host "================================================================" -ForegroundColor Green

foreach ($src in $sources) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
