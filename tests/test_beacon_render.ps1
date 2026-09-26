$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.9 beaconing render + verdict fixture test
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
$names = @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport')
$defs = ''
foreach ($n in $names) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

# --- fixture case dir ---
$case = Join-Path $env:TEMP ("ophira_beacon_test_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'
$rawDir = Join-Path $case 'raw'
New-Item -ItemType Directory -Path $csvDir, $rawDir -Force | Out-Null
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null

# beacon candidates: 1 high + 1 medium
@'
"Severity","Rank","Process","RemoteIp","Port","Events","SpanMin","MedianIntervalSec","Jitter","Regularity","Flags"
"high",3,"C:\Users\u\AppData\Roaming\beacon.exe","203.0.113.10","443",60,59,59,0.04,1,"public-ip;user-path;flagged-process"
"medium",2,"C:\Tools\updater.exe","8.8.8.8","53",25,40,120,0.3,0.8,"public-ip"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'beacon_candidates.csv') -Encoding UTF8

# one HIGH scored process (cross-ref)
@'
"Name","Path","Verdict","Score","Reasons"
"beacon.exe","C:\Users\u\AppData\Roaming\beacon.exe","HIGH",90,"user path;unsigned;network"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'flash_process_scored.csv') -Encoding UTF8

foreach ($empty in @('hayabusa_timeline', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }

# --- 1. verdict engine ---
$v = Get-CompromiseVerdict
$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
Check "verdict level = LIKELY COMPROMISED (3)" ($v.LevelRank -eq 3)
Check "beacon-high signal present (floor 3)" (@($v.Signals | Where-Object { $_.Signal -match 'highly regular' }).Count -eq 1)
Check "beacon-med signal present (floor 2)" (@($v.Signals | Where-Object { $_.Signal -match 'periodic callbacks' }).Count -eq 1)
Check "counts BeaconHigh=1 BeaconMedium=1" ($v.Counts.BeaconHigh -eq 1 -and $v.Counts.BeaconMedium -eq 1)

# --- 2. report render ---
$script:Verdict = $v
$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "report.html written" ([bool]$html)
Check "beaconing nav anchor" ($html -match "href='#beacons'")
Check "beacon section header" ($html -match 'C2 beaconing candidates')
Check "high beacon row (203.0.113.10)" ($html -match '203\.0\.113\.10')
Check "beacon.exe process in table" ($html -match 'beacon\.exe')
Check "beacon IP in IOC block (defanged)" ($html -match 'ip\s+203\[\.?\]')
Check "verdict banner LIKELY COMPROMISED" ($html -match 'LIKELY COMPROMISED')
Check "interval rendered (~59s)" ($html -match '~59s')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept for inspection: $CaseDir" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }

