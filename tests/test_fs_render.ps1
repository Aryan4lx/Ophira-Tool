$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.10 verdict + report render test for file-system forensics artifacts
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

$case = Join-Path $env:TEMP ("ophira_fs_render_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'
New-Item -ItemType Directory -Path $csvDir, $rawDir -Force | Out-Null
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }

@'
"WindowStart","WriteEvents","DistinctFiles"
"2026-09-25 08:30",4200,900
"2026-09-25 08:31",3800,880
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'usn_write_bursts.csv') -Encoding UTF8
@'
"Entry","Created","LastModified","Size","Name","Path","Flags"
"1000","2026-08-01 10:00:00","2026-08-01 10:00:00","204800","evil.exe","C:\Users\u\AppData\Roaming\evil.exe","exec;user-path"
"1005","2026-09-25 09:00:00","2026-09-25 09:00:00","900","dropped.ps1","C:\Users\u\AppData\Local\Temp\dropped.ps1","exec;user-path;recent"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'mft_recent.csv') -Encoding UTF8
@'
"SourceFile","SourceCreated","ExecutableName","Size","Hash","RunCount","LastRun"
"C:\Windows\Prefetch\BEACON.EXE-AB12CD34.pf","2026-09-24 10:00:00","BEACON.EXE#beacon.exe","204800","AB12CD34","99","2026-09-25 08:00:00"
"C:\Windows\Prefetch\SVCHOST.EXE-11223344.pf","2026-09-01 10:00:00","SVCHOST.EXE#svchost.exe","48000","11223344","3","2026-09-25 07:00:00"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'prefetch_parsed.csv') -Encoding UTF8

foreach ($empty in @('hayabusa_timeline', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'beacon_candidates', 'flash_process_scored')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

$v = Get-CompromiseVerdict
Check "verdict = LIKELY COMPROMISED (3)" ($v.LevelRank -eq 3)
Check "USN mass-modification signal floor 3" (@($v.Signals | Where-Object { $_.Signal -match 'mass file modification' }).Count -eq 1)
Check "coverage includes USN journal" (@($v.Coverage | Where-Object { $_.Source -match 'USN journal' -and $_.Collected }).Count -eq 1)
Check "coverage includes MFT timeline" (@($v.Coverage | Where-Object { $_.Source -match 'MFT file timeline' -and $_.Collected }).Count -eq 1)

$script:Verdict = $v
$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "nav link #filesystem" ($html -match "href='#filesystem'")
Check "section header" ($html -match 'File-system evidence')
Check "ransomware banner" ($html -match 'Ransomware-style mass file modification')
Check "burst window row 08:30" ($html -match '2026-09-25 08:30')
Check "mft user-path row (evil.exe)" ($html -match 'evil\.exe')
Check "prefetch table present + BEACON.EXE" ($html -match 'BEACON\.EXE')
Check "prefetch sorted by RunCount (99-row before 3-row)" ($html.IndexOf('BEACON.EXE') -lt $html.IndexOf('SVCHOST.EXE'))
Check "verdict banner LIKELY COMPROMISED" ($html -match 'LIKELY COMPROMISED')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept: $CaseDir" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }

