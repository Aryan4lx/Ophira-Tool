# v2.12 Phase D test: evidence index + snapshot sections + ATT&CK layer + SIEM record kinds
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath $repoScript -Raw
$names = @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'New-AttackLayer', 'New-SiemExport')
$defs = ''
foreach ($n in $names) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$case = Join-Path $env:TEMP ("ophira_pd_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'
New-Item -ItemType Directory -Path $csvDir, $rawDir -Force | Out-Null
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168; $ScriptVersion = '9.99'
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }

@'
"RealTimeProtection","AMServiceEnabled","AntispywareEnabled","AntivirusSigAgeDays","QuickScanAge","FullScanAge","LastQuickScan"
"True","True","True","2","1","30","2026-09-25"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'defender_status.csv') -Encoding UTF8
@'
"ThreatName","SeverityID","IsActive","Resources"
"Trojan:Win32/Emotet",4,"True","file:C:\Users\u\evil.exe"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'defender_threats.csv') -Encoding UTF8
@'
"Source","Target","Type"
"TERMSRV","10.0.0.5","DOMAIN/ADMIN"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'saved_credentials.csv') -Encoding UTF8
@'
"Target","UsernameHint","LastUsed"
"10.1.2.3","admin@corp","2026-09-24"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'rdp_client_targets.csv') -Encoding UTF8
@'
"DisplayName","OwnerAccount","JobState","TransferType","Files"
"suspicious_download","CORP\u","Suspended","Download","C:\Users\u\out.zip"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'bits_jobs.csv') -Encoding UTF8
@'
"Timestamp","Computer","EventID","Level","RuleTitle","Details","MitreTactics","MitreTags"
"2026-09-24 10:00:00.000 +00:00","TESTHOST","1","high","Suspicious PowerShell","-enc command","Exec","T1059.001"
"2026-09-24 10:05:00.000 +00:00","TESTHOST","1","low","Run key persistence","reg add","Persis","T1547.001"
"2026-09-24 10:05:00.000 +00:00","TESTHOST","1","info","Same as above","","Persis","T1547.001"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'hayabusa_timeline.csv') -Encoding UTF8
@'
"Severity","Rank","Process","RemoteIp","Port","Events","SpanMin","MedianIntervalSec","Jitter","Regularity","Flags"
"high",3,"C:\Users\u\beacon.exe","203.0.113.10","443",60,59,59,0.04,1,"public-ip;user-path"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'beacon_candidates.csv') -Encoding UTF8
@'
"WindowStart","WriteEvents","DistinctFiles"
"2026-09-25 08:30",4200,900
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'usn_write_bursts.csv') -Encoding UTF8

foreach ($empty in @('yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'mft_recent', 'prefetch_parsed', 'asep_sweep', 'certificates')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

$v = Get-CompromiseVerdict
$script:Verdict = $v
$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw

Check "nav: evidence index link" ($html -match "href='#evidence'")
Check "snapshot: defender status" ($html -match 'RealTimeProtection')
Check "snapshot: defender threat (Emotet)" ($html -match 'Emotet')
Check "snapshot: saved creds (TERMSRV)" ($html -match 'TERMSRV')
Check "snapshot: RDP outbound (10.1.2.3)" ($html -match '10\.1\.2\.3')
Check "snapshot: BITS job" ($html -match 'suspicious_download')
Check "evidence index: table header" ($html -match 'Evidence index')
Check "evidence index: row count column" ($html -match '<td>3</td>' -and $html -match 'hayabusa_timeline\.csv')
Check "evidence index: description present" ($html -match 'Sigma detection timeline')
Check "evidence index: key files meta (supertimeline/siem/layer)" ($html -match 'supertimeline\.csv' -and $html -match 'siem_export\.ndjson' -and $html -match 'attack_layer\.json')

New-AttackLayer
$layerFile = Join-Path $CaseDir 'attack_layer.json'
Check "attack layer file written" (Test-Path -LiteralPath $layerFile)
$layer = Get-Content -LiteralPath $layerFile -Raw | ConvertFrom-Json
Check "layer: 2 techniques (T1059.001, T1547.001)" (@($layer.techniques).Count -eq 2)
Check "layer: T1547.001 score 2" (@($layer.techniques | Where-Object { $_.techniqueID -eq 'T1547.001' }).Count -eq 1 -and "$(@($layer.techniques | Where-Object { $_.techniqueID -eq 'T1547.001' })[0].score)" -eq '2')
Check "layer: domain enterprise-attack" ("$($layer.domain)" -eq 'enterprise-attack')

New-SiemExport
$siemFile = Join-Path $CaseDir 'siem_export.ndjson'
Check "siem export written" (Test-Path -LiteralPath $siemFile)
$siem = Get-Content -LiteralPath $siemFile
$kinds = @($siem | ForEach-Object { ($_ | ConvertFrom-Json).kind } | Sort-Object -Unique)
Check "siem: beacon record" ($kinds -contains 'beacon')
Check "siem: mass_modification record" ($kinds -contains 'mass_modification')
Check "siem: verdict record" ($kinds -contains 'verdict')
Check "siem: sigma_alert record" ($kinds -contains 'sigma_alert')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept: $CaseDir" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
