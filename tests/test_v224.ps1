$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.24 - master timeline weave (normalized schema, ~25 sources), MFT drive-letter fix,
# entity-card +/-15min context rendering
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

# ============================================================================
# PART 1 - master timeline weave through the real New-SuperTimeline
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'New-SuperTimeline')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_t224_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-HayabusaExe { $null }
function Invoke-NativeTool { param($ExePath, $ToolArgs, $WorkingDirectory, $QuietLog) }

New-Csv (Join-Path $CsvDir 'security_auth_events.csv') '"Time","EventId","Account","SourceIp","LogonType","LogonId"' @(
    '"2026-09-28 14:00:00","4624","bob","10.1.1.5","10","0x1234"'
)
New-Csv (Join-Path $CsvDir 'security_proc_events.csv') '"Time","EventId","Account","LogonId","NewProcess","CommandLine","ParentProcess"' @(
    '"2026-09-28 14:01:00","4688","bob","0x1234","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","powershell.exe -enc AAAA","C:\Windows\explorer.exe"'
)
New-Csv (Join-Path $CsvDir 'prefetch_parsed.csv') '"Executable","RunCount","LastRun"' @(
    '"C:\Windows\prefetch\EVIL.EXE","7","2026-09-28 14:02:00"'
)
New-Csv (Join-Path $CsvDir 'mft_recent.csv') '"Drive","Entry","Created","CreatedFN","LastModified","Size","Name","Path","Flags"' @(
    '"C:","100001","2026-09-28 14:03:00","2026-09-28 14:03:00","2026-09-28 14:03:00","4096","evil.exe","C:\Users\public\evil.exe","exec;user-path"'
)
New-Csv (Join-Path $CsvDir 'sysmon_dns.csv') '"Time","Image","QueryName","QueryResults","ProcessId"' @(
    '"2026-09-28 14:04:00","C:\Users\public\evil.exe","evil-c2.example.com","203.0.113.1","4242"'
)
New-Csv (Join-Path $CsvDir 'browser_history.csv') '"URL","Title","visit_time"' @(
    '"http://evil.example.com/payload","payload","2026-09-28 13:55:00"'
)
New-Csv (Join-Path $CsvDir 'wer_reports.csv') '"Time","App","Module","File"' @(
    '"2026-09-28 14:06:00","C:\evil\tool.exe","crashme.dll","ReportArchive\appcrash\Report.wer"'
)
New-Csv (Join-Path $CsvDir 'session_activity.csv') '"Time","SessionAccount","SourceIp","LogonType","Activity","Detail"' @(
    '"2026-09-28 14:07:00","bob","10.1.1.5","10","process","evil.exe cmd /c whoami"'
)
New-Csv (Join-Path $CsvDir 'hunt_findings.csv') '"Found","Rule","Severity","Entity","Attck","Evidence"' @(
    '"2026-09-28T14:05:00.0000000Z","Downloaded then executed","high","C:\Users\public\evil.exe","T1105","x"'
)

New-SuperTimeline

$tl = @(Import-Csv -LiteralPath (Join-Path $CsvDir 'supertimeline.csv'))
Check "weave: 7 timed fixture rows all present (derived sources excluded)" ($tl.Count -eq 7)
Check "weave: normalized schema (Timestamp/Source/Type/Actor/Entity/Detail)" (@($tl[0].PSObject.Properties.Name) -join ',' -eq 'Timestamp,Source,Type,Actor,Entity,Detail')
Check "weave: sorted ascending chronologically" ((@($tl | ForEach-Object { [datetime]$_.Timestamp }) | Sort-Object) -join '|' -eq (@($tl | ForEach-Object { [datetime]$_.Timestamp }) -join '|'))
Check "weave: 4688 row carries actor + parent + cmdline" (@($tl | Where-Object { $_.Source -eq 'security_proc_events' -and $_.Actor -eq 'bob' -and "$($_.Detail)" -match 'explorer\.exe.*powershell\.exe -enc AAAA' }).Count -eq 1)
Check "weave: prefetch row typed + run count in detail" (@($tl | Where-Object { $_.Type -eq 'prefetch run' -and "$($_.Detail)" -match 'run count 7' -and $_.Actor -eq 'EVIL.EXE' }).Count -eq 1)
Check "weave: mft row entity is drive-prefixed path" (@($tl | Where-Object { $_.Source -eq 'mft_recent' -and $_.Entity -eq 'C:\Users\public\evil.exe' }).Count -eq 1)
Check "weave: browser row found via *time* column" (@($tl | Where-Object { $_.Source -eq 'browser_history' -and $_.Entity -match 'evil\.example\.com' }).Count -eq 1)
Check "weave: derived sources (session/hunt) NOT woven" (@($tl | Where-Object { $_.Source -match 'session_activity|hunt_findings' }).Count -eq 0)
Check "weave: timestamps normalized (no raw .NET date noise)" (@($tl | Where-Object { $_.Timestamp -match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$' }).Count -eq $tl.Count)

# ============================================================================
# PART 2 - structural: MFT drive fix + entity-card context wiring
# ============================================================================
Check "5.5: MFT paths get drive-letter prefix" ($src -match '\$path = if \(\$parent\) \{ "\$dl\$parent\\\$name" \}')
Check "report: entity-card context window wired" ($src -match 'Context: everything else happening' -and $src -match '\$fs\.AddMinutes\(-15\)')
Check "report: context reads supertimeline" ($src -match "Import-CaseCsv 'supertimeline'")
Check "evidence index: master timeline description updated" ($src -match 'MASTER TIMELINE: gathered evidence woven chronologically')

# ============================================================================
# PART 3 - context window rendered in the report
# ============================================================================
$rd = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $rd += $m.Value + "`r`n"
}
Invoke-Expression $rd
$case3 = Join-Path $env:TEMP "ophira_c224_$stamp"
$CsvDir = Join-Path $case3 'csv'; $RawDir = Join-Path $case3 'raw'; $CaseDir = $case3; $MemDir = Join-Path $case3 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Computer = 'H1'; $LogHours = 168
$script:CurrentCaseID = 'C'; $script:CurrentAnalyst = 'f'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
# multi-source entity with FirstSeen inside the fixture timeline window
New-Csv (Join-Path $CsvDir 'entities_binaries.csv') '"Categories","CatCount","Name","Path","Verdict","Signer","FirstSeen","LastSeen","Hashes","Bytes","Evidence"' @(
    '"running;hunt",2,"evil.exe","C:\Users\public\evil.exe","HIGH",9,"2026-09-28 14:03:00","2026-09-28 14:06:00","","","hunt: [high] x"'
)
Copy-Item -LiteralPath (Join-Path $case1 'csv\supertimeline.csv') -Destination (Join-Path $CsvDir 'supertimeline.csv')
foreach ($empty in @('hunt_findings', 'hayabusa_timeline', 'beacon_candidates', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'ioc_hits_browser', 'posture', 'memory_malfind', 'prefetch_parsed', 'mft_recent', 'usn_write_bursts', 'dns_beacon_candidates', 'loldrivers_hits', 'ps_decoded_commands', 'certificates', 'asep_sweep', 'parse_needed', 'srum_usage', 'entities_accounts', 'entities_remotes', 'memory_live_scan', 'session_activity', 'process_chains')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rendered = Get-Content (Join-Path $CaseDir 'report.html') -Raw
Check "report: context window rendered for top entity" ($rendered -match 'Context: everything else happening')
Check "report: context includes in-window DNS row" ($rendered -match 'evil-c2\.example\.com')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case3)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
