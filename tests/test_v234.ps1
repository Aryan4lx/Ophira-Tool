$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.34 - report timeline preview (client-side filter over the last 2000 supertimeline rows)
# + release workflow (tag -> kit zip + SHA256SUMS + CHANGELOG notes) + hosts.txt.example.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - timeline preview rendered by the real New-HtmlReport
# ============================================================================
$rd = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $rd += $m.Value + "`r`n"
}
Invoke-Expression $rd
$case1 = Join-Path $env:TEMP "ophira_v34_$stamp"
$CsvDir = Join-Path $case1 'csv'; $RawDir = Join-Path $case1 'raw'; $CaseDir = $case1; $MemDir = Join-Path $case1 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Computer = 'H1'; $LogHours = 168
$script:CurrentCaseID = 'C'; $script:CurrentAnalyst = 'f'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$tlHeader = '"Timestamp","Source","Type","Actor","Entity","Detail"'
@($tlHeader,
  '"2026-09-28 14:00:00","sysmon_dns","DNS query","bob","evil-c2.example.com","resolved 203.0.113.9"',
  '"2026-09-28 14:02:00","security_proc_events","process creation","alice","cmd.exe","cmdline ""whoami"" run (parent explorer)"',
  '"2026-09-28 14:05:00","hayabusa","sigma high","SYSTEM","winupd.exe","renamed LOLBin"') |
  Set-Content -LiteralPath (Join-Path $CsvDir 'supertimeline.csv') -Encoding UTF8
foreach ($empty in @('hunt_findings', 'hayabusa_timeline', 'beacon_candidates', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'ioc_hits_browser', 'posture', 'memory_malfind', 'prefetch_parsed', 'mft_recent', 'usn_write_bursts', 'dns_beacon_candidates', 'loldrivers_hits', 'ps_decoded_commands', 'certificates', 'asep_sweep', 'parse_needed', 'srum_usage', 'entities_accounts', 'entities_remotes', 'memory_live_scan', 'session_activity', 'process_chains', 'entities_binaries')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rendered = Get-Content (Join-Path $CaseDir 'report.html') -Raw
Check "timeline: nav link + section header" ($rendered -match "href='#timeline'" -and $rendered -match 'Timeline preview \(newest 3 of 3 rows\)')
Check "timeline: rows embedded as JSON" (([regex]::Matches($rendered, [regex]::Escape('"Source":"sysmon_dns"'))).Count -ge 1 -and ([regex]::Matches($rendered, [regex]::Escape('"Source":"hayabusa"'))).Count -ge 1 -and ([regex]::Matches($rendered, [regex]::Escape('"Source":"security_proc_events"'))).Count -ge 1)
Check "timeline: JSON embedded inside the script block" ($rendered -match '(?s)<script>\s*var TL = \[.*?\];')
Check "timeline: double quote in Detail escaped (valid JS)" ($rendered -match [regex]::Escape('\"whoami\"'))
Check "timeline: source dropdown lists distinct sources" ($rendered -match '<option>sysmon_dns</option>' -and $rendered -match '<option>hayabusa</option>' -and $rendered -match ([regex]::Escape("<option value=''>all</option>")))
Check "timeline: full-CSV pointer + Mode Timeline pointer" ($rendered -match 'csv\\supertimeline\.csv' -and $rendered -match '-Mode Timeline')
Check "timeline: filter UI wired (text/date/source + draw)" ($rendered -match "id='tlq'" -and $rendered -match "type='date'" -and $rendered -match "id='tlsrc'" -and $rendered -match 'function tlDraw' -and $rendered -match 'tlDraw\(\);')
Check "timeline: render cap 500 + status line" ($rendered -match '\+\+n>=500' -and $rendered -match "id='tlstat'")
Check "timeline: newest-first rendering" ($rendered -match 'for\(var i=TL\.length-1;i>=0;i--\)')

# degrade: empty supertimeline renders section without crash
"# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir 'supertimeline.csv') -Encoding UTF8
$null = New-HtmlReport
$rendered2 = Get-Content (Join-Path $CaseDir 'report.html') -Raw
Check "timeline: empty supertimeline -> newest 0 of 0, empty JSON array" ($rendered2 -match 'Timeline preview \(newest 0 of 0 rows\)' -and $rendered2 -match [regex]::Escape('var TL = [];'))

# ============================================================================
# PART 2 - release workflow
# ============================================================================
$wfPath = Join-Path (Split-Path -Parent $PSScriptRoot) ".github\workflows\release.yml"
Check "release: workflow exists" (Test-Path $wfPath)
$wf = Get-Content -LiteralPath $wfPath -Raw
Check "release: triggers on v* tags" ($wf -match 'tags:' -and $wf -match "'v\*'")
Check "release: windows runner + contents write" ($wf -match 'windows-latest' -and $wf -match 'contents: write')
Check "release: kit = script + bat + docs + license + hosts example" ((@('Ophira.ps1', 'RUN-OPHIRA.bat', 'README.md', 'CHANGELOG.md', 'LICENSE', 'hosts.txt.example') | Where-Object { $wf -match [regex]::Escape("'$_'") }).Count -eq 6)
Check "release: missing kit file fails the build" ($wf -match 'throw "missing kit file')
Check "release: zip named per tag + SHA256SUMS over every file" ($wf -match 'Ophira-\$tag\.zip' -and $wf -match 'SHA256SUMS' -and $wf -match 'Get-FileHash \$f -Algorithm SHA256')
Check "release: version-tag consistency gate" ($wf -match 'Ophira\.ps1 version does not match tag')
Check "release: notes extracted from the tag's CHANGELOG section" ($wf -match 'Escape\(\$env:GITHUB_REF_NAME\)' -and $wf -match 'no CHANGELOG section for')
Check "release: gh release create with zip + sums + notes file" ($wf -match 'gh release create' -and $wf -match '--notes-file')

# ============================================================================
# PART 3 - hosts.txt.example ships safe (no active targets)
# ============================================================================
$exPath = Join-Path (Split-Path -Parent $PSScriptRoot) "hosts.txt.example"
Check "hosts example: file exists" (Test-Path $exPath)
$active = @(Get-Content -LiteralPath $exPath | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
Check "hosts example: zero active targets (all lines commented)" ($active.Count -eq 0)
Check "hosts example: matches the deploy wizard's comment-strip parser" ($src -match [regex]::Escape("-replace '#.*$', '').Trim()"))

Remove-Item $case1 -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
