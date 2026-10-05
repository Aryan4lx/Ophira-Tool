$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.39 - collapsed-message 4624 parse fix, report UX: ATT&CK expandable technique rows,
# sigma drill-down ALL events (in-report pager/search/copy), click-to-copy clip cells,
# supertimeline = gathered evidence only (scanner outputs unwoven, no JS embed).
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - 4624 parse on a whitespace-COLLAPSED message (the real-world shape)
# ============================================================================
$m41 = [regex]::Match($src, "(?s)Id = '4\.1';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '4\.2'")
if (-not $m41.Success) { throw 'extract failed: module 4.1' }
$defs41 = ''
foreach ($n in @('Get-EventDataRows')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs41 += $m.Value + "`r`n"
}
Invoke-Expression $defs41
function Get-LogStart { $null }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $MaxMsg)
    $msg = 'An account was successfully logged on. Subject: Security ID: S-1-5-18 Account Name: DESKTOP-88Q1H74$ Account Domain: WORKGROUP Logon ID: 0x3E7 New Logon: Security ID: S-1-5-21-1 Account Name: Aryan Account Domain: DESKTOP-88Q1H74 Logon ID: 0x52609325 Linked Logon ID: 0x52609361 Network Account Name: - Network Account Domain: - Logon GUID: - Process Information: New Process ID: 0x1 Process Name: - Network Information: Workstation Name: DESKTOP-88Q1H74 Source Network Address: 192.168.1.50 Source Port: 0 Detailed Authentication Information: Logon Type: 2'
    @(, [pscustomobject]@{ TimeCreated = (Get-Date '2026-10-05 13:00:00'); Id = 4624; Message = $msg })
}
function Export-Evtx { param($LogName, $FileName) }
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$mod41 = [pscustomobject]@{ Id = '4.1'; Name = 'Security log'; Run = [scriptblock]::Create($m41.Groups[1].Value) }
& $mod41.Run
$a = @($saved['security_auth_events'])[0]
Check "4624 collapsed: Account = 'Aryan' (not the whole message)" ("$($a.Account)" -eq 'Aryan')
Check "4624 collapsed: AccountDomain = 'DESKTOP-88Q1H74'" ("$($a.AccountDomain)" -eq 'DESKTOP-88Q1H74')
Check "4624 collapsed: SubjectAccount = 'DESKTOP-88Q1H74`$' (first match)" ("$($a.SubjectAccount)" -eq 'DESKTOP-88Q1H74$')
Check "4624 collapsed: LogonId = New Logon session 0x52609325" ("$($a.LogonId)" -eq '0x52609325')
Check "4624 collapsed: LogonType + SourceIp" ("$($a.LogonType)" -eq '2' -and "$($a.SourceIp)" -eq '192.168.1.50')

# NT AUTHORITY domain with a space must survive the bounded capture
function Get-FilteredEvents { param($LogName, $Ids, $Start, $MaxMsg)
    $msg = 'An account was successfully logged on. Subject: Account Name: - Account Domain: - Logon ID: 0x0 New Logon: Account Name: SYSTEM Account Domain: NT AUTHORITY Logon ID: 0x3E7 Logon Type: 5 Source Network Address: -'
    @(, [pscustomobject]@{ TimeCreated = (Get-Date); Id = 4624; Message = $msg })
}
& $mod41.Run
$a2 = @($saved['security_auth_events'])[0]
Check "4624 collapsed: 'NT AUTHORITY' domain kept intact" ("$($a2.AccountDomain)" -eq 'NT AUTHORITY' -and "$($a2.Account)" -eq 'SYSTEM')

# ============================================================================
# PART 2 - report render: ATT&CK expandable, sigma in-report browser, clip cells
# ============================================================================
$rd = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $rd += $m.Value + "`r`n"
}
Invoke-Expression $rd
$case1 = Join-Path $env:TEMP "ophira_v39_$stamp"
$CsvDir = Join-Path $case1 'csv'; $RawDir = Join-Path $case1 'raw'; $CaseDir = $case1; $MemDir = Join-Path $case1 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Computer = 'H1'; $LogHours = 168
$script:CurrentCaseID = 'C'; $script:CurrentAnalyst = 'f'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }

function New-Csv([string]$path, [string]$header, [string[]]$lines) { @($header) + $lines | Set-Content -LiteralPath $path -Encoding UTF8 }
# sigma timeline: 30 events across 2 rules (rule B has 30 rows -> drill must embed ALL of them)
$b = @()
for ($i = 1; $i -le 30; $i++) { $b += ('"2026-10-05 09:33:{0:00}","med","H1",4104,"Rule B - Potentially Malicious PwSh","execution","T1059.001","ScriptBlock line {1} of thirty"' -f $i, $i) }
$hayLines = @('"2026-10-05 08:00:00","high","H1",4624,"Suspicious Remote Logon","privilege-escalation","T1078","explicit credentials logon"') + $b
New-Csv (Join-Path $CsvDir 'hayabusa_timeline.csv') '"Timestamp","Level","Computer","EventID","RuleTitle","MitreTactics","MitreTags","Details"' $hayLines
$tl = '"2026-09-28 14:00:00","sysmon_dns","DNS query","bob","evil-c2.example.com","resolved 203.0.113.9"'
New-Csv (Join-Path $CsvDir 'supertimeline.csv') '"Timestamp","Source","Type","Actor","Entity","Detail"' @($tl)
New-Csv (Join-Path $CsvDir 'ps_decoded_commands.csv') '"Timestamp","Channel","EventID","DecodedText"' @(
    '"' + ('x' * 600) + '"')
foreach ($empty in @('hunt_findings', 'beacon_candidates', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'ioc_hits_browser', 'posture', 'memory_malfind', 'prefetch_parsed', 'mft_recent', 'usn_write_bursts', 'dns_beacon_candidates', 'loldrivers_hits', 'certificates', 'asep_sweep', 'parse_needed', 'srum_usage', 'entities_accounts', 'entities_remotes', 'memory_live_scan', 'session_activity', 'process_chains', 'entities_binaries', 'flash_process_scored', 'system_new_services', 'remote_access', 'svchost_audit')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rendered = Get-Content (Join-Path $CaseDir 'report.html') -Raw

Check "attack: technique rows expandable (techrow + hidden event row)" ($rendered -match "class='techrow'" -and $rendered -match "id='ev_T1078'" -and $rendered -match 'display:none')
Check "attack: matched events listed inside the expand" (([regex]::Matches($rendered, 'Suspicious Remote Logon')).Count -ge 2)
Check "attack: click-to-toggle wired" ($rendered -match 'click to show/hide the matched events')
Check "sigma: RULES map embedded with ALL 30 rows of rule B" ($rendered -match 'var RULES = ' -and ([regex]::Matches($rendered, [regex]::Escape('ScriptBlock line'))).Count -eq 30)
Check "sigma: per-rule search + level + page inputs" ($rendered -match 'q_Rule_B' -and $rendered -match 'l_Rule_B' -and $rendered -match 'p_Rule_B')
Check "sigma: renderRule + pager functions present" ($rendered -match 'function renderRule' -and $rendered -match 'function pgRule' -and $rendered -match 'renderRule\(')
Check "sigma: rows carry full detail + clip cell (click copy)" ($rendered -match 'data-full' -and $rendered -match 'class="clip path"')
Check "report: copied toast + delegated click/dblclick handlers" ($rendered -match "id='copied'" -and $rendered -match "addEventListener\('click'" -and $rendered -match "addEventListener\('dblclick'")
Check "report: pscmds truncated preview with FULL text in data-full" ($rendered -match "class='path clip'" -and $rendered -match [regex]::Escape('xxxxx'))
Check "timeline: no JS preview in the report" ($rendered -notmatch 'var TL = ')
Check "timeline: evidence-only pointer section" ($rendered -match 'Master timeline \(gathered evidence chronology\)' -and $rendered -match 'scanner conclusions')

# ============================================================================
# PART 3 - supertimeline weave: evidence only
# ============================================================================
foreach ($gone in @("\$weave 'hayabusa_timeline'", "\$weave 'hunt_findings'", "\$weave 'session_activity'", "\$weave 'logging_gaps'")) {
    Check "weave: $gone removed" ($src -notmatch [regex]::Escape($gone))
}
Check "weave: evidence sources retained" ((@('$weave ''security_auth_events''', '$weave ''security_proc_events''', '$weave ''sysmon_proc_create''', '$weave ''mft_recent''', '$weave ''prefetch_parsed''', '$weave ''amcache''') | Where-Object { $src -match [regex]::Escape($_) }).Count -eq 6)
Check "weave: policy comment present" ($src -match 'scanner/derived outputs')

Remove-Item $case1 -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
