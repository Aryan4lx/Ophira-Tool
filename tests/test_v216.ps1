$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.16 - sigma rule logs + report drill-down, Find-SigmaRuleFile, process pivot
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

# ============================================================================
# PART 1 - New-SigmaRuleLogs: per-rule CSVs + index
# ============================================================================
$m = [regex]::Match($src, "(?s)function New-SigmaRuleLogs \{.*?\r?\n\}")
if (-not $m.Success) { throw 'New-SigmaRuleLogs extract failed' }
$mLvl = [regex]::Match($src, "(?s)function Get-LvlRank\b.*?\r?\n\}")
if (-not $mLvl.Success) { throw 'Get-LvlRank extract failed - must be a TOP-LEVEL function (column-0 braces)' }
Invoke-Expression ($mLvl.Value + "`r`n" + $m.Value)
$case1 = Join-Path $env:TEMP "ophira_srl_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
New-Csv (Join-Path $CsvDir 'hayabusa_timeline.csv') '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"' @(
    '"2026-09-25 08:00:00","Suspicious: Rust/BEBEA x2","high","H1","Sec",4688,11,"cmd: evil.exe","d","guid-a"',
    '"2026-09-25 08:01:00","Suspicious: Rust/BEBEA x2","high","H1","Sec",4688,12,"cmd: evil.exe 2","d","guid-a"',
    '"2026-09-25 09:00:00","Potentially Bad","med","H1","Sec",4688,13,"d2","d","guid-b"'
)
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows; if ($Rows -and @($Rows).Count -gt 0) { $Rows | Export-Csv -LiteralPath (Join-Path $script:CsvDir "$Name.csv") -NoTypeInformation } }
function Import-CaseCsv {
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    $f = Join-Path $CsvDir $Name
    if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) { try { return @(Import-Csv $f) } catch { return @() } }
    return @()
}
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression ($mLvl.Value + "`r`n" + $m.Value)
New-SigmaRuleLogs
$srlDir = Join-Path $CsvDir 'sigma_rules'
Check "rule logs: one CSV per rule + index" ((Test-Path (Join-Path $srlDir 'Suspicious_Rust_BEBEA_x2.csv')) -and (Test-Path (Join-Path $srlDir 'Potentially_Bad.csv')) -and (Test-Path (Join-Path $srlDir 'index.csv')))
$aRows = @(Import-Csv (Join-Path $srlDir 'Suspicious_Rust_BEBEA_x2.csv'))
Check "rule logs: rule CSV carries event rows w/ RecordID" ($aRows.Count -eq 2 -and $aRows[0].RecordID -eq '11')
$idx = @(Import-Csv (Join-Path $srlDir 'index.csv'))
Check "rule logs: index sorted worst-first with hit counts" ($idx[0].Rule -eq 'Suspicious: Rust/BEBEA x2' -and [int]$idx[0].Hits -eq 2)
Check "regression: Get-LvlRank/Split-TagList/Get-TacticLabel defined at TOP level (column 0)" (($src -match '(?m)^function Get-LvlRank') -and ($src -match '(?m)^function Split-TagList') -and ($src -match '(?m)^function Get-TacticLabel'))

# ============================================================================
# PART 2 - report drill-down renders per-rule details blocks
# ============================================================================
$defs = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m2 = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m2.Success) { throw "extract failed: $n" }
    $defs += $m2.Value + "`r`n"
}
Invoke-Expression $defs
$case2 = Join-Path $env:TEMP "ophira_dd_$stamp"
$csvDir2 = Join-Path $case2 'csv'; $RawDir = Join-Path $case2 'raw'; $CaseDir = $case2; $MemDir = Join-Path $case2 'mem'
New-Item -ItemType Directory -Path $csvDir2, $RawDir -Force | Out-Null
$CsvDir = $csvDir2
$Computer = 'H1'; $LogHours = 168
$script:CurrentCaseID = 'C-1'; $script:CurrentAnalyst = 'f'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
New-Csv (Join-Path $CsvDir 'hayabusa_timeline.csv') '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"' @(
    '"2026-09-25 08:00:00","CobaltStrike Service Install","crit","H1","System",7045,21,"Service: evil","d","guid-c"',
    '"2026-09-25 08:05:00","CobaltStrike Service Install","crit","H1","System",7045,22,"Service: evil2","d","guid-c"'
)
foreach ($empty in @('beacon_candidates', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'ioc_hits_browser', 'posture', 'memory_malfind', 'prefetch_parsed', 'mft_recent', 'usn_write_bursts', 'dns_beacon_candidates', 'loldrivers_hits', 'ps_decoded_commands', 'certificates', 'asep_sweep')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rendered = Get-Content (Join-Path $CaseDir 'report.html') -Raw
Check "drill-down: details block per rule rendered" ($rendered -match '<details><summary>' -and $rendered -match 'CobaltStrike Service Install')
Check "drill-down: ALL events embedded in the RULES map (EID + details)" ($rendered -match 'Service: evil2' -and $rendered -match 'function renderRule')
Check "drill-down: links the per-rule CSV" ($rendered -match 'csv\\sigma_rules\\CobaltStrike_Service_Install\.csv')

# ============================================================================
# PART 3 - Find-SigmaRuleFile: GUID lookup in bundled rules
# ============================================================================
$m = [regex]::Match($src, "(?s)function Find-SigmaRuleFile \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Find-SigmaRuleFile extract failed' }
Invoke-Expression $m.Value
$hbFake = Join-Path $env:TEMP "ophira_hb_$stamp"
$rulesFake = Join-Path $hbFake 'rules\sigma\proc'
New-Item -ItemType Directory -Path $rulesFake -Force | Out-Null
Set-Content (Join-Path $rulesFake 'some_rule.yml') -Value "id: 11111111-2222-3333-4444-555555555555`r`ntitle: Fake Rule" -Encoding UTF8
$exeFake = Get-Item (Join-Path $hbFake 'rules') | Get-ChildItem -Recurse -Filter '*.yml' | Select-Object -First 1
$fakeExeItem = [pscustomobject]@{ DirectoryName = $hbFake }
$found = Find-SigmaRuleFile -RuleId '11111111-2222-3333-4444-555555555555' -HayabusaExe $fakeExeItem
Check "rule lookup: GUID finds the yml" ($found -and (Split-Path $found -Leaf) -eq 'some_rule.yml')
Check "rule lookup: unknown GUID returns null" ($null -eq (Find-SigmaRuleFile -RuleId '99999999-2222-3333-4444-555555555555' -HayabusaExe $fakeExeItem))

# ============================================================================
# PART 4 - Invoke-FocusEngine (v2.40, replaces the flat pivot): name + hash
# (with auto-resolve) on a case
# ============================================================================
$defs = ''
foreach ($n in @('Open-CaseSession', 'Invoke-FocusEngine')) {
    $m2 = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m2.Success) { throw "extract failed: $n" }
    $defs += $m2.Value + "`r`n"
}
$mapM = [regex]::Match($src, '(?s)\$script:CsvCatMap = @\{.*?\r?\n\}')
$gcpM = [regex]::Match($src, "(?s)function Get-CaseCsvPath \{.*?\r?\n\}")
if (-not $mapM.Success -or -not $gcpM.Success) { throw 'extract failed: CsvCatMap/Get-CaseCsvPath' }
Invoke-Expression ($mapM.Value + "`r`n" + $gcpM.Value + "`r`n" + $defs)
$ScriptVersion = '2.40'
$case4 = Join-Path $env:TEMP "ophira_pivot_$stamp"
$csv4 = Join-Path $case4 'csv'
New-Item -ItemType Directory -Path $csv4 -Force | Out-Null
Set-Content (Join-Path $case4 'case.json') -Value '{"Computer":"PV","CaseID":"C-2","Analyst":"a","StartedUTC":"2026-09-25T08:00:00.0000000Z","AdminElevated":true,"SysmonPresent":true,"LogHours":168,"Tool":"Ophira v2.15"}' -Encoding UTF8
New-Csv (Join-Path $csv4 'processes.csv') '"Name","Path","Pid"' @(
    '"evil.exe","C:\Users\u\AppData\Roaming\evil.exe","4321"',
    '"notepad.exe","C:\Windows\notepad.exe","500"'
)
New-Csv (Join-Path $csv4 'services_flagged.csv') '"Service","Binary","Path"' @(
    '"evilSvc","evil.exe","C:\Users\u\AppData\Roaming\evil.exe"'
)
New-Csv (Join-Path $csv4 'process_hashes.csv') '"Name","Path","SHA256"' @(
    '"evil.exe","C:\Users\u\AppData\Roaming\evil.exe","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
    '"notepad.exe","C:\Windows\notepad.exe","BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"'
)
$okName = Invoke-FocusEngine -Path $case4 -Indicator 'evil'
$fDir = Join-Path $case4 'focus'
$pivot1 = @()
try { $pivot1 = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_hits.csv') -ErrorAction Stop) } catch { }
Check "focus: name match returns success" ($okName -eq $true)
Check "focus: name hits across processes + services" (@($pivot1 | Where-Object Source -eq 'processes').Count -ge 1 -and @($pivot1 | Where-Object Source -eq 'services_flagged').Count -ge 1)
Check "focus: benign notepad not matched by 'evil'" (@($pivot1 | Where-Object { $_.Detail -match 'notepad' }).Count -eq 0)
Check "focus: dossier + terms written into the case focus folder" ((Test-Path (Join-Path $fDir 'focus_report.html')) -and (Test-Path (Join-Path $fDir 'focus_terms.json')))
$okHash = Invoke-FocusEngine -Path $case4 -Indicator 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$pivot2 = @()
try { $pivot2 = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_hits.csv') -ErrorAction Stop) } catch { }
Check "focus: hash match + auto-resolve pulls services row" ($okHash -and @($pivot2 | Where-Object Source -eq 'services_flagged').Count -ge 1 -and $pivot2.Count -ge 3)
Check "focus: hits csv written into the case" (Test-Path (Join-Path $fDir 'focus_hits.csv'))

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case2, $hbFake, $case4)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }



