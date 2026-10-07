$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.19 - hunt rules R1-R7 + verdict wiring + report section
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
# PART 1 - hunt rules R1-R7 through the real function
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_hunt_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }

# R1 fixture: copy a real LOLBin (cmd.exe) under a decoy name so VersionInfo says "cmd"
$decoy = Join-Path $case1 'svcst.exe'
Copy-Item -LiteralPath "$env:SystemRoot\System32\cmd.exe" -Destination $decoy -Force
New-Csv (Join-Path $CsvDir 'processes.csv') '"Name","Path","PID","PPID"' @(
    ('"svcst.exe","{0}","4321","800"' -f $decoy)
)
# R2: proxy DLL from user path (high) + unsigned proxy DLL outside Windows (medium)
New-Csv (Join-Path $CsvDir 'sysmon_image_load.csv') '"Time","Process","Dll","Signed","Signature","Company","Description"' @(
    '"2026-09-27 10:00:00","C:\app\svc.exe","C:\Users\u\AppData\Roaming\version.dll","false","","",""',
    '"2026-09-27 10:01:00","C:\app\svc.exe","D:\apps\winmm.dll","false","","",""'
)
# R3: version.dll in system32 AND user dir (amcache)
New-Csv (Join-Path $CsvDir 'amcache.csv') '"Name","Path"' @(
    '"version.dll","C:\Windows\System32\version.dll"',
    '"version.dll","C:\Users\u\AppData\Roaming\version.dll"'
)
# R4: browser download later executed
New-Csv (Join-Path $CsvDir 'browser_downloads.csv') '"TargetFilePath","URL"' @(
    '"C:\Users\u\Downloads\evil.exe","http://evil.example.com/payload"'
)
New-Csv (Join-Path $CsvDir 'amcache2.csv') '"Name","Path"' @('"x","y"')
# amcache already has evil.exe? no - add execution evidence via processes:
# processes.csv already has svcst.exe; add evil.exe to amcache fixture instead:
$f = Join-Path $CsvDir 'amcache.csv'
$lines = @('"Name","Path"', '"version.dll","C:\Windows\System32\version.dll"', '"version.dll","C:\Users\u\AppData\Roaming\version.dll"', '"evil.exe","C:\Users\u\Downloads\evil.exe"')
Set-Content -LiteralPath $f -Value $lines -Encoding UTF8
# R5: USB devices + LNK pointing to E:\
New-Csv (Join-Path $CsvDir 'usb_devices.csv') '"DeviceKey","FriendlyName","Serial","LastWrite"' @(
    '"Disk&Ven_Kingston","Kingston DataTraveler","ABC123","2026-09-01 10:00:00"'
)
New-Csv (Join-Path $CsvDir 'lnk_parsed.csv') '"Name","Path","Target"' @(
    '"report.lnk","C:\Users\u\Recent\report.lnk","E:\staging\report.docx"'
)
# R6 + R7: auth events
New-Csv (Join-Path $CsvDir 'security_auth_events.csv') '"Time","EventId","Account","SourceIp","LogonType"' @(
    '"2026-09-27 09:00:00","4720","backdooradm","-","0"',
    '"2026-09-27 09:05:00","4728","backdooradm","-","0"',
    '"2026-09-27 10:00:00","4624","adm","203.0.113.50","10"',
    '"2026-09-27 10:05:00","4624","adm","203.0.113.50","10"',
    '"2026-09-27 11:00:00","4624","user1","192.168.1.10","2"'
)

New-HuntFindings

$hf = @($saved['hunt_findings'])
Check "R1: renamed LOLBin detected (svcst.exe = cmd)" (@($hf | Where-Object { $_.Rule -match 'Renamed LOLBin' -and $_.Entity -eq $decoy }).Count -eq 1)
Check "R2: proxy DLL in user path = high" (@($hf | Where-Object { $_.Rule -match 'proxy DLL in user-writable' -and $_.Entity -match 'version\.dll' }).Count -eq 1)
Check "R2: unsigned proxy DLL outside Windows = medium" (@($hf | Where-Object { $_.Rule -match 'unsigned proxy DLL' -and $_.Entity -match 'winmm\.dll' }).Count -eq 1)
Check "R3: version.dll in system32 + user dir = high" (@($hf | Where-Object { $_.Rule -match 'DLL side-load - planted' }).Count -eq 1)
Check "R4: downloaded then executed = high" (@($hf | Where-Object { $_.Rule -match 'Downloaded then executed' -and $_.Entity -match 'evil\.exe' }).Count -eq 1)
Write-Host ('  DBG findings: ' + ((@($hf) | ForEach-Object { $_.Rule + ' [' + $_.Severity + ']' }) -join ' | '))
Check "R5: USB trail = info" (@($hf | Where-Object { $_.Rule -match 'USB execution trail' -and $_.Severity -eq 'info' }).Count -eq 1)
Check "R6: account lifecycle = info" (@($hf | Where-Object { $_.Rule -match 'Account lifecycle' }).Count -eq 1)
Check "R7: public RDP-in = medium with source IP" (@($hf | Where-Object { $_.Rule -match 'public internet IP' -and $_.Entity -eq '203.0.113.50' }).Count -eq 1)
Check "R7: private RDP logon NOT flagged" (@($hf | Where-Object { "$($_.Evidence)" -match '192\.168\.1\.10' }).Count -eq 0)

# ============================================================================
# PART 2 - verdict wiring: high-precision hunt rules = floor-2 signal
# ============================================================================
$vd = ''
foreach ($n in @('Import-CaseCsv', 'Get-CompromiseVerdict')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $vd += $m.Value + "`r`n"
}
Invoke-Expression $vd
$case2 = Join-Path $env:TEMP "ophira_hv_$stamp"
$CsvDir = Join-Path $case2 'csv'; $RawDir = Join-Path $case2 'raw'; $MemDir = Join-Path $case2 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Sysmon = $true; $LogHours = 168
function Test-IsAdmin { $true }
function Get-ToolsDir { $null }
foreach ($n in @('hunt_findings', 'flash_process_scored', 'flash_ioc_hits', 'ioc_hits_amcache', 'yara_hits', 'hayabusa_timeline', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'beacon_candidates', 'dns_beacon_candidates', 'usn_write_bursts', 'asep_sweep', 'memory_malfind', 'ioc_hits_browser', 'entities_binaries')) {
    @($saved['hunt_findings']) | Export-Csv -LiteralPath (Join-Path $CsvDir "$n.csv") -NoTypeInformation -Encoding UTF8
}
$v = Get-CompromiseVerdict
Check "verdict: hunt signal floor-2 present" (@($v.Signals | Where-Object { "$($_.Signal)" -match 'Hunt technique' -and $_.Weight -eq 2 }).Count -eq 1)
Check "verdict: rank SUSPICIOUS+ from hunt alone" ($v.LevelRank -ge 2)
Check "verdict: counts expose HuntHighPrecision" ($v.Counts.HuntHighPrecision -ge 4)
Check "coverage: hunt rules row present" (@($v.Coverage | Where-Object { "$($_.Source)" -match 'Hunt rules' }).Count -eq 1)

# ============================================================================
# PART 3 - report render
# ============================================================================
$rd = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $rd += $m.Value + "`r`n"
}
Invoke-Expression $rd
$case3 = Join-Path $env:TEMP "ophira_hr_$stamp"
$CsvDir = Join-Path $case3 'csv'; $RawDir = Join-Path $case3 'raw'; $CaseDir = $case3; $MemDir = Join-Path $case3 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Computer = 'H1'; $LogHours = 168
$script:CurrentCaseID = 'C'; $script:CurrentAnalyst = 'f'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
foreach ($n in @('hunt_findings')) { $saved[$n] | Export-Csv -LiteralPath (Join-Path $CsvDir "$n.csv") -NoTypeInformation -Encoding UTF8 }
foreach ($empty in @('hayabusa_timeline', 'beacon_candidates', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'ioc_hits_browser', 'posture', 'memory_malfind', 'prefetch_parsed', 'mft_recent', 'usn_write_bursts', 'dns_beacon_candidates', 'loldrivers_hits', 'ps_decoded_commands', 'certificates', 'asep_sweep', 'parse_needed', 'srum_usage', 'entities_binaries', 'entities_accounts', 'entities_remotes', 'memory_live_scan')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rendered = Get-Content (Join-Path $CaseDir 'report.html') -Raw
Check "report: hunt section + renamed-LOLBin row rendered" ($rendered -match "name='hunt'" -and $rendered -match 'Renamed LOLBin')
Check "report: ATT&CK column carried (T1036.003)" ($rendered -match 'T1036\.003')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case2, $case3)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }



