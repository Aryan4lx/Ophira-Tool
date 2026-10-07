$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.18 - entity correlation (binaries/accounts/remotes) + report Connections section + repo path guard
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
# PART 1 - New-EntityCorrelation: three-way join on a synthetic case
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Get-LvlRank', 'Test-IsPublicIp', 'New-EntityCorrelation')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_ent_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }

New-Csv (Join-Path $CsvDir 'flash_process_scored.csv') '"Name","Path","Verdict","Score","Evidence","Signer"' @(
    '"evil.exe","C:\Users\u\AppData\Roaming\evil.exe","HIGH",90,"user path;unsigned",""'
)
New-Csv (Join-Path $CsvDir 'processes.csv') '"Name","Path","PID"' @(
    '"evil.exe","C:\Users\u\AppData\Roaming\evil.exe","4321"',
    '"notepad.exe","C:\Windows\notepad.exe","500"'
)
New-Csv (Join-Path $CsvDir 'process_hashes.csv') '"Name","Path","SHA256"' @(
    '"evil.exe","C:\Users\u\AppData\Roaming\evil.exe","AAAA1111"'
)
New-Csv (Join-Path $CsvDir 'services_flagged.csv') '"Service","Binary","Path"' @(
    '"evilSvc","C:\Users\u\AppData\Roaming\evil.exe","evilSvc"'
)
New-Csv (Join-Path $CsvDir 'sysmon_network.csv') '"Time","Image","DestIp","DestPort","Protocol"' @(
    '"2026-09-27 10:00:00","C:\Users\u\AppData\Roaming\evil.exe","203.0.113.9","443","tcp"',
    '"2026-09-27 10:01:00","C:\Users\u\AppData\Roaming\evil.exe","203.0.113.9","443","tcp"'
)
New-Csv (Join-Path $CsvDir 'beacon_candidates.csv') '"Severity","Rank","Process","RemoteIp","Port","Events","SpanMin","MedianIntervalSec","Jitter","Regularity","Flags"' @(
    '"high",3,"C:\Users\u\AppData\Roaming\evil.exe","203.0.113.9","443",60,59,60,0.03,1,"public-ip;user-path"'
)
New-Csv (Join-Path $CsvDir 'srum_usage.csv') '"App","BytesSent","BytesReceived"' @(
    '"\device\harddiskvolume3\users\u\appdata\roaming\evil.exe","450000000","12000000"',
    '"\device\harddiskvolume3\windows\system32\svchost.exe","900000","5000000"'
)
New-Csv (Join-Path $CsvDir 'mft_recent.csv') '"Drive","Entry","Created","LastModified","Size","Name","Path","Flags"' @(
    '"C:","9001","2026-08-01 10:00:00.0000000","2026-08-01 10:00:00.0000000","204800","evil.exe","C:\Users\u\AppData\Roaming\evil.exe","exec;user-path"'
)
New-Csv (Join-Path $CsvDir 'security_auth_events.csv') '"Time","EventId","Account","SourceIp","LogonType"' @(
    '"2026-09-27 09:00:00","4624","admin","192.168.1.50","10"',
    '"2026-09-27 09:05:00","4625","admin","1.2.3.4","3"',
    '"2026-09-27 09:06:00","4625","admin","1.2.3.4","3"',
    '"2026-09-27 09:07:00","4624","SYSTEM","-","5"'
)
New-Csv (Join-Path $CsvDir 'security_bruteforce_candidates.csv') '"SourceIp","FailedLogons"' @(
    '"1.2.3.4","2"'
)
New-Csv (Join-Path $CsvDir 'rdp_client_targets.csv') '"User","TargetServer","UsernameHint","LastWrite"' @(
    '"S-1-5-21-1000","srv01.corp.local","adm","2026-09-20 10:00:00"'
)
New-Csv (Join-Path $CsvDir 'powershell_console_history.csv') '"User","File","KB","LastWrite"' @(
    '"admin","C:\Users\admin\AppData\...\ConsoleHost_history.txt","25.5","2026-09-26 20:00:00"'
)

New-EntityCorrelation

$eb = @($saved['entities_binaries'])
$ea = @($saved['entities_accounts'])
$er = @($saved['entities_remotes'])
$evil = @($eb | Where-Object { $_.Name -eq 'evil.exe' })[0]
Check "binaries: evil.exe correlated across >=5 categories" ([int]$evil.CatCount -ge 5)
Check "binaries: verdict + signer + hash carried" ($evil.Verdict -eq 'HIGH' -and "$($evil.Hashes)" -match 'AAAA1111')
Check "binaries: evidence from svc-persist + beacon + srum" (("$($evil.Categories)" -match 'svc-persist') -and ("$($evil.Categories)" -match 'beacon') -and ("$($evil.Categories)" -match 'srum-usage'))
Check "binaries: SRUM bytes captured" ("$($evil.Bytes)" -match '450000000')
Check "binaries: benign notepad stays low-category" ([int](@($eb | Where-Object { $_.Name -eq 'notepad.exe' })[0].CatCount) -le 2)
Check "binaries: sorted worst-first (evil.exe first)" ($eb[0].Name -eq 'evil.exe')
$adm = @($ea | Where-Object { $_.Account -eq 'admin' })[0]
Check "accounts: admin logons/failed/console joined" ([int]$adm.Logons -ge 1 -and [int]$adm.Failed -eq 2 -and [double]"$($adm.ConsoleHistoryKB)" -ge 25)
Check "accounts: RDP logon evidence recorded" ("$($adm.Evidence)" -match 'rdp-in')
Check "accounts: SYSTEM filtered out" (@($ea | Where-Object { $_.Account -eq 'SYSTEM' }).Count -eq 0)
$beaconIp = @($er | Where-Object { $_.Remote -eq '203.0.113.9' })[0]
Check "remotes: beacon ip has conns + talker + beacon flag" ([int]$beaconIp.Connections -ge 2 -and "$($beaconIp.Talkers)" -match 'evil.exe' -and $beaconIp.Beacon -eq 'high')
$brute = @($er | Where-Object { $_.Remote -eq '1.2.3.4' })[0]
Check "remotes: brute-force source flagged" ([int]$brute.FailedLogons -eq 2)
Check "remotes: rdp target hostname tracked" (@($er | Where-Object { $_.Remote -eq 'srv01.corp.local' }).Count -eq 1)
Check "accounts: rdp-out keyed by SID account" (@($ea | Where-Object { "$($_.RdpOutTargets)" -match 'srv01' }).Count -eq 1)

# ============================================================================
# PART 2 - report Connections section renders
# ============================================================================
$defs = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case2 = Join-Path $env:TEMP "ophira_entR_$stamp"
$CsvDir = Join-Path $case2 'csv'; $RawDir = Join-Path $case2 'raw'; $CaseDir = $case2; $MemDir = Join-Path $case2 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Computer = 'H1'; $LogHours = 168
$script:CurrentCaseID = 'C-9'; $script:CurrentAnalyst = 'f'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
# reuse part-1 entity outputs
foreach ($n in @('entities_binaries', 'entities_accounts', 'entities_remotes')) {
    $saved[$n] | Export-Csv -LiteralPath (Join-Path $CsvDir "$n.csv") -NoTypeInformation -Encoding UTF8
}
foreach ($empty in @('hayabusa_timeline', 'beacon_candidates', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'ioc_hits_browser', 'posture', 'memory_malfind', 'prefetch_parsed', 'mft_recent', 'usn_write_bursts', 'dns_beacon_candidates', 'loldrivers_hits', 'ps_decoded_commands', 'certificates', 'asep_sweep', 'parse_needed', 'srum_usage')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $CsvDir "$empty.csv") -Encoding UTF8
}
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rendered = Get-Content (Join-Path $CaseDir 'report.html') -Raw
Check "report: Connections section + nav present" ($rendered -match "name='entities'" -and $rendered -match '#entities')
Check "report: binary drill-down card with category count" ($rendered -match "evil\.exe</b> - <span class='high'>\d+ evidence categories")
Check "report: account + remote tables rendered" ($rendered -match 'Account activity' -and $rendered -match 'Remote endpoints' -and $rendered -match '1\.2\.3\.4')

# ============================================================================
# PART 3 - repo path-length guard (long-path ZIP fix)
# ============================================================================
$root = Split-Path -Parent $PSScriptRoot
$tooLong = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName.Length -gt 250 } | Select-Object -First 3)
Check "repo: no file path exceeds 250 chars (GitHub ZIP MAX_PATH guard)" ($tooLong.Count -eq 0)
if ($tooLong.Count -gt 0) { $tooLong | ForEach-Object { Write-Host "      $($_.FullName.Length): $_" -ForegroundColor DarkYellow } }

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }


