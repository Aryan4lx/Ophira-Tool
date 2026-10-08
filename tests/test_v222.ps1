$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.22 - bundled Sysmon config wiring + hunt rule R22 timestamp-forgery checks
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
# PART 1 - R22 timestamp forgery through the real function
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_h222_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$Computer = 'W1'

$future = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-dd HH:mm:ss')
$old400 = (Get-Date).ToUniversalTime().AddDays(-400).ToString('yyyy-MM-dd HH:mm:ss')
$old500 = (Get-Date).ToUniversalTime().AddDays(-500).ToString('yyyy-MM-dd HH:mm:ss')
$recent = (Get-Date).ToUniversalTime().AddDays(-5).ToString('yyyy-MM-dd HH:mm:ss')

# mft_recent: evil.exe = future $Si + ancient FILE_NAME (two checks);
# backd.exe = backdated $Si vs recent FILE_NAME (skew only); clean.exe = consistent
# v2.44 FP fixtures: inflight.dll (WinSxS staging skew), launcher.exe (browser-updater
# re-creation), shortcut.lnk (870-day $Si skew on a non-PE) - all legitimate, must NOT flag;
# tampd.exe (same skew class but in a user path) must STILL flag
New-Csv (Join-Path $CsvDir 'mft_recent.csv') '"Drive","Entry","Created","CreatedFN","LastModified","Size","Name","Path","Flags"' @(
    ('"C:","100001","{0}","{1}","{0}","4096","evil.exe","C:\Users\public\evil.exe","exec;user-path"' -f $future, $old400),
    ('"C:","100002","{0}","{1}","{0}","4096","backd.exe","C:\Windows\Temp\backd.exe","exec"' -f $old500, $recent),
    ('"C:","100003","{0}","{0}","{0}","4096","clean.exe","C:\Windows\System32\clean.exe","exec;recent"' -f $recent),
    ('"C:","100004","{0}","{1}","{0}","4096","inflight.dll","C:\Windows\WinSxS\Temp\InFlight\5d71ca\amd64_microsoft-windows-x\adhsvc.dll",""' -f $old400, $recent),
    ('"C:","100005","{0}","{1}","{0}","4096","launcher.exe","C:\Program Files\Mozilla Firefox\updated\desktop-launcher\launcher.exe",""' -f $old400, $recent),
    ('"C:","100006","{0}","{1}","{0}","4096","shortcut.lnk","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\System Configuration.lnk",""' -f $old400, $recent),
    ('"C:","100007","{0}","{1}","{0}","4096","tampd.exe","C:\Users\public\tampd.exe","exec;user-path"' -f $old400, $recent),
    ('"C:","100008","{0}","{1}","{0}","4096","cookie_exporter.exe","C:\Program Files (x86)\Microsoft\Edge\Application\154.0.4258.53\cookie_exporter.exe",""' -f $old400, $recent)
)
# amcache: evil.exe ran 500 days ago (ran-before-born); backd/clean consistent with their births;
# inflight/launcher/shortcut have old execution rows that the exclusions must forgive
New-Csv (Join-Path $CsvDir 'amcache.csv') '"Name","KeyTimeStamp","Path"' @(
    ('"evil.exe","{0}","C:\users\public\evil.exe"' -f $old500),
    ('"backd.exe","{0}","c:\windows\temp\backd.exe"' -f $recent),
    ('"clean.exe","{0}","c:\windows\system32\clean.exe"' -f $recent),
    ('"inflight.dll","{0}","c:\windows\winsxs\temp\inflight\5d71ca\amd64_microsoft-windows-x\adhsvc.dll"' -f $old500),
    ('"launcher.exe","{0}","c:\program files\mozilla firefox\updated\desktop-launcher\launcher.exe"' -f $old500),
    ('"shortcut.lnk","{0}","c:\programdata\microsoft\windows\start menu\programs\administrative tools\system configuration.lnk"' -f $old500),
    ('"tampd.exe","{0}","c:\users\public\tampd.exe"' -f $old500),
    ('"cookie_exporter.exe","{0}","c:\program files (x86)\microsoft\edge\application\154.0.4258.53\cookie_exporter.exe"' -f $old500)
)
New-Csv (Join-Path $CsvDir 'flash_process_scored.csv') '"Name","Path","PID","Verdict","Score","Evidence","Signer"' @(
    '"evil.exe","C:\Users\public\evil.exe","4242","HIGH","9","c2",""',
    '"notepad.exe","C:\Windows\System32\notepad.exe","500","LOW","0","",""'
)
New-Csv (Join-Path $CsvDir 'sysmon_file_time.csv') '"Time","EventId","Image","TargetFilename","CreationUtcTime","PreviousCreationUtcTime"' @(
    '"2026-09-28 10:30:00","2","C:\Users\public\evil.exe","C:\Users\public\evil.exe","2019-01-01 00:00:00","2026-09-28 10:29:59"'
)

New-HuntFindings

$hf = @($saved['hunt_findings'])
$r22 = @($hf | Where-Object { $_.Rule -match 'Timestamp forgery indicators' })
Check "R22: evil.exe flagged (future + skew + ran-before)" (@($r22 | Where-Object { "$($_.Entity)" -match 'evil\.exe' }).Count -eq 1)
Check "R22: all three checks + EID 2 corroboration in evidence" (@($r22 | Where-Object { "$($_.Entity)" -match 'evil\.exe' -and "$($_.Evidence)" -match 'is in the future' -and "$($_.Evidence)" -match 'birth attributes disagree' -and "$($_.Evidence)" -match 'predates claimed birth' -and "$($_.Evidence)" -match 'EID 2' }).Count -eq 1)
Check "R22: backd.exe flagged (skew only)" (@($r22 | Where-Object { "$($_.Entity)" -match 'backd\.exe' -and "$($_.Evidence)" -match 'day skew' }).Count -eq 1)
Check "R22: backd.exe has NO ran-before-born (amcache consistent)" (@($r22 | Where-Object { "$($_.Entity)" -match 'backd\.exe' -and "$($_.Evidence)" -match 'predates' }).Count -eq 0)
Check "R22: clean.exe NOT flagged" (@($r22 | Where-Object { "$($_.Entity)" -match 'clean\.exe' }).Count -eq 0)
Check "R22: severity medium (report-only)" (@($r22 | Where-Object { $_.Severity -eq 'medium' }).Count -eq 3)
# v2.44 FP exclusions: servicing staging, browser updaters, Store VFS and non-PE copies are legitimate
Check "R22 v2.44: WinSxS InFlight staging skew NOT flagged" (@($r22 | Where-Object { "$($_.Entity)" -match 'inflight\.dll' }).Count -eq 0)
Check "R22 v2.44: browser-updater re-created binary NOT flagged" (@($r22 | Where-Object { "$($_.Entity)" -match 'launcher\.exe' }).Count -eq 0)
Check "R22 v2.44: Edge versioned-dir replacement NOT flagged (live-case shape)" (@($r22 | Where-Object { "$($_.Entity)" -match 'cookie_exporter\.exe' }).Count -eq 0)
Check "R22 v2.44: non-PE (.lnk) $Si skew NOT flagged" (@($r22 | Where-Object { "$($_.Entity)" -match 'shortcut\.lnk' }).Count -eq 0)
Check "R22 v2.44: same skew on a user-path PE still flags" (@($r22 | Where-Object { "$($_.Entity)" -match 'tampd\.exe' -and "$($_.Evidence)" -match 'day skew' -and "$($_.Evidence)" -match 'predates' }).Count -eq 1)

# ============================================================================
# PART 2 - bundled Sysmon config + structural wiring
# ============================================================================
$cfgFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\sysmon\ophira-sysmon.xml'
Check "config: ophira-sysmon.xml shipped in tools\sysmon\" (Test-Path -LiteralPath $cfgFile)
if (Test-Path -LiteralPath $cfgFile) {
    $ok = $false
    try { $cfg = [xml](Get-Content -LiteralPath $cfgFile -Raw); $ok = $null -ne $cfg.Sysmon } catch { }
    Check "config: parses as valid Sysmon XML" $ok
    $raw = Get-Content -LiteralPath $cfgFile -Raw
    Check "config: EID 10 lsass include + source excludes" ($raw -match 'ProcessAccess onmatch="include"' -and $raw -match 'lsass\.exe' -and $raw -match 'SourceImage condition="begin with">C:\\Windows\\System32\\')
    Check "config: EID 13 hot keys (Run + IFEO + ms-settings)" ($raw -match 'CurrentVersion\\Run' -and $raw -match 'Image File Execution Options' -and $raw -match 'ms-settings')
    Check "config: DnsQuery kept unfiltered (no System32 exclude)" ($raw -match 'DnsQuery' -and $raw -notmatch '(?m)^\s*<Image condition="begin with">C:\\Windows\\System32\\</Image>\s*</DnsQuery>')
}
Check "report: Sysmon config-gap hint wired" ($src -match 'Sysmon config gap' -and $src -match 'sysmon64\.exe -accepteula -i ophira-sysmon\.xml')
Check "setup: kit inventory mentions the config" ($src -match "tools\\sysmon\\ophira-sysmon\.xml - recommended Sysmon config")
Check "5.5: mft_recent carries CreatedFN (FILE_NAME birth)" ($src -match 'CreatedFN = \$\(if \(\$cCreated30\)')
Check "hunt: R22 rule emitted" ($src -match "'Timestamp forgery indicators'")

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $case1 -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
