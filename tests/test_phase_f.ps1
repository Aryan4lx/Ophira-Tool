# v2.13 Phase F: (1) module 8.9 posture live registry run  (2) USN ransom-ext fixture through module 5.5  (3) report posture/recs wiring
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath $repoScript -Raw
$names = @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Test-IsUserWritablePath')
$defs = ''
foreach ($n in $names) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }

# ---------- part 1: module 8.9 posture live ----------
$m89 = [regex]::Match($src, "(?s)Id = '8\.9';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '8\.10'")
if (-not $m89.Success) { throw 'module 8.9 extract failed' }
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
& ([scriptblock]::Create($m89.Groups[1].Value))
$posture = @($saved['posture'])
Check "8.9 live: checks executed ($($posture.Count))" ($posture.Count -ge 6)
Check "8.9 live: schema Check/Status/Detail" ($posture.Count -gt 0 -and ((@($posture[0].PSObject.Properties.Name) -join ',') -match 'Check'))
$validStatus = @($posture | Where-Object { $_.Status -in @('GOOD', 'BAD', 'WARN') })
Check "8.9 live: all statuses valid" ($validStatus.Count -eq $posture.Count)
Check "8.9 live: LSA + SMBv1 + RDP + PS-logging present" (@($posture | Where-Object { $_.Check -match 'LSA|SMBv1|RDP|PowerShell script-block' }).Count -ge 4)

# ---------- part 2: USN ransom-ext through module 5.5 ----------
$m55 = [regex]::Match($src, "(?s)Id = '5\.5';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '6\.1'")
if (-not $m55.Success) { throw 'module 5.5 extract failed' }
$saved2 = @{}
$case = Join-Path $env:TEMP ("ophira_f_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'; $fakeTools = Join-Path $env:TEMP 'fakesbecmd'
New-Item -ItemType Directory -Path $csvDir, $rawDir, $fakeTools -Force | Out-Null
Set-Content -LiteralPath (Join-Path $fakeTools 'MFTECmd.exe') -Value 'fake'
$CsvDir = $csvDir; $RawDir = $rawDir
function Get-ToolsDir { $fakeTools }
function Save-Rows { param([string]$Name, $Rows) $script:saved2[$Name] = $Rows }
$script:callNo = 0
function Invoke-NativeTool {
    param($ExePath, $ToolArgs)
    $script:callNo++
    $outDir = $ToolArgs[([array]::IndexOf($ToolArgs, '--csv')) + 1]
    if ("$($ToolArgs[1])" -match 'MFT$') {
        'nope' | Set-Content -LiteralPath (Join-Path $outDir 'mft_full.csv') -Encoding UTF8
    } else {
        $lines = @('"EntryNumber","Offset","TimeStamp","Reason","SourceFile"')
        $burstT = [datetime]'2026-09-26 08:30:00'
        for ($i = 0; $i -lt 1200; $i++) {
            $ext = 'docx'
            if ($i -ge 600 -and $i -lt 1100) { $ext = 'jpg' }
            if ($i -ge 1100) { $ext = 'locked' }
            $lines += ('"5{0:d4}","1{0}","{1}","DataExtend, Close","file{2}.{3}"' -f $i, $burstT.ToString('yyyy-MM-dd HH:mm:ss.ffffff'), ($i % 150), $ext)
        }
        for ($i = 0; $i -lt 40; $i++) {
            $ext2 = 'docx'
            if ($i -lt 30) { $ext2 = 'locked' }
            $lines += ('"6{0:d4}","2{0}","{1}","FileCreate,RenameNewName,Close","victim{2}.{3}"' -f $i, $burstT.ToString('yyyy-MM-dd HH:mm:ss.ffffff'), $i, $ext2)
        }
        $quietT = [datetime]'2026-09-26 09:00:00'
        for ($i = 0; $i -lt 40; $i++) { $lines += ('"7{0:d4}","3{0}","{1}","Close","cfg{0}.ini"' -f $i, $quietT.ToString('yyyy-MM-dd HH:mm:ss.ffffff')) }
        $lines -join "`r`n" | Set-Content -LiteralPath (Join-Path $outDir 'usn_full.csv') -Encoding UTF8
    }
}
& ([scriptblock]::Create($m55.Groups[1].Value))
$bursts = @($saved2['usn_write_bursts'])
Check "5.5: burst windows found (per NTFS drive)" ($bursts.Count -ge 1)
Check "5.5: burst has Drive column" (@($bursts | Where-Object { "$($_.Drive)" -match ':$' }).Count -eq $bursts.Count)
Check "5.5: ransom-ext detected (.locked)" (@($bursts | Where-Object { "$($_.RansomExt)" -match 'locked' }).Count -ge 1)

# ---------- part 3: verdict + report wiring ----------
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }

@'
"Check","Status","Detail"
"LSA Protection (RunAsPPL)","BAD","LSASS runs unprotected - set RunAsPPL=1"
"SMBv1 protocol","GOOD","SMBv1 disabled"
"UAC","GOOD","UAC enabled"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'posture.csv') -Encoding UTF8
@'
"Process","PID","StartVPN","EndVPN","Protection","CommitCharge","PrivateMemory"
"evil.exe","4321","0x17f0000","0x1800000","PAGE_EXECUTE_READWRITE","0x3000","0x3000"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'memory_malfind.csv') -Encoding UTF8
@'
"Indicator","Host","URL","Title","Match"
"evil-corp.example","www.evil-corp.example","http://www.evil-corp.example/payload","download","browser-history"
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'ioc_hits_browser.csv') -Encoding UTF8

foreach ($empty in @('hayabusa_timeline', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'flash_process_scored', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed', 'asep_sweep', 'certificates', 'beacon_candidates', 'defender_status', 'saved_credentials', 'rdp_client_targets', 'bits_jobs')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

$v = Get-CompromiseVerdict
$script:Verdict = $v
Check "verdict: malfind signal (floor 2)" (@($v.Signals | Where-Object { $_.Signal -match 'malfind' }).Count -eq 1)
Check "verdict: browser IOC signal (floor 2)" (@($v.Signals | Where-Object { $_.Signal -match 'browser history' }).Count -eq 1)
Check "verdict = LIKELY (two strong signals escalate)" ($v.LevelRank -eq 3)
$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "report: posture table" ($html -match 'Security posture \(hardening audit\)')
Check "report: malfind table (evil.exe)" ($html -match 'evil\.exe')
Check "report: browser IOC table" ($html -match 'evil-corp\.example')
Check "report: hardening recommendation" ($html -match 'Hardening: LSA Protection')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $fakeTools -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
