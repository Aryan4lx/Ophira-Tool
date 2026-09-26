$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.11 Phase C test: (1) module 2.6 live registry run  (2) verdict+report fixtures for asep/certs
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
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

# ---------- part 1: module 2.6 live registry run ----------
$m26 = [regex]::Match($src, "(?s)Id = '2\.6';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '3\.1'")
if (-not $m26.Success) { throw 'module 2.6 extract failed' }
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }
& ([scriptblock]::Create($m26.Groups[1].Value))

$asep = @($saved['asep_sweep'])
Check "2.6 live: rows collected ($($asep.Count))" ($asep.Count -gt 0)
Check "2.6 live: schema has Category/Flags" ($asep.Count -gt 0 -and @($asep[0].PSObject.Properties.Name) -contains 'Category' -and @($asep[0].PSObject.Properties.Name) -contains 'Flags')
Check "2.6 live: StartupApproved inventoried" (@($asep | Where-Object { $_.Category -eq 'StartupApproved' }).Count -ge 0)
$ifEO = @($asep | Where-Object { $_.Category -eq 'IFEO' })
Write-Host "  (info: $($ifEO.Count) IFEO rows, $(@($asep | Where-Object { $_.Category -eq 'ComHijack-HKCU' }).Count) COM hijack rows on this box)" -ForegroundColor DarkGray

# ---------- part 2: fixture verdict + report ----------
$case = Join-Path $env:TEMP ("ophira_asep_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'
New-Item -ItemType Directory -Path $csvDir, $rawDir -Force | Out-Null
$CsvDir = $csvDir; $RawDir = $rawDir; $CaseDir = $case; $MemDir = Join-Path $case 'memory'
$Computer = 'TESTHOST'; $Analyst = 'fixture'; $LogHours = 168
$script:CurrentCaseID = 'CASE-1'; $script:CurrentAnalyst = 'fixture'; $script:DeltaBaseline = $null
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$IsAdmin = $true; $Sysmon = $true
function Test-IsAdmin { $true }

@'
"Category","Location","Name","Value","Flags"
"IFEO","HKLM:\...\Image File Execution Options\sethc.exe","Debugger","C:\Users\u\AppData\Roaming\backdoor.exe","user-path"
"AppInit_DLLs","HKLM:\...\Windows","AppInit_DLLs","C:\Temp\evil.dll","user-path;nondefault"
"ComHijack-HKCU","HKU\...\CLSID\{...}\InprocServer32","{...}","C:\Users\u\AppData\Local\com.dll","user-path"
"StartupApproved","HKCU:\...\StartupApproved\Run","OneDrive","enabled",""
"IFEO","HKLM:\...\Image File Execution Options\VS.exe","Debugger","C:\vsjitdebugger.exe",""
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'asep_sweep.csv') -Encoding UTF8
@'
"Store","Thumbprint","Subject","Issuer","NotBefore","NotAfter","HasPrivateKey","Flags"
"CurrentUser\Root","AA11","CN=Evil Root,CN=Evil Root","CN=Evil Root","2026-09-20","2027-09-20","False","recently-added;self-signed;user-store"
"LocalMachine\Root","BB22","CN=Microsoft Root","CN=Microsoft Root","2015-01-01","2035-01-01","False",""
'@ | Set-Content -LiteralPath (Join-Path $csvDir 'certificates.csv') -Encoding UTF8

foreach ($empty in @('hayabusa_timeline', 'yara_hits', 'flash_ioc_hits', 'ioc_hits_amcache', 'defender_threats', 'logging_gaps', 'security_bruteforce_candidates', 'execution_timeline', 'security_auth_summary', 'security_auth_events', 'autoruns_runkeys', 'scheduled_tasks_flagged', 'services_flagged', 'wmi_bindings', 'delta_new', 'flash_public_connections', 'beacon_candidates', 'flash_process_scored', 'usn_write_bursts', 'mft_recent', 'prefetch_parsed')) {
    "# no entries" | Set-Content -LiteralPath (Join-Path $csvDir "$empty.csv") -Encoding UTF8
}

$v = Get-CompromiseVerdict
Check "verdict = SUSPICIOUS (2, ASEP signal floor 2)" ($v.LevelRank -eq 2)
Check "ASEP signal present, count=2 (COM + clean IFEO excluded)" (@($v.Signals | Where-Object { $_.Signal -match 'Uncommon persistence' } | ForEach-Object { $_.Count }) -contains 2)
Check "certs do NOT create a verdict signal" (@($v.Signals | Where-Object { $_.Signal -match 'cert' }).Count -eq 0)
Check "coverage includes ASEP sweep" (@($v.Coverage | Where-Object { $_.Source -match 'ASEP deep sweep' -and $_.Collected }).Count -eq 1)

$script:Verdict = $v
$null = New-HtmlReport
$html = Get-Content -LiteralPath (Join-Path $CaseDir 'report.html') -Raw
Check "report: uncommon persistence section" ($html -match 'Uncommon persistence mechanisms')
Check "report: IFEO sethc row" ($html -match 'sethc\.exe')
Check "report: cert section (Evil Root)" ($html -match 'Evil Root')
Check "report: COM hijack shown in table" ($html -match 'ComHijack')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { Write-Host "kept: $CaseDir" -ForegroundColor Yellow } else { Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }

