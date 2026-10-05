$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.23 - KAPE parity pack: Application log (4.10), host extras (8.13), server logs + NTDS (8.14),
# SDB persistence in ASEP sweep, StartupInfo/WER parsers
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - StartupInfo + WER parsers on fixtures
# ============================================================================
$defs = ''
foreach ($n in @('Get-StartupInfoRows', 'Get-WerReportRows')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$fx = Join-Path $env:TEMP "ophira_x223_$stamp"
$siDir = Join-Path $fx 'StartupInfo'
New-Item -ItemType Directory -Path $siDir, (Join-Path $fx 'WER\ReportArchive\appcrash_evil') -Force | Out-Null

@'
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <Session id="1" UserSID="S-1-5-21-1">
    <Application Path="C:\Users\public\beacon.exe" ExecutionCount="3" LastExecutionTime="2026-09-28T08:00:00.0000000Z"/>
    <Application Path="C:\Windows\System32\notepad.exe" ExecutionCount="12" LastExecutionTime="2026-09-28T09:00:00.0000000Z"/>
  </Session>
</Events>
'@ | Set-Content -LiteralPath (Join-Path $siDir '{S-1-5-21-1}_1_20260928.xml') -Encoding UTF8

$werLines = @(
    '[Version]', 'EventTime=133770000000000000', 'ResponseUrl=', '[Signature]',
    'Sig[0].Name=Application Name', 'Sig[0].Value=tool.exe', 'Sig[1].Name=Application Version', 'Sig[1].Value=crashme.dll',
    'DynamicSig[1].Name=OS Version', 'AppPath=C:\evil\tool.exe'
)
Set-Content -LiteralPath (Join-Path $fx 'WER\ReportArchive\appcrash_evil\Report.wer') -Value $werLines -Encoding Unicode

$si = @(Get-StartupInfoRows -Path $siDir)
Check "startupinfo: 2 app rows parsed" ($si.Count -eq 2)
Check "startupinfo: path + count + last-run captured" (@($si | Where-Object { "$($_.App)" -match 'beacon\.exe' -and $_.Count -eq '3' -and "$($_.LastRun)" -match '2026-09-28' }).Count -eq 1)

$wer = @(Get-WerReportRows -Path (Join-Path $fx 'WER'))
Check "wer: report parsed (UTF-16 key=value)" ($wer.Count -eq 1)
Check "wer: app + module + filetime converted" ("$($wer[0].App)" -match 'tool\.exe' -and "$($wer[0].Module)" -match 'crashme\.dll' -and "$($wer[0].Time)" -match '^\d{4}-')

# ============================================================================
# PART 2 - module 4.10 Application log Run block live
# ============================================================================
$m = [regex]::Match($src, "(?s)Id = '4\.10';.*?Run = \{(.*?)\r?\n        \} \}")
if (-not $m.Success) { throw "extract failed: module 4.10" }
foreach ($n in @('Get-FilteredEvents')) {
    $mm = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    Invoke-Expression $mm.Value
}
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Export-Evtx { param([string]$LogName, [string]$FileName) $script:exported = $FileName }
function Get-LogStart { $null }
$CsvDir = Join-Path $fx 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
& ([scriptblock]::Create($m.Groups[1].Value))
Check "4.10: application_events saved (live log, any count)" ($saved.ContainsKey('application_events'))
Check "4.10: Application.evtx export requested" ("$script:exported" -eq 'Application.evtx')

# ============================================================================
# PART 3 - structural wiring
# ============================================================================
Check "whitelist: StartupInfo/WER parsers shared with workers" ($src -match "'Get-StartupInfoRows', 'Get-WerReportRows'")
Check "modules: 8.13 saves startup_info + wer_reports" ($src -match "Save-Rows -Name 'startup_info'" -and $src -match "Save-Rows -Name 'wer_reports'")
Check "modules: 8.14 saves server_logs inventory" ($src -match "Save-Rows -Name 'server_logs'")
Check "modules: QuickAssist + RemoteHelp temp paths collected" ($src -match 'Temp\\QuickAssist' -and $src -match 'Temp\\RemoteHelp')
Check "modules: PCA + RecentFileCache + MOF + GPO dirs covered" ($src -match 'appcompat\\pca' -and $src -match 'RecentFileCache\.bcf' -and $src -match 'wbem\\MOF' -and $src -match 'GroupPolicyUsers')
Check "modules: NTDS.dit NEVER touched (no copy code, policy comment)" (($src -notmatch 'Copy-LockedFile -Source \$ntds') -and ($src -match 'NTDS\.dit is deliberately NEVER touched'))
Check "asep: SDB shim persistence check (Custom + InstalledSDB)" ($src -match 'AppCompatFlags\\Custom' -and $src -match 'InstalledSDB')
Check "supertimeline: application_events merged" ($src -match "'rdp_connections', 'application_events'")
Check "parse_needed: RecentFileCache -> AppCompatParser row" ($src -match "Artifact = 'recentfilecache\.csv'")
Check "evidence index: new artifacts documented" ($src -match "'application_events'" -and $src -match "'startup_info'" -and $src -match "'wer_reports'" -and $src -match "'server_logs'")
Check "coverage: host-extras row present" ($src -match 'Host extras \(WER/StartupInfo/QuickAssist/GPO\)')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $fx -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
