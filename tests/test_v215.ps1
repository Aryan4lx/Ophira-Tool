$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.15 - Parse mode, parse_needed honesty, Full-preset NTFS preservation, RegenerateOutputs wiring
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - Get-ParseNeeds: classification of missing artifacts
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-ParseNeeds \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Get-ParseNeeds extract failed' }
$case1 = Join-Path $env:TEMP "ophira_pn_$stamp"
$CsvDir = Join-Path $case1 'csv'; $RawDir = Join-Path $case1 'raw'
New-Item -ItemType Directory -Path $CsvDir, "$RawDir\prefetch", "$RawDir\browser", "$RawDir\registry" -Force | Out-Null
Set-Content (Join-Path "$RawDir\registry" 'Amcache.hve') -Value 'x'
Set-Content (Join-Path $CsvDir 'amcache.csv') -Value "A`r`nB"   # already parsed on endpoint
function Get-DotNetRelease { '.NET Framework 4.8 (release 528040); .NET 9 desktop runtime: absent' }
function Import-CaseCsv { param([string]$Name) @() }
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression $m.Value
$null = Get-ParseNeeds
$pn = @($saved['parse_needed'])
Check "parse_needed: amcache.csv present -> no row" (@($pn | Where-Object { $_.Artifact -eq 'amcache.csv' }).Count -eq 0)
Check "parse_needed: prefetch missing+raw present -> Parse command" ("$(@($pn | Where-Object { $_.Artifact -eq 'prefetch_parsed.csv' }).HowToFinish)" -match 'Mode Parse')
Check "parse_needed: browser missing+net9 absent -> .NET reason" ("$(@($pn | Where-Object { $_.Artifact -eq 'browser_history.csv' }).HowToFinish)" -match 'lacks \.NET 9')
Check "parse_needed: shellbags -> endpoint-only" ("$(@($pn | Where-Object { $_.Artifact -eq 'shellbags.csv' }).HowToFinish)" -match 'endpoint-only')
Check "parse_needed: hayabusa missing+no raw evtx -> not collected" ("$(@($pn | Where-Object { $_.Artifact -eq 'hayabusa_timeline.csv' }).HowToFinish)" -match 'not collected')

# ============================================================================
# PART 2 - Invoke-RegenerateOutputs: wiring + verdict.json + $Case update
# ============================================================================
$m = [regex]::Match($src, "(?s)function Invoke-RegenerateOutputs \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Invoke-RegenerateOutputs extract failed' }
$case2 = Join-Path $env:TEMP "ophira_rg_$stamp"
$CsvDir = Join-Path $case2 'csv'; $CaseDir = $case2
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$script:calls = [System.Collections.Generic.List[string]]::new()
function New-SuperTimeline { $script:calls.Add('supertimeline') }
function New-LoggingGaps { $script:calls.Add('gaps') }
function Get-ParseNeeds { $script:calls.Add('parseneeds') }
function Get-CompromiseVerdict { $script:calls.Add('verdict'); [pscustomobject]@{ Level = 'SUSPICIOUS'; LevelRank = 2; ConfidencePercent = 80; Signals = @(); Caveats = @() } }
function New-SiemExport { $script:calls.Add('siem') }
function New-AttackLayer { $script:calls.Add('layer') }
function New-HtmlReport { $script:calls.Add('report') }
Invoke-Expression $m.Value
$caseObj = [pscustomobject]@{ Computer = 'X' }
Invoke-RegenerateOutputs -Case $caseObj
Check "regen: supertimeline/gaps/parse_needed/verdict/siem/layer/report all ran" ((@($script:calls).Count -eq 7) -and $script:calls -contains 'supertimeline' -and $script:calls -contains 'report')
Check "regen: verdict.json written" (Test-Path (Join-Path $case2 'verdict.json'))
Check "regen: Case got Verdict member (Level + Confidence)" ($caseObj.Verdict.Level -eq 'SUSPICIOUS' -and $caseObj.Verdict.ConfidencePercent -eq 80)
Check "regen: script Verdict set" ($script:Verdict.LevelRank -eq 2)

# ============================================================================
# PART 3 - Invoke-ParseMode end-to-end on a synthetic case FOLDER
# ============================================================================
foreach ($fn in @('Open-CaseSession', 'Invoke-ParseMode')) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$fn extract failed" }
    Invoke-Expression $m.Value
}
$case3 = Join-Path $env:TEMP "ophira_pm_$stamp"
$csv3 = Join-Path $case3 'csv'; $raw3 = Join-Path $case3 'raw'
New-Item -ItemType Directory -Path $csv3, "$raw3\prefetch", "$raw3\recent", "$raw3\evtx", "$raw3\registry" -Force | Out-Null
Set-Content (Join-Path $case3 'case.json') -Value '{"Computer":"SRV01","CaseID":"C-1","Analyst":"A","StartedUTC":"2026-09-25T08:00:00.0000000Z","FinishedUTC":"2026-09-25T08:05:00.0000000Z","AdminElevated":true,"SysmonPresent":true,"LogHours":168,"Tool":"Ophira v2.14"}' -Encoding UTF8
Set-Content (Join-Path "$raw3\prefetch" 'a.pf') -Value 'pf'
Set-Content (Join-Path "$raw3\recent" 'doc.lnk') -Value 'lnk'
Set-Content (Join-Path "$raw3\evtx" 'Security.evtx') -Value 'evtx'
Set-Content (Join-Path "$raw3\registry" 'SYSTEM.hiv') -Value 'hive'
$tools3 = Join-Path $env:TEMP "ophira_pm_tools_$stamp"
New-Item -ItemType Directory -Path $tools3 -Force | Out-Null
foreach ($t in @('PECmd.exe', 'LECmd.exe')) { Set-Content (Join-Path $tools3 $t) -Value 'fake' }
function Get-ToolsDir { $tools3 }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Invoke-BrowserIocXref { }
$regenCalled = $false
function Invoke-RegenerateOutputs { param($Case) $script:regenCalled = $true }
# fake raw-driven modules (4.6/5.4/8.4) + record the native-tool calls for the parse halves
$script:Modules = @(
    [pscustomobject]@{ Id = '4.6'; Name = 'fake detection pack'; Run = { Set-Content (Join-Path $script:CsvDir 'hayabusa_timeline.csv') -Value 'h' } }
    [pscustomobject]@{ Id = '5.4'; Name = 'fake execution history'; Run = { Set-Content (Join-Path $script:CsvDir 'execution_timeline.csv') -Value 'e' } }
    [pscustomobject]@{ Id = '8.4'; Name = 'fake EZ parsers'; Run = { Set-Content (Join-Path $script:CsvDir 'amcache.csv') -Value 'a' } }
)
$script:nativeCalls = [System.Collections.Generic.List[string]]::new()
function Invoke-NativeTool {
    param($ExePath, $ToolArgs, $WorkingDirectory, [switch]$QuietLog, $CaptureOut)
    $exeName = if ($ExePath -is [System.IO.FileInfo]) { $ExePath.Name } else { Split-Path $ExePath -Leaf }
    $script:nativeCalls.Add("$exeName|$($ToolArgs -join ' ')")
    $dir = $ToolArgs[([array]::IndexOf($ToolArgs, '--csv')) + 1]
    $name = if ($ToolArgs -contains '--csvf') { $ToolArgs[([array]::IndexOf($ToolArgs, '--csvf')) + 1] } else { 'out.csv' }
    Set-Content (Join-Path $dir $name) -Value 'parsed'
    return 0
}
Invoke-Expression $m.Value
$ok = Invoke-ParseMode -Path $case3
Check "parse mode: returns success" ($ok -eq $true)
Check "parse mode: fake raw-driven modules ran (3 outputs)" ((Test-Path (Join-Path $csv3 'hayabusa_timeline.csv')) -and (Test-Path (Join-Path $csv3 'execution_timeline.csv')) -and (Test-Path (Join-Path $csv3 'amcache.csv')))
Check "parse mode: PECmd ran against raw\prefetch" (@($script:nativeCalls | Where-Object { $_ -match '^PECmd\.exe\|-d .*prefetch' }).Count -eq 1)
Check "parse mode: LECmd ran against raw\recent" (@($script:nativeCalls | Where-Object { $_ -match '^LECmd\.exe\|-d .*recent' }).Count -eq 1)
Check "parse mode: prefetch_parsed.csv + lnk_parsed.csv produced" ((Test-Path (Join-Path $csv3 'artifacts\prefetch_parsed.csv')) -and (Test-Path (Join-Path $csv3 'artifacts\lnk_parsed.csv')))
Check "parse mode: jumplists skipped (no raw input)" (@($script:nativeCalls | Where-Object { $_ -match 'JLECmd' }).Count -eq 0)
Check "parse mode: regeneration invoked" ($regenCalled -eq $true)
$cjAfter = Get-Content (Join-Path $case3 'case.json') -Raw | ConvertFrom-Json
Check "parse mode: case.json stamped AnalystParsedUTC" ([bool]$cjAfter.AnalystParsedUTC)
Check "parse mode: parse session logged to collection.log" ((Get-Content (Join-Path $case3 'collection.log') -Raw) -match 'analyst parse session')

# ============================================================================
# PART 4 - module 5.5 Full-preset preservation with free-disk guard
# ============================================================================
$m55 = [regex]::Match($src, "(?s)Id = '5\.5';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '6\.1'")
if (-not $m55.Success) { throw 'module 5.5 extract failed' }
$mIso = [regex]::Match($src, "(?s)function Test-IsUserWritablePath \{.*?\r?\n\}")
Invoke-Expression $mIso.Value
$tools55 = Join-Path $env:TEMP "ophira_ntfs_tools_$stamp"
New-Item -ItemType Directory -Path $tools55 -Force | Out-Null
Set-Content (Join-Path $tools55 'MFTECmd.exe') -Value 'fake'
function Get-ToolsDir { $tools55 }
$script:freeBytes = 50GB
function Get-PSDrive {
    param($Name, $PSProvider)
    if ($PSProvider) { return @([pscustomobject]@{ Name = 'C'; Free = $script:freeBytes }) }
    return [pscustomobject]@{ Free = $script:freeBytes }
}
function Invoke-NativeTool {
    param($ExePath, $ToolArgs, $WorkingDirectory, [switch]$QuietLog, $CaptureOut)
    $outDir = $ToolArgs[([array]::IndexOf($ToolArgs, '--csv')) + 1]
    $name = $ToolArgs[([array]::IndexOf($ToolArgs, '--csvf')) + 1]
    if ($name -eq 'mft_full.csv') {
        @'
"EntryNumber","FileName","Extension","FileSize","ParentPath","IsDirectory","Created","LastModified"
"1000","evil.exe",".exe","204800","C:\Users\u\AppData\Roaming","false","2026-08-01 10:00:00.0000000","2026-08-01 10:00:00.0000000"
'@ | Set-Content -LiteralPath (Join-Path $outDir $name) -Encoding UTF8
    } else {
        '"EntryNumber","Offset","TimeStamp","Reason","SourceFile"' | Set-Content -LiteralPath (Join-Path $outDir $name) -Encoding UTF8
    }
    return 0
}
$run55 = [scriptblock]::Create($m55.Groups[1].Value)
# run A: Full preset + plenty of disk -> preserved
$caseA = Join-Path $env:TEMP "ophira_ntfsA_$stamp"
$CsvDir = Join-Path $caseA 'csv'; $RawDir = Join-Path $caseA 'raw'; $CaseDir = $caseA; $Preset = 'Full'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$saved = @{}
& $run55
Check "full preset: mft_full_C.csv preserved under raw\analysis" (Test-Path (Join-Path $RawDir 'analysis\mft_full_C.csv'))
Check "full preset: usn_full_C.csv preserved under raw\analysis" (Test-Path (Join-Path $RawDir 'analysis\usn_full_C.csv'))
# run B: Standard preset -> not preserved
$caseB = Join-Path $env:TEMP "ophira_ntfsB_$stamp"
$CsvDir = Join-Path $caseB 'csv'; $RawDir = Join-Path $caseB 'raw'; $CaseDir = $caseB; $Preset = 'Standard'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
& $run55
Check "standard preset: no full preservation" (-not (Test-Path (Join-Path $RawDir 'analysis\mft_full_C.csv')))
# run C: Full preset but <10GB free -> guarded skip
$caseC = Join-Path $env:TEMP "ophira_ntfsC_$stamp"
$CsvDir = Join-Path $caseC 'csv'; $RawDir = Join-Path $caseC 'raw'; $CaseDir = $caseC; $Preset = 'Full'; $script:freeBytes = 1GB
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
& $run55
Check "full preset + low disk: preservation skipped" (-not (Test-Path (Join-Path $RawDir 'analysis\mft_full_C.csv')))

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case2, $case3, $tools3, $tools55, $caseA, $caseB, $caseC)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
