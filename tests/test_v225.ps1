$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.25 - analyst deep-dive pack: RECmd batch registry enrichment, EvtxECmd full evtx->CSV,
# -Mode Timeline pivot (window filter + summary)
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
# PART 1 - Timeline mode end-to-end on a synthetic case
# ============================================================================
foreach ($fn in @('Open-CaseSession', 'Invoke-TimelineMode')) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$fn extract failed" }
    Invoke-Expression $m.Value
}
$mapM = [regex]::Match($src, '(?s)\$script:CsvCatMap = @\{.*?\r?\n\}')
$gcpM = [regex]::Match($src, "(?s)function Get-CaseCsvPath \{.*?\r?\n\}")
if (-not $mapM.Success -or -not $gcpM.Success) { throw 'extract failed: CsvCatMap/Get-CaseCsvPath' }
Invoke-Expression ($mapM.Value + "`r`n" + $gcpM.Value)
$case1 = Join-Path $env:TEMP "ophira_tl225_$stamp"
$csv1 = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $csv1 -Force | Out-Null
Set-Content (Join-Path $case1 'case.json') -Value '{"Computer":"W1","CaseID":"C-1","Analyst":"A","StartedUTC":"2026-09-28T12:00:00.0000000Z","AdminElevated":true,"SysmonPresent":true,"LogHours":168,"Tool":"Ophira v2.24"}' -Encoding UTF8
New-Csv (Join-Path $csv1 'supertimeline.csv') '"Timestamp","Source","Type","Actor","Entity","Detail"' @(
    '"2026-09-28 13:00:00","security_auth_events","logon","early","10.0.0.1","before window"',
    '"2026-09-28 14:00:00","security_auth_events","logon (type 10)","bob","10.1.1.5","LogonId 0x1234"',
    '"2026-09-28 14:02:00","security_proc_events","process created (4688)","bob","powershell.exe","parent explorer.exe"',
    '"2026-09-28 14:05:00","sysmon_dns","DNS query (Sysmon 22)","evil.exe","evil-c2.example.com","resolved 203.0.113.1"',
    '"2026-09-28 15:00:00","wer_reports","app crash (WER)","tool.exe","","after window"'
)
$ok = Invoke-TimelineMode -Path $case1 -Start '2026-09-28 14:00' -End '2026-09-28 14:05'
Check "timeline: mode returns success" ($ok -eq $true)
$outFile = Join-Path $csv1 'timeline_20260928_1400_20260928_1405.csv'
Check "timeline: windowed CSV written with exact expected name" (Test-Path $outFile)
$rows = @(Import-Csv -LiteralPath $outFile -ErrorAction SilentlyContinue)
Check "timeline: exactly the 3 in-window rows" ($rows.Count -eq 3)
Check "timeline: out-of-window rows excluded" (@($rows | Where-Object { $_.Timestamp -match '13:00|15:00' }).Count -eq 0)
Check "timeline: edges inclusive (14:00 and 14:05 kept)" (@($rows | Where-Object { $_.Timestamp -match '14:00:00|14:05:00' }).Count -eq 2)
# swapped start/end swaps back
$ok2 = Invoke-TimelineMode -Path $case1 -Start '2026-09-28 14:05' -End '2026-09-28 14:00'
Check "timeline: swapped start/end still works" ($ok2 -eq $true -and (Test-Path $outFile))
# empty case -> clean failure
$caseE = Join-Path $env:TEMP "ophira_tlE225_$stamp"
New-Item -ItemType Directory -Path (Join-Path $caseE 'csv') -Force | Out-Null
Set-Content (Join-Path $caseE 'case.json') -Value '{"Computer":"E"}' -Encoding UTF8
$okE = Invoke-TimelineMode -Path $caseE -Start '2026-09-28 14:00' -End '2026-09-28 14:05'
Check "timeline: no supertimeline -> clean false" ($okE -eq $false)

# ============================================================================
# PART 2 - Parse mode runs RECmd batch + EvtxECmd conversion
# ============================================================================
foreach ($fn in @('Open-CaseSession', 'Invoke-ParseMode')) {
    $m = [regex]::Match($src, "(?s)function $fn \{.*?\r?\n\}")
    if (-not $m.Success) { throw "$fn extract failed" }
    Invoke-Expression $m.Value
}
$case2 = Join-Path $env:TEMP "ophira_pd225_$stamp"
$csv2 = Join-Path $case2 'csv'; $raw2 = Join-Path $case2 'raw'
New-Item -ItemType Directory -Path $csv2, "$raw2\prefetch", "$raw2\evtx", "$raw2\registry" -Force | Out-Null
Set-Content (Join-Path $case2 'case.json') -Value '{"Computer":"H2","CaseID":"C-2","Analyst":"A","StartedUTC":"2026-09-28T12:00:00.0000000Z","AdminElevated":true,"SysmonPresent":true,"LogHours":168,"Tool":"Ophira v2.24"}' -Encoding UTF8
Set-Content (Join-Path "$raw2\prefetch" 'a.pf') -Value 'pf'
Set-Content (Join-Path "$raw2\evtx" 'Security.evtx') -Value 'evtx'
Set-Content (Join-Path "$raw2\registry" 'SYSTEM.hiv') -Value 'hive'
$tools2 = Join-Path $env:TEMP "ophira_pd_tools225_$stamp"
New-Item -ItemType Directory -Path $tools2 -Force | Out-Null
foreach ($t in @('PECmd.exe', 'RECmd.exe', 'EvtxECmd.exe')) { Set-Content (Join-Path $tools2 $t) -Value 'fake' }
function Get-ToolsDir { $tools2 }
function Get-KitRoot { Split-Path -Parent $PSScriptRoot }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Invoke-BrowserIocXref { }
function Invoke-RegenerateOutputs { param($Case) }
$script:Modules = @(
    [pscustomobject]@{ Id = '4.6'; Name = 'fake detection pack'; Run = { } }
    [pscustomobject]@{ Id = '5.4'; Name = 'fake execution history'; Run = { } }
    [pscustomobject]@{ Id = '8.4'; Name = 'fake EZ parsers'; Run = { } }
)
$script:nativeCalls = [System.Collections.Generic.List[string]]::new()
$savedRows = @{}
function Save-Rows { param([string]$Name, $Rows) $script:savedRows[$Name] = $Rows }
function Invoke-NativeTool {
    param($ExePath, $ToolArgs, $WorkingDirectory, [switch]$QuietLog, $CaptureOut)
    $exeName = if ($ExePath -is [System.IO.FileInfo]) { $ExePath.Name } else { Split-Path $ExePath -Leaf }
    $script:nativeCalls.Add("$exeName|$($ToolArgs -join ' ')")
    $dir = $ToolArgs[([array]::IndexOf($ToolArgs, '--csv')) + 1]
    $name = if ($ToolArgs -contains '--csvf') { $ToolArgs[([array]::IndexOf($ToolArgs, '--csvf')) + 1] } else { 'out.csv' }
    if ($exeName -match 'RECmd') {
        @('RecordNumber,Last Write Timestamp,Key Path,Value Name,Value Type,Value',
          '1,"2026-09-28 10:00:00","SOFTWARE\Microsoft\Windows\CurrentVersion\Run","Backdoor","RegSz","C:\Users\public\evil.exe"') | Set-Content (Join-Path $dir $name)
    } else {
        Set-Content (Join-Path $dir $name) -Value 'parsed'
    }
    return 0
}
$okP = Invoke-ParseMode -Path $case2
Check "parse: mode returns success" ($okP -eq $true)
Check "parse: RECmd ran with bundled batch against SYSTEM.hiv" (@($script:nativeCalls | Where-Object { $_ -match '^RECmd\.exe\|--bn .*ophira-registry\.bn -f .*SYSTEM\.hiv' }).Count -eq 1)
Check "parse: EvtxECmd converted Security.evtx" (@($script:nativeCalls | Where-Object { $_ -match '^EvtxECmd\.exe\|-f .*Security\.evtx --csv' }).Count -eq 1)
Check "parse: evtx_ecmd folder created" (Test-Path (Join-Path $csv2 'evtx_ecmd\Security.csv'))
$rr = $savedRows['registry_recmd']
Check "parse: registry_recmd mapped (Hive/KeyPath/ValueName/Value columns)" (@($rr).Count -eq 1 -and $rr[0].Hive -eq 'SYSTEM' -and "$($rr[0].KeyPath)" -match 'CurrentVersion\\Run' -and "$($rr[0].Value)" -match 'evil\.exe')

# ============================================================================
# PART 3 - structural wiring
# ============================================================================
Check "params: -Mode Timeline + window params wired" ($src -match "'Process', 'Timeline'" -and $src -match '\$TimelineStart' -and $src -match '\$TimelineEnd')
Check "dispatch: Timeline mode reachable from menu and -Mode" (($src -match "return 'Timeline'") -and ($src -match "Invoke-TimelineMode -Path"))
Check "setup catalog: RECmd + EvtxECmd entries" ($src -match "Name = 'RECmd';.*ericzimmermanstools" -and $src -match "Name = 'EvtxECmd';.*ericzimmermanstools.*Target = 'analyst'")
$bnFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\recmd\ophira-registry.bn'
Check "batch: ophira-registry.bn bundled" (Test-Path $bnFile)
if (Test-Path $bnFile) {
    $bnText = Get-Content -LiteralPath $bnFile
    $keys = @($bnText | Where-Object { $_ -match '^(Software|NTUSER|UsrClass|ControlSet\d*|Select)[\\,]' })
    Check "batch: >=25 explicit key lines across all hive roots" ($keys.Count -ge 25)
    Check "batch: covers persistence + lateral + execution surfaces" ((($keys -join ' ') -match 'Run') -and (($keys -join ' ') -match 'Terminal Server Client') -and (($keys -join ' ') -match 'USBSTOR'))
}
Check "evidence index: registry_recmd documented" ($src -match "'registry_recmd'")
Check "report: evtx_ecmd mentioned in case meta" ($src -match 'csv\\evtx_ecmd')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $caseE, $case2, $tools2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
