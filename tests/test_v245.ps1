$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.45 - auto-correlation on the general report: auto-focus when a process scores HIGH
# (trigger + detail json verified in test_focus + the live case), plus:
# - shipped rule tuning APPLIED to the rule files (hayabusa 4.x ignores level_tuning.txt at
#   scan time; Setup/UpdateRules now rewrite levels via Apply-ShippedRuleTuning)
# - R5 USB trail no longer flags the kit's own raw copies
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
# PART 1 - shipped tuning file + applier wiring
# ============================================================================
$tunePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\endpoint\hayabusa\ophira-level-tuning.txt'
Check "tuning: shipped ophira-level-tuning.txt exists next to the hayabusa exe (survives rules refresh)" (Test-Path -LiteralPath $tunePath)
$tune = Get-Content -LiteralPath $tunePath -ErrorAction SilentlyContinue
$bad = @($tune | Where-Object { "$_" -and "$_" -notmatch '^(#|id,new_level|[0-9a-fA-F-]{36},(informational|low|medium|high|critical)\b)' })
Check "tuning: every non-comment line parses (id,level - no full-line comments, hayabusa rejects those)" ($bad.Count -eq 0)
Check "tuning: entries include the v2.41 clean-host demotions" (($tune -match 'dbbfd9f3-9508-478b-887e-03ddb9236909') -and ($tune -match 'cc429813-21db-4019-b520-2f19648e1ef1') -and ($tune -match 'a1be9170-2ada-e8bb-285c-3e1ff336189e'))
Check "tuning: rules\config\level_tuning.txt kept for hayabusa's config-presence check" (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\endpoint\hayabusa\rules\config\level_tuning.txt'))
Check "tuning: Apply-ShippedRuleTuning called from Setup + UpdateRules" (([regex]::Matches($src, 'Apply-ShippedRuleTuning -HayabusaExe')).Count -ge 2)
Check "tuning: Setup preserves ophira-level-tuning.txt across the hayabusa re-extract" ($src -match [regex]::Escape('$keepTuning = Join-Path $dest ''ophira-level-tuning.txt'''))

# behavioral: the applier rewrites levels in a fake rules tree, UTF8-safe, comment lines skipped
$m = [regex]::Match($src, "(?s)function Apply-ShippedRuleTuning \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Apply-ShippedRuleTuning extract failed' }
Invoke-Expression $m.Value
$hayDir = Join-Path $env:TEMP "ophira_v245tune_$stamp"
$rulesDir = Join-Path $hayDir 'rules\builtin'
New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
$tuneFile = Join-Path $hayDir 'ophira-level-tuning.txt'
@(
    '# comment lines and garbage are skipped',
    '11111111-1111-1111-1111-111111111111,informational # demote me',
    '22222222-2222-2222-2222-222222222222,critical',
    'not-a-tuning-line'
) | Set-Content -LiteralPath $tuneFile -Encoding ASCII
$y1 = Join-Path $rulesDir 'rule1.yml'
[IO.File]::WriteAllText($y1, "id: 11111111-1111-1111-1111-111111111111`nlevel: high`ndetails: 'sep A " + [char]0x00A6 + " B'")
$y2 = Join-Path $rulesDir 'rule2.yml'
[IO.File]::WriteAllText($y2, "id: 22222222-2222-2222-2222-222222222222`nlevel: low")
$exeStub = Join-Path $hayDir 'hayabusa.exe'
Set-Content -LiteralPath $exeStub -Value 'stub' -Encoding ASCII
Apply-ShippedRuleTuning -HayabusaExe (Get-Item $exeStub)
$c1 = [IO.File]::ReadAllText($y1)
Check "tuning: level rewritten to informational" ($c1 -match '(?m)^level: informational$')
Check "tuning: non-ASCII details preserved (UTF8 round-trip, no ?? mangling)" ($c1 -match [regex]::Escape([char]0x00A6))
$c2 = [IO.File]::ReadAllText($y2)
Check "tuning: second entry rewritten to critical" ($c2 -match '(?m)^level: critical$')

# ============================================================================
# PART 2 - R5 USB trail: the kit's own raw copies are not USB evidence
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m2 = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m2.Success) { throw "extract failed: $n" }
    $defs += $m2.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_v245usb_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$Computer = 'W1'
$CaseDir = $case1

New-Csv (Join-Path $CsvDir 'usb_devices.csv') '"Name","Serial","FirstWrite","LastWrite"' @('"Kingston","PKS-123","2026-09-01","2026-10-01"')
New-Csv (Join-Path $CsvDir 'lnk_parsed.csv') '"SourceFile","TargetPath","Arguments","Machine","DriveType","Guid"' @(
    ('"{0}\raw\recent\document.csv.lnk","E:\data\doc.txt","","","",""' -f $case1),
    '"E:\usbshare\payload.doc.lnk","F:\payload.doc","","","",""'
)
New-HuntFindings
$hf = @($saved['hunt_findings'])
$usb = @($hf | Where-Object { $_.Rule -match 'USB execution trail' })
Check "usb: real non-C: reference still found" (@($usb | Where-Object { "$($_.Evidence)" -match 'payload\.doc' }).Count -eq 1)
Check "usb: the kit's own raw\*.lnk copies NOT flagged" (@($usb | Where-Object { "$($_.Evidence)" -match 'document\.csv\.lnk' }).Count -eq 0)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($hayDir, $case1)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
