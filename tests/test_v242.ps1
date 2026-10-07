$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.42 - CSV sortment (category subfolders + flat-first fallback) + report enrichment
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - sortment behavioral: mapped write, flat fallback, unknown names
# ============================================================================
$defs = ''
foreach ($n in @('Save-Rows', 'Import-CaseCsv', 'Get-CaseCsvPath', 'Test-CaseCsv', 'Get-CaseCsvFullPath')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case = Join-Path $env:TEMP "ophira_sort_$stamp"
$CsvDir = Join-Path $case 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$log = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:log.Add($Message) }

$rows = @([pscustomobject]@{ Image = 'C:\x\evil.exe'; DestIp = '9.9.9.9' })
Save-Rows -Name 'sysmon_network' -Rows $rows
Check "sortment: mapped CSV written into csv\logs\" (Test-Path (Join-Path $CsvDir 'logs\sysmon_network.csv'))
Check "sortment: nothing flat at the old path" (-not (Test-Path (Join-Path $CsvDir 'sysmon_network.csv')))
Check "sortment: log line shows the relative subpath" (@($log | Where-Object { $_ -match 'csv\\logs\\sysmon_network\.csv' }).Count -eq 1)
Save-Rows -Name 'totally_unknown_csv' -Rows $rows
Check "sortment: unknown names stay flat" (Test-Path (Join-Path $CsvDir 'totally_unknown_csv.csv'))
$back = @(Import-CaseCsv 'sysmon_network')
Check "sortment: Import-CaseCsv reads through the map" ($back.Count -eq 1 -and $back[0].DestIp -eq '9.9.9.9')

# old flat case fallback
New-Item -ItemType Directory -Path (Join-Path $case 'old\csv') -Force | Out-Null
$oldCsv = Join-Path $case 'old\csv'
Set-Content -LiteralPath (Join-Path $oldCsv 'processes.csv') -Value @('"Name","PID"', '"legacy.exe","123"') -Encoding UTF8
$CsvDir = $oldCsv
$old = @(Import-CaseCsv 'processes')
Check "sortment: OLD flat cases still read (flat-first fallback)" ($old.Count -eq 1 -and $old[0].Name -eq 'legacy.exe')
Set-Content -LiteralPath (Join-Path $oldCsv 'supertimeline.csv') -Value @('"Timestamp"', '"2026-01-01"') -Encoding UTF8
Check "sortment: Test-CaseCsv finds flat supertimeline" (Test-CaseCsv 'supertimeline')

# ============================================================================
# PART 2 - static wiring
# ============================================================================
Check "wiring: Save-Rows writes via Get-CaseCsvFullPath" ($src -match [regex]::Escape('$path = Get-CaseCsvFullPath $Name'))
Check "wiring: sortment helpers whitelisted for module workers" (($src -match [regex]::Escape("'Get-CaseCsvPath', 'Test-CaseCsv', 'Get-CaseCsvFullPath'")))
Check "wiring: hayabusa timeline output path mapped" ($src -match [regex]::Escape("Get-CaseCsvFullPath 'hayabusa_timeline'"))
Check "wiring: coverage checks use Test-CaseCsv" (([regex]::Matches($src, 'Test-CaseCsv ')).Count -ge 20)
Check "wiring: canary B-side reads are flat-mapped" (([regex]::Matches($src, 'Import-CsvFlatMapped ')).Count -ge 10)
Check "wiring: evidence index recurses into category folders" ($src -match "(?s)Evidence index.*?-Recurse")
Check "wiring: focus scan recurses with subdir exclusions" (($src -match [regex]::Escape("-Filter '*.csv' -File -Recurse")) -and ($src -match [regex]::Escape("@('sigma_rules', 'evtx_ecmd', 'recmd_out') -notcontains")))
Check "enrichment: timeline table + client-side filter rendered" (($src -match "name='timeline'") -and ($src -match 'tlFilter') -and ($src -match 'Newest 150 of'))
Check "enrichment: entities expanded to 12 + 30-min context + focus hint" (($src -match [regex]::Escape('Select-Object -First 12)')) -and ($src -match 'AddMinutes\(-30\)') -and ($src -match '-Mode Focus -ProcessName'))
Check "enrichment: case narrative gains the focus paragraph" ($src -match 'FOCUSED ANALYSIS')

# ============================================================================
# PART 3 - narrative focus paragraph behavioral
# ============================================================================
$mN = [regex]::Match($src, "(?s)function Get-CaseNarrative \{.*?\r?\n\}")
if (-not $mN.Success) { throw 'extract failed: Get-CaseNarrative' }
Invoke-Expression $mN.Value
$CsvDir = Join-Path $case 'csv'
New-Item -ItemType Directory -Path (Join-Path $case 'focus') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $case 'focus\focus_terms.json') -Value '{"Indicator":"malware.exe","HitCount":12,"InstanceCount":3,"Rounds":2,"SourcesHit":{"sysmon_network":5}}' -Encoding UTF8
$Computer = 'SORTTEST'
$StartTime = Get-Date
$ScriptVersion = '2.42'
$script:Verdict = [pscustomobject]@{ Level = 'SUSPICIOUS'; ConfidencePercent = 60; OwnerLine = 'test'; LevelRank = 2
    Signals = @(); Coverage = @(); Caveats = @() }
$draft = @(Get-CaseNarrative)
Check "narrative: focus paragraph rendered with dossier stats" (@($draft | Where-Object { $_ -match 'FOCUSED ANALYSIS' -and $_ -match 'malware\.exe' -and $_ -match 'focus\\focus_report\.html' }).Count -eq 1)
Set-Content -LiteralPath (Join-Path $case 'focus\focus_terms.json') -Value '{"Indicator":"x"}' -Encoding UTF8
$draft2 = @(Get-CaseNarrative)
Check "narrative: partial terms json does not crash the draft" ($draft2.Count -ge 1)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
