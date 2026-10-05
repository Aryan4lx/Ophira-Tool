$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.35 - flexible analysis window (-LogWindow 168/30d/3m/dates, -LogStart/-LogEnd with end-cap),
# deploy wizard back-navigation, timeline preview 10k embed + 120k supertimeline cap.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ============================================================================
# PART 1 - window parsing + resolution through the real functions
# ============================================================================
$defs = ''
foreach ($n in @('ConvertTo-LogStart', 'Resolve-LogWindow', 'Get-LogStart', 'Get-LogRangeText')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$LogStart = ''; $LogEnd = ''; $LogWindow = ''
$within = { param($dt, $expected, $tolSec) [math]::Abs((($dt) - ($expected)).TotalSeconds) -lt $tolSec }
$now = Get-Date

$LogWindow = '30d'
$err = Resolve-LogWindow
Check "window: 30d parsed" ($err -eq '' -and (& $within $script:LogStartDT $now.AddDays(-30) 90))
$LogWindow = '3m'
$null = Resolve-LogWindow
Check "window: 3m = 3 calendar months" (& $within $script:LogStartDT $now.AddMonths(-3) 90)
$LogWindow = '72h'
$null = Resolve-LogWindow
Check "window: 72h explicit unit" (& $within $script:LogStartDT $now.AddHours(-72) 90)
$LogWindow = '72'
$null = Resolve-LogWindow
Check "window: bare number = hours" (& $within $script:LogStartDT $now.AddHours(-72) 90)
$LogWindow = '2026-09-01 08:00'
$null = Resolve-LogWindow
Check "window: explicit date accepted" ($script:LogStartDT -eq [datetime]'2026-09-01 08:00')
$LogWindow = 'nonsense'
Check "window: garbage -> loud error" ("$err" -ne '' -or ("$(Resolve-LogWindow)" -match 'not understood'))
$LogWindow = '0'
$script:LogHours = 168
$err = Resolve-LogWindow
Check "window: 0 = all time (LogHours cleared, Get-LogStart null)" ($err -eq '' -and $script:LogHours -eq 0 -and $null -eq (Get-LogStart))

$LogWindow = '30d'; $LogStart = '2026-09-01 08:00'
$null = Resolve-LogWindow
Check "window: -LogStart wins over -LogWindow" ($script:LogStartDT -eq [datetime]'2026-09-01 08:00')
$LogWindow = ''; $LogEnd = '2026-08-01 08:00'
Check "window: end before start rejected" ("$(Resolve-LogWindow)" -match 'must be after')
$LogStart = ''; $LogEnd = ''
$script:LogHours = 168
$null = Resolve-LogWindow
Check "window: empty params -> clean, hours path used" ($null -ne (Get-LogStart))

$script:LogStartDT = [datetime]'2026-09-01 08:00'
$script:LogEndDT = [datetime]'2026-09-05 10:00'
Check "range text: explicit window shown" ((Get-LogRangeText) -eq 'From 2026-09-01 08:00 to 2026-09-05 10:00')
$script:LogStartDT = $null; $script:LogEndDT = $null
$script:LogHours = 168
Check "range text: hours -> Last 7d" ((Get-LogRangeText) -eq 'Last 7d')
$script:LogHours = 5
Check "range text: odd hours shown as h" ((Get-LogRangeText) -eq 'Last 5h')
Check "window: -LogWindow/-LogStart/-LogEnd params exist" ($src -match '\[string\]\$LogWindow = ' -and $src -match '\[string\]\$LogStart = ' -and $src -match '\[string\]\$LogEnd = ')
Check "window: resolver failure exits loudly" ($src -match [regex]::Escape('if ($rwErr) { Write-Host "  Ophira: $rwErr" -ForegroundColor Red; exit 1 }'))

# ============================================================================
# PART 2 - EndTime cap wired into both event helpers
# ============================================================================
$evDefs = ''
foreach ($n in @('Get-FilteredEvents', 'Get-EventDataRows')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $evDefs += $m.Value + "`r`n"
}
Invoke-Expression $evDefs
$script:capFilters = @()
function Get-WinEvent { param($FilterHashtable, $ErrorAction) $script:capFilters += $FilterHashtable; return @() }
$script:LogEndDT = [datetime]'2026-09-05 10:00'
$null = Get-FilteredEvents -LogName Security -Ids @(4624)
$null = Get-EventDataRows -LogName Security -Id @(4688) -Fields ([ordered]@{ A = 'a' })
Check "endcap: FilterHashtable gains EndTime in both helpers" ($script:capFilters.Count -eq 2 -and @($script:capFilters | Where-Object { "$($_.GetType().Name)" -eq 'Hashtable' -and "$($_.Keys)" -match 'EndTime' -and $_.EndTime -eq $script:LogEndDT }).Count -eq 2)
$script:LogEndDT = $null
$script:capFilters = @()
$null = Get-FilteredEvents -LogName Security -Ids @(4624) -Start ([datetime]'2026-09-01 00:00')
Check "endcap: no EndTime key when unset; StartTime still honored" (-not $script:capFilters[0].ContainsKey('EndTime') -and $script:capFilters[0].StartTime -eq [datetime]'2026-09-01 00:00')

# ============================================================================
# PART 3 - wiring: worker seed, hayabusa, case.json, adopt, menu, deploy, wizard
# ============================================================================
Check "workers: LogStartDT/LogEndDT seeded into preamble" (($src -match '\$script:LogStartDT = \$\(' -and $src -match '\$script:LogEndDT = \$\('))
Check "hayabusa: --start-timeline/--end-timeline with explicit window" ($src -match "'--start-timeline'" -and $src -match "'--end-timeline'")
Check "hayabusa: time-offset retained for hours mode" ($src -match "'--time-offset'")
Check "case.json: LogStart/LogEnd recorded" (($src -match 'LogStart = \$\(' -and $src -match 'LogEnd = \$\('))
Check "parse adopt: window restored from case.json" ($src -match [regex]::Escape('if ("$($meta.LogStart)") { $script:LogStartDT = [datetime]$meta.LogStart }'))
Check "menu: [L] toggle clears explicit window" ($src -match [regex]::Escape('$script:LogStartDT = $null'))
Check "menu: header uses Get-LogRangeText" (([regex]::Matches($src, [regex]::Escape('$range = Get-LogRangeText'))).Count -eq 2)
Check "deploy: -DeployLogWindow plumbed through worker + remote cmd" ($src -match '\[string\]\$DeployLogWindow' -and $src -match 'AddArgument\(\$DeployLogWindow\)' -and $src -match [regex]::Escape('if ($logWindow) { $cmd += " -LogWindow ''"'))
Check "deploy wizard: prompt accepts units + dates" ($src -match '168 = hours, 30d, 3m, 0 = all, or start date')
Check "caveats: wording mentions -LogWindow" ($src -match '-LogWindow 30d, -LogWindow 3m')

# ============================================================================
# PART 4 - deploy wizard back-navigation
# ============================================================================
Check "wizard: Read-WizardLine helper with B/back sentinel" ($src -match 'function Read-WizardLine' -and $src -match [regex]::Escape('^(?i)b(ack)?$') -and $src -match '\(B = back\)')
Check "wizard: step loop present" ($src -match '\$step = 1' -and $src -match 'while \(\$true\) \{[\r\n ]+switch \(\$step\)')
Check "wizard: confirm step accepts B (returns to advanced)" ($src -match [regex]::Escape('Read-WizardLine "  Start? [Y/n]"'))
Check "wizard: B at first step cancels" ($src -match [regex]::Escape('if ($null -eq $targetsIn) { Write-Host "  Deploy cancelled."'))
Check "wizard: back from credentials re-asks targets" ($src -match [regex]::Escape('if ($null -eq $cIn) { $step = 1; continue }'))
Check "wizard: banner mentions back" ($src -match 'Answer ''B'' at any question to go back')

# ============================================================================
# PART 5 - cap bumps
# ============================================================================
Check "preview: 10,000-row embed" ($src -match 'Select-Object -Last 10000')
Check "preview: 1000-row render cap + updated meta text" ($src -match '\+\+n>=1000' -and $src -match 'newest 10,000 rows, rendered newest-first, max 1,000')
Check "supertimeline: total cap 120000" ($src -match 'if \(\$sorted\.Count -gt 120000\)')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
