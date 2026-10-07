$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.41 - clean-host FP fixes: (1) Defender-channel sigma rows excluded from the sigma signals
# (they double-counted with the dedicated Defender signal - one old Defender alert used to
# declare LIKELY COMPROMISED), (2) crit sigma needs >=3 events from >=2 distinct rules for
# floor 3, (3) confirmed noisy-on-clean rules demoted in the shipped hayabusa level tuning
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

# ============================================================================
# PART 1 - static wiring
# ============================================================================
Check "verdict: Defender-channel sigma rows excluded from the sigma signals" ($src -match [regex]::Escape('$hayNonDef = @($hay | Where-Object { "$($_.Channel)" -notmatch'))
Check "verdict: crit floor gated to >=3 events from >=2 distinct rules" ($src -match [regex]::Escape('if ($hayCrit.Count -ge 3 -and $hayCritRules -ge 2) { 3 } else { 2 }'))
Check "verdict: sigma counts object keeps int shape (SigmaCritical.Count)" ($src -match [regex]::Escape('SigmaCritical = $hayCrit.Count'))
Check "A0b: sysmon registry parser captures ProcessGuid" ($src -match [regex]::Escape("TargetObject = 'TargetObject'; Image = 'Image'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid'"))
Check "A0b: sysmon file-time parser captures ProcessGuid" ($src -match [regex]::Escape("PreviousCreationUtcTime = 'PreviousCreationUtcTime'; ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid'"))
$tune = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\endpoint\hayabusa\rules\config\level_tuning.txt') -Raw
foreach ($fp in @(@('dbbfd9f3-9508-478b-887e-03ddb9236909', 'Suspicious Service Path'), @('cc429813-21db-4019-b520-2f19648e1ef1', 'Suspicious Service Name'), @('a1be9170-2ada-e8bb-285c-3e1ff336189e', 'AV Relevant File Paths'))) {
    Check "tuning: $($fp[1]) demoted in shipped hayabusa config" ($tune -match [regex]::Escape($fp[0]))
}

# ============================================================================
# PART 2 - behavioral: real Get-CompromiseVerdict against synthetic timelines
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-CompromiseVerdict \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Get-CompromiseVerdict extract failed' }
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Get-DotNetRelease')) {
    $m2 = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if ($m2.Success) { $defs += $m2.Value + "`r`n" }
}
Invoke-Expression ($defs + $m.Value)
$case = Join-Path $env:TEMP "ophira_fp_$stamp"
$CsvDir = Join-Path $case 'csv'
$RawDir = Join-Path $case 'raw'
$MemDir = Join-Path $case 'memory'
New-Item -ItemType Directory -Path $CsvDir, $RawDir, $MemDir -Force | Out-Null
$script:EndpointAdmin = $true
$Sysmon = $true

$caseData = @{}
function Import-CaseCsv { param([string]$Name) if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }; if ($caseData.ContainsKey($Name)) { return @($caseData[$Name]) }; return @() }

# Case A - ONE old Defender crit alert (the user's clean-host scenario): sigma signal must NOT
# appear (channel-excluded, no double count with the Defender signal) -> SUSPICIOUS at most
$caseData['hayabusa_timeline.csv'] = @(
    [pscustomobject]@{ Timestamp = '2026-10-05 09:00:00'; Level = 'crit'; RuleTitle = 'Defender Alert (Severe)'; RuleID = '810bfd3a'; Channel = 'Defender'; Details = 'Trojan:Win32/Old' }
)
$caseData['defender_threats.csv'] = @(
    [pscustomobject]@{ ThreatName = 'Trojan:Win32/Old'; Time = '2026-10-05 09:00:00' }
)
$v = Get-CompromiseVerdict
$sigA = @(@($v.Signals) | Where-Object { $_.Signal -eq 'Sigma detection - critical' })
Check "case A: lone Defender-channel crit row does NOT create the sigma signal" ($sigA.Count -eq 0)
Check "case A: Defender signal still present (no evidence lost)" (@(@($v.Signals) | Where-Object { $_.Signal -eq 'Defender detection history' }).Count -eq 1)
Check "case A: verdict stays SUSPICIOUS, not LIKELY COMPROMISED" ($v.LevelRank -eq 2)

# Case B - a real crit storm: 4 events across 2 distinct non-Defender rules -> floor 3
$caseData['hayabusa_timeline.csv'] = @(
    [pscustomobject]@{ Timestamp = '2026-10-05 10:00:00'; Level = 'crit'; RuleTitle = 'CobaltStrike Service Install'; RuleID = 'r1'; Channel = 'Sys'; Details = '' },
    [pscustomobject]@{ Timestamp = '2026-10-05 10:01:00'; Level = 'crit'; RuleTitle = 'CobaltStrike Service Install'; RuleID = 'r1'; Channel = 'Sys'; Details = '' },
    [pscustomobject]@{ Timestamp = '2026-10-05 10:02:00'; Level = 'crit'; RuleTitle = 'Mimikatz Execution'; RuleID = 'r2'; Channel = 'Sec'; Details = '' },
    [pscustomobject]@{ Timestamp = '2026-10-05 10:03:00'; Level = 'crit'; RuleTitle = 'Mimikatz Execution'; RuleID = 'r2'; Channel = 'Sec'; Details = '' }
)
$caseData['defender_threats.csv'] = @()
$v = Get-CompromiseVerdict
$sigB = @(@($v.Signals) | Where-Object { $_.Signal -eq 'Sigma detection - critical' })
Check "case B: multi-rule crit storm keeps floor 3" ($sigB.Count -eq 1 -and $sigB[0].Weight -eq 3)
Check "case B: verdict LIKELY COMPROMISED" ($v.LevelRank -eq 3)

# Case C - 2 crit events from ONE rule (single-rule FP class): floor 2, no compromise claim
$caseData['hayabusa_timeline.csv'] = @(
    [pscustomobject]@{ Timestamp = '2026-10-05 11:00:00'; Level = 'crit'; RuleTitle = 'One Noisy Rule'; RuleID = 'r9'; Channel = 'Sec'; Details = '' },
    [pscustomobject]@{ Timestamp = '2026-10-05 11:05:00'; Level = 'crit'; RuleTitle = 'One Noisy Rule'; RuleID = 'r9'; Channel = 'Sec'; Details = '' }
)
$v = Get-CompromiseVerdict
$sigC = @(@($v.Signals) | Where-Object { $_.Signal -eq 'Sigma detection - critical' })
Check "case C: single-rule crit pair demotes to floor 2" ($sigC.Count -eq 1 -and $sigC[0].Weight -eq 2)
Check "case C: verdict SUSPICIOUS" ($v.LevelRank -eq 2)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
