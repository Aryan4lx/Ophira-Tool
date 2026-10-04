$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.31 - narrative case draft: Get-CaseNarrative builds a plain-language executive summary
# from the verdict + hunt findings; written to case_draft.txt and rendered in the report.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
$case1 = Join-Path $env:TEMP "ophira_v31_$stamp"

# ============================================================================
# PART 1 - narrative through the real function (strong-signal case)
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-CaseNarrative \{.*?\r?\n\}")
if (-not $m.Success) { throw 'extract failed: Get-CaseNarrative' }
$m2 = [regex]::Match($src, "(?s)function Import-CaseCsv \{.*?\r?\n\}")
if (-not $m2.Success) { throw 'extract failed: Import-CaseCsv' }
Invoke-Expression ($m2.Value + "`r`n" + $m.Value)
$CaseDir = $case1
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
@('"Found","Rule","Severity","Entity","Attck","Evidence"',
  '"2026-10-04 12:00:00","Renamed LOLBin at rest (Sysmon identity mismatch)","high","C:\Users\Public\winupd.exe","T1036.003","executed as winupd.exe but identity cmd"',
  '"2026-10-04 12:05:00","Account lifecycle - created + group change","info","canary_test","T1136","1 account + 1 group change"',
  '"2026-10-04 12:06:00","Discovery command storm","medium","recon","T1087","20 recon commands"') |
  Set-Content -LiteralPath (Join-Path $CsvDir 'hunt_findings.csv') -Encoding UTF8
$Computer = 'DC-IIS'
$script:HostRole = 'DC'
$StartTime = Get-Date '2026-10-04 12:00:00'
$ScriptVersion = '2.31'
$script:Verdict = [pscustomobject]@{
    Level = 'LIKELY COMPROMISED'; LevelRank = 3; ConfidencePercent = 78
    OwnerLine = 'This machine shows strong signs of compromise.'
    Signals = @(
        [pscustomobject]@{ Signal = 'Defender real-time protection DISABLED'; Weight = 3; Count = 1; Detail = 'DC-IIS' },
        [pscustomobject]@{ Signal = 'Hunt technique - renamed binary'; Weight = 2; Count = 1; Detail = 'Renamed LOLBin at rest' }
    )
    Caveats = @('Sysmon arrived mid-window - early activity may be missing')
    Coverage = @(
        [pscustomobject]@{ Source = 'registry hives'; Collected = $true; Weight = 2 },
        [pscustomobject]@{ Source = 'memory acquisition'; Collected = $false; Weight = 2 }
    )
}
$lines = @(Get-CaseNarrative)
$text = $lines -join "`n"
Check "draft: assessment line with verdict + confidence" (($lines | Where-Object { $_ -match 'ASSESSMENT: LIKELY COMPROMISED \(confidence 78%' }).Count -eq 1)
Check "draft: strong signal rendered with detail" (($lines | Where-Object { $_ -match 'Defender real-time protection DISABLED x1 \(DC-IIS\)' }).Count -eq 1)
Check "draft: weight-2 signal prefixed as 'Also seen'" (($lines | Where-Object { $_ -match 'Also seen: Hunt technique' }).Count -eq 1)
Check "draft: high findings as leads, info/medium excluded" (($lines | Where-Object { $_ -match 'T1036\.003.*winupd' }).Count -eq 1 -and $text -notmatch 'Discovery command storm')
Check "draft: missing coverage named + absence caveat" (($lines | Where-Object { $_ -match 'memory acquisition' }).Count -eq 1 -and $text -match 'NOT proof of absence')
Check "draft: caveats listed" (($lines | Where-Object { $_ -match 'Sysmon arrived mid-window' }).Count -eq 1)
Check "draft: edit-me footer" (($lines | Where-Object { $_ -match 'Machine-generated starting draft' }).Count -eq 1)

# ============================================================================
# PART 2 - no-verdict case degrades gracefully
# ============================================================================
$script:Verdict = $null
$lines2 = @(Get-CaseNarrative)
Check "draft: no verdict -> honest note, no crash" (($lines2 | Where-Object { $_ -match 'verdict engine did not run' }).Count -eq 1)

# ============================================================================
# PART 3 - wiring: regen writes the file, report renders it, index mentions it
# ============================================================================
Check "regen: case_draft.txt written after verdict" ($src -match [regex]::Escape("Get-CaseNarrative | Set-Content -LiteralPath (Join-Path `$CaseDir 'case_draft.txt')"))
Check "report: draft section rendered after verdict" ($src -match [regex]::Escape("<a name='draft'></a><h2>Case draft (auto-written - edit before use)</h2>"))
Check "report: draft guarded when engine failed" ($src -match '(?s)VERDICT UNAVAILABLE.*?Get-CaseNarrative')
Check "evidence index: case_draft.txt mentioned" ($src -match [regex]::Escape('case_draft.txt</b> (auto-written executive draft'))

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
