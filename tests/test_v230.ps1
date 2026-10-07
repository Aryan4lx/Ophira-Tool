$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.30 - RDP bitmap cache raw copy + case.json/fleet Preset + analyze verdict summary
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
# PART 1 - module 4.4 copies the RDP bitmap cache through the real module code
# ============================================================================
$m44 = [regex]::Match($src, "(?s)Id = '4\.4';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '4\.5'")
if (-not $m44.Success) { throw 'extract failed: module 4.4' }
Invoke-Expression ('
function Get-LogStart { $null }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $MaxMsg) @() }
function Export-Evtx { param($LogName, $FileName) }
function Save-Rows { param([string]$Name, $Rows) $script:saved30[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = ''Gray'') $script:log30.Add($Message) }
')
$saved30 = @{}
$log30 = New-Object System.Collections.Generic.List[string]
$base30 = Join-Path $env:TEMP "ophira_v30_$stamp"
$CsvDir = Join-Path $base30 'csv'; $RawDir = Join-Path $base30 'raw'
New-Item -ItemType Directory -Path $CsvDir, "$RawDir\rdp_cache", "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache" -Force | Out-Null
Set-Content "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache\canary.bmc" -Value 'bmc'
Set-Content "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache\other.bin" -Value 'not a bmc'
$mod44 = [pscustomobject]@{ Id = '4.4'; Name = 'RDP logs'; Run = [scriptblock]::Create($m44.Groups[1].Value) }
& $mod44.Run
Check "4.4: .bmc files copied to raw\rdp_cache" (Test-Path "$RawDir\rdp_cache\canary.bmc")
Check "4.4: non-.bmc files skipped" (-not (Test-Path "$RawDir\rdp_cache\other.bin"))
Check "4.4: copy logged with count + viewer hint" (@($log30 | Where-Object { $_ -match 'RDP bitmap cache: 1 file' -and $_ -match 'RdpCacheStudio' }).Count -eq 1)
Check "4.4: RDP event logs still saved" ($saved30['rdp_localsession'].Count -eq 0 -and $saved30['rdp_connections'].Count -eq 0)

# ============================================================================
# PART 2 - case metadata + fleet inventory wiring (text-level)
# ============================================================================
Check "case.json: Preset recorded" ($src -match [regex]::Escape('Preset = $Preset'))
Check "fleet_hosts: Preset column in inventory" ($src -match [regex]::Escape('Role, Preset, Signals, Caveats'))
Check "fleet_hosts: Preset read from case.json" ($src -match [regex]::Escape('Preset = $(if ($meta -and $meta.Preset)'))
Check "analyze: console verdict distribution line" ($src -match [regex]::Escape('VERDICTS: ') -and $src -match 'VerdictRank -ge 3')
Check "report: raw pointer mentions rdp_cache + RdpCacheStudio" ($src -match [regex]::Escape('raw\rdp_cache') -and $src -match 'RdpCacheStudio')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
