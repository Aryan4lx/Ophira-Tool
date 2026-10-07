$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.32 - cross-host canary: -CanaryTarget lateral leg (remote audits incl. Detailed File Share,
# SMB touch as canary_test, labeled write to admin share, B-side scorecard, remote restore).
# Also: 4624/4625 parse now takes the New Logon section (last match) - Account/LogonId fix.
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
# PART 1 - wiring: param + dispatch + consent
# ============================================================================
Check "param: -CanaryTarget exists" ($src -match '\[string\]\$CanaryTarget')
Check "dispatch: both sites pass -Target" (([regex]::Matches($src, [regex]::Escape('Invoke-CanaryMode -KeepLogging:$KeepLogging -Target $CanaryTarget'))).Count -eq 2)
Check "canary: -Target/-TargetUser params on function" ($src -match '(?s)function Invoke-CanaryMode \{.*?param\(\[switch\]\$KeepLogging, \[string\]\$Target, \[string\]\$TargetUser\)')
Check "remote: credential splat for second-hop sessions" ($src -match '(?s)\$rc = @\{ ComputerName = \$Target; ErrorAction = .Stop. \}.*?if \(\$tCred\) \{ \$rc\.Credential = \$tCred \}.*?Invoke-Command @rc -ScriptBlock')
Check "remote: env-var override for lab automation" ($src -match 'OPHIRA_CANARY_TARGET_PASS' -and $src -match 'Get-Credential -UserName \$TargetUser')
Check "consent: lateral warning + target file name" ($src -match 'receive an SMB session' -and $src -match 'canary_lateral\.exe')
Check "consent: domain-joined caveat" ($src -match 'domain-joined and reachable')

# ============================================================================
# PART 2 - lateral battery: remote audits, SMB leg, ordering
# ============================================================================
Check "remote: Detailed File Share audit enabled on target" ($src -match [regex]::Escape("'Detailed File Share'"))
Check "remote: unreachable target degrades to single-host" ($src -match [regex]::Escape('continuing single-host'))
Check "ordering: canary user created BEFORE lateral leg" ($src -match ('(?s)user canary_test \$canPass /add.*?' + [regex]::Escape('net.exe use "\\$Target\C$" $usePass /user:')))
Check "lateral: SMB as target admin (or canary_test fallback) + labeled write + unmap" ($src -match '\$useUser = \$tCred\.UserName' -and $src -match [regex]::Escape('canary_lateral.exe') -and $src -match [regex]::Escape('net.exe use "\\$Target\C$" /delete'))
Check "lateral: remote labeled file cleaned up" ($src -match [regex]::Escape('Remove-Item C:\Users\Public\canary_lateral.exe'))
Check "collect: target via Invoke-DeployMode Standard CANARY" ($src -match [regex]::Escape("Invoke-DeployMode -Targets @(`$Target) -DeployPreset 'Standard'"))
Check "scorecard: B-side 4624/5145/attribution/R12 rows" ((@('lateral logon','5145 share access captured','session attribution join','R12  admin-share executable staging') | Where-Object { $src -match [regex]::Escape($_) }).Count -eq 4)
Check "scorecard: fleet stitch pointer printed" ($src -match 'Fleet stitch check')
Check "restore: remote audit undo after local" ($src -match [regex]::Escape("Target audit state restored") -and $src -match [regex]::Escape('/subcategory:"$($p2[1])" /success:disable'))

# ============================================================================
# PART 3 - 4624 parse fix: Account/LogonId from the New Logon section
# ============================================================================
$m41 = [regex]::Match($src, "(?s)Id = '4\.1';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '4\.2'")
if (-not $m41.Success) { throw 'extract failed: module 4.1' }
$defs3 = ''
foreach ($n in @('Get-EventDataRows')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs3 += $m.Value + "`r`n"
}
Invoke-Expression $defs3
function Get-LogStart { $null }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $MaxMsg)
    $msg4624 = "An account was successfully logged on.`r`n`r`nSubject:`r`n`tAccount Name:`t-`r`n`tAccount Domain:`t-`r`n`tLogon ID:`t0x0`r`n`r`nNew Logon:`r`n`tAccount Name:`tcanary_test`r`n`tAccount Domain:`tCORP`r`n`tLogon ID:`t0xABCDEF`r`n`tLinked Logon ID:`t0x0`r`n`tLogon Type:`t3`r`n`r`nNetwork Information:`r`n`tSource Network Address:`t192.168.16.129"
    @(, [pscustomobject]@{ TimeCreated = (Get-Date '2026-10-04 12:00:00'); Id = 4624; Message = $msg4624 })
}
function Export-Evtx { param($LogName, $FileName) }
$saved4 = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved4[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$mod41 = [pscustomobject]@{ Id = '4.1'; Name = 'Security log'; Run = [scriptblock]::Create($m41.Groups[1].Value) }
& $mod41.Run
$a = @($saved4['security_auth_events'])[0]
Check "4624: Account = New Logon account (canary_test), not subject '-'" ("$($a.Account)" -eq 'canary_test')
Check "4624: LogonId = New Logon session (0xABCDEF), not 0x0" ("$($a.LogonId)" -eq '0xABCDEF')
Check "4624: Linked Logon ID (0x0) does not shadow the New Logon session" (($src -match [regex]::Escape('$nlIdx = $msg.IndexOf(''New Logon'')')))
Check "5140/5145: LogonId mapped to SubjectLogonId (Win11 field name)" ($src -match [regex]::Escape("LogonId = 'SubjectLogonId'"))
Check "4624: SubjectAccount captured separately" ("$($a.SubjectAccount)" -eq '-')
Check "4624: LogonType + SourceIp still parsed" ("$($a.LogonType)" -eq '3' -and "$($a.SourceIp)" -eq '192.168.16.129')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
