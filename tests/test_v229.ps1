$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.29 - detection canary: consent-gated self-test (enable logging, plant labeled activity,
# collect, score hunt rules). CI runs fixture/text checks only - no audit changes here.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ============================================================================
# PART 1 - wiring: param, menu, dispatch
# ============================================================================
Check "param: Canary in ValidateSet" ($src -match [regex]::Escape("'Process', 'Timeline', 'Canary'"))
Check "param: -KeepLogging switch exists" ($src -match '\[switch\]\$KeepLogging')
Check "menu: [C] canary entry shown" ($src -match '\[C\]  Detection canary')
Check "menu: C returns Canary" ($src -match [regex]::Escape("'^(?i)c$' { return 'Canary' }"))
Check "dispatch: menu site wired" ($src -match [regex]::Escape("'Canary' { Invoke-CanaryMode -KeepLogging:`$KeepLogging | Out-Null }`r`n                'Links'"))
Check "dispatch: -Mode site wired" ($src -match [regex]::Escape("'Canary' { Invoke-CanaryMode -KeepLogging:`$KeepLogging | Out-Null }`r`n    }`r`n    exit 0"))

# ============================================================================
# PART 2 - consent + guard rails
# ============================================================================
Check "consent: explicit y/N gate with lab-only warning" ($src -match [regex]::Escape('Run the canary here? [y/N]') -and $src -match 'Lab / validation use only')
Check "guard: elevated relaunch when not admin" ($src -match [regex]::Escape('Canary needs admin'))
Check "guard: SimpleUI owners never see it" ($src -match [regex]::Escape('not available in the simple owner UI'))
Check "restore: audit state captured before change" ($src -match [regex]::Escape('$before = (& auditpol.exe /get /subcategory:"$sub" 2>$null | Out-String)'))
Check "restore: auditpol undo" ($src -match [regex]::Escape('/subcategory:"$($p2[1])" /success:disable'))
Check "restore: regkey delete-undo for created values" ($src -match [regex]::Escape('Remove-ItemProperty -LiteralPath $p2[1] -Name $p2[2]'))
Check "restore: regkey value-undo for changed values" ($src -match [regex]::Escape('Set-ItemProperty -LiteralPath $p2[1] -Name $p2[2] -Value $p2[3]'))
Check "restore: skipped under -KeepLogging" ($src -match [regex]::Escape('if (-not $KeepLogging -and $undo.Count -gt 0)'))

# ============================================================================
# PART 3 - battery: logging enables + planted activity
# ============================================================================
Check "logging: Process Creation + account mgmt + group mgmt audits" ($src -match [regex]::Escape("'Process Creation', 'User Account Management', 'Security Group Management'"))
Check "logging: 4688 cmdline registry enable" ($src -match 'ProcessCreationIncludeCmdLine_Enabled')
Check "logging: script block logging enable" ($src -match 'EnableScriptBlockLogging')
Check "battery: renamed cmd labeled canary_renamed" ($src -match [regex]::Escape("'canary_renamed.exe'"))
Check "battery: canary_test user created AND removed" ($src -match 'net\.exe user canary_test /add' -and $src -match 'net\.exe user canary_test /delete')
Check "battery: privileged group add AND remove" ($src -match 'localgroup administrators canary_test /add' -and $src -match 'localgroup administrators canary_test /delete')
Check "battery: recon burst >=8 distinct tools" ((@('whoami.exe','net.exe','nltest.exe','systeminfo.exe','ipconfig.exe','quser.exe','tasklist.exe','klist.exe','netstat.exe') | Where-Object { $src -match [regex]::Escape("& $($_)") }).Count -ge 8)
Check "battery: certutil benign fetch" ($src -match 'certutil\.exe -urlcache')
Check "battery: planted files cleaned up" ($src -match [regex]::Escape("Remove-Item $canExe"))

# ============================================================================
# PART 4 - collection + scorecard
# ============================================================================
Check "collection: Standard preset (Quick lacks 4688/auth parses)" ($src -match [regex]::Escape('-Preset Standard -CaseID CANARY'))
Check "collection: canary case identified by delta" ($src -match [regex]::Escape('$before -notcontains $_'))
Check "scorecard: 4 expected rules" ((@('Renamed LOLBin at rest','Account lifecycle','proxy-execution','Discovery command storm') | Where-Object { $src -match [regex]::Escape($_) }).Count -eq 4)
Check "scorecard: FIRED / MISS / BLIND verdicts" ($src -match 'FIRED' -and $src -match 'MISS - data present' -and $src -match 'BLIND - no telemetry')
Check "scorecard: MISS means file-a-bug, BLIND names the reason" ($src -match [regex]::Escape('rule silent: file this') -and $src -match 'DataWhy')
Check "scorecard: pipeline summary + verdict shown" ($src -match 'canary detections fired' -and $src -match 'ConfidencePercent')

# ============================================================================
# PART 5 - module 4.1: account-management EIDs (4720/4732) reach security_auth_events
# (canary caught R6 dead on real hosts - fixtures had fed it synthetic rows)
# ============================================================================
$m41 = [regex]::Match($src, "(?s)Id = '4\.1';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '4\.2'")
if (-not $m41.Success) { throw 'extract failed: module 4.1' }
$defs4 = ''
foreach ($n in @('Get-EventDataRows')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs4 += $m.Value + "`r`n"
}
Invoke-Expression $defs4
function Get-LogStart { $null }
function Get-FilteredEvents { param($LogName, $Ids, $Start, $MaxMsg)
    @(New-Object pscustomobject -Property @{ TimeCreated = (Get-Date '2026-10-04 12:00:00'); Id = 4624; Message = 'Account Name: bob`r`nLogon Type: 2`r`nLogon ID: 0x111`r`nSource Network Address: -' })
}
function Export-Evtx { param($LogName, $FileName) }
$saved4 = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved4[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-EventDataRowsStub { param($LogName, $Id, $Start, $Cap, $Fields)
    if (@($Id) -contains 4720) {
        @([pscustomobject]@{ Time = (Get-Date '2026-10-04 12:01:00'); EventId = 4720; Account = 'canary_test'; SourceIp = ''; LogonType = ''; LogonId = '' },
          [pscustomobject]@{ Time = (Get-Date '2026-10-04 12:02:00'); EventId = 4732; Account = 'canary_test'; SourceIp = ''; LogonType = ''; LogonId = '' })
    } else { @() }
}
# route the module's Get-EventDataRows calls through the stub while keeping the real one for other tests
$realGEDR = ${function:Get-EventDataRows}
function Get-EventDataRows { param($LogName, $Id, $Start, $Cap, $Fields) Get-EventDataRowsStub -LogName $LogName -Id $Id -Start $Start -Cap $Cap -Fields $Fields }
$mod41 = [pscustomobject]@{ Id = '4.1'; Name = 'Security log'; Run = [scriptblock]::Create($m41.Groups[1].Value) }
& $mod41.Run
${function:Get-EventDataRows} = $realGEDR
$auth4 = @($saved4['security_auth_events'])
Check "4.1: 4720 account creation in security_auth_events" (@($auth4 | Where-Object { "$($_.EventId)" -eq '4720' -and $_.Account -eq 'canary_test' }).Count -eq 1)
Check "4.1: 4732 group change in security_auth_events" (@($auth4 | Where-Object { "$($_.EventId)" -eq '4732' }).Count -eq 1)
Check "4.1: 4624 logon rows still present" (@($auth4 | Where-Object { "$($_.EventId)" -eq '4624' }).Count -eq 1)
Check "4.1: bruteforce + summary still built from auth rows" (@($saved4['security_bruteforce_candidates']).Count -ge 0 -and @($saved4['security_auth_summary']).Count -ge 1)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
