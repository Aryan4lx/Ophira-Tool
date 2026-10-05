$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.36 - svchost masquerade detection: module 1.7 audits live -k groups vs the Svchost
# registry key + ServiceDll paths + unregistered loaded DLLs; hunt rule R27 consumes the audit.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - module 1.7 through the real Run block (stubs for registry/processes/modules)
# ============================================================================
$m17 = [regex]::Match($src, "(?s)Id = '1\.7';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '2\.1'")
if (-not $m17.Success) { throw 'extract failed: module 1.7' }
function Get-ItemProperty { param($Path, $Name, $ErrorAction)
    if ("$Path" -match 'CurrentVersion\\Svchost$') {
        return [pscustomobject]@{ netsvcs = @('W32Time', 'wuauserv', 'evilsvc', 'nsistub') }
    }
    if ("$Path" -match 'Services\\evilsvc\\Parameters') { return [pscustomobject]@{ ServiceDll = 'C:\ProgramData\evil.dll' } }
    if ("$Path" -match 'Services\\W32Time\\Parameters') { return [pscustomobject]@{ ServiceDll = 'C:\Windows\System32\w32time.dll' } }
    if ("$Path" -match 'Services\\wuauserv\\Parameters') { throw 'missing Parameters key' }
    throw "no stub for $Path"
}
function Get-WmiOrCim { param([string]$Class, [string]$Filter = '', [string]$Namespace = '')
    @(
        [pscustomobject]@{ Name = 'svchost.exe'; ProcessId = 100; CommandLine = 'C:\Windows\system32\svchost.exe -k netsvcs -p' }
        [pscustomobject]@{ Name = 'svchost.exe'; ProcessId = 200; CommandLine = 'C:\Windows\system32\svchost.exe -k ghostgrp' }
        [pscustomobject]@{ Name = 'explorer.exe'; ProcessId = 300; CommandLine = 'C:\Windows\explorer.exe' }
    )
}
function Get-Process { param($Id, $ErrorAction)
    if ($Id -eq 100) {
        $mods = @(
            [pscustomobject]@{ FileName = 'C:\Windows\System32\ntdll.dll' }
            [pscustomobject]@{ FileName = 'C:\ProgramData\evilmod.dll' }
            [pscustomobject]@{ FileName = 'C:\ProgramData\msdll.dll' }
        )
        return [pscustomobject]@{ Id = $Id; Modules = $mods }
    }
    throw 'access denied'
}
function Get-SignatureInfo { param([string]$Path)
    if ("$Path" -match 'msdll\.dll') { return [pscustomobject]@{ Status = 'Valid'; Signer = 'Microsoft Corporation' } }
    return [pscustomobject]@{ Status = 'NotSigned'; Signer = '' }
}
function Test-Path { param($LiteralPath) "$LiteralPath" -notmatch 'nsistub' }
$saved17 = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved17[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$RawDir = "$env:TEMP\v36_raw_$stamp"; $CsvDir = "$env:TEMP\v36_csv_$stamp"
$mod17 = [pscustomobject]@{ Id = '1.7'; Name = 'Svchost masquerade audit'; Run = [scriptblock]::Create($m17.Groups[1].Value) }
& $mod17.Run
$ra = @($saved17['svchost_audit'])
Check "1.7: unregistered -k group flagged (ghostgrp)" (@($ra | Where-Object { $_.Type -eq 'UnregisteredGroup' -and $_.Group -eq 'ghostgrp' -and "$($_.PID)" -eq '200' }).Count -eq 1)
Check "1.7: ServiceDll outside System32 flagged (evilsvc -> ProgramData)" (@($ra | Where-Object { $_.Type -eq 'OutOfPathServiceDll' -and $_.Service -eq 'evilsvc' -and "$($_.Path)" -match 'ProgramData\\evil\.dll' }).Count -eq 1)
Check "1.7: missing ServiceDll flagged (wuauserv - key exists, no value)" (@($ra | Where-Object { $_.Type -eq 'ServiceDllMissing' -and $_.Service -eq 'wuauserv' }).Count -eq 1)
Check "1.7: no Parameters key at all (nsistub) NOT flagged (stock-legal)" (@($ra | Where-Object { $_.Service -eq 'nsistub' }).Count -eq 0)
Check "1.7: legit in-path ServiceDll (w32time) NOT flagged" (@($ra | Where-Object { "$($_.Path)" -match 'w32time\.dll' }).Count -eq 0)
Check "1.7: unregistered unsigned loaded DLL flagged" (@($ra | Where-Object { $_.Type -eq 'UnregisteredModule' -and "$($_.Path)" -match 'evilmod\.dll' -and "$($_.PID)" -eq '100' }).Count -eq 1)
Check "1.7: Microsoft-signed module NOT flagged" (@($ra | Where-Object { "$($_.Path)" -match 'msdll\.dll' }).Count -eq 0)
Check "1.7: Windows system DLL NOT flagged" (@($ra | Where-Object { "$($_.Path)" -match 'ntdll\.dll' }).Count -eq 0)
Check "1.7: schema Type/Group/Service/PID/Path/Detail" ("$(@($ra)[0].PSObject.Properties.Name -join ',')" -eq 'Type,Group,Service,PID,Path,Detail')

# ============================================================================
# PART 2 - R27 through the real New-HuntFindings
# ============================================================================
$mhf = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
if (-not $mhf.Success) { throw 'extract failed: New-HuntFindings' }
$caseCsv = @{
    'svchost_audit' = @(
        [pscustomobject]@{ Type = 'UnregisteredGroup'; Group = 'ghostgrp'; Service = ''; PID = '200'; Path = ''; Detail = 'not registered' },
        [pscustomobject]@{ Type = 'OutOfPathServiceDll'; Group = 'netsvcs'; Service = 'evilsvc'; PID = ''; Path = 'C:\ProgramData\evil.dll'; Detail = 'outside System32' },
        [pscustomobject]@{ Type = 'ServiceDllMissing'; Group = 'netsvcs'; Service = 'wuauserv'; PID = ''; Path = ''; Detail = 'no ServiceDll value' },
        [pscustomobject]@{ Type = 'UnregisteredModule'; Group = ''; Service = ''; PID = '100'; Path = 'C:\ProgramData\evilmod.dll'; Detail = 'unsigned module' }
    )
}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
$savedHF = @()
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:savedHF = @($Rows) } }
Invoke-Expression $mhf.Value
New-HuntFindings
$hf = $script:savedHF
$r27 = @($hf | Where-Object { $_.Rule -eq 'Svchost masquerade indicator' })
Check "R27: 4 audit rows -> 4 findings" ($r27.Count -eq 4)
Check "R27: unregistered group + out-of-path = high" (@($r27 | Where-Object { $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'UnregisteredGroup|OutOfPathServiceDll' }).Count -eq 2)
Check "R27: missing dll + unregistered module = medium" (@($r27 | Where-Object { $_.Severity -eq 'medium' }).Count -eq 2)
Check "R27: entity falls back to path then service" (@($r27 | Where-Object { $_.Entity -eq 'C:\ProgramData\evil.dll' }).Count -eq 1 -and @($r27 | Where-Object { "$($_.Entity)" -match 'svchost -k ghostgrp' }).Count -eq 1)
Check "R27: T1036.005 tag" (@($r27 | Where-Object { "$($_.Attck)" -eq 'T1036.005' }).Count -eq 4)

# ============================================================================
# PART 3 - wiring: verdict, coverage, evidence index, module placement
# ============================================================================
Check "verdict: high-rule regex includes Svchost masquerade" ($src -match 'authorized_keys\|Svchost masquerade')
Check "verdict: signal label mentions svchost masquerade" ($src -match 'SSH keys / svchost masquerade')
Check "coverage: svchost audit row" ($src -match "Add-Cov 'Svchost masquerade audit'")
Check "evidence index: svchost_audit documented" ($src -match "'svchost_audit'\s+= 'Live svchost -k groups")
Check "module: 1.7 VOLATILE Quick preset on" (($src -match "Id = '1\.7'; Cat = 'VOLATILE'") -and ($src -match 'Quick = \$true;\s*\r?\n\s*Run = \{\r?\n\s*# Live svchost'))
Check "SharedFunctions: Get-SignatureInfo available to workers" ($src -match '(?s)\$script:SharedFunctions = @\(.*?Get-SignatureInfo')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
