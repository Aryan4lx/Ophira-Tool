$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.14 - DNS beaconing (4.8), LOLDrivers xref (8.10), -Mode Tune, supertimeline dedupe, verdict wiring
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
$defs = ''
foreach ($n in @('Test-IsPublicIp', 'Test-IsUserWritablePath')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

function New-Csv { param($Path, [string[]]$Header, [string[]]$Lines) ($Header + $Lines) | Set-Content -LiteralPath $Path -Encoding UTF8 }

# ============================================================================
# PART 1 - module 4.8: network + DNS beaconing through the real Run block
# ============================================================================
$m48 = [regex]::Match($src, "(?s)Id = '4\.8';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '5\.1'")
if (-not $m48.Success) { throw 'module 4.8 extract failed' }

$case = Join-Path $env:TEMP ("ophira_v214_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'
New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
$CsvDir = $csvDir; $RawDir = Join-Path $case 'raw'; $MemDir = Join-Path $case 'mem'
$Sysmon = $true; $LogHours = 168
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Import-CaseCsv {
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    $f = Join-Path $CsvDir $Name
    if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) { try { return @(Import-Csv $f) } catch { return @() } }
    return @()
}

$base = [datetime]'2026-09-25 08:30:00'
$netLines = @(); $dnsLines = @()
for ($i = 0; $i -lt 60; $i++) {
    $t = $base.AddSeconds($i * 60).ToString('yyyy-MM-dd HH:mm:ss')
    $netLines += ('"{0}","C:\Users\u\App\beacon.exe","203.0.113.99","443","tcp"' -f $t)
    $dnsLines += ('"{0}","C:\Users\u\App\beacon.exe","evil-c2-domain.com","type:  5 evil-c2-domain.com;203.0.113.10;","1234"' -f $t)
    $dnsLines += ('"{0}","C:\Windows\System32\svchost.exe","benign-cdn.com","type:  5 benign-cdn.com;10.0.0.5;","999"' -f $t)
}
New-Csv (Join-Path $csvDir 'sysmon_network.csv') @('"Time","Image","DestIp","DestPort","Protocol"') $netLines
New-Csv (Join-Path $csvDir 'sysmon_dns.csv') @('"Time","Image","QueryName","QueryResults","ProcessId"') $dnsLines

& ([scriptblock]::Create($m48.Groups[1].Value))

$netB = @($saved['beacon_candidates'])
$dnsB = @($saved['dns_beacon_candidates'])
Check "net beacon: high row for 203.0.113.99" (@($netB | Where-Object { "$($_.RemoteIp)" -eq '203.0.113.99' -and "$($_.Severity)" -eq 'high' }).Count -eq 1)
Check "net beacon: interval ~60s, reg 1" ("$($netB[0].MedianIntervalSec)" -eq '60' -and "$($netB[0].Regularity)" -eq '1')
Check "dns beacon: high row for evil-c2-domain.com" (@($dnsB | Where-Object { "$($_.Domain)" -eq 'evil-c2-domain.com' -and "$($_.Severity)" -eq 'high' }).Count -eq 1)
Check "dns beacon: resolved public IP captured" ("$(@($dnsB | Where-Object { "$($_.Domain)" -eq 'evil-c2-domain.com' })[0].ResolvedIp)" -eq '203.0.113.10')
Check "dns beacon: benign private-IP domain NOT high/med" (@($dnsB | Where-Object { "$($_.Domain)" -eq 'benign-cdn.com' -and "$($_.Severity)" -match '^(high|medium)$' }).Count -eq 0)
Check "dns beacon: user-path flag set on beacon row" ("$(@($dnsB | Where-Object { "$($_.Domain)" -eq 'evil-c2-domain.com' })[0].Flags)" -match 'user-path')

# ============================================================================
# PART 2 - module 8.10: LOLDrivers hash xref
# ============================================================================
$m810 = [regex]::Match($src, "(?s)Id = '8\.10';.*?Run = \{(.*?)\r?\n        \} \}\r?\n\)")
if (-not $m810.Success) { throw 'module 8.10 extract failed' }
$toolsTmp = Join-Path $env:TEMP ("ophira_lol_" + (Get-Date -Format 'HHmmss'))
$lolDir = Join-Path $toolsTmp 'loldrivers'
$drvDir = Join-Path $toolsTmp 'fakedrivers'
New-Item -ItemType Directory -Path $lolDir, $drvDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $lolDir 'samples_malicious.sha256') -Value 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' -Encoding ASCII
Set-Content -LiteralPath (Join-Path $lolDir 'samples_vulnerable.sha256') -Value 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' -Encoding ASCII
foreach ($f in @('evil.sys', 'vuln.sys', 'clean.sys')) { Set-Content -LiteralPath (Join-Path $drvDir $f) -Value 'fake driver' -Encoding ASCII }
function Get-ToolsDir { $toolsTmp }
function Get-FileHash { param($LiteralPath, $Algorithm)
    $n = Split-Path $LiteralPath -Leaf
    $h = @{ 'evil.sys' = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; 'vuln.sys' = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'; 'clean.sys' = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' }[$n]
    [pscustomobject]@{ Hash = $h; Path = $LiteralPath }
}
New-Csv (Join-Path $csvDir 'drivers.csv') @('"Name","DisplayName","PathName","State","StartMode"') @(
    ('"evilSvc","Evil Driver","{0}","Running","3"' -f (Join-Path $drvDir 'evil.sys')),
    ('"vulnSvc","Vuln Driver","\\??\{0}","Running","3"' -f (Join-Path $drvDir 'vuln.sys')),
    ('"cleanSvc","Clean Driver","{0}","Running","3"' -f (Join-Path $drvDir 'clean.sys')),
    ('"goneSvc","Missing","{0}","Stopped","3"' -f (Join-Path $drvDir 'gone.sys'))
)
$saved = @{}
& ([scriptblock]::Create($m810.Groups[1].Value))
$lolHits = @($saved['loldrivers_hits'])
Check "loldrivers: malicious hit detected" (@($lolHits | Where-Object { $_.Status -eq 'malicious' -and $_.Name -eq 'evilSvc' }).Count -eq 1)
Check "loldrivers: \\??\ prefix stripped, vulnerable hit" (@($lolHits | Where-Object { $_.Status -eq 'vulnerable' -and $_.Name -eq 'vulnSvc' }).Count -eq 1)
Check "loldrivers: clean driver not flagged" (@($lolHits | Where-Object { $_.Name -eq 'cleanSvc' }).Count -eq 0)
Check "loldrivers: exactly 2 hits (missing file skipped)" ($lolHits.Count -eq 2)

# ============================================================================
# PART 3 - Invoke-TuneMode: picker writes hayabusa-native tuning files
# ============================================================================
$mTune = [regex]::Match($src, "(?s)function Invoke-TuneMode \{.*?\r?\n\}")
if (-not $mTune.Success) { throw 'Invoke-TuneMode extract failed' }
$hbDir = Join-Path $env:TEMP ("ophira_hb_" + (Get-Date -Format 'HHmmss'))
$cfgDir = Join-Path $hbDir 'rules\config'
New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $hbDir 'hayabusa.exe') -Value 'fake' -Encoding ASCII
'# Replaced by Hayabusa rules:' | Set-Content -LiteralPath (Join-Path $cfgDir 'exclude_rules.txt') -Encoding UTF8
$kitTmp = Join-Path $env:TEMP ("ophira_kit_" + (Get-Date -Format 'HHmmss'))
$caseCsv = Join-Path $kitTmp 'OPHIRA_TEST_20260101_000000\csv'
New-Item -ItemType Directory -Path $caseCsv -Force | Out-Null
New-Csv (Join-Path $caseCsv 'hayabusa_timeline.csv') @('"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"') @(
    $((1..50 | ForEach-Object { '"2026-09-25 08:00:00","Suspicious Misc","high","H1","Sec",4688,' + $_ + ',"d","","guid-r1"' }))
    $((1..30 | ForEach-Object { '"2026-09-25 09:00:00","Potentially Bad","med","H1","Sec",4688,' + $_ + ',"d","","guid-r2"' }))
)
function Get-KitRoot { $kitTmp }
function Get-HayabusaExe { Get-Item (Join-Path $hbDir 'hayabusa.exe') }
$queue = [System.Collections.Queue]::new()
@('1,2', 'E', 'D') | ForEach-Object { $queue.Enqueue($_) }
function Read-Host { param($Prompt) $queue.Dequeue() }
Invoke-Expression $mTune.Value
$null = Invoke-TuneMode
$exTxt = Get-Content (Join-Path $cfgDir 'exclude_rules.txt') -Raw
$lvFile = Join-Path $cfgDir 'level_tuning.txt'
$lvTxt = if (Test-Path $lvFile) { Get-Content $lvFile -Raw } else { '' }
Check "tune: exclude_rules.txt got guid-r1 in native format" ("$exTxt" -match 'guid-r1 # "Suspicious Misc" \(Ophira Tune')
Check "tune: original exclude_rules content preserved" ("$exTxt" -match 'Replaced by Hayabusa rules')
Check "tune: level_tuning.txt created with header + demote line" (("$lvTxt" -match '(?m)^id,new_level\r?$') -and ("$lvTxt" -match 'guid-r2,informational # "Potentially Bad" - Originally med'))

# ============================================================================
# PART 4 - supertimeline: sort-csv dedupe call
# ============================================================================
$mST = [regex]::Match($src, "(?s)function New-SuperTimeline \{.*?\r?\n\}")
if (-not $mST.Success) { throw 'New-SuperTimeline extract failed' }
$stCase = Join-Path $env:TEMP ("ophira_st_" + (Get-Date -Format 'HHmmss'))
$CsvDir = Join-Path $stCase 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
New-Csv (Join-Path $CsvDir 'security_events.csv') @('"TimeCreated","Id","Provider","Level","Message"') @(
    '"2026-09-25 10:00:00","4624","Microsoft-Windows-Security-Auditing","Information","An account logged on"',
    '"2026-09-25 11:00:00","4625","Microsoft-Windows-Security-Auditing","Information","Logon failed"'
)
$stLines = @(
    '"2026-09-25 09:00:00","Bad Rule","high","H1","Sec",4688,1,"d","","guid-x"',
    '"2026-09-25 09:00:00","Bad Rule","high","H1","Sec",4688,1,"d","","guid-x"',
    '"2026-09-25 09:30:00","Other Rule","low","H1","Sec",4688,2,"d","","guid-y"'
)
New-Csv (Join-Path $CsvDir 'hayabusa_timeline.csv') @('"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"') $stLines
$script:sortCsvCalled = $false
function Get-HayabusaExe { Get-Item (Join-Path $hbDir 'hayabusa.exe') }
function Invoke-NativeTool { param($ExePath, $ToolArgs, $WorkingDirectory, [switch]$QuietLog, $CaptureOut)
    if ("$($ToolArgs[0])" -eq 'sort-csv') {
        $script:sortCsvCalled = $true
        $f = $ToolArgs[([array]::IndexOf($ToolArgs, '-f')) + 1]
        $lines = @(Get-Content -LiteralPath $f)
        $dup = $lines[1..($lines.Count-1)] | Select-Object -Unique
        @($lines[0]) + $dup | Set-Content -LiteralPath $f -Encoding UTF8
        return 0
    }
    return 0
}
Invoke-Expression $mST.Value
$null = New-SuperTimeline
$stRows = @(Import-Csv (Join-Path $CsvDir 'supertimeline.csv'))
Check "supertimeline: sort-csv invoked" $script:sortCsvCalled
Check "supertimeline: duplicate hayabusa row deduped (4 rows)" ($stRows.Count -eq 4)
Check "supertimeline: sources merged (hayabusa + security)" (@($stRows | Where-Object Source -eq 'hayabusa').Count -eq 2 -and @($stRows | Where-Object Source -eq 'security_events').Count -eq 2)

# ============================================================================
# PART 5 - verdict wiring for DNS beacons + LOLDrivers
# ============================================================================
$mVerdict = [regex]::Match($src, "(?s)function Get-CompromiseVerdict \{.*?\r?\n\}")
if (-not $mVerdict.Success) { throw 'Get-CompromiseVerdict extract failed' }
$vdCase = Join-Path $env:TEMP ("ophira_vd_" + (Get-Date -Format 'HHmmss'))
$CsvDir = Join-Path $vdCase 'csv'; $RawDir = Join-Path $vdCase 'raw'; $MemDir = Join-Path $vdCase 'mem'
New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$Sysmon = $true; $LogHours = 168
function Test-IsAdmin { $true }
function Get-ToolsDir { $null }
function Import-CaseCsv {
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    $f = Join-Path $CsvDir $Name
    if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) { try { return @(Import-Csv $f) } catch { return @() } }
    return @()
}
New-Csv (Join-Path $CsvDir 'dns_beacon_candidates.csv') @('"Severity","Rank","Process","Domain","ResolvedIp","Events","SpanMin","MedianIntervalSec","Jitter","Regularity","Flags"') @(
    '"high","3","C:\Users\u\App\beacon.exe","evil-c2-domain.com","203.0.113.10","60","59","60","0.03","1","public-ip;user-path"'
)
New-Csv (Join-Path $CsvDir 'loldrivers_hits.csv') @('"Status","Name","DisplayName","Path","SHA256"') @(
    '"malicious","evilSvc","Evil Driver","C:\Windows\System32\drivers\evil.sys","AAAA"'
)
Invoke-Expression $mVerdict.Value
$v = Get-CompromiseVerdict
Check "verdict: DNS beacon signal floor 3 present" (@($v.Signals | Where-Object { "$($_.Signal)" -match 'DNS beaconing' -and $_.Weight -eq 3 }).Count -eq 1)
Check "verdict: LOLDrivers malicious signal present" (@($v.Signals | Where-Object { "$($_.Signal)" -match 'LOLDrivers' }).Count -eq 1)
Check "verdict: rank escalated to LIKELY COMPROMISED (two signals)" ($v.LevelRank -ge 3)
Check "verdict: counts expose DnsBeaconHigh + LolDriversMalicious" ($v.Counts.DnsBeaconHigh -eq 1 -and $v.Counts.LolDriversMalicious -eq 1)
Check "verdict: DNS + LOLDrivers coverage rows present" (@($v.Coverage | Where-Object { "$($_.Source)" -match 'DNS query telemetry|LOLDrivers' }).Count -eq 2)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case, $toolsTmp, $hbDir, $kitTmp, $stCase, $vdCase)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
