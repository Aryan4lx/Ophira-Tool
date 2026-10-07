$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.40 - focus engine: iterative entity expansion, multi-instance grouping per path+hash,
# masquerade split, ProcessGuid instance attribution, activity chain, common-name guard
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
# static wiring + A0 instance-identity collectors
# ============================================================================
Check "params: Focus in ValidateSet (after Canary - keeps old regexes valid)" ($src -match [regex]::Escape("'Process', 'Timeline', 'Canary', 'Focus'"))
Check "menu: option 9 returns Focus" ($src -match [regex]::Escape("'^(?i)9$' { return 'Focus' }"))
Check "dispatch: Focus + Process both call the engine" (([regex]::Matches($src, [regex]::Escape('Invoke-FocusEngine -Path $ParsePath -Indicator $ProcessName'))).Count -ge 2)
Check "A0: Sysmon EID1 captures ProcessId/ProcessGuid/ParentImage" (($src -match [regex]::Escape("ProcessId = 'ProcessId'; ProcessGuid = 'ProcessGuid'; ParentImage = 'ParentImage'")) -and $src -match [regex]::Escape("ParentProcessGuid = 'ParentProcessGuid'"))
Check "A0: 4688 captures NewProcessId + creator ProcessId" ($src -match [regex]::Escape("NewProcessId = 'NewProcessId'; CreatorPid = 'ProcessId'"))
Check "A0: Sysmon EID3 network rows carry ProcessGuid" ($src -match [regex]::Escape("ProcessGuid = `$d['ProcessGuid']; ProcessId = `$d['ProcessId']"))
Check "A0: Sysmon EID7 image loads carry ProcessGuid" ($src -match [regex]::Escape("ProcessId = `$d['ProcessId']; ProcessGuid = `$d['ProcessGuid']"))
Check "report: focus section + nav anchor present" (($src -match [regex]::Escape("name='focus'")) -and ($src -match [regex]::Escape('<a href=''#focus''>Focus</a>')))
Check "auto-parse: analyze wizard routes single cases to the parse flow" ($src -match [regex]::Escape('Single case detected -> finishing it'))

# ============================================================================
# engine behavior on a synthetic multi-instance + masquerade case
# ============================================================================
$defs = ''
foreach ($n in @('Open-CaseSession', 'Invoke-FocusEngine')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$ScriptVersion = '2.40'

$case = Join-Path $env:TEMP "ophira_focus_$stamp"
$csv = Join-Path $case 'csv'
New-Item -ItemType Directory -Path $csv -Force | Out-Null
Set-Content (Join-Path $case 'case.json') -Value '{"Computer":"FT","CaseID":"C-40","Analyst":"t","StartedUTC":"2026-10-05T08:00:00.0000000Z","AdminElevated":true,"SysmonPresent":true,"LogHours":168,"Tool":"Ophira v2.40"}' -Encoding UTF8

New-Csv (Join-Path $csv 'processes.csv') '"PID","PPID","Name","Path","CommandLine","Created"' @(
    '"4812","100","malware.exe","C:\Users\dev\AppData\Roaming\malware.exe","""C:\Users\dev\AppData\Roaming\malware.exe"" -p","2026-10-05 14:02:11"',
    '"5620","900","malware.exe","C:\Users\dev\AppData\Roaming\malware.exe","""C:\Users\dev\AppData\Roaming\malware.exe""","2026-10-05 14:19:03"',
    '"700","100","malware.exe","C:\Windows\System32\malware.exe","x","2026-10-05 09:00:00"',
    '"500","4","svchost.exe","C:\Windows\System32\svchost.exe","-k DcomLaunch","2026-10-05 08:00:00"'
)
New-Csv (Join-Path $csv 'sysmon_proc_create.csv') '"Time","EventId","Image","OriginalFileName","CommandLine","User","ProcessId","ProcessGuid","ParentImage","ParentProcessGuid"' @(
    '"2026-10-05 14:02:11.910","1","C:\Users\dev\AppData\Roaming\malware.exe","runner.exe","malware.exe -p","FT\dev","4812","{7a1f-aaaa}","C:\Windows\explorer.exe","{1111-1111}"',
    '"2026-10-05 14:19:03.100","1","C:\Users\dev\AppData\Roaming\malware.exe","runner.exe","malware.exe","FT\dev","5620","{7a1f-bbbb}","C:\Windows\System32\cmd.exe","{2222-2222}"',
    '"2026-10-05 14:02:40.000","1","C:\Windows\System32\cmd.exe","Cmd.Exe","cmd /c C:\Users\dev\AppData\Roaming\malware.exe --install","FT\dev","4900","{7a1f-cccc}","C:\Users\dev\AppData\Roaming\malware.exe","{7a1f-aaaa}"'
)
New-Csv (Join-Path $csv 'sysmon_network.csv') '"Time","Image","DestIp","DestPort","Protocol","ProcessGuid","ProcessId"' @(
    '"2026-10-05 14:03:00.000","C:\Users\dev\AppData\Roaming\malware.exe","185.199.10.7","443","tcp","{7a1f-aaaa}","4812"',
    '"2026-10-05 14:05:00.000","C:\Users\dev\AppData\Roaming\malware.exe","185.199.10.7","443","tcp","{7a1f-aaaa}","4812"'
)
New-Csv (Join-Path $csv 'security_proc_events.csv') '"Time","EventId","Account","LogonId","NewProcess","CommandLine","ParentProcess","NewProcessId","CreatorPid"' @(
    '"2026-10-05 14:19:03.000","4688","FT\dev","0x3e7","C:\Users\dev\AppData\Roaming\malware.exe","malware.exe","cmd.exe","0x15f4","0x6f4"'
)
New-Csv (Join-Path $csv 'process_hashes.csv') '"Name","Path","SHA256"' @(
    '"malware.exe","C:\Users\dev\AppData\Roaming\malware.exe","AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999"'
)
New-Csv (Join-Path $csv 'supertimeline.csv') '"Timestamp","Source","Type","Actor","Entity","Detail"' @(
    '"2026-10-05 14:02:11","sysmon_proc_create","process create (Sysmon 1)","dev","malware.exe","parent explorer.exe"',
    '"2026-10-05 14:03:00","sysmon_network","network connect","dev","malware.exe","185.199.10.7:443"',
    '"2026-10-05 14:19:03","sysmon_proc_create","process create (Sysmon 1)","dev","malware.exe","respawn after kill"',
    '"2026-10-05 12:00:00","prefetch_parsed","prefetch run","dev","notepad.exe","unrelated"'
)
New-Csv (Join-Path $csv 'beacon_candidates.csv') '"RemoteIp","RemotePort","IntervalSec","Hits","Jitter","Score","Detail"' @(
    '"185.199.10.7","443","60","22","0.08","high","regular intervals - C2 pattern"'
)
New-Csv (Join-Path $csv 'yara_hits.csv') '"Time","Binary","Rule","Score","Detail"' @(
    '"2026-10-05 14:20:00","C:\Users\dev\AppData\Roaming\malware.exe","MALWARE_FAMILY_Test","high","YARA match on flagged binary"'
)
New-Csv (Join-Path $csv 'sysmon_dns.csv') '"Time","Image","QueryName","QueryResults","ProcessId","ProcessGuid"' @(
    '"2026-10-05 14:03:10.000","C:\Users\dev\AppData\Roaming\malware.exe","evil-c2.example","185.199.10.7","4812","{7a1f-aaaa}"'
)
New-Csv (Join-Path $csv 'sysmon_image_load.csv') '"Time","Process","Dll","Signed","Signature","Company","Description","ProcessId","ProcessGuid"' @(
    '"2026-10-05 14:02:20.000","C:\Users\dev\AppData\Roaming\malware.exe","C:\Windows\System32\wininet.dll","true","Microsoft Windows","Microsoft Corporation","Internet Extensions","4812","{7a1f-aaaa}"'
)
New-Csv (Join-Path $csv 'sysmon_registry.csv') '"Time","EventId","EventType","TargetObject","Image","ProcessId","ProcessGuid"' @(
    '"2026-10-05 14:02:25.000","13","SetValue","HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware","C:\Users\dev\AppData\Roaming\malware.exe","4812","{7a1f-aaaa}"'
)
New-Csv (Join-Path $csv 'sysmon_file_time.csv') '"Time","EventId","Image","TargetFilename","CreationUtcTime","PreviousCreationUtcTime","ProcessId","ProcessGuid"' @(
    '"2026-10-05 14:02:30.000","2","C:\Users\dev\AppData\Roaming\malware.exe","C:\Users\dev\AppData\Roaming\malware.cfg","2026-10-05 14:02:30.000","2020-01-01 00:00:00.000","4812","{7a1f-aaaa}"'
)

$ok = Invoke-FocusEngine -Path $case -Indicator 'malware.exe'
$fDir = Join-Path $case 'focus'
Check "engine: name seed returns success" ($ok -eq $true)

$hits = @(); try { $hits = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_hits.csv') -ErrorAction Stop) } catch { }
Check "hits: matched across process/network/proc-create sources" (@($hits | Where-Object Source -eq 'sysmon_network').Count -ge 2 -and @($hits | Where-Object Source -eq 'sysmon_proc_create').Count -ge 2)
Check "hits: ip pivot pulls the beacon row (IP never carries the name)" (@($hits | Where-Object Source -eq 'beacon_candidates').Count -ge 1 -and @($hits | Where-Object { "$($_.MatchedOn)" -match '^ip ' }).Count -ge 1)
Check "hits: yara detection surface matched" (@($hits | Where-Object Source -eq 'yara_hits').Count -eq 1)
Check "hits: unrelated notepad timeline row excluded" (@($hits | Where-Object { $_.Detail -match 'notepad' }).Count -eq 0)

$terms = $null
try { $terms = Get-Content -LiteralPath (Join-Path $fDir 'focus_terms.json') -Raw | ConvertFrom-Json } catch { }
Check "terms: json written with case identity" ($terms -and "$($terms.Computer)" -eq 'FT' -and [int]$terms.HitCount -gt 0)
Check "masquerade: both paths discovered as separate entity groups" (@($terms.Paths | Where-Object { $_ -like '*system32\malware.exe' }).Count -eq 1 -and @($terms.Paths | Where-Object { $_ -like '*roaming\malware.exe' }).Count -eq 1)
Check "guard: OS-infra names (explorer/cmd/svchost) not expanded as seeds" (@($terms.Names | Where-Object { $_ -match '^(explorer|cmd|svchost)\.exe$' }).Count -eq 0)
Check "instance-identity: ProcessGuids captured from EID1 rows" (@($terms.Guids | Where-Object { $_ -match '7a1f' }).Count -ge 2 -and -not $terms.Degraded)

$inst = @(); try { $inst = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_instances.csv') -ErrorAction Stop) } catch { }
$malInst = @($inst | Where-Object { "$($_.Image)" -match 'roaming\\malware\.exe' })
Check "instances: both roaming instances listed once each with PIDs + GUIDs" (@($malInst | Where-Object Pid -eq '4812').Count -eq 1 -and @($malInst | Where-Object Pid -eq '5620').Count -eq 1 -and "$($malInst[0].Guid)" -match '7a1f')

$chain = @(); try { $chain = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_chain.csv') -ErrorAction Stop) } catch { }
Check "chain: timeline filtered to the entity, oldest first" ($chain.Count -ge 3 -and "$($chain[0].Timestamp)" -match '^2026-10-05 14:02' -and @($chain | Where-Object { "$($_.Entity)" -match 'notepad' }).Count -eq 0)

$html = Get-Content -LiteralPath (Join-Path $fDir 'focus_report.html') -Raw
Check "dossier: masquerade warning rendered" ($html -match 'MASQUERADE WARNING')
Check "dossier: instance rows carry PIDs" ($html -match '4812' -and $html -match '5620')
Check "dossier: sections include detection surface + network" (($html -match 'Detection surface') -and ($html -match 'Network activity'))
Check "dossier: corroborated hint banner from yara hit" ($html -match 'CORROBORATED')
Check "per-instance: guid-joined detail in dossier (dns/dll/reg/file/child)" (($html -match 'evil-c2\.example') -and ($html -match 'wininet\.dll') -and ($html -match 'Run\\Malware') -and ($html -match 'malware\.cfg') -and ($html -match 'everything it did'))
Check "graph: layered SVG with instance/child/network nodes" (($html -match '<svg') -and ($html -match 'Activity graph') -and ($html -match 'child PID 4900') -and ($html -match 'NET 185\.199\.10\.7:443'))

# PID seed: resolves via the live snapshot to the same entity
$ok2 = Invoke-FocusEngine -Path $case -Indicator '4812'
$hits2 = @(); try { $hits2 = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_hits.csv') -ErrorAction Stop) } catch { }
Check "pid seed: live PID resolves to the entity's path" ($ok2 -and @($hits2 | Where-Object Source -eq 'processes').Count -ge 1)

# no-GUID case degrades gracefully
$case2 = Join-Path $env:TEMP "ophira_focus2_$stamp"
$csv2 = Join-Path $case2 'csv'
New-Item -ItemType Directory -Path $csv2 -Force | Out-Null
Set-Content (Join-Path $case2 'case.json') -Value '{"Computer":"F2","CaseID":"C-41","Analyst":"t","StartedUTC":"2026-10-05T08:00:00.0000000Z","AdminElevated":true,"SysmonPresent":false,"LogHours":168,"Tool":"Ophira v2.40"}' -Encoding UTF8
New-Csv (Join-Path $csv2 'processes.csv') '"PID","PPID","Name","Path"' '"1000","4","legacy.exe","C:\Users\dev\AppData\legacy.exe"'
$ok3 = Invoke-FocusEngine -Path $case2 -Indicator 'legacy.exe'
$terms3 = $null
try { $terms3 = Get-Content -LiteralPath (Join-Path $case2 'focus\focus_terms.json') -Raw | ConvertFrom-Json } catch { }
Check "degraded: no-GUID case flags attribution as limited" ($ok3 -and $terms3 -and $terms3.Degraded)

# empty indicator fails cleanly
$ok4 = Invoke-FocusEngine -Path $case -Indicator 'zzz-nothing-matches-xyz'
Check "empty result: engine still succeeds with zero-hit outputs" ($ok4 -eq $true)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case, $case2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
