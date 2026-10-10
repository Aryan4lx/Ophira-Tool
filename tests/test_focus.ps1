$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.40 - focus engine: iterative entity expansion, multi-instance grouping per path+hash,
# masquerade split, ProcessGuid instance attribution, activity chain, common-name guard
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

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
# v2.45: auto-focus + decision-first report wiring
Check "auto-focus: trigger fires on HIGH process / YARA high / live IOC" (($src -match [regex]::Escape("`$hiProc = @(Import-CaseCsv 'flash_process_scored' | Where-Object { `"`$(`$_.Verdict)`" -eq 'HIGH'")) -and ($src -match [regex]::Escape("`$seedWhy = `"YARA `$(`$yh[0].Severity) hit`"")) -and ($src -match [regex]::Escape("'live IOC hit'")))
Check "auto-focus: manual dossier wins (trigger skips when terms.json exists)" ($src -match [regex]::Escape('if (-not (Test-Path -LiteralPath $focusTermsP))'))
Check "auto-focus: Invoke-RegenerateOutputs calls the core in-session" ($src -match [regex]::Escape('Invoke-FocusCore -Indicator $seed -Meta'))
Check "engine: core split exists as its own function" (($src -match '(?m)^function Invoke-FocusCore \{') -and ($src -match '(?m)^function Invoke-FocusEngine \{'))
Check "engine: core persists focus_instances_detail.json" ($src -match 'focus_instances_detail\.json')
Check "report: leads nav + section present" (($src -match [regex]::Escape("<a href='#leads'>Leads</a>")) -and ($src -match 'Triage leads - decide these first'))
Check "report: verdict banner do-now + clickable signals" (($src -match [regex]::Escape('<b>Do now:</b>')) -and ($src -match 'click a signal to jump'))
Check "report: focus embed reads the detail json" ($src -match [regex]::Escape('focus_instances_detail.json') -and $src -match 'Activity graph \(parents')
Check "hunt R5: USB trail skips the kit's own raw copies" ($src -match [regex]::Escape('OPHIRA_[^\\]*\\raw\\'))
Check "canary R4: scorecard runs the focus core on canary_ngrok (FIRED/MISS/BLIND)" (($src -match [regex]::Escape("'FOCUS auto-dossier (canary_ngrok)'")) -and ($src -match [regex]::Escape('Invoke-FocusCore -Indicator ''canary_ngrok.exe''')))
Check "detail json: lineage + respawn persisted for the report embed" (($src -match [regex]::Escape('Lineage = $lnI; Respawn = $rpI')))

# ============================================================================
# engine behavior on a synthetic multi-instance + masquerade case
# ============================================================================
$defs = ''
foreach ($n in @('Open-CaseSession', 'Invoke-FocusEngine', 'Invoke-FocusCore')) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
$mapM = [regex]::Match($src, '(?s)\$script:CsvCatMap = @\{.*?\r?\n\}')
$gcpM = [regex]::Match($src, "(?s)function Get-CaseCsvPath \{.*?\r?\n\}")
if (-not $mapM.Success -or -not $gcpM.Success) { throw 'extract failed: CsvCatMap/Get-CaseCsvPath' }
Invoke-Expression ($mapM.Value + "`r`n" + $gcpM.Value + "`r`n" + $defs)
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
New-Csv (Join-Path $csv 'beacon_candidates.csv') '"Severity","Rank","Process","RemoteIp","Port","Events","SpanMin","MedianIntervalSec","Jitter","Regularity","Flags"' @(
    '"high","3","C:\Users\dev\AppData\Roaming\malware.exe","185.199.10.7","443","38","190","60","0.06","0.94","user-path"',
    '"medium","2","","185.199.10.7","8443","12","60","120","0.10","0.88",""'
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
New-Csv (Join-Path $csv 'sysmon_file_create.csv') '"Time","EventId","Image","TargetFilename","CreationUtcTime","ProcessId","ProcessGuid","Hashes"' @(
    '"2026-10-05 14:02:28.000","11","C:\Users\dev\AppData\Roaming\malware.exe","C:\Users\dev\AppData\Roaming\payload.dll","2026-10-05 14:02:28.000","4812","{7a1f-aaaa}","SHA256=DEADBEEF00000000000000000000000000000000000000000000000000001234"',
    '"2026-10-05 14:02:29.000","11","C:\Windows\System32\notepad.exe","C:\Users\dev\AppData\Local\Temp\benign.txt","2026-10-05 14:02:29.000","777","{9999-zzzz}","SHA256=AAAA"'
)
New-Csv (Join-Path $csv 'sysmon_file_delete.csv') '"Time","EventId","Image","TargetFilename","ProcessId","ProcessGuid","Hashes","Archived"' @(
    '"2026-10-05 14:21:00.000","23","C:\Users\dev\AppData\Roaming\malware.exe","C:\Users\dev\AppData\Roaming\logs.txt","4812","{7a1f-aaaa}","SHA256=CAFEBABE","false"'
)
# v2.48: injection + pipe fixtures - malware (guid aaaa) injected into its own child cmd (cccc),
# rundll32 injected INTO malware, and a C2-family pipe created by instance aaaa
New-Csv (Join-Path $csv 'sysmon_remote_thread.csv') '"Time","EventId","SourceImage","TargetImage","SourceProcessGuid","TargetProcessGuid","NewThreadId","StartModule","StartFunction","User"' @(
    '"2026-10-05 14:02:45.000","8","C:\Users\dev\AppData\Roaming\malware.exe","C:\Windows\System32\cmd.exe","{7a1f-aaaa}","{7a1f-cccc}","3110","","LoadLibraryA","FT\dev"',
    '"2026-10-05 14:03:30.000","8","C:\Windows\System32\rundll32.exe","C:\Users\dev\AppData\Roaming\malware.exe","{4444-4444}","{7a1f-aaaa}","3220","C:\Windows\System32\kernel32.dll","GetProcAddress","FT\dev"'
)
New-Csv (Join-Path $csv 'sysmon_pipes.csv') '"Time","EventId","Image","PipeName","EventType","User","ProcessId","ProcessGuid"' @(
    '"2026-10-05 14:02:50.000","17","C:\Users\dev\AppData\Roaming\malware.exe","\msagent_f00d","CreatePipe","FT\dev","4812","{7a1f-aaaa}"',
    '"2026-10-05 14:02:51.000","17","C:\Windows\System32\svchost.exe","\wkssvc","CreatePipe","LOCAL SYSTEM","500","{7777-7777}"'
)
# v2.47: persistence + lineage fixtures (7045 install, run-key autorun, explorer grandparent)
New-Csv (Join-Path $csv 'system_new_services.csv') '"Time","Service","Binary","Type"' @(
    '"2026-10-05 14:05:00.000","MalwareSvc","C:\Users\dev\AppData\Roaming\malware.exe","NewService"'
)
New-Csv (Join-Path $csv 'autoruns_runkeys.csv') '"Location","Hive","User","Name","Value"' @(
    '"HKCU\Software\Microsoft\Windows\CurrentVersion\Run","HKU","S-1-5-21-1000","MalwareAuto","C:\Users\dev\AppData\Roaming\malware.exe"'
)
New-Csv (Join-Path $csv 'sysmon_proc_create_explore.csv') '"Time","EventId","Image","OriginalFileName","CommandLine","User","ProcessId","ProcessGuid","ParentImage","ParentProcessGuid"' @(
    '"2026-10-05 09:00:00.000","1","C:\Windows\explorer.exe","EXPLORER.EXE","explorer.exe","DEVLAB01\dev","100","{1111-0000}","C:\Windows\System32\winlogon.exe","{0000-0001}"'
)
# merge the explorer row into sysmon_proc_create (single source of truth for the engine cache)
$spc = Join-Path $csv 'sysmon_proc_create.csv'
(Get-Content $spc) + (Get-Content (Join-Path $csv 'sysmon_proc_create_explore.csv') | Select-Object -Skip 1) | Set-Content $spc -Encoding UTF8
Remove-Item (Join-Path $csv 'sysmon_proc_create_explore.csv') -Force

$ok = Invoke-FocusEngine -Path $case -Indicator 'malware.exe'
$fDir = Join-Path $case 'focus'
Check "engine: name seed returns success" ($ok -eq $true)

$hits = @(); try { $hits = @(Import-Csv -LiteralPath (Join-Path $fDir 'focus_hits.csv') -ErrorAction Stop) } catch { }
Check "hits: matched across process/network/proc-create sources" (@($hits | Where-Object Source -eq 'sysmon_network').Count -ge 2 -and @($hits | Where-Object Source -eq 'sysmon_proc_create').Count -ge 2)
Check "hits: ip pivot pulls the beacon row (IP never carries the name)" (@($hits | Where-Object Source -eq 'beacon_candidates').Count -ge 2 -and @($hits | Where-Object { "$($_.Source)" -eq 'beacon_candidates' -and "$($_.Detail)" -match '8443' -and "$($_.MatchedOn)" -match '^ip ' }).Count -ge 1)
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
Check "per-instance: EID11 file creates joined by guid - dropped files listed" (($html -match 'Files created \(') -and ($html -match 'payload\.dll') -and ($html -match 'DEADBEEF') -and ($html -notmatch 'benign\.txt'))
Check "per-instance: EID23 file deletes rendered as anti-forensics evidence" (($html -match 'Files deleted \(') -and ($html -match 'logs\.txt') -and ($html -match 'anti-forensics'))
Check "graph: layered SVG with instance/child/network nodes" (($html -match '<svg') -and ($html -match 'Activity graph') -and ($html -match 'child PID 4900') -and ($html -match 'NET 185\.199\.10\.7:443'))
Check "graph: file-drop and delete chips rendered" (($html -match 'DROP payload\.dll') -and ($html -match 'DEL logs\.txt'))
# v2.48: injection + pipe chips/sections/edges
Check "injection: CrtIn section - rundll32 injected INTO instance 4812" (($html -match 'Cross-process injection INTO this instance \(1\)') -and ($html -match 'rundll32\.exe') -and ($html -match 'GetProcAddress'))
Check "injection: CrtOut section - threads created in the child cmd" (($html -match 'Remote threads this instance created in OTHER processes \(1\)') -and ($html -match 'LoadLibraryA'))
Check "pipes: C2-family pipe joined onto the instance, stock pipe excluded" (($html -match 'Named pipes created/connected \(1\)') -and ($html -match 'msagent_f00d') -and ($html -notmatch 'wkssvc'))
Check "graph: INJECT/THREAD/PIPE chips rendered" (($html -match 'INJECT&lt;- rundll32\.exe') -and ($html -match 'THREAD-&gt; cmd\.exe') -and ($html -match 'PIPE \\msagent_f00d'))
Check "graph: red cross-instance injection edge between tracked instances" ($html -match "stroke='#a33'")
Check "dossier: injection hits routed to the Process events section" (($html -match 'Process events \(') -and ($html -match 'sysmon_remote_thread'))

# v2.45: per-instance detail json for the main report embed
$fDetail = $null
try { $fDetail = Get-Content -LiteralPath (Join-Path $fDir 'focus_instances_detail.json') -Raw | ConvertFrom-Json } catch { }
Check "detail: json written with indicator + graph svg" ($fDetail -and "$($fDetail.Indicator)" -eq 'malware.exe' -and "$($fDetail.GraphSvg)" -match '<svg')
Check "detail: instance 4812 carries guid-joined sections" (@($fDetail.Instances | Where-Object { "$($_.Pid)" -eq '4812' }).Count -eq 1 -and @($fDetail.Instances | Where-Object { "$($_.Guid)" -match '7a1f-aaaa' }).Count -ge 1)
$i4812 = @($fDetail.Instances | Where-Object { "$($_.Pid)" -eq '4812' })[0]
Check "detail: sections populated (children/net/dns/dll/reg/file/drop/del)" ($i4812 -and @($i4812.Children).Count -ge 1 -and @($i4812.Net).Count -ge 2 -and @($i4812.Dns).Count -ge 1 -and @($i4812.Dll).Count -ge 1 -and @($i4812.Reg).Count -ge 1 -and @($i4812.File).Count -ge 1 -and @($i4812.FileCreate).Count -ge 1 -and @($i4812.FileDelete).Count -ge 1)
Check "detail: benign notepad drop NOT in instance sections" (@($i4812.FileCreate | Where-Object { "$($_.TargetFilename)" -match 'benign\.txt' }).Count -eq 0)
Check "detail: CrtIn/CrtOut/Pipes persisted for instance 4812" ((@($i4812.CrtIn).Count -eq 1) -and (@($i4812.CrtOut).Count -eq 1) -and (@($i4812.Pipes).Count -eq 1))
$im4812out = @($i4812.CrtOut)[0]
Check "detail: CrtOut row names the child cmd target" ($im4812out -and "$($im4812out.TargetImage)" -match 'cmd\.exe' -and "$($im4812out.TargetProcessGuid)" -match '7a1f-cccc')
# v2.47: ancestry walk-up, persistence + beacon joins, target/relative split, respawn narration
Check "lineage: instance 4812 walks up to explorer then winlogon (2 hops)" ((@($i4812.Lineage).Count -ge 2) -and (@($i4812.Lineage) -join '|') -match 'explorer\.exe' -and (@($i4812.Lineage) -join '|') -match 'winlogon\.exe')
Check "persistence: 7045 install + run-key autorun joined onto the instance" ((@($i4812.Persist).Count -ge 2) -and (@($i4812.Persist | ForEach-Object { $_.Kind }) -contains 'service install (7045)') -and (@($i4812.Persist | ForEach-Object { $_.Kind }) -contains 'autorun (run key)'))
Check "beacon: per-instance C2 cadence joined (beacon_candidates by image)" ((@($i4812.Beacon).Count -ge 1) -and "$($i4812.Beacon[0].Detail)" -match 'median interval')
$im5620 = @($fDetail.Instances | Where-Object { "$($_.Pid)" -eq '5620' })[0]
Check "respawn: same-path instance 17 min later narrated" ($im5620 -and "$($im5620.Respawn)" -match 'respawned after \d+h1[67]m')

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

# ============================================================================
# v2.45: the general report embeds the correlation (leads section + focus embed)
# (rebuild the dossier first - the no-match probe above overwrote terms/detail json)
$null = Invoke-FocusEngine -Path $case -Indicator 'malware.exe'
New-Csv (Join-Path $csv 'flash_process_scored.csv') '"PID","Name","Path","Score","Verdict","Evidence","Flags","Signer"' @(
    '"4812","malware.exe","C:\Users\dev\AppData\Roaming\malware.exe","9","HIGH","runs-from-user-path; unsigned/no-company; public-conn:185.199.10.7:443; persistence:service(2)","USER-WRITABLE-PATH",""',
    '"500","svchost.exe","C:\Windows\System32\svchost.exe","0","LOW","","","Microsoft Corporation"'
)
New-Csv (Join-Path $csv 'entities_binaries.csv') '"Categories","CatCount","Name","Path","Verdict","Signer","FirstSeen","LastSeen","Hashes","Bytes","Evidence"' @(
    '"verdict;running;hash;conn;beacon;yara;svc-persist","7","malware.exe","C:\Users\dev\AppData\Roaming\malware.exe","HIGH","","2026-10-05 14:02:11","2026-10-05 14:21:00","AAAABBBB","","runs-from-user-path"'
)
$rd = ''
foreach ($n in @('ConvertTo-HtmlEsc', 'New-VtLink', 'Import-CaseCsv', 'Get-CompromiseVerdict', 'New-HtmlReport', 'Get-LvlRank', 'Split-TagList', 'Get-TacticLabel')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "report extract failed: $n" }
    $rd += $m.Value + "`r`n"
}
Invoke-Expression $rd
$RawDir = Join-Path $case 'raw'; $MemDir = Join-Path $case 'mem'; $CaseDir = $case
New-Item -ItemType Directory -Path $RawDir, $MemDir -Force | Out-Null
$Computer = 'FT'; $LogHours = 168; $script:LogStartDT = $null
$script:CurrentCaseID = 'C-40'; $script:CurrentAnalyst = 't'; $script:DeltaBaseline = $null
$IsAdmin = $true; $Sysmon = $true
$StartTime = Get-Date; $script:DeltaCount = 0; $script:ShareOk = $false
$script:EndpointAdmin = $true
function Test-IsAdmin { $true }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$script:Verdict = Get-CompromiseVerdict
$null = New-HtmlReport
$rep = Get-Content -LiteralPath (Join-Path $case 'report.html') -Raw
Check "report: leads section right after the verdict block" (($rep -match 'Triage leads - decide these first') -and ($rep.IndexOf('Triage leads') -lt $rep.IndexOf("name='coverage'")))
Check "report: HIGH process lead card with evidence + identity" (($rep -match 'malware\.exe \(PID 4812\)') -and ($rep -match 'correlation score 9') -and ($rep -match 'runs-from-user-path'))
Check "report: lead corroboration chips from entity categories" (($rep -match 'corroborated by 7 evidence categories') -and ($rep -match 'svc-persist') -and ($rep -match 'beacon'))
Check "report: lead links into the focus correlation story" ($rep -match "full correlation story \(instances, activity graph, everything it did\) in the Focus section")
Check "report: do-now block for the verdict rank" ($rep -match 'Do now:')
Check "report: signals clickable to their sections" ($rep -match 'click a signal to jump')
Check "report: focus embed renders the activity graph inline" ($rep -match 'Activity graph \(parents -> instances -> children -> what they did\)')
Check "report: focus embed renders per-instance sections" (($rep -match 'Instance PID 4812[^<]*everything it did') -and ($rep -match 'Files dropped \(1\)') -and ($rep -match 'payload\.dll') -and ($rep -match 'anti-forensics'))
Check "report: focus embed renders persistence + beacon + lineage + respawn" (($rep -match 'Persistence \(2\)') -and ($rep -match 'C2 beaconing \(1\)') -and ($rep -match 'Arrived via:') -and ($rep -match 'respawned after'))
Check "report: focus embed renders injection + pipe sections" (($rep -match 'Cross-process injection INTO this instance \(1\)') -and ($rep -match 'Remote threads created in other processes \(1\)') -and ($rep -match 'Named pipes \(1\)') -and ($rep -match 'msagent_f00d'))
Check "report: focus embed excludes the benign row" ($rep -notmatch 'benign\.txt')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case, $case2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
