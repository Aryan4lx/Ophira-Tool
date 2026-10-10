$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.48 - R2 injection/pipe pack: Sysmon EID 8/17/18 parses (sysmon_remote_thread/sysmon_pipes),
# hunt rules R28 (cross-process injection) + R29 (C2-style named pipe), focus engine
# INJECT/THREAD/PIPE joins + chips + cross-instance edges, timeline weave, coverage,
# canary pipe plant, sysmon config blocks.
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
# PART 1 - static wiring
# ============================================================================
Check "collect: EID id list includes 17/18" ($src -match [regex]::Escape('$ids = @(1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17, 18, 20, 21, 22, 23, 25)'))
Check "collect: EID 8 parse saved as sysmon_remote_thread" (($src -match [regex]::Escape("Save-Rows -Name 'sysmon_remote_thread' -Rows")) -and ($src -match [regex]::Escape("SourceProcessGuid = 'SourceProcessGuid'; TargetProcessGuid = 'TargetProcessGuid'")))
Check "collect: EID 17/18 parse saved as sysmon_pipes" (($src -match [regex]::Escape('-Id @(17, 18)')) -and ($src -match [regex]::Escape("Save-Rows -Name 'sysmon_pipes' -Rows")))
Check "sortment: both new CSVs mapped to logs" (($src -match [regex]::Escape("'sysmon_remote_thread' = 'logs'")) -and ($src -match [regex]::Escape("'sysmon_pipes' = 'logs'")))
Check "evidence index: entries for both new CSVs" (($src -match [regex]::Escape("'sysmon_remote_thread'            =")) -and ($src -match [regex]::Escape("'sysmon_pipes'                    =")))
Check "weave: remote thread + pipe rows in the master timeline" (($src -match [regex]::Escape("weave 'sysmon_remote_thread'")) -and ($src -match [regex]::Escape("weave 'sysmon_pipes'")))
Check "coverage: injection/pipe telemetry row" ($src -match "Add-Cov 'Injection/pipe telemetry \(Sysmon 8/17/18\)'")
Check "verdict: high-rule regex includes R28/R29" (($src -match 'Cross-process injection\|C2-style named pipe') -and ($src -match 'svchost masquerade / injection / C2 pipe'))
Check "config gap: hint covers EID 8/17/18" (($src -match 'remote-thread \(EID 8\) / named-pipe \(EID 17/18\)') -and ($src -match [regex]::Escape("(Import-CaseCsv 'sysmon_pipes').Count -eq 0")))
$xmlRaw = Get-Content (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\sysmon\ophira-sysmon.xml') -Raw
Check "sysmon xml: CreateRemoteThread + PipeEvent blocks" (($xmlRaw -match '<CreateRemoteThread onmatch="exclude">') -and ($xmlRaw -match '<PipeEvent onmatch="exclude">'))
Check "sysmon xml: config header bumped to v2.48" ($xmlRaw -match 'configuration \(v2\.48\)')

# focus engine
Check "focus: column-specific guid filter for EID 8 joins" (($src -match [regex]::Escape('$guidFilterCol = {')) -and ($src -match [regex]::Escape("& `$guidFilterCol 'sysmon_remote_thread' 'TargetProcessGuid' `$gl")))
Check "focus: CrtIn/CrtOut/Pipes in the per-instance detail" ((($src -match [regex]::Escape("CrtIn = @(& `$guidFilterCol 'sysmon_remote_thread' 'TargetProcessGuid' `$gl)"))) -and ($src -match [regex]::Escape("CrtOut = @(& `$guidFilterCol 'sysmon_remote_thread' 'SourceProcessGuid' `$gl)")) -and ($src -match [regex]::Escape("Pipes = @(& `$guidFilter 'sysmon_pipes' `$gl `$pl)")))
Check "focus: INJECT/THREAD/PIPE graph chips" (($src.Contains('"INJECT<- $(')) -and ($src.Contains('"THREAD-> $(')) -and ($src.Contains('"PIPE $(')))
Check "focus: INJECT chips + injection edges render red" (($src -match [regex]::Escape("if (`$chip -match '^INJECT') { `$chipStroke = '#a33' }")) -and ($src -match [regex]::Escape("`$edges.Add(@{ F = `$srcInst; T = `$tn; Stroke = '#a33' })")))
Check "focus: dossier sections for injection in/out + pipes" ((($src -match 'Cross-process injection INTO this instance')) -and ($src -match 'Remote threads this instance created in OTHER processes') -and ($src -match 'Named pipes created/connected'))
Check "focus: detail json persists CrtIn/CrtOut/Pipes" ((($src -match [regex]::Escape('CrtIn = @($_.CrtIn | Select-Object -First 25)'))) -and ($src -match [regex]::Escape('CrtOut = @($_.CrtOut | Select-Object -First 25)')) -and ($src -match [regex]::Escape('Pipes = @($_.Pipes | Select-Object -First 25)')))
Check "report: embed sections include injection + pipes" (($src -match [regex]::Escape("@('Cross-process injection INTO this instance', 'CrtIn'")) -and ($src -match [regex]::Escape("@('Named pipes', 'Pipes'")))
Check "dossier: secMap routes the new sources to Process events" ($src -match [regex]::Escape('sysmon_events|sysmon_remote_thread|sysmon_pipes)'))

# canary
Check "canary: pipe plant (canary_msagent_f00d created + connected)" (($src -match "NamedPipeServerStream\('canary_msagent_f00d'") -and ($src -match "NamedPipeClientStream\('\.', 'canary_msagent_f00d'"))
Check "canary: scorecard R29 row reads hunt findings + pipe rows" (($src -match [regex]::Escape("'R29  C2-style named pipe (canary_msagent_f00d)'")) -and ($src -match [regex]::Escape("`$pipeRows | Where-Object { `"`$_`" -match 'canary_msagent' }")))
Check "canary: R28 printed n/a (real remote thread too invasive)" ($src -match [regex]::Escape('R28  cross-process injection  n/a'))
Check "canary: consent text mentions the pipe plant" ($src -match 'a self-labeled named pipe \(canary_msagent_f00d, created \+ closed\)')

# ============================================================================
# PART 2 - R28/R29 through the real New-HuntFindings
# ============================================================================
$mhf = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
$muwp = [regex]::Match($src, "(?s)function Test-IsUserWritablePath \{.*?\r?\n\}")
if (-not $mhf.Success -or -not $muwp.Success) { throw 'extract failed: New-HuntFindings/Test-IsUserWritablePath' }
$caseCsv = @{
    'sysmon_remote_thread' = @(
        [pscustomobject]@{ Time = '2026-10-05 14:03:00.000'; EventId = 8; SourceImage = 'C:\Users\dev\AppData\Roaming\malware.exe'; TargetImage = 'C:\Windows\explorer.exe'; SourceProcessGuid = '{aaaa}'; TargetProcessGuid = '{bbbb}'; NewThreadId = '3110'; StartModule = ''; StartFunction = 'LoadLibraryA'; User = 'DEV\dev' },
        [pscustomobject]@{ Time = '2026-10-05 14:03:05.000'; EventId = 8; SourceImage = 'C:\Users\dev\AppData\Roaming\malware.exe'; TargetImage = 'C:\Windows\explorer.exe'; SourceProcessGuid = '{aaaa}'; TargetProcessGuid = '{bbbb}'; NewThreadId = '3112'; StartModule = ''; StartFunction = 'LoadLibraryA'; User = 'DEV\dev' },
        [pscustomobject]@{ Time = '2026-10-05 14:04:00.000'; EventId = 8; SourceImage = 'C:\Users\Public\dumper.exe'; TargetImage = 'C:\Windows\system32\lsass.exe'; SourceProcessGuid = '{cccc}'; TargetProcessGuid = '{dddd}'; NewThreadId = '3220'; StartModule = 'C:\Windows\syswow64\kernel32.dll'; StartFunction = ''; User = 'DEV\dev' },
        [pscustomobject]@{ Time = '2026-10-05 14:05:00.000'; EventId = 8; SourceImage = 'C:\Windows\System32\svchost.exe'; TargetImage = 'C:\Windows\System32\svchost.exe'; SourceProcessGuid = '{eeee}'; TargetProcessGuid = '{eeee}'; NewThreadId = '3300'; StartModule = ''; StartFunction = ''; User = 'LOCAL SYSTEM' }
    )
    'sysmon_pipes' = @(
        [pscustomobject]@{ Time = '2026-10-05 14:06:00.000'; EventId = 17; Image = 'C:\Users\Public\payload.exe'; PipeName = '\msagent_f00d'; EventType = 'CreatePipe'; User = 'DEV\dev'; ProcessId = '4242'; ProcessGuid = '{ffff}' },
        [pscustomobject]@{ Time = '2026-10-05 14:06:10.000'; EventId = 18; Image = 'C:\Windows\System32\rundll32.exe'; PipeName = '\pipy_ab12'; EventType = 'ConnectPipe'; User = 'DEV\dev'; ProcessId = '4300'; ProcessGuid = '{1234}' },
        [pscustomobject]@{ Time = '2026-10-05 14:07:00.000'; EventId = 17; Image = 'C:\Users\dev\app\legittool.exe'; PipeName = '\mytool_ipc'; EventType = 'CreatePipe'; User = 'DEV\dev'; ProcessId = '4400'; ProcessGuid = '{5678}' },
        [pscustomobject]@{ Time = '2026-10-05 14:08:00.000'; EventId = 17; Image = 'C:\Windows\System32\svchost.exe'; PipeName = '\silent_backup_channel'; EventType = 'CreatePipe'; User = 'LOCAL SYSTEM'; ProcessId = '900'; ProcessGuid = '{9abc}' }
    )
}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
$savedHF = @()
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:savedHF = @($Rows) } }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
Invoke-Expression ($muwp.Value + "`r`n" + $mhf.Value)
New-HuntFindings
$hf = $script:savedHF

$r28 = @($hf | Where-Object { $_.Rule -eq 'Cross-process injection (remote thread)' })
Check "R28: high - malware injected into explorer" (@($r28 | Where-Object { "$($_.Entity)" -match 'malware\.exe -> C:\\Windows\\explorer\.exe$' -and $_.Severity -eq 'high' }).Count -eq 1)
Check "R28: dedup per source->target pair (repeat row not re-reported)" (@($r28 | Where-Object { "$($_.Entity)" -match 'malware\.exe -> C:\\Windows\\explorer\.exe$' }).Count -eq 1)
Check "R28: lsass target named as credential-dump tell" (@($r28 | Where-Object { "$($_.Entity)" -match 'dumper\.exe -> C:\\Windows\\system32\\lsass\.exe$' -and "$($_.Evidence)" -match 'credential-dump tell' }).Count -eq 1)
Check "R28: self-injection (same image) skipped" (@($r28 | Where-Object { "$($_.Entity)" -match 'svchost' }).Count -eq 0)
Check "R28: T1055 tag" (@($r28 | Where-Object { "$($_.Attck)" -eq 'T1055' }).Count -eq 2)
Check "R28: start function in evidence" (@($r28 | Where-Object { "$($_.Evidence)" -match 'LoadLibraryA' }).Count -eq 1)

$r29hi = @($hf | Where-Object { $_.Rule -eq 'C2-style named pipe (known C2 family)' })
Check "R29: high - msagent family pipe created" (@($r29hi | Where-Object { "$($_.Entity)" -eq '\msagent_f00d' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'payload\.exe' }).Count -eq 1)
Check "R29: high - pipy family pipe connected" (@($r29hi | Where-Object { "$($_.Entity)" -eq '\pipy_ab12' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'rundll32\.exe' }).Count -eq 1)
Check "R29: high - created/connected verbs correct" ((@($r29hi | Where-Object { "$($_.Evidence)" -match 'created by' }).Count -eq 1) -and (@($r29hi | Where-Object { "$($_.Evidence)" -match 'connected by' }).Count -eq 1))
Check "R29: high dedup per pipe name" ($r29hi.Count -eq 2)
Check "R29: T1095 tag" (@($r29hi | Where-Object { "$($_.Attck)" -eq 'T1095' }).Count -eq 2)
$r29med = @($hf | Where-Object { $_.Rule -eq 'Named pipe created from user-writable path' })
Check "R29: medium - pipe from user-writable image" (@($r29med | Where-Object { "$($_.Entity)" -eq '\mytool_ipc' -and "$($_.Evidence)" -match 'legittool\.exe' }).Count -eq 1)
Check "R29: silent - system-path non-family pipe not flagged" (@($hf | Where-Object { "$($_.Entity)" -eq '\silent_backup_channel' }).Count -eq 0)

# ============================================================================
# PART 3 - run report-level wiring through the real New-HtmlReport consumers is
# covered by test_focus; here: sigma-free verdict regex + evidence index text
# ============================================================================
Check "evidence index: remote-thread rows describe the injection story" ($src -match [regex]::Escape('who injected into whom'))
Check "evidence index: pipes described as C2 channel evidence" ($src -match [regex]::Escape('C2-style pipe channels'))

Write-Host ""
Write-Host "test_v248: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
