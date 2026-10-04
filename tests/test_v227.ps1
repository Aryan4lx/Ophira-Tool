$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.27 - real-host pilot fixes: worker kit-root seed, deploy empty-CaseID, VSS copy retry helper,
# structured Sysmon EID1 + R1b renamed-LOLBin-at-rest rule + timeline weave
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'

# ============================================================================
# PART 1 - R1b (renamed LOLBin at rest) through the real hunt function
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_h227_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$Computer = 'TESTHOST'

($(
'"Time","Image","OriginalFileName","CommandLine","User"',
'"2026-10-04 11:27:39.910","C:\Users\Public\winupd.exe","Cmd.Exe","""C:\Users\Public\winupd.exe"" /c ""dir C:\ > C:\Users\Public\out.txt""","CORP\admin"',
'"2026-10-04 11:27:40.000","C:\Windows\System32\cmd.exe","Cmd.Exe","cmd.exe","CORP\admin"',
'"2026-10-04 11:27:41.000","C:\Users\Public\thing.exe","TotallyFine.App.exe","thing.exe","CORP\admin"',
'"2026-10-04 11:27:42.000","C:\Users\Public\winupd.exe","Cmd.Exe","again","CORP\admin"'
) | Set-Content -LiteralPath (Join-Path $CsvDir 'sysmon_proc_create.csv') -Encoding UTF8)

New-HuntFindings
$hf = @($saved['hunt_findings'])
$r1b = @($hf | Where-Object { $_.Rule -match 'Renamed LOLBin at rest' })
Check "R1b: winupd.exe (Cmd.Exe identity) = high finding" ($r1b.Count -eq 1 -and $r1b[0].Severity -eq 'high')
Check "R1b: evidence carries identity + cmdline" ($r1b[0].Evidence -match "embedded identity 'cmd'" -and $r1b[0].Evidence -match 'dir C:\\')
Check "R1b: ATT&CK tag T1036.003" ("$($r1b[0].Attck)" -match 'T1036\.003')
Check "R1b: legit cmd.exe NOT flagged" (@($hf | Where-Object { $_.Rule -match 'Renamed LOLBin at rest' -and $_.Entity -match 'System32' }).Count -eq 0)
Check "R1b: non-LOLBin original name NOT flagged" (@($hf | Where-Object { $_.Rule -match 'Renamed LOLBin at rest' -and $_.Entity -match 'thing\.exe' }).Count -eq 0)
Check "R1b: duplicate rows deduped to one finding" ($r1b.Count -eq 1)

# ============================================================================
# PART 2 - Copy-LockedFile failure path (retry + error detail logged)
# ============================================================================
$defs2 = ''
foreach ($n in @('Copy-LockedFile')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs2 += $m.Value + "`r`n"
}
Invoke-Expression $defs2
$log2 = New-Object System.Collections.Generic.List[string]
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') $script:log2.Add($Message) }
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$ok2 = Copy-LockedFile -Source (Join-Path $env:TEMP "no_such_file_$stamp.bin") -Dest (Join-Path $env:TEMP "out_$stamp.bin")
$sw.Stop()
# retry loop: Retries=2 -> 3 attempts incl. 3s+6s sleeps (esentutl fails fast on a missing source)
Check "Copy-LockedFile: missing source returns false" ($ok2 -eq $false)
Check "Copy-LockedFile: failure detail logged" (@($log2 | Where-Object { $_ -match 'locked-file copy failed' -and $_ -match 'no_such_file' }).Count -ge 1)
Check "Copy-LockedFile: retried (>=8s incl. backoff sleeps)" ($sw.Elapsed.TotalSeconds -ge 8)

# ============================================================================
# PART 3 - Get-KitRoot worker seed
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-KitRoot \{.*?\r?\n\}")
if (-not $m.Success) { throw 'extract failed: Get-KitRoot' }
Invoke-Expression $m.Value
$KitRoot = 'C:\fake\kit'
Check "Get-KitRoot: seeded override wins in workers" ((Get-KitRoot) -eq 'C:\fake\kit')
Remove-Variable KitRoot
# iex-defined functions have no $PSScriptRoot - the fallback is the caller's CWD
Check "Get-KitRoot: falls back to CWD without seed" ((Get-KitRoot) -eq (Get-Location).Path)

# ============================================================================
# PART 4 - wiring (worker preamble seed, deploy CaseID guard, module outputs)
# ============================================================================
Check "preamble: worker seed emits KitRoot" ($src -match 'KitRoot = \(Get-KitRoot\)')
Check "deploy: -CaseID only built when non-empty" ($src -match 'if \(\$caseID\) \{ \$cmd \+=')
Check "deploy: no unconditional empty -CaseID in remote command" ($src -notmatch [regex]::Escape('-OutputPath "$remoteDir\out" -CaseID'))
Check "module 4.3: structured EID1 saved as sysmon_proc_create" ($src -match [regex]::Escape("Save-Rows -Name 'sysmon_proc_create' -Rows"))
Check "evidence index: sysmon_proc_create documented" ($src -match "'sysmon_proc_create'\s+= 'Sysmon EID 1")
Check "supertimeline: EID1 woven with ORIGINAL NAME highlight" (($src -match [regex]::Escape("'sysmon_proc_create' 5000")) -and ($src -match 'ORIGINAL NAME:'))
Check "SRUM copy goes through Copy-LockedFile" ($src -match 'Copy-LockedFile -Source \$sru -Dest \$out')
Check "NTDS copy goes through Copy-LockedFile" ($src -match 'Copy-LockedFile -Source \$ntds')
Check "browser fallback copy goes through Copy-LockedFile" ($src -match 'ok = Copy-LockedFile -Source \$src')
Check "no raw esentutl /vss calls left outside the helper" (([regex]::Matches($src, 'esentutl\.exe /y /vss|/vss /d')).Count -eq 1)
Check "SharedFunctions: Copy-LockedFile whitelisted for workers" ($src -match "'Get-KitRoot', 'Get-ToolsDir', 'Copy-LockedFile'")
Check "verdict: huntHi regex still covers R1b rule name" ($src -match [regex]::Escape("-match 'Renamed LOLBin|side-load"))

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
