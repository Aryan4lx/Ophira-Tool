$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.21 - role presets (Get-HostRole, DC/WebServer role packs), Kerberos/DS + IIS modules,
# hunt rules R16-R21, session attribution, process lineage, Win7 parse-compat sweep
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
# PART 1 - Get-HostRole (shadow Test-Path/Get-Service, then restore)
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-HostRole\b.*?\r?\n\}")
if (-not $m.Success) { throw "extract failed: Get-HostRole" }
$script:fakePaths = @('HKLM:\SOFTWARE\Microsoft\InetStp')
function script:Test-Path { param($Path) $script:fakePaths -contains $Path }
function script:Get-Service { param([string]$Name) $null }
Invoke-Expression $m.Value
$script:HostRole = Get-HostRole
Check "role: IIS key present -> WebServer" ($script:HostRole -eq 'WebServer')
$script:fakePaths = @('HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
$script:HostRole = Get-HostRole
Check "role: NTDS key present -> DC" ($script:HostRole -eq 'DC')
$script:fakePaths = @()
$script:HostRole = Get-HostRole
Check "role: nothing present -> Workstation" ($script:HostRole -eq 'Workstation')
Remove-Item function:Test-Path, function:Get-Service -ErrorAction SilentlyContinue

# ============================================================================
# PART 2 - preset role packs
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-PresetSelection\b.*?\r?\n\}")
if (-not $m.Success) { throw "extract failed: Get-PresetSelection" }
Invoke-Expression $m.Value
$script:Modules = @(
    [pscustomobject]@{ Id = '1.1'; Default = $true; Quick = $true },
    [pscustomobject]@{ Id = '3.2'; Default = $true; Quick = $false },
    [pscustomobject]@{ Id = '4.9'; Default = $false; Quick = $false },
    [pscustomobject]@{ Id = '7.1'; Default = $false; Quick = $false },
    [pscustomobject]@{ Id = '8.12'; Default = $false; Quick = $false }
)
$IncludeMemory = $false
$script:HostRole = 'Workstation'
$sel = Get-PresetSelection -P 'Standard'
Check "preset: Standard on workstation - no role pack" (-not $sel['4.9'] -and -not $sel['8.12'] -and $sel['1.1'])
$script:HostRole = 'DC'
$sel = Get-PresetSelection -P 'Standard'
Check "preset: Standard on DC auto-enables 4.9" ($sel['4.9'] -and -not $sel['8.12'])
$script:HostRole = 'WebServer'
$sel = Get-PresetSelection -P 'Full'
Check "preset: Full on IIS box auto-enables 8.12, still excludes 7.1/3.2" ($sel['8.12'] -and -not $sel['7.1'] -and -not $sel['3.2'])
$script:HostRole = 'Workstation'
$sel = Get-PresetSelection -P 'DC'
Check "preset: explicit DC forces 4.9 regardless of detected role" ($sel['4.9'])
$sel = Get-PresetSelection -P 'WebServer'
Check "preset: explicit WebServer forces 8.12" ($sel['8.12'])
$script:HostRole = 'DC'
$sel = Get-PresetSelection -P 'Quick'
Check "preset: Quick never carries role pack" (-not $sel['4.9'] -and $sel['1.1'])

# ============================================================================
# PART 3 - hunt rules R16-R21 through the real function
# ============================================================================
$defs = ''
foreach ($n in @('Import-CaseCsv', 'Test-IsPublicIp', 'Test-IsUserWritablePath', 'New-HuntFindings')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case1 = Join-Path $env:TEMP "ophira_h221_$stamp"
$CsvDir = Join-Path $case1 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$Computer = 'DC01'

# R16: DCSync by user account (high); machine account and unrelated 4662 clean
New-Csv (Join-Path $CsvDir 'security_ds_access.csv') '"Time","EventId","Account","Object","OpType","Properties"' @(
    '"2026-09-28 09:00:00","4662","eviladmin","domain.local/Users/krbtgt","Object Access","{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {e3514235-4b06-11d1-ab04-00c04fc2dcd2}"',
    '"2026-09-28 09:01:00","4662","DC01$","domain.local/DC/dc01","Object Access","{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"',
    '"2026-09-28 09:02:00","4662","eviladmin","domain.local/OU/SomeOU","Object Access","{bf9679c0-0de6-11d0-a285-00aa003049e2}"'
)
# R17 (10+ RC4 SPNs from one IP) + R18 (pre-auth 0) + R19 spray (4771 accounts a1-a8 + 4625 a9/a10 cross-source)
$kerLines = @()
foreach ($i in 1..12) { $kerLines += ('"2026-09-28 10:00:{0:D2}","4769","svcuser","svc{0}.domain.local","9.9.9.9","0x17","0x0","-","-"' -f $i) }
foreach ($i in 1..3) { $kerLines += ('"2026-09-28 10:05:{0:D2}","4769","svcuser","few{0}.domain.local","9.9.9.9","0x17","0x0","-","-"' -f $i) }
$kerLines += '"2026-09-28 11:00:00","4768","roastme","krbtgt","10.0.0.99","-","0x0","0","-"'
foreach ($i in 1..8) { $kerLines += ('"2026-09-28 12:00:{0:D2}","4771","spray{0}","krbtgt","7.7.7.7","-","0x18","-","-"' -f $i) }
$kerLines += '"2026-09-28 12:00:10","4769","normaluser","cifs/fileserver","10.0.0.5","0x12","0x0","-","-"'
New-Csv (Join-Path $CsvDir 'security_kerberos.csv') '"Time","EventId","Account","Service","IpAddress","TicketEnc","Status","PreAuth","Workstation"' $kerLines
New-Csv (Join-Path $CsvDir 'security_auth_events.csv') '"Time","EventId","Account","SourceIp","LogonType","LogonId"' @(
    '"2026-09-28 12:00:20","4625","spray9","7.7.7.7","3",""',
    '"2026-09-28 12:00:21","4625","spray10","7.7.7.7","3",""'
)
# R20: w3wp spawned cmd (high); w3wp spawned explorer NOT in kid list = clean
New-Csv (Join-Path $CsvDir 'security_proc_events.csv') '"Time","EventId","Account","LogonId","NewProcess","CommandLine","ParentProcess"' @(
    '"2026-09-28 13:00:00","4688","iis_app","0x9999","C:\Windows\System32\cmd.exe","cmd.exe /c whoami","C:\Windows\System32\inetsrv\w3wp.exe"'
)
# R21: suspicious-uri fires; server-errors stays report-data only
New-Csv (Join-Path $CsvDir 'iis_anomalies.csv') '"Kind","Detail","Sample"' @(
    '"suspicious-uri","/cmd.aspx (status 200)","query=cmd=whoami ip=9.9.9.9 ua=java"',
    '"server-errors","50 x HTTP 500 from 10.1.1.1","/a | /b | /c"'
)

New-HuntFindings

$hf = @($saved['hunt_findings'])
Check "R16: DCSync by eviladmin = high" (@($hf | Where-Object { $_.Rule -match 'DCSync' -and $_.Entity -eq 'eviladmin' -and $_.Severity -eq 'high' }).Count -eq 1)
Check "R16: machine account DC01`$ NOT flagged" (@($hf | Where-Object { $_.Rule -match 'DCSync' -and "$($_.Entity)" -match '\$$' }).Count -eq 0)
Check "R16: unrelated 4662 GUID NOT flagged" (@($hf | Where-Object { $_.Rule -match 'DCSync' -and $_.Evidence -match 'SomeOU' }).Count -eq 0)
Check "R17: Kerberoasting burst from 9.9.9.9 = medium" (@($hf | Where-Object { $_.Rule -match 'Kerberoasting' -and $_.Entity -eq '9.9.9.9' -and $_.Severity -eq 'medium' }).Count -eq 1)
Check "R18: AS-REP no-preauth = medium" (@($hf | Where-Object { $_.Rule -match 'AS-REP' -and $_.Entity -eq 'roastme' }).Count -eq 1)
Check "R19: spray across 4771+4625 = high" (@($hf | Where-Object { $_.Rule -match 'Password spray' -and $_.Entity -eq '7.7.7.7' -and $_.Evidence -match 'across 10 accounts' }).Count -eq 1)
Check "R19: normal RC4 AES TGS NOT flagged" (@($hf | Where-Object { $_.Rule -match 'Kerberoasting' -and $_.Evidence -match '0x12' }).Count -eq 0)
Check "R20: w3wp -> cmd = high" (@($hf | Where-Object { $_.Rule -match 'Web server spawned interpreter' -and $_.Entity -match 'w3wp\.exe -> cmd\.exe' }).Count -eq 1)
Check "R21: suspicious-uri anomaly = medium, server-errors NOT" (@($hf | Where-Object { $_.Rule -match 'Web traffic anomaly' -and $_.Evidence -match 'cmd\.aspx' }).Count -eq 1 -and @($hf | Where-Object { $_.Evidence -match 'HTTP 500' }).Count -eq 0)

# ============================================================================
# PART 4 - session attribution + process lineage through the real functions
# ============================================================================
$defs = ''
foreach ($n in @('New-SessionAttribution', 'New-ProcessChains')) {
    $m = [regex]::Match($src, "(?s)function $n\b.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$case2 = Join-Path $env:TEMP "ophira_s221_$stamp"
$CsvDir = Join-Path $case2 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
New-Csv (Join-Path $CsvDir 'security_auth_events.csv') '"Time","EventId","Account","SourceIp","LogonType","LogonId"' @(
    '"2026-09-28 08:00:00","4624","janedoe","10.1.1.5","10","0x1234"',
    '"2026-09-28 08:05:00","4624","janedoe","10.1.1.5","2","0x5678"'
)
New-Csv (Join-Path $CsvDir 'security_proc_events.csv') '"Time","EventId","Account","LogonId","NewProcess","CommandLine","ParentProcess"' @(
    '"2026-09-28 08:06:00","4688","janedoe","0x1234","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","powershell.exe -enc AAAA","C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"',
    '"2026-09-28 08:05:30","4688","janedoe","0x1234","C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE","winword.exe /n doc.rtf","C:\Windows\explorer.exe"'
)
New-Csv (Join-Path $CsvDir 'security_share_access.csv') '"Time","EventId","Account","LogonId","ShareName","RelativeTargetName","SourceIp","AccessList"' @(
    '"2026-09-28 08:07:00","5145","janedoe","0x1234","\\*\ADMIN$","stage.dll","-","%%4415"'
)
New-SessionAttribution
$sa = @($saved['session_activity'])
Check "attribution: 3 activity rows joined to session 0x1234 (2 proc + 1 share)" ($sa.Count -eq 3)
Check "attribution: session account + source IP carried" (@($sa | Where-Object { $_.SessionAccount -eq 'janedoe' -and $_.SourceIp -eq '10.1.1.5' }).Count -eq 3)
Check "attribution: share row falls back to session IP" (@($sa | Where-Object { $_.Activity -eq 'share' -and "$($_.Detail)" -match 'ADMIN\$ -> stage\.dll' }).Count -eq 1)

New-Csv (Join-Path $CsvDir 'processes.csv') '"Name","Path","PID","PPID"' @(
    '"beacon.exe","C:\Users\public\beacon.exe","99","88"',
    '"cmd.exe","C:\Windows\System32\cmd.exe","88","4"'
)
New-Csv (Join-Path $CsvDir 'flash_process_scored.csv') '"Name","Path","PID","Verdict","Score","Evidence","Signer"' @(
    '"beacon.exe","C:\Users\public\beacon.exe","99","HIGH","9","c2",""',
    '"powershell.exe","C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","1234","HIGH","7","enc",""',
    '"notepad.exe","C:\Windows\System32\notepad.exe","500","LOW","0","",""'
)
New-Csv (Join-Path $CsvDir 'hunt_findings.csv') '"Found","Rule","Severity","Entity","Attck","Evidence"' @(
    '"2026-09-28T08:07:00Z","Downloaded then executed","high","C:\Users\public\beacon.exe","T1105","x"'
)
New-ProcessChains
$pc = @($saved['process_chains'])
$beaconChain = @($pc | Where-Object { "$($_.Entity)" -match 'beacon\.exe' })
$psChain = @($pc | Where-Object { "$($_.Entity)" -match 'powershell\.exe' })
Check "lineage: beacon.exe chain via live PPID (cmd.exe -> beacon.exe)" ($beaconChain.Count -eq 1 -and "$($beaconChain[0].Chain)" -match 'cmd\.exe -> beacon\.exe')
Check "lineage: powershell chain via 4688 (explorer -> winword -> powershell)" ($psChain.Count -eq 1 -and "$($psChain[0].Chain)" -match 'explorer\.exe -> winword\.exe -> powershell\.exe')
Check "lineage: LOW-verdict notepad not chained" (@($pc | Where-Object { "$($_.Entity)" -match 'notepad' }).Count -eq 0)

# ============================================================================
# PART 5 - IIS W3C parser on a fixture
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-IisW3cRows\b.*?\r?\n\}")
if (-not $m.Success) { throw "extract failed: Get-IisW3cRows" }
Invoke-Expression $m.Value
$logDir = Join-Path $env:TEMP "ophira_iis_$stamp"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
@('#Software: IIS', '#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)',
  '2026-09-28 13:00:00 9.9.9.9 GET /index.html - 200 Mozilla/5.0',
  '2026-09-28 13:00:01 9.9.9.9 POST /cmd.aspx cmd=whoami 200 java/1.8') | Set-Content -LiteralPath (Join-Path $logDir 'u_ex.log') -Encoding ASCII
$rows = Get-IisW3cRows -Path $logDir
Check "iis: 2 W3C rows parsed" ($rows.Count -eq 2)
Check "iis: fields mapped (POST /cmd.aspx status 200)" ("$($rows[1].'cs-method')" -eq 'POST' -and "$($rows[1].'cs-uri-stem')" -eq '/cmd.aspx' -and "$($rows[1].'sc-status')" -eq '200')
$capRows = @(Get-IisW3cRows -Path $logDir -Cap 1)
Check "iis: cap respected" ($capRows.Count -eq 1)
Remove-Item -LiteralPath $logDir -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================================
# PART 6 - structural wiring + parse-compat guarantees
# ============================================================================
Check "compat: no PS3+ operators or PS5 ::new in source" ($src -notmatch ' -in @' -and $src -notmatch ' -notin ' -and $src -notmatch '::new\(')
Check "whitelist: Get-IisW3cRows in SharedFunctions" ($src -match "'Get-IisW3cRows'")
Check "regen: hunt runs BEFORE entity correlation (hunt category fresh in one pass)" ([regex]::Match($src, "try \{ New-HuntFindings \}[\s\S]*?try \{ New-EntityCorrelation \}").Success)
Check "regen: session attribution + lineage called" ($src -match 'New-SessionAttribution' -and $src -match 'New-ProcessChains')
Check "case.json records Role" ($src -match 'Role = \$script:HostRole')
Check "fleet: Role column in fleet_hosts" ($src -match 'Select-Object Host, Verdict, VerdictRank, Confidence, Role,')
Check "verdict: huntHi regex covers DCSync/spray/webshell" ($src -match 'DCSync\|Password spray\|Web server spawned')
Check "modules: 4.9 saves kerberos + ds CSVs" ($src -match "Save-Rows -Name 'security_kerberos'" -and $src -match "Save-Rows -Name 'security_ds_access'")
Check "modules: 8.12 saves iis_requests + iis_anomalies" ($src -match "Save-Rows -Name 'iis_requests'" -and $src -match "Save-Rows -Name 'iis_anomalies'")

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
foreach ($d in @($case1, $case2)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
if ($fail -gt 0) { exit 1 } else { exit 0 }
