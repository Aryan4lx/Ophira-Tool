<#
Ophira v2.37  -  Windows Incident Response Triage Toolkit
READ-ONLY by design: never modifies the system, only reads and copies data
into its own output folder. Intended to be handed to a system owner or run
by a responder during early triage / threat hunting.
#>

[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Deploy', 'Analyze', 'Setup', 'Links', 'UpdateRules', 'Tune', 'Parse', 'Process', 'Timeline', 'Canary')]
    [string]$Mode = 'Collect',
    [string]$CaseID = "",
    [string]$Analyst = "",
    [string]$OutputPath = "",
    [ValidateSet('Flash', 'Quick', 'Standard', 'Full', 'Custom', 'DC', 'WebServer')]
    [string]$Preset = 'Standard',
    [switch]$NoMenu,
    [switch]$SimpleUI,
    [switch]$IncludeMemory,
    [switch]$PushTools,
    [switch]$Sequential,
    [switch]$NoElevate,
    [int]$LogHours = 168,
    [string]$LogWindow = '',
    [string]$LogStart = '',
    [string]$LogEnd = '',
    [string]$SharePath = "",
    [string[]]$ComputerName,
    [string]$TargetsFile = '',
    [int]$MaxThreads = 8,
    [string]$AnalyzePath = '.',
    [string]$ParsePath = '',
    [string]$ProcessName = '',
    [string]$TimelineStart = '',
    [string]$TimelineEnd = '',
    [string]$HayabusaPath = '',
    [string]$CanaryTarget = '',
    [string]$CanaryTargetUser = '',
    [switch]$KeepLogging,
    [string]$DeltaPath = '',
    [string[]]$SetupTools,
    [System.Management.Automation.PSCredential]$Credential
)

$ScriptVersion = "2.37"
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " Ophira needs PowerShell 5.0 or newer - this host runs" -ForegroundColor Red
    Write-Host " PowerShell v$($PSVersionTable.PSVersion). Collection here is not possible." -ForegroundColor Red
    Write-Host " What works instead:" -ForegroundColor White
    Write-Host "  - Run Ophira on a PC with PowerShell 5.1 and use menu option 2" -ForegroundColor Gray
    Write-Host "    (Push & run on REMOTE PCs) - it reaches this host over WinRM" -ForegroundColor Gray
    Write-Host "  - Or collect manually: evtx logs, registry hives, Prefetch folder" -ForegroundColor Gray
    Write-Host "  - Or have the security team install WMF 5.1 on this host first" -ForegroundColor Gray
    Write-Host "================================================================" -ForegroundColor Red
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    exit 1
}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostRole {
    # v2.21 lightweight role fingerprint: DC (NTDS present), WebServer (IIS installed), else Workstation.
    try {
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters') { return 'DC' }
    } catch { }
    try {
        if ((Test-Path 'HKLM:\SOFTWARE\Microsoft\InetStp') -or (Get-Service W3SVC -ErrorAction SilentlyContinue)) { return 'WebServer' }
    } catch { }
    return 'Workstation'
}
$script:HostRole = Get-HostRole

function Get-ArgString {
    $parts = @()
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $parts += "-$k" } }
        elseif ($v -is [bool]) { $parts += "-$k`:$v" }
        elseif ($v -is [int]) { $parts += "-$k $v" }
        else { $parts += "-$k `"$v`"" }
    }
    if ($script:ExtraRelaunchArgs.Count -gt 0) { $parts += $script:ExtraRelaunchArgs }
    $parts -join ' '
}

function Get-KitRoot {
    if ($KitRoot) { return $KitRoot }
    if ($PSScriptRoot) { return $PSScriptRoot }
    return (Get-Location).Path
}

$cfgFile = Join-Path (Get-KitRoot) 'ophira.config.txt'
$script:OphiraRole = ''
$script:CfgTargets = ''
$script:CfgDeployPreset = ''
$script:CfgPushTools = $false
$script:CfgDeployShare = ''
$script:CfgThreads = 0
$script:ExtraRelaunchArgs = @()
if (Test-Path -LiteralPath $cfgFile) {
    try {
        foreach ($line in (Get-Content -LiteralPath $cfgFile)) {
            $l = ($line -replace '#.*$', '').Trim()
            if ($l -match '^(SHARE|CASE|ANALYST|ROLE|TARGETS|PRESET|PUSHTOOLS|DEPLOYSHARE|THREADS)\s*=\s*(.+)$') {
                $val = $Matches[2].Trim()
                switch ($Matches[1]) {
                    'SHARE' { if (-not $PSBoundParameters.ContainsKey('SharePath') -and $val) { $SharePath = $val } }
                    'CASE' { if (-not $PSBoundParameters.ContainsKey('CaseID') -and $val) { $CaseID = $val } }
                    'ANALYST' { if (-not $PSBoundParameters.ContainsKey('Analyst') -and $val) { $Analyst = $val } }
                    'ROLE' { if ($val -match '^(?i)(responder|owner)$') { $script:OphiraRole = $val.ToLower() } }
                    'TARGETS' { $script:CfgTargets = $val }
                    'PRESET' { if ($val -match '^(?i)(quick|standard)$') { $script:CfgDeployPreset = (Get-Culture).TextInfo.ToTitleCase($val.ToLower()) } }
                    'PUSHTOOLS' { $script:CfgPushTools = ($val -match '^(?i)(1|y|yes|true|t)$') }
                    'DEPLOYSHARE' { $script:CfgDeployShare = $val }
                    'THREADS' { $n = 0; if ([int]::TryParse($val, [ref]$n) -and $n -gt 0) { $script:CfgThreads = $n } }
                }
            }
        }
    } catch { }
}

function Save-OphiraConfig {
    param([hashtable]$Values)
    try {
        $path = Join-Path (Get-KitRoot) 'ophira.config.txt'
        $lines = @()
        if (Test-Path -LiteralPath $path) { $lines = @(Get-Content -LiteralPath $path) }
        foreach ($key in $Values.Keys) {
            $pattern = "^\s*$key\s*="
            $found = $false
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match $pattern) { $lines[$i] = "$key=$($Values[$key])"; $found = $true }
            }
            if (-not $found) { $lines += "$key=$($Values[$key])" }
        }
        Set-Content -LiteralPath $path -Value $lines -Encoding UTF8
        return $true
    } catch { return $false }
}
$script:SimpleUI = [bool]$SimpleUI

function Write-CaseLog {
    param([string]$Message, [string]$Color = 'Gray', [switch]$NoConsole)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    if (-not $NoConsole -and -not $script:SimpleUI) { Write-Host $line -ForegroundColor $Color }
    Add-Content -LiteralPath $CaseLog -Value $line -Encoding UTF8
}

function Out-Flash {
    param([string]$Text, [string]$Color = 'White')
    if (-not $script:SimpleUI) { Write-Host $Text -ForegroundColor $Color }
    $script:FlashLines.Add(($Text -replace "\x1b\[[0-9;]*m", ''))
}

function Save-Rows {
    param([string]$Name, $Rows)
    $path = Join-Path $CsvDir "$Name.csv"
    try {
        if ($Rows -and @($Rows).Count -gt 0) {
            @($Rows) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
            Write-CaseLog ("    saved {0} rows -> csv\{1}.csv" -f @($Rows).Count, $Name) 'DarkGray'
        } else {
            "# no entries" | Set-Content -LiteralPath $path -Encoding UTF8
            Write-CaseLog "    csv\$Name.csv (empty)" 'DarkGray'
        }
    } catch {
        "FAILED: $($_.Exception.Message)" | Set-Content -LiteralPath $path -Encoding UTF8
        Write-CaseLog "    csv\$Name.csv FAILED" 'DarkYellow'
    }
}

function Out-RawText {
    param([string]$SubDir, [string]$Name, [string[]]$Text)
    try {
        $dir = Join-Path $RawDir $SubDir
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $path = Join-Path $dir $Name
        if ($Text) { $Text | Set-Content -LiteralPath $path -Encoding UTF8 } else { "# empty" | Set-Content -LiteralPath $path -Encoding UTF8 }
    } catch { }
}

function Invoke-ExeCapture {
    param([string]$SubDir, [string]$Name, [string]$Exe, [string]$Arguments)
    try {
        $out = if ($Arguments) { & $Exe $Arguments 2>&1 } else { & $Exe 2>&1 }
        Out-RawText -SubDir $SubDir -Name $Name -Text (@($out) | ForEach-Object { "$_" })
    } catch { }
}

function Get-WmiOrCim {
    param([string]$Class, [string]$Filter = '', [string]$Namespace = '')
    try {
        $extra = @{}
        if ($Namespace) { $extra.Namespace = $Namespace }
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) { return Get-CimInstance -ClassName $Class -Filter $Filter @extra }
            return Get-CimInstance -ClassName $Class @extra
        } else {
            if ($Filter) { return Get-WmiObject -Class $Class -Filter $Filter @extra }
            return Get-WmiObject -Class $Class @extra
        }
    } catch { return $null }
}

function Convert-WmiDate {
    param($Value)
    if (-not $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    try { return [System.Management.ManagementDateTimeConverter]::ToDateTime("$Value") } catch { return $null }
}

function Test-IsPublicIp {
    param([string]$IpString)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IpString, [ref]$ip)) { return $false }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq 'InterNetworkV6') {
    if ($b[0] -eq 0 -and $b[1] -eq 0) { return $false }
    if ((($b[0] -band 0xFE) -eq 0xFC)) { return $false }
    if ($b[0] -eq 0xFE -and (($b[1] -band 0xC0) -eq 0x80)) { return $false }
    if ($b[0] -eq 0xFF) { return $false }
    return $true
    }
    if ($b[0] -eq 0) { return $false }
    if ($b[0] -eq 10 -or $b[0] -eq 127) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 172 -and $b[1] -eq 31) { return $false }
    if ($b[0] -ge 224) { return $false }
    return $true
}

function Test-IsUserWritablePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($Path -match '(?i)\\Users\\|\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\|\\AppData\\|\\Users\\Public\\|\\PerfLogs\\|\\Intel\\|\\AMD\\|\\Windows\\Tasks\\|\\Downloads\\|\\Desktop\\|\\Temporary Internet')
}

function Get-SignatureInfo {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        $signer = ''
        if ($sig.SignerCertificate) { $signer = ($sig.SignerCertificate.Subject -replace ',.*$', '') -replace '^CN=', '' }
        return [pscustomobject]@{ Status = "$($sig.Status)"; Signer = $signer }
    } catch { return $null }
}

function Get-ProcessInventory {
    $wmi = Get-WmiOrCim -Class Win32_Process
    if (-not $wmi) { return @() }
    $meta = @{}
    try {
        Get-Process | ForEach-Object {
            $c = ''; $d = ''
            try { $c = $_.Company; $d = $_.Description } catch { }
            $meta[[int]$_.Id] = @{ Company = $c; Desc = $d }
        }
    } catch { }
    $fileMeta = @{}

    $rows = foreach ($p in $wmi) {
        $m = $meta[[int]$p.ProcessId]
        $flags = New-Object System.Collections.Generic.List[string]
        $path = $p.ExecutablePath
        $company = ''; $desc = ''
        if ($path) {
            if ($m -and $m.Company) { $company = $m.Company; $desc = $m.Desc }
            elseif (Test-Path -LiteralPath $path) {
                if (-not $fileMeta.ContainsKey($path)) {
                    try {
                        $vi = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
                        $fileMeta[$path] = @{ Company = $vi.CompanyName; Desc = $vi.FileDescription }
                    } catch { $fileMeta[$path] = @{ Company = ''; Desc = '' } }
                }
                $company = $fileMeta[$path].Company
                $desc = $fileMeta[$path].Desc
                if (-not $company) { $flags.Add('NO-COMPANY') }
            } else { $flags.Add('BINARY-MISSING') }
        }
        if (Test-IsUserWritablePath $path) { $flags.Add('USER-WRITABLE-PATH') }
        if ($p.Name -match '(?i)^svchost\.exe$' -and $path -and $path -notmatch '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\') { $flags.Add('SVCHOST-OUT-OF-SYSTEM32') }
        if ($p.Name -match '(?i)^(lsass|csrss|services|winlogon|smss)\.exe$' -and $path -and $path -notmatch '(?i)\\Windows\\System32\\|\\Windows\\SysWOW64\\') { $flags.Add('CRITICAL-PROC-ODD-PATH') }
        [pscustomobject]@{
            PID          = $p.ProcessId
            PPID         = $p.ParentProcessId
            Name         = $p.Name
            Path         = $path
            Company      = $company
            Description  = $desc
            CommandLine  = $p.CommandLine
            Created      = (Convert-WmiDate $p.CreationDate)
            Flags        = ($flags -join ';')
        }
    }
    return $rows
}

function Get-ConnectionTable {
    $rows = @()
    $pmap = @{}
    try { Get-Process | ForEach-Object { $pmap[[int]$_.Id] = $_.Path } } catch { }
    $tcp = $null
    try { $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue } catch { }
    if ($tcp) {
        $rows = foreach ($c in $tcp) {
            $procPath = $pmap[[int]$c.OwningProcess]
            [pscustomobject]@{
                Proto = 'TCP'; LocalAddress = $c.LocalAddress; LocalPort = $c.LocalPort
                RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort; State = $c.State
                PID = $c.OwningProcess; ProcessPath = $procPath
                Public = (Test-IsPublicIp "$($c.RemoteAddress)")
            }
        }
    } else {
        $lines = & netstat.exe -ano 2>$null | Where-Object { $_ -match '^\s*(TCP|UDP)' }
        $rows = foreach ($l in $lines) {
            $t = ($l -replace '^\s+', '') -split '\s+'
            $proto = $t[0]
            $local = ($t[1] -split ':')[0]; $lport = ($t[1] -split ':')[-1]
            $remote = ''; $rport = ''; $state = ''
            if ($proto -eq 'TCP') { $remote = ($t[2] -split ':')[0]; $rport = ($t[2] -split ':')[-1]; $state = $t[3]; $pid = $t[4] }
            else { $remote = $t[2]; $state = ''; $pid = $t[3] }
            $procPath = $pmap[[int]$pid]
            [pscustomobject]@{
                Proto = $proto; LocalAddress = $local; LocalPort = $lport
                RemoteAddress = $remote; RemotePort = $rport; State = $state
                PID = $pid; ProcessPath = $procPath
                Public = (Test-IsPublicIp "$remote")
            }
        }
    }
    return $rows
}

function Get-DnsCacheRows {
    try {
        if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
            return @(Get-DnsClientCache | Select-Object Entry, Data, Type, TimeToLive)
        }
    } catch { }
    $out = & ipconfig.exe /displaydns 2>$null
    return @($out | Select-String -Pattern 'Record Name|--------' | ForEach-Object { "$_".Trim() })
}

function Get-ArpRows {
    try {
        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
            return @(Get-NetNeighbor | Where-Object { $_.IPAddress -notmatch '^(224\.|239\.|ff)' } |
                Select-Object IPAddress, LinkLayerAddress, State, ifIndex)
        }
    } catch { }
    $out = & arp.exe -a 2>$null
    return @($out | Select-String -Pattern '\d+\.\d+\.\d+\.\d+' | ForEach-Object { "$_".Trim() })
}

function Get-SysmonState {
    $present = $false
    try {
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64') { $present = $true }
        elseif (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon') { $present = $true }
        elseif (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) { $present = $true }
    } catch { }
    return $present
}

function Get-ToolsDir {
    $root = Get-KitRoot
    if (Test-Path (Join-Path $root 'tools')) { return (Join-Path $root 'tools') }
    return $null
}

function Copy-LockedFile {
    # Read-only copy of an in-use file via esentutl VSS snapshot, with retry - parallel
    # esentutl /vss calls (e.g. SRUM + NTDS in different workers) race on the VSS snapshot set.
    param([string]$Source, [string]$Dest, [int]$Retries = 2)
    $errTxt = ''
    for ($i = 0; $i -le $Retries; $i++) {
        $errTxt = & esentutl.exe /y "$Source" /vss /d "$Dest" 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $Dest)) { return $true }
        if ($i -lt $Retries) { Start-Sleep -Seconds (3 * ($i + 1)) }
    }
    $tail = (@($errTxt -split "\r?\n") | Where-Object { "$_".Trim() } | Select-Object -Last 1)
    Write-CaseLog "    locked-file copy failed ($Source): $tail" 'DarkYellow'
    return $false
}

function Get-HayabusaExe {
    $tDir = Get-ToolsDir
    if (-not $tDir) { return $null }
    return Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1
}

function Get-LogStart {
    if ($script:LogStartDT) { return $script:LogStartDT }
    if ($script:LogHours -gt 0) { return (Get-Date).AddHours(-1 * $script:LogHours) }
    return $null
}

function ConvertTo-LogStart {
    # Accepts a window expression: 90 (hours), 90h, 30d, 3m (months), 0 = all-time,
    # or an explicit start date (2026-09-01 / '2026-09-01 08:00'). Returns a [datetime]
    # start, the string 'ALL' for 0, or $null when not understood.
    param([string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return $null }
    if ($v -match '^(?i)0\s*(h|d|m)?$') { return 'ALL' }
    if ($v -match '^(?i)(\d+)\s*(h|d|m)$') {
        $n = [int]$Matches[1]
        $now = Get-Date
        switch ($Matches[2].ToLower()) {
            'd' { return $now.AddDays(-$n) }
            'm' { return $now.AddMonths(-$n) }
            default { return $now.AddHours(-$n) }
        }
    }
    if ($v -match '^\d+$') { return (Get-Date).AddHours(-1 * [int]$v) }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($v, [ref]$dt)) { return $dt }
    return $null
}

function Resolve-LogWindow {
    # Validates -LogStart/-LogEnd/-LogWindow into $script:LogStartDT/$script:LogEndDT.
    # Precedence: explicit -LogStart > -LogWindow > -LogHours. Returns '' or an error message.
    $script:LogStartDT = $null
    $script:LogEndDT = $null
    foreach ($pair in @(@($LogStart, '-LogStart'), @($LogEnd, '-LogEnd'))) {
        $v = "$($pair[0])".Trim()
        if (-not $v) { continue }
        $dt = [datetime]::MinValue
        if (-not [datetime]::TryParse($v, [ref]$dt)) { return "$($pair[1]) '$v' is not a valid date (examples: 2026-09-01, '2026-09-01 08:00')" }
        if ($pair[1] -eq '-LogStart') { $script:LogStartDT = $dt } else { $script:LogEndDT = $dt }
    }
    $w = "$LogWindow".Trim()
    if ($w) {
        $r = ConvertTo-LogStart $w
        if ($null -eq $r) { return "-LogWindow '$w' not understood (use 90h / 30d / 3m / 0 = all, or a start date like 2026-09-01)" }
        if ("$r" -eq 'ALL') { $script:LogHours = 0 }
        elseif (-not $script:LogStartDT) { $script:LogStartDT = $r }
    }
    if ($script:LogStartDT -and $script:LogEndDT -and $script:LogEndDT -le $script:LogStartDT) { return '-LogEnd must be after -LogStart' }
    return ''
}

function Get-LogRangeText {
    if ($script:LogStartDT) { return "From $($script:LogStartDT.ToString('yyyy-MM-dd HH:mm'))$(if ($script:LogEndDT) { " to $($script:LogEndDT.ToString('yyyy-MM-dd HH:mm'))" })" }
    if ($script:LogHours -eq 0) { return 'All time' }
    if ($script:LogHours % 24 -eq 0) { return "Last $([int]($script:LogHours/24))d" }
    return "Last $($script:LogHours)h"
}

$rwErr = Resolve-LogWindow
if ($rwErr) { Write-Host "  Ophira: $rwErr" -ForegroundColor Red; exit 1 }

function Test-TrustedPublisher {
    param([string]$Signer)
    if (-not $Signer) { return $false }
    $trusted = @('Microsoft', 'Google', 'Mozilla', 'Adobe', 'Apple', 'Intel', 'NVIDIA', 'Dell', 'HP Inc', 'Lenovo', 'Citrix', 'VMware', 'Oracle', 'Python Software Foundation', 'GitHub', 'Slack', 'Discord', 'Zoom Video Communications', 'Dropbox', 'Notepad++')
    try {
        $tDir = Get-ToolsDir
        if ($tDir) {
            $tf = Join-Path $tDir 'trusted.txt'
            if (Test-Path -LiteralPath $tf) {
                $trusted += @(Get-Content -LiteralPath $tf | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
            }
        }
    } catch { }
    foreach ($t in $trusted) { if ($Signer -match [regex]::Escape($t)) { return $true } }
    return $false
}

function Get-IocList {
    # IOC feeds: classic tools\iocs.txt PLUS v2.26 feed folder tools\iocs\*.json
    # (STIX 2.x bundles and MISP exports - drop files in, no network, no API keys).
    # $iocs.Feed maps each indicator to its source feed for hit attribution.
    $tDir = Get-ToolsDir
    if (-not $tDir) { return $null }
    $iocs = @{ Hashes = @{}; Sha1 = @{}; Ips = @{}; Domains = @{}; Names = @{}; Feed = @{} }
    $addIoc = {
        param([string]$kind, [string]$key, [string]$feed)
        if (-not $key) { return }
        if ($kind -eq 'sha1') { $iocs.Sha1[$key] = $true; $iocs.Hashes[$key] = $true }
        elseif ($kind -eq 'hash') { $iocs.Hashes[$key] = $true }
        elseif ($kind -eq 'ip') { $iocs.Ips[$key] = $true }
        elseif ($kind -eq 'name') { $iocs.Names[$key] = $true }
        else { $iocs.Domains[$key] = $true }
        if (-not $iocs.Feed.ContainsKey($key)) { $iocs.Feed[$key] = $feed }
    }
    $f = Join-Path $tDir 'iocs.txt'
    if (Test-Path -LiteralPath $f) {
        foreach ($line in (Get-Content -LiteralPath $f)) {
            $l = ($line -replace '#.*$', '').Trim()
            if (-not $l) { continue }
            if ($l -match '^[a-fA-F0-9]{40}$') { & $addIoc 'sha1' $l.ToUpper() 'iocs.txt' }
            elseif ($l -match '^[a-fA-F0-9]{32,64}$') { & $addIoc 'hash' $l.ToUpper() 'iocs.txt' }
            elseif ($l -match '^(\d{1,3}\.){3}\d{1,3}$') { & $addIoc 'ip' $l 'iocs.txt' }
            else { & $addIoc 'domain' $l.ToLower() 'iocs.txt' }
        }
    }
    $feedDir = Join-Path $tDir 'iocs'
    if (Test-Path -LiteralPath $feedDir) {
        foreach ($jf in @(Get-ChildItem -LiteralPath $feedDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            $feedName = $jf.BaseName
            try {
                $j = Get-Content -LiteralPath $jf.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                # STIX 2.x bundle
                if ($j.type -eq 'bundle' -and $j.objects) {
                    foreach ($o in @($j.objects)) {
                        if ("$($o.type)" -ne 'indicator' -or -not "$($o.pattern)") { continue }
                        $p = "$($o.pattern)"
                        foreach ($m in ([regex]::Matches($p, "(?i)hashes\.'?(?:SHA|MD5)[^']*'?\s*=\s*'([a-f0-9]{32,64})'"))) {
                            & $addIoc $(if ($m.Groups[1].Value.Length -eq 40) { 'sha1' } else { 'hash' }) $m.Groups[1].Value.ToUpper() $feedName
                        }
                        foreach ($m in ([regex]::Matches($p, "(?i)domain-name:value\s*=\s*'([^']+)'"))) { & $addIoc 'domain' $m.Groups[1].Value.ToLower() $feedName }
                        foreach ($m in ([regex]::Matches($p, "(?i)(ipv4|ipv6)-addr:value\s*=\s*'([^']+)'"))) { & $addIoc 'ip' $m.Groups[2].Value $feedName }
                        foreach ($m in ([regex]::Matches($p, "(?i)file:name\s*=\s*'([^']+)'"))) { & $addIoc 'name' $m.Groups[1].Value.ToLower() $feedName }
                    }
                }
                # MISP export (direct or response-wrapped)
                $attrs = $null
                if ($j.Attribute) { $attrs = @($j.Attribute) }
                elseif ($j.response -and $j.response.Attribute) { $attrs = @($j.response.Attribute) }
                if ($attrs) {
                    foreach ($a in $attrs) {
                        $av = "$($a.value)"; $at = "$($a.type)"
                        if (-not $av -or -not $at) { continue }
                        switch -Regex ($at) {
                            '^(md5|sha256)$' { & $addIoc 'hash' $av.ToUpper() $feedName }
                            '^sha1$' { & $addIoc 'sha1' $av.ToUpper() $feedName }
                            '^(domain|hostname)' { & $addIoc 'domain' $av.ToLower() $feedName }
                            '^ip-(dst|src)' { & $addIoc 'ip' $av $feedName }
                            '^filename' { & $addIoc 'name' $av.ToLower() $feedName }
                        }
                    }
                }
            } catch { Write-CaseLog "    IOC feed '$feedName' failed to parse: $($_.Exception.Message)" 'DarkYellow' }
        }
    }
    if ($iocs.Hashes.Count -eq 0 -and $iocs.Ips.Count -eq 0 -and $iocs.Domains.Count -eq 0) { return $null }
    return $iocs
}

function Show-ToolLinks {
    Write-Host ""
    Write-Host "=== Ophira companion tools ===" -ForegroundColor Cyan
    $rows = @(
        [pscustomobject]@{ Tool = 'winpmem (RAM capture)'; Url = 'https://github.com/Velocidex/winpmem/releases'; Use = 'module 7.1 memory capture; drop exe in tools\' }
        [pscustomobject]@{ Tool = 'hayabusa (Sigma hunt)'; Url = 'https://github.com/Yamato-Security/hayabusa/releases'; Use = 'module 4.6 on-host Sigma timeline; get win-x64.zip' }
        [pscustomobject]@{ Tool = 'volatility3 (memory analysis)'; Url = 'https://github.com/volatilityfoundation/volatility3/releases'; Use = 'offline: pslist/netscan/malfind; get win-exes zip, keep vol.exe' }
        [pscustomobject]@{ Tool = 'chainsaw (artifact analysis)'; Url = 'https://github.com/WithSecureOpenSource/chainsaw/releases'; Use = 'offline: sigma hunt + shimcache/amcache timeline' }
        [pscustomobject]@{ Tool = 'AmcacheParser (EZ)'; Url = 'https://github.com/EricZimmerman/AmcacheParser/releases'; Use = 'module 8.4 execution inventory + SHA1 x IOC' }
        [pscustomobject]@{ Tool = 'RBCmd (EZ)'; Url = 'https://github.com/EricZimmerman/RBCmd/releases'; Use = 'module 8.4 recycle bin parse' }
        [pscustomobject]@{ Tool = 'yara-x (binary scanning)'; Url = 'https://github.com/VirusTotal/yara-x/releases'; Use = 'module 4.7 YARA scan of flagged binaries; bundled pack in tools\yara\rules' }
        [pscustomobject]@{ Tool = 'MFTECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 5.5 live $MFT + USN journal forensics' }
        [pscustomobject]@{ Tool = 'PECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 5.1 prefetch parse (run counts)' }
        [pscustomobject]@{ Tool = 'LECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.5 LNK parse (Recent docs)' }
        [pscustomobject]@{ Tool = 'JLECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.5 Jump List parse' }
        [pscustomobject]@{ Tool = 'SBECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.8 ShellBags (folder browsing history)' }
        [pscustomobject]@{ Tool = 'RECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'Parse mode: batch registry deep-dive over saved hives (bundled batch: tools\recmd\ophira-registry.bn)' }
        [pscustomobject]@{ Tool = 'EvtxECmd (EZ)'; Url = 'https://ericzimmerman.github.io/'; Use = 'Parse mode: FULL evtx->CSV conversion into csv\evtx_ecmd (timeframe deep-dives beyond the EID-filtered parses)' }
        [pscustomobject]@{ Tool = 'SQLECmd (EZ, .NET 9)'; Url = 'https://ericzimmerman.github.io/'; Use = 'module 8.7 browser SQLite parse (History/Downloads)' }
        [pscustomobject]@{ Tool = 'LOLDrivers datasets'; Url = 'https://github.com/magicsword-io/LOLDrivers'; Use = 'module 8.10 malicious/vulnerable driver hash lists into tools\loldrivers' }
        [pscustomobject]@{ Tool = 'velociraptor (enterprise)'; Url = 'https://github.com/Velocidex/velociraptor/releases'; Use = 'if you move to always-on agent-based DFIR' }
    )
    $rows | Format-Table Tool, Url, Use -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host "Tip: -Mode Setup downloads winpmem/hayabusa/volatility3/chainsaw into tools\ automatically." -ForegroundColor Yellow
}

function Invoke-SetupMode {
    param([string[]]$Wanted)
    if ($Wanted) { $Wanted = @($Wanted | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $toolsDir = Join-Path (Get-KitRoot) 'tools'
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    $catalog = @(
        [pscustomobject]@{ Name = 'winpmem';     Repo = 'Velocidex/winpmem';                Pattern = '^go-winpmem_amd64.*signed\.exe$|^winpmem.*x64.*\.exe$'; Zip = $false; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'hayabusa';    Repo = 'Yamato-Security/hayabusa';         Pattern = '^hayabusa-[\d\.]+-win-x64\.zip$'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'volatility3'; Repo = 'volatilityfoundation/volatility3'; Pattern = '^volatility3-win-exes-.*\.zip$'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'chainsaw';    Repo = 'WithSecureOpenSource/chainsaw';     Pattern = '^chainsaw_all_platforms\+rules\.zip$'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'AmcacheParser'; Direct = 'https://download.ericzimmermanstools.com/AmcacheParser.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'RBCmd';       Direct = 'https://download.ericzimmermanstools.com/RBCmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'MFTECmd';     Direct = 'https://download.ericzimmermanstools.com/MFTECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'PECmd';       Direct = 'https://download.ericzimmermanstools.com/PECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'LECmd';       Direct = 'https://download.ericzimmermanstools.com/LECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'JLECmd';      Direct = 'https://download.ericzimmermanstools.com/JLECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'SBECmd';      Direct = 'https://download.ericzimmermanstools.com/SBECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'SQLECmd';     Direct = 'https://download.ericzimmermanstools.com/net9/SQLECmd.zip'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'RECmd';       Direct = 'https://download.ericzimmermanstools.com/RECmd.zip'; Zip = $true; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'EvtxECmd';    Direct = 'https://download.ericzimmermanstools.com/EvtxECmd.zip'; Zip = $true; Target = 'analyst' }
        [pscustomobject]@{ Name = 'loldrivers';  Raw = @('https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_malicious.sha256', 'https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/hashes/samples_vulnerable.sha256'); Zip = $false; Target = 'endpoint' }
        [pscustomobject]@{ Name = 'yara';        Repo = 'VirusTotal/yara-x';                 Pattern = '^yara-x-v[\d\.]+-x86_64-pc-windows-msvc\.zip$'; Zip = $true; Target = 'endpoint' }
    )
    $installed = @()
    foreach ($t in $catalog) {
        if ($Wanted -and $Wanted.Count -gt 0 -and $Wanted -notcontains $t.Name) { continue }
        Write-Host ""
        Write-Host "=== $($t.Name) ===" -ForegroundColor Cyan
        try {
            $target = if ($t.PSObject.Properties['Target'] -and $t.Target) { $t.Target } else { 'endpoint' }
            if ($t.PSObject.Properties['Raw'] -and $t.Raw) {
                $confirm = Read-Host "  download to tools\$target\$($t.Name)\? [Y/n]"
                if ($confirm -match '^[Nn]') { continue }
                $dest = Join-Path (Join-Path $toolsDir $target) $t.Name
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                foreach ($u in @($t.Raw)) {
                    $fn = ($u -split '/')[-1]
                    Invoke-WebRequest -Uri $u -OutFile (Join-Path $dest $fn) -UseBasicParsing -ErrorAction Stop
                }
                Write-Host "  saved -> tools\$target\$($t.Name)\" -ForegroundColor Green
                $installed += $t.Name
                continue
            }
            $assetUrl = $null
            $assetName = $null
            if ($t.PSObject.Properties['Direct' ] -and $t.Direct) {
                $assetUrl = $t.Direct
                $assetName = ($t.Direct -split '/')[-1]
                Write-Host "  source: ericzimmermanstools.com ($assetName)"
            } else {
                $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$($t.Repo)/releases/latest" -Headers @{ 'User-Agent' = 'Ophira' } -TimeoutSec 30 -ErrorAction Stop
                $asset = @($rel.assets | Where-Object { $_.name -match $t.Pattern } | Select-Object -First 1)[0]
                if (-not $asset) { Write-Host "  no matching asset found in latest release ($($rel.tag_name)) - download manually: https://github.com/$($t.Repo)/releases" -ForegroundColor Yellow; continue }
                $mb = [math]::Round($asset.size / 1MB, 1)
                Write-Host "  latest: $($asset.name) ($mb MB)"
                $assetUrl = $asset.browser_download_url
                $assetName = $asset.name
            }
            $confirm = Read-Host "  download to tools\? [Y/n]"
            if ($confirm -match '^[Nn]') { continue }
            $tmp = Join-Path ([IO.Path]::GetTempPath()) $assetName
            Invoke-WebRequest -Uri $assetUrl -OutFile $tmp -UseBasicParsing -ErrorAction Stop
            if ($t.Zip) {
                $dest = Join-Path (Join-Path $toolsDir $target) $t.Name
                $keepRules = $null
                if ($t.Name -eq 'yara') {
                    $keepRules = Join-Path $dest 'rules'
                    if (Test-Path $keepRules) {
                        $bak = "$keepRules.bak"
                        if (Test-Path $bak) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
                        Move-Item -LiteralPath $keepRules -Destination $bak -Force -ErrorAction SilentlyContinue
                    } else { $keepRules = $null }
                }
                if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
                Expand-Archive -LiteralPath $tmp -DestinationPath $dest -Force -ErrorAction Stop
                Get-ChildItem -Path $dest -Recurse -File -ErrorAction SilentlyContinue | Unblock-File
                if ($keepRules -and (Test-Path "$keepRules.bak")) { Move-Item -LiteralPath "$keepRules.bak" -Destination $keepRules -Force -ErrorAction SilentlyContinue }
                Write-Host "  extracted -> tools\$($t.Name)\" -ForegroundColor Green
            } else {
                Copy-Item -LiteralPath $tmp -Destination (Join-Path $toolsDir $assetName) -Force -ErrorAction Stop
                Write-Host "  saved -> tools\$assetName" -ForegroundColor Green
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $installed += $t.Name
        } catch {
            Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
            if ($t.PSObject.Properties['Direct'] -and $t.Direct) { Write-Host "  manual download: $($t.Direct)" -ForegroundColor Yellow }
            else { Write-Host "  manual download: https://github.com/$($t.Repo)/releases" -ForegroundColor Yellow }
        }
    }
    Write-Host ""
    Write-Host "Setup done: $(if ($installed) { $installed -join ', ' } else { 'nothing installed' })" -ForegroundColor $(if ($installed) { 'Green' } else { 'Yellow' })
    Write-Host "tools\endpoint\ = shipped to remote hosts via Deploy (-PushTools). tools\analyst\ = never shipped (your PC only)." -ForegroundColor Gray
    Write-Host "Ophira finds tools recursively in both folders." -ForegroundColor Gray
}

function Compress-ToolZip {
    # AV-resilient packaging: Defender flags some bundled Sigma .yml files and blocks
    # Compress-Archive entirely. Zip per-entry and skip whatever AV objects to.
    param([string]$SourceDir, [string]$DestZip)
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    if (Test-Path $DestZip) { Remove-Item $DestZip -Force }
    $zipPath = $DestZip
    if ($zipPath.Length -gt 240) { $zipPath = "\\?\$zipPath" }
    $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
    $added = 0
    $skipped = 0
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $SourceDir -Recurse -File)) {
            $rel = $f.FullName.Substring($SourceDir.Length + 1).Replace('\', '/')
            $srcPath = $f.FullName
            if ($srcPath.Length -gt 240) { $srcPath = "\\?\$srcPath" }
            try {
                $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $srcPath, $rel, [IO.Compression.CompressionLevel]::Fastest)
                $added++
            } catch { $skipped++ }
        }
    } finally { $zip.Dispose() }
    return [pscustomobject]@{ Added = $added; Skipped = $skipped }
}

function Invoke-DeployMode {
    param([string[]]$Targets, [string]$DeployPreset, $Cred, [string]$DeployCaseID, [string]$DeploySharePath, [int]$Threads = 8, [bool]$PushBin = $false, [int]$DeployLogHours = 0, [string]$DeployLogWindow = '')

    $kit = Get-KitRoot
    $scriptPath = Join-Path $kit 'Ophira.ps1'
    $tools = Join-Path $kit 'tools'
    $outFolder = Join-Path $kit 'collections'
    if (-not (Test-Path $scriptPath)) { Write-Host "Ophira.ps1 not found in $kit" -ForegroundColor Red; return }
    if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $toolsDir = if (Test-Path $tools) { $tools } else { $null }
    $binZip = $null
    if ($PushBin -and $toolsDir) {
        $epDir = Join-Path $toolsDir 'endpoint'
        $legacyHay = Join-Path $toolsDir 'hayabusa'
        $packDir = if (Test-Path $epDir) { $epDir } elseif (Test-Path $legacyHay) { $legacyHay } else { $null }
        if ($packDir) {
            try {
                $what = if ($packDir -eq $epDir) { 'endpoint toolset (hayabusa/chainsaw/yara/EZ/loldrivers/winpmem)' } else { 'hayabusa (legacy layout)' }
                Write-Host "Packaging $what for push (bin push)..." -ForegroundColor Cyan
                $binZip = Join-Path ([IO.Path]::GetTempPath()) 'ophira-bin-endpoint.zip'
                $zipRes = Compress-ToolZip -SourceDir $packDir -DestZip $binZip
                $skipNote = if ($zipRes.Skipped -gt 0) { ", $($zipRes.Skipped) files skipped (AV-blocked)" } else { '' }
                Write-Host ("  packaged ({0} MB, {1} files{2}) - will be REMOVED from targets after run" -f [math]::Round((Get-Item $binZip).Length / 1MB, 1), $zipRes.Added, $skipNote) -ForegroundColor Gray
            } catch { Write-Host "  bin packaging failed: $($_.Exception.Message) - continuing without on-host tools" -ForegroundColor Yellow; $binZip = $null }
        } else { Write-Host "  tools\endpoint not found - PushTools has nothing to push" -ForegroundColor Yellow }
    }

    $worker = {
        param($c, $scriptPath, $toolsDir, $preset, $caseID, $sharePath, $cred, $outFolder, $binZip, $logHours, $logWindow)
        $result = [pscustomobject]@{ Host = $c; Ok = $false; Detail = '' }
        $s = $null
        $remoteDir = 'C:\Windows\Temp\Ophira'
        try {
            $sp = @{ ComputerName = $c; SessionOption = (New-PSSessionOption -NoMachineProfile) }
            if ($cred) { $sp.Credential = $cred }
            $s = New-PSSession @sp -ErrorAction Stop
            Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $remoteDir -ErrorAction Stop | Out-Null
            Copy-Item -Path $scriptPath -Destination "$remoteDir\Ophira.ps1" -ToSession $s -Force
            if ($toolsDir) {
                $rd = "$remoteDir\tools"
                Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $rd | Out-Null
                Get-ChildItem $toolsDir -File -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
                    Copy-Item -Path $_.FullName -Destination "$rd\$($_.Name)" -ToSession $s -Force
                }
            }
            if ($binZip -and (Test-Path -LiteralPath $binZip)) {
                Copy-Item -Path $binZip -Destination "$remoteDir\bin.zip" -ToSession $s -Force -ErrorAction Stop
                Invoke-Command -Session $s -ScriptBlock {
                    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
                    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                    $null = New-Item -ItemType Directory -Path "$using:remoteDir\tools" -Force
                    $zip = [IO.Compression.ZipFile]::OpenRead("$using:remoteDir\bin.zip")
                    $skipped = 0
                    try {
                        foreach ($entry in $zip.Entries) {
                            if ("$($entry.Name)" -eq '') { continue }
                            $dest = Join-Path "$using:remoteDir\tools" $entry.FullName
                            if ($dest.Length -gt 240) { $dest = "\\?\$dest" }
                            $destDir = Split-Path $dest -Parent
                            if (-not (Test-Path $destDir)) { $null = New-Item -ItemType Directory -Path $destDir -Force }
                            try { [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true) } catch { $skipped++ }
                        }
                    } finally { $zip.Dispose() }
                    Remove-Item "$using:remoteDir\bin.zip" -Force -ErrorAction SilentlyContinue
                } -ErrorAction Stop
            }
            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteDir\Ophira.ps1`" -Mode Collect -NoMenu -NoElevate -Preset $preset -OutputPath `"$remoteDir\out`""
            if ($caseID) { $cmd += " -CaseID `"$caseID`"" }
            if ($sharePath) { $cmd += " -SharePath `"$sharePath`"" }
            if ($logHours -ge 0) { $cmd += " -LogHours $logHours" }
            if ($logWindow) { $cmd += " -LogWindow '" + ($logWindow -replace "'", "''") + "'" }
            $res = Invoke-Command -Session $s -ScriptBlock {
                param($k, $t)
                $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $k -Wait -PassThru -WindowStyle Hidden
                $z = Get-ChildItem "$t\out" -Filter '*.zip' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($z) { $z.FullName } else { "NORESULT:exit=$($p.ExitCode)" }
            } -ArgumentList $cmd, $remoteDir
            if ($res -and $res -notmatch '^NORESULT') {
                if ($sharePath) {
                    $result.Detail = "uploaded to share ($res)"
                } else {
                    Copy-Item -Path $res -Destination $outFolder -FromSession $s -Force -ErrorAction Stop
                    $result.Detail = "pulled $(Split-Path $res -Leaf)"
                }
                $result.Ok = $true
            } else { $result.Detail = "no result zip ($res)" }
        } catch { $result.Detail = $_.Exception.Message }
        finally {
            if ($s) {
                Invoke-Command -Session $s -ScriptBlock { Remove-Item 'C:\Windows\Temp\Ophira' -Recurse -Force -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
                Remove-PSSession $s -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        return $result
    }

    function Invoke-DeployBatch {
        param([string[]]$Batch)
        $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Threads))
        $pool.Open()
        $jobs = New-Object System.Collections.ArrayList
        foreach ($c in $Batch) {
            $ps = [powershell]::Create()
            $null = $ps.AddScript($worker.ToString()).AddArgument($c).AddArgument($scriptPath).AddArgument($toolsDir).AddArgument($DeployPreset).AddArgument($DeployCaseID).AddArgument($DeploySharePath).AddArgument($Cred).AddArgument($outFolder).AddArgument($binZip).AddArgument($DeployLogHours).AddArgument($DeployLogWindow)
            $ps.RunspacePool = $pool
            $null = $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Target = $c })
        }
        $results = @()
        while ($jobs.Count -gt 0) {
            $doneIdx = @()
            for ($i = 0; $i -lt $jobs.Count; $i++) {
                if ($jobs[$i].Handle.IsCompleted) { $doneIdx += $i }
            }
            foreach ($i in ($doneIdx | Sort-Object -Descending)) {
                $j = $jobs[$i]
                try {
                    $out = @($j.PS.EndInvoke($j.Handle))
                    foreach ($o in $out) {
                        $results += $o
                        $mark = if ($o.Ok) { 'OK  ' } else { 'FAIL' }
                        $col = if ($o.Ok) { 'Green' } else { 'Red' }
                        Write-Host ("  [{0}] {1,-25} {2}" -f $mark, $o.Host, $o.Detail) -ForegroundColor $col
                    }
                } catch {
                    $results += [pscustomobject]@{ Host = $j.Target; Ok = $false; Detail = "worker error: $($_.Exception.Message)" }
                    Write-Host ("  [FAIL] {0,-25} worker error" -f $j.Target) -ForegroundColor Red
                }
                $j.PS.Dispose()
                $jobs.RemoveAt($i)
            }
            if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 500 }
        }
        $pool.Close()
        $pool.Dispose()
        return $results
    }

    $total = $Targets.Count
    Write-Host "Deploying to $total hosts ($Threads parallel, $DeployPreset preset)..." -ForegroundColor Cyan
    $results = @(Invoke-DeployBatch -Batch $Targets)
    $retry = @($results | Where-Object { -not $_.Ok } | Select-Object -ExpandProperty Host -Unique)
    if ($retry.Count -gt 0) {
        Write-Host "`nRetrying $($retry.Count) failed host(s) sequentially..." -ForegroundColor Yellow
        $results += @(Invoke-DeployBatch -Batch $retry)
        $results = @($results | Group-Object Host | ForEach-Object {
            $good = @($_.Group | Where-Object Ok)
            if ($good.Count -gt 0) { $good[0] } else { $_.Group | Select-Object -Last 1 }
        })
    }
    $ok = @($results | Where-Object Ok)
    $fail = @($results | Where-Object { -not $_.Ok })
    if ($binZip -and (Test-Path -LiteralPath $binZip)) { Remove-Item $binZip -Force -ErrorAction SilentlyContinue }
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  DEPLOYMENT SUMMARY: $($ok.Count)/$total succeeded" -ForegroundColor $(if ($fail.Count) { 'Yellow' } else { 'Green' })
    if ($fail.Count) { $fail | ForEach-Object { Write-Host "  FAILED: $($_.Host) - $($_.Detail)" -ForegroundColor Red } }
    Write-Host "  Collections in: $(if ($DeploySharePath) { $DeploySharePath } else { $outFolder })"
    Write-Host "  Next: .\Ophira.ps1 -Mode Analyze -AnalyzePath <that folder>" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

function Invoke-AnalyzeMode {
    param([string]$Path, [string]$HayabusaExe)
    if (-not (Test-Path $Path)) { Write-Host "Path not found: $Path" -ForegroundColor Red; return }
    $OutFolder = $Path
    if (-not $HayabusaExe) {
        $tDir = Get-ToolsDir
        if ($tDir) {
            $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1
            if ($h) { $HayabusaExe = $h.FullName }
        }
    } elseif (-not (Test-Path $HayabusaExe)) {
        Write-Host "hayabusa not found at $HayabusaExe" -ForegroundColor Red; $HayabusaExe = ''
    }
    $sources = @()
    $sources += Get-ChildItem $Path -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue
    $sources += Get-ChildItem $Path -Filter 'IRCASE_*.zip' -File -ErrorAction SilentlyContinue
    foreach ($d in (Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(OPHIRA|IRCASE)_' })) {
        if ((Test-Path (Join-Path $d.FullName 'case.json')) -and -not ($sources | Where-Object { $_.BaseName -eq $d.Name })) { $sources += $d }
    }
    if (-not $sources) { Write-Host "No OPHIRA_*/IRCASE_* packages found in $Path" -ForegroundColor Red; return }
    $findings = @()
    $hosts = @()
    $evtxDirs = @()
    $signerRows = @()
    $extractWorker = {
        param($zipPath, $tmp)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tmp)
        return $tmp
    }
    $extractJobs = New-Object System.Collections.ArrayList
    $pool = [runspacefactory]::CreateRunspacePool(1, 4)
    $pool.Open()
    foreach ($src in $sources) {
        if ($src -is [System.IO.FileInfo]) {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
            if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
            $ps = [powershell]::Create()
            $null = $ps.AddScript($extractWorker.ToString()).AddArgument($src.FullName).AddArgument($tmp)
            $ps.RunspacePool = $pool
            $null = $extractJobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Src = $src; Tmp = $tmp })
        }
    }
    $extractMap = @{}
    while ($extractJobs.Count -gt 0) {
        $doneIdx = @()
        for ($i = 0; $i -lt $extractJobs.Count; $i++) {
            if ($extractJobs[$i].Handle.IsCompleted) { $doneIdx += $i }
        }
        foreach ($i in ($doneIdx | Sort-Object -Descending)) {
            $j = $extractJobs[$i]
            try { $null = $j.PS.EndInvoke($j.Handle); $extractMap[$j.Src.Name] = $j.Tmp }
            catch { Write-Host "cannot extract $($j.Src.Name): $($_.Exception.Message)" -ForegroundColor Red }
            $j.PS.Dispose()
            $extractJobs.RemoveAt($i)
        }
        if ($extractJobs.Count -gt 0) { Start-Sleep -Milliseconds 200 }
    }
    $pool.Close()
    $pool.Dispose()
    $lateralRaw = New-Object System.Collections.Generic.List[object]
    $hostIps = @{}
    foreach ($src in $sources) {
        $tmp = $null
        $dir = $src.FullName
        if ($src -is [System.IO.FileInfo]) {
            if (-not $extractMap.ContainsKey($src.Name)) { continue }
            $tmp = $extractMap[$src.Name]
            $dir = $tmp
        }
        $host_ = $src.Name -replace '^(OPHIRA|IRCASE)_', '' -replace '_\d{8}_\d{6}.*$', ''
        $caseJson = Join-Path $dir 'case.json'
        $meta = $null
        if (Test-Path $caseJson) { try { $meta = Get-Content $caseJson -Raw | ConvertFrom-Json } catch { } }
        if ($meta -and $meta.Computer) { $host_ = $meta.Computer }
        $vd = $null
        $verdictJson = Join-Path $dir 'verdict.json'
        if (Test-Path $verdictJson) { try { $vd = Get-Content $verdictJson -Raw | ConvertFrom-Json } catch { } }
        $hosts += [pscustomobject]@{
            Host = $host_; Source = $src.Name; CaseID = $meta.CaseID
            Role = $(if ($meta -and $meta.Role) { "$($meta.Role)" } else { '' })
            Preset = $(if ($meta -and $meta.Preset) { "$($meta.Preset)" } else { '' })
            Collected = $meta.StartedUTC; Admin = $meta.AdminElevated; Sysmon = $meta.SysmonPresent
            Verdict = "$(if ($vd) { $vd.Level } else { '' })"
            VerdictRank = $(if ($vd) { [int]$vd.LevelRank } else { -1 })
            Confidence = $(if ($vd) { $vd.ConfidencePercent } else { $null })
            Signals = $(if ($vd) { @($vd.Signals).Count } else { 0 })
            Caveats = $(if ($vd) { @($vd.Caveats).Count } else { 0 })
        }
        $csvDir = Join-Path $dir 'csv'
        if (Test-Path $csvDir) {
            $map = @{
                'flash_process_scored.csv'           = 'ProcAnomaly'
                'flash_ioc_hits.csv'                 = 'IOC-HIT'
                'flash_public_connections.csv'       = 'PublicConn'
                'scheduled_tasks_flagged.csv'        = 'TaskFlagged'
                'services_flagged.csv'               = 'ServiceFlagged'
                'security_bruteforce_candidates.csv' = 'BruteForce'
                'defender_threats.csv'               = 'AVDetection'
                'system_new_services.csv'            = 'NewService'
                'process_hashes.csv'                 = 'FileHash'
                'loldrivers_hits.csv'                = 'LolDriver'
                'dns_beacon_candidates.csv'          = 'DnsBeacon'
                'hunt_findings.csv'                  = 'HuntHit'
            }
            foreach ($k in $map.Keys) {
                $f = Join-Path $csvDir $k
                if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) {
                    try {
                        $rows = Import-Csv $f
                        foreach ($r in @($rows)) {
                            $detail = ''
                            if ($k -eq 'process_hashes.csv') { $detail += "$($r.SHA256) $($r.Path) " }
                            if ($r.PSObject.Properties['Name']) { $detail += "$($r.Name) " }
                            if ($r.PSObject.Properties['Path']) { $detail += "$($r.Path) " }
                            if ($r.PSObject.Properties['Indicator']) { $detail += "[$($r.Indicator)] $($r.Where)" }
                            if ($r.PSObject.Properties['SourceIp']) { $detail += "$($r.SourceIp) ($($r.FailedLogons) failures)" }
                            if ($r.PSObject.Properties['ThreatName']) { $detail += "$($r.ThreatName) $($r.Resources)" }
                            if ($r.PSObject.Properties['RemoteAddress']) { $detail += "$($r.RemoteAddress):$($r.RemotePort) <- $($r.ProcessPath)" }
                            if ($r.PSObject.Properties['Service']) { $detail += "$($r.Service) $($r.Binary)" }
                            if ($r.PSObject.Properties['Verdict']) { $detail = "[$($r.Verdict) $($r.Score)] " + $detail + " {$($r.Evidence)}" }
                            if ($k -eq 'hunt_findings.csv') { $detail = "[$($r.Severity)] $($r.Rule): $($r.Entity) - $($r.Evidence)" }
                        if ($k -eq 'flash_process_scored.csv' -and $r.PSObject.Properties['Signer'] -and "$($r.Signer)") {
                            $signerRows += [pscustomobject]@{ Host = $host_; Signer = "$($r.Signer)"; Name = "$($r.Name)"; Verdict = "$($r.Verdict)" }
                        }
                            if (-not $detail) { $detail = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' }
                            $findings += [pscustomobject]@{ Host = $host_; Type = $map[$k]; Detail = $detail.Trim(); Source = $k }
                        }
                    } catch { }
                }
            }
            # lateral-chain input: share access rows + local IPs for cross-host stitching (v2.20)
            $sa = Join-Path $csvDir 'security_share_access.csv'
            if (Test-Path $sa) {
                try {
                    foreach ($r in (Import-Csv $sa)) {
                        $ip = "$($r.SourceIp)"
                        if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { continue }
                        $lateralRaw.Add([pscustomobject]@{ Host = $host_; Time = "$($r.Time)"; EventId = "$($r.EventId)"; Account = "$($r.Account)"; ShareName = "$($r.ShareName)"; TargetName = "$($r.RelativeTargetName)"; SourceIp = $ip })
                    }
                } catch { }
            }
            $ni = Join-Path $csvDir 'net_interfaces.csv'
            if (Test-Path $ni) {
                try {
                    foreach ($r in (Import-Csv $ni)) {
                        foreach ($ip in ("$($r.IPv4)" -split ',')) {
                            $ip = $ip.Trim()
                            if ($ip) { $hostIps[$ip] = $host_ }
                        }
                    }
                } catch { }
            }
        }
        $e = Join-Path $dir 'raw\evtx'
        if (Test-Path $e) { $evtxDirs += $e }
    }
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  FLEET ANALYSIS - $($hosts.Count) hosts, $($findings.Count) findings" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    $byType = $findings | Group-Object Type | Sort-Object Count -Descending
    Write-Host "`n  Findings by type:" -ForegroundColor White
    foreach ($g in $byType) { Write-Host ("    {0,-14} {1}" -f $g.Name, $g.Count) }
    $withVerdict = @($hosts | Where-Object { $_.VerdictRank -ge 0 })
    if ($withVerdict.Count -gt 0) {
        Write-Host "`n  Verdicts:" -ForegroundColor White
        foreach ($g in @($withVerdict | Group-Object Verdict)) { Write-Host ("    {0,-30} {1} host(s)" -f $g.Name, $g.Count) }
        $attention = @($withVerdict | Where-Object { $_.VerdictRank -ge 3 } | Sort-Object VerdictRank -Descending)
        if ($attention.Count -gt 0) {
            Write-Host "    ATTENTION FIRST:" -ForegroundColor Red
            foreach ($a in $attention) { Write-Host ("      {0,-22} {1} (conf {2}%)" -f $a.Host, $a.Verdict, $a.Confidence) -ForegroundColor Red }
        }
        if ($hosts.Count -gt $withVerdict.Count) { Write-Host "    ($($hosts.Count - $withVerdict.Count) legacy case(s) without verdict - rerun those hosts with Ophira v2.6+)" -ForegroundColor DarkGray }
    }
    $highRisk = @($findings | Where-Object { @('IOC-HIT', 'AVDetection', 'HuntHit') -contains $_.Type })
    if ($highRisk.Count) {
        Write-Host "`n  *** HIGH-PRIORITY (IOC hits / AV detections / hunt hits) ***" -ForegroundColor Red
        $highRisk | Group-Object Host | ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor Red }
    }
    $crossHost = @()
    foreach ($g in ($findings | Where-Object { @('ProcAnomaly', 'IOC-HIT', 'TaskFlagged', 'ServiceFlagged', 'FileHash') -contains $_.Type } | Group-Object { ($_.Detail -split ' ')[0] })) {
        $hs = @($g.Group | Select-Object -ExpandProperty Host -Unique)
        if ($hs.Count -gt 1) { $crossHost += [pscustomobject]@{ Indicator = $g.Name; Hosts = ($hs -join ', '); HostCount = $hs.Count } }
    }
    $proposedTrusted = @()
    if ($signerRows.Count -gt 0 -and $hosts.Count -ge 2) {
        $threshold = [Math]::Max(2, [Math]::Ceiling($hosts.Count * 0.6))
        foreach ($g in ($signerRows | Group-Object Signer)) {
            $sh = @($g.Group | Select-Object -ExpandProperty Host -Unique)
            $anyHigh = @($g.Group | Where-Object { $_.Verdict -eq 'HIGH' })
            if ($sh.Count -ge $threshold -and $anyHigh.Count -eq 0) {
                $proposedTrusted += [pscustomobject]@{ Signer = $g.Name; Hosts = $sh.Count; Samples = (($g.Group | Select-Object -ExpandProperty Name -Unique | Select-Object -First 3) -join '; ') }
            }
        }
        if ($proposedTrusted.Count -gt 0) {
            $pt = Join-Path $OutFolder 'proposed_trusted.txt'
            $pl = @("# Proposed trusted publishers - generated by Ophira fleet baselining $(Get-Date -Format u)")
            $pl += "# These publishers appear on >= 60% of $($hosts.Count) hosts with no HIGH verdicts."
            $pl += "# Review, then copy the lines you trust into tools\trusted.txt to cut future false positives."
            $pl += ""
            $pl += @($proposedTrusted | Select-Object -ExpandProperty Signer)
            $pl | Set-Content -LiteralPath $pt -Encoding UTF8
            Write-Host "`n  Baselining: $($proposedTrusted.Count) publishers proposed as trusted -> proposed_trusted.txt" -ForegroundColor Cyan
        }
    }
    if ($crossHost.Count) {
        Write-Host "`n  SAME INDICATOR ON MULTIPLE HOSTS (outbreak signal):" -ForegroundColor Magenta
        $crossHost | Sort-Object HostCount -Descending | Select-Object -First 20 | ForEach-Object {
            Write-Host ("    {0,-45} {1} hosts: {2}" -f $_.Indicator, $_.HostCount, $_.Hosts) -ForegroundColor Magenta
        }
    }
    $hayOut = $null
    $lateral = New-Object System.Collections.Generic.List[object]
    foreach ($r in $lateralRaw) {
        if (-not $hostIps.ContainsKey($r.SourceIp)) { continue }
        $from = $hostIps[$r.SourceIp]
        if ($from -eq $r.Host) { continue }
        $null = $lateral.Add([pscustomobject]@{ FromHost = $from; ToHost = $r.Host; Account = $r.Account; Share = $r.ShareName; Target = $r.TargetName; Time = $r.Time; SourceIp = $r.SourceIp; EventId = $r.EventId })
    }
    if ($lateral.Count -gt 0) {
        $latCsv = Join-Path $OutFolder 'fleet_lateral_chain.csv'
        $lateral.ToArray() | Sort-Object FromHost, ToHost | Export-Csv -LiteralPath $latCsv -NoTypeInformation -Encoding UTF8
        Write-Host "`n  LATERAL MOVEMENT CHAINS (share access from another collected host): $($lateral.Count) -> fleet_lateral_chain.csv" -ForegroundColor Magenta
        foreach ($l in ($lateral.ToArray() | Sort-Object FromHost, ToHost | Select-Object -First 20)) {
            Write-Host ("    {0} -> {1} [{2}] share={3} target={4} ({5})" -f $l.FromHost, $l.ToHost, $l.Account, $l.Share, $l.Target, $l.SourceIp) -ForegroundColor Magenta
        }
    }
    if ($HayabusaExe -and $evtxDirs.Count -gt 0) {
        Write-Host "`n  Running hayabusa fleet timeline over $($evtxDirs.Count) hosts' evtx..." -ForegroundColor Cyan
        $merged = Join-Path ([IO.Path]::GetTempPath()) 'fleet_merged_evtx'
        if (Test-Path $merged) { Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $merged -Force | Out-Null
        $i = 0
        foreach ($e in $evtxDirs) {
            $i++
            Get-ChildItem $e -Filter '*.evtx' -File -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $merged ("{0}_{1}" -f $i, $_.Name)) -Force
            }
        }
        $hayOut = Join-Path $OutFolder 'fleet_hayabusa_timeline.csv'
        $hayHtml = Join-Path $OutFolder 'fleet_hayabusa_report.html'
        Write-Host "    hayabusa fleet timeline running..." -ForegroundColor Cyan
        $null = Invoke-NativeTool -ExePath $HayabusaExe -ToolArgs @('dfir-timeline', '-p', 'verbose', '-d', $merged, '-o', $hayOut, '-H', $hayHtml, '-q', '-w', '-U', '-C', '-K', '-m', 'low', '-E') -WorkingDirectory (Split-Path $HayabusaExe -Parent) -QuietLog
        if (Test-Path $hayOut) {
            $null = Invoke-NativeTool -ExePath $HayabusaExe -ToolArgs @('sort-csv', '-f', $hayOut, '-o', $hayOut, '-C', '-q', '-K') -WorkingDirectory (Split-Path $HayabusaExe -Parent) -QuietLog
            $n = @(Get-Content $hayOut | Select-Object -Skip 1).Count
            Write-Host "    hayabusa: $n detections (deduped) -> $hayOut" -ForegroundColor Yellow
        }
        Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue
    }
    $reportCsv = Join-Path $OutFolder 'fleet_report.csv'
    $findings | Sort-Object Host, Type | Export-Csv -LiteralPath $reportCsv -NoTypeInformation -Encoding UTF8
    $hostsCsv = Join-Path $OutFolder 'fleet_hosts.csv'
    $hosts | Sort-Object Host | Select-Object Host, Verdict, VerdictRank, Confidence, Role, Preset, Signals, Caveats, Collected, Admin, Sysmon, Source, CaseID | Export-Csv -LiteralPath $hostsCsv -NoTypeInformation -Encoding UTF8

    $fleetHtml = Join-Path $OutFolder 'fleet_report.html'
    $css = @'
<style>
body{background:#0f1115;color:#d7dce3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 10px;color:#8ab4f8;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
.meta{color:#7d8590;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #2a2f3a;padding:6px 10px;text-align:left}
th{background:#1d222c;color:#8ab4f8}tr:nth-child(even){background:#151920}
.HIGH{color:#ff8789;font-weight:700}.IOC{color:#ff8789}.path{font-family:Consolas,monospace;font-size:12px;color:#8ab4f8;word-break:break-all}
.V4{color:#ff8789;font-weight:800}.V3{color:#ff8789;font-weight:700}.V2{color:#ffce6b}.V1{color:#7ee2a8}.V0{color:#9ec1f0}.VN{color:#7d8590}
.chips{margin:14px 0}.chip{display:inline-block;padding:5px 13px;border-radius:14px;margin-right:6px;font-size:13px;font-weight:600;background:#243447;color:#9ec1f0}
a{color:#8ab4f8}.foot{margin-top:40px;color:#565e6b;font-size:11px}
</style>
'@
    $fsb = New-Object System.Text.StringBuilder
    $null = $fsb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira Fleet</title>$css</head><body>")
    $null = $fsb.AppendLine("<h1>OPHIRA FLEET REPORT</h1><div class='meta'>$(Get-Date -Format u) - $($hosts.Count) hosts - $($findings.Count) findings - Ophira v$ScriptVersion</div>")
    if (@($hosts | Where-Object { $_.VerdictRank -ge 0 }).Count -gt 0) {
        $chipParts = @()
        foreach ($lvl in @(4, 3, 2, 1, 0)) {
            $n = @($hosts | Where-Object VerdictRank -eq $lvl).Count
            if ($n -gt 0) { $chipParts += "<span class='chip V$lvl'>$((@{4='COMPROMISED';3='LIKELY COMPROMISED';2='SUSPICIOUS';1='NO EVIDENCE';0='INCONCLUSIVE'})[$lvl]): $n</span>" }
        }
        $leg = @($hosts | Where-Object VerdictRank -lt 0).Count
        if ($leg -gt 0) { $chipParts += "<span class='chip VN'>no verdict: $leg</span>" }
        $null = $fsb.AppendLine("<div class='chips'>$($chipParts -join '')</div>")
    }
    $null = $fsb.AppendLine("<h2>Host summary (worst verdict first)</h2><table><tr><th>Host</th><th>Verdict</th><th>Conf</th><th>Role</th><th>High-priority</th><th>Proc anomalies</th><th>Brute force</th><th>Collected</th></tr>")
    foreach ($h in ($hosts | Sort-Object -Property @{Expression='VerdictRank';Descending=$true}, 'Host')) {
        $hf = @($findings | Where-Object Host -eq $h.Host)
        $hp = @($hf | Where-Object { @('IOC-HIT', 'AVDetection') -contains $_.Type }).Count
        $pa = @($hf | Where-Object { $_.Type -eq 'ProcAnomaly' -and $_.Detail -match '^\[HIGH' }).Count
        $bf = @($hf | Where-Object Type -eq 'BruteForce').Count
        $rowClass = if ($hp -gt 0 -or $pa -gt 0) { 'HIGH' } else { '' }
        $vCell = if ($h.VerdictRank -ge 0) { "<span class='V$($h.VerdictRank)'>$(ConvertTo-HtmlEsc $h.Verdict)</span>" } else { "<span class='VN'>n/a</span>" }
        $cCell = if ($h.VerdictRank -ge 0) { "$($h.Confidence)%" } else { '' }
        $null = $fsb.AppendLine("<tr><td class='$rowClass'>$(ConvertTo-HtmlEsc $h.Host)</td><td>$vCell</td><td>$cCell</td><td>$(ConvertTo-HtmlEsc $h.Role)</td><td>$hp</td><td>$pa</td><td>$bf</td><td>$(ConvertTo-HtmlEsc $h.Collected)</td></tr>")
    }
    $null = $fsb.AppendLine("</table><div class='meta'>Per-host verdict details: each case zip's verdict.json + report.html. Host list CSV: fleet_hosts.csv</div>")
    if ($highRisk.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>High-priority findings (IOC / AV / hunt)</h2><table><tr><th>Host</th><th>Type</th><th>Detail</th></tr>")
        foreach ($f in ($highRisk | Sort-Object Host | Select-Object -First 100)) {
            $null = $fsb.AppendLine("<tr><td class='IOC'>$(ConvertTo-HtmlEsc $f.Host)</td><td>$(ConvertTo-HtmlEsc $f.Type)</td><td class='path'>$(ConvertTo-HtmlEsc $f.Detail)</td></tr>")
        }
        $null = $fsb.AppendLine("</table><div class='meta'>HuntHit rows are high/medium technique detections from each host's csv\hunt_findings.csv</div>")
    }
    if ($lateral.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>Lateral movement chains (share access between collected hosts)</h2><table><tr><th>From</th><th>To</th><th>Account</th><th>Share</th><th>Target</th><th>Time</th><th>Source IP</th></tr>")
        foreach ($l in ($lateral.ToArray() | Sort-Object FromHost, ToHost | Select-Object -First 100)) {
            $null = $fsb.AppendLine("<tr><td class='IOC'>$(ConvertTo-HtmlEsc $l.FromHost)</td><td>$(ConvertTo-HtmlEsc $l.ToHost)</td><td>$(ConvertTo-HtmlEsc $l.Account)</td><td>$(ConvertTo-HtmlEsc $l.Share)</td><td class='path'>$(ConvertTo-HtmlEsc $l.Target)</td><td>$(ConvertTo-HtmlEsc $l.Time)</td><td>$(ConvertTo-HtmlEsc $l.SourceIp)</td></tr>")
        }
        $null = $fsb.AppendLine("</table><div class='meta'>Joined each host's csv\security_share_access.csv SourceIp against every other host's csv\net_interfaces.csv. CSV: fleet_lateral_chain.csv</div>")
    }
    if ($hayOut -and (Test-Path $hayOut)) {
        $ftech = @{}
        try {
            foreach ($r in (Import-Csv -LiteralPath $hayOut)) {
                $comp = "$($r.Computer)"
                foreach ($m in [regex]::Matches("$($r.MitreTags)", 'T\d{4}(?:\.\d{3})?')) {
                    $k = $m.Value
                    if (-not $ftech.ContainsKey($k)) { $ftech[$k] = @{ N = 0; Hosts = @{} } }
                    $ftech[$k].N++
                    if ($comp) { $ftech[$k].Hosts[$comp] = $true }
                }
            }
        } catch { }
        if ($ftech.Count -gt 0) {
            $null = $fsb.AppendLine("<h2>Fleet ATT&CK roll-up (Sigma-tagged detections across hosts)</h2><table><tr><th>Technique</th><th>Detections</th><th>Hosts</th></tr>")
            foreach ($k in @($ftech.Keys | Sort-Object { $ftech[$_].N } -Descending | Select-Object -First 40)) {
                $href = 'https://attack.mitre.org/techniques/' + ($k -replace '\.', '/')
                $null = $fsb.AppendLine("<tr><td><a target='_blank' href='$href'>$k</a></td><td>$($ftech[$k].N)</td><td>$($ftech[$k].Hosts.Count)</td></tr>")
            }
            $null = $fsb.AppendLine("</table><div class='meta'>Load attack_layer_fleet.json at navigator.mitre.org for the full heat map.</div>")
            try {
                $layerTech = @($ftech.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ techniqueID = $_; score = $ftech[$_].N } })
                $flayer = [pscustomobject]@{
                    name = "Ophira Fleet - $(Split-Path $Path -Leaf)"
                    domain = 'enterprise-attack'
                    description = "Ophira v$ScriptVersion fleet Sigma detections"
                    versions = @{ navigator = '4.9'; layer = '4.5' }
                    techniques = $layerTech
                }
                $flayer | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutFolder 'attack_layer_fleet.json') -Encoding UTF8
            } catch { }
        }
    }
    if ($crossHost.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>Cross-host indicators (outbreak signal)</h2><table><tr><th>Indicator</th><th>Hosts</th><th>Count</th></tr>")
        foreach ($c in ($crossHost | Sort-Object HostCount -Descending | Select-Object -First 30)) {
            $null = $fsb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $c.Indicator)</td><td>$(ConvertTo-HtmlEsc $c.Hosts)</td><td><b>$($c.HostCount)</b></td></tr>")
        }
        $null = $fsb.AppendLine("</table>")
    }
    if ($proposedTrusted.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>Fleet baselining - proposed trusted publishers</h2><div class='meta'>Present on >= 60% of hosts, never HIGH. Review proposed_trusted.txt and merge into tools\trusted.txt to reduce false positives.</div><table><tr><th>Publisher</th><th>Hosts</th><th>Sample binaries</th></tr>")
        foreach ($p in ($proposedTrusted | Sort-Object Hosts -Descending)) {
            $null = $fsb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $p.Signer)</td><td>$($p.Hosts)</td><td>$(ConvertTo-HtmlEsc $p.Samples)</td></tr>")
        }
        $null = $fsb.AppendLine("</table>")
    }
    if ($hayOut -and (Test-Path $hayOut)) {
        try {
            $hayRows = @(Import-Csv -LiteralPath $hayOut)
            $ruleCol = $null
            foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
                if ($hayRows.Count -gt 0 -and $hayRows[0].PSObject.Properties[$cand]) { $ruleCol = $cand; break }
            }
            if ($hayRows.Count -gt 0 -and $ruleCol) {
                $null = $fsb.AppendLine("<h2>Top Sigma detections across fleet</h2><table><tr><th>Alert</th><th>Hits</th><th>Max level</th><th>Hosts</th></tr>")
                foreach ($g in ($hayRows | Group-Object $ruleCol | Sort-Object Count -Descending | Select-Object -First 20)) {
                    $lvl = (@($g.Group | ForEach-Object { $_.Level }) | Sort-Object -Descending | Select-Object -First 1) -join ''
                    $lvlClass = switch -Regex ("$lvl") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                    $hostsN = @($g.Group | ForEach-Object { $_.Computer } | Select-Object -Unique).Count
                    $null = $fsb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td>$($g.Count)</td><td class='$lvlClass'>$lvl</td><td>$hostsN</td></tr>")
                }
                $null = $fsb.AppendLine("</table><div class='meta'>Full timeline: fleet_hayabusa_timeline.csv / fleet_hayabusa_report.html</div>")
            }
        } catch { }
    }
    $null = $fsb.AppendLine("<div class='foot'>Generated by Ophira -Mode Analyze. Per-host details: fleet_report.csv; Sigma timeline: fleet_hayabusa_timeline.csv / fleet_hayabusa_report.html</div></body></html>")
    $fsb.ToString() | Set-Content -LiteralPath $fleetHtml -Encoding UTF8

    $summaryTxt = Join-Path $OutFolder 'fleet_summary.txt'
    $lines = @()
    $lines += "Ophira fleet analysis - $(Get-Date -Format u)"
    $lines += "Hosts: $($hosts.Count)  Findings: $($findings.Count)"
    $lines += ""
    $lines += "HOSTS:"
    foreach ($h in $hosts) { $lines += "  $($h.Host)  collected=$($h.Collected) admin=$($h.Admin) sysmon=$($h.Sysmon) src=$($h.Source)" }
    $lines += ""
    $lines += "HIGH PRIORITY:"
    if ($highRisk.Count) { foreach ($f in $highRisk) { $lines += "  $($f.Host) $($f.Type) $($f.Detail)" } } else { $lines += "  none" }
    $lines += ""
    $lines += "CROSS-HOST INDICATORS:"
    if ($crossHost.Count) { foreach ($c in $crossHost) { $lines += "  $($c.Indicator) -> $($c.Hosts)" } } else { $lines += "  none" }
    $lines += ""
    $lines += "PROPOSED TRUSTED PUBLISHERS (fleet baselining):"
    if ($proposedTrusted.Count) { foreach ($p in $proposedTrusted) { $lines += "  $($p.Signer) ($($p.Hosts) hosts)" } } else { $lines += "  none" }
    $lines | Set-Content -LiteralPath $summaryTxt -Encoding UTF8
    $vdTot = @($hosts | Where-Object { "$($_.Verdict)" } | Group-Object Verdict | Sort-Object { $_.Group[0].VerdictRank } -Descending)
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ("  VERDICTS: " + (($vdTot | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '  |  ')) -ForegroundColor $(if (@($hosts | Where-Object { $_.VerdictRank -ge 3 }).Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  fleet_hosts.csv   : $hostsCsv" -ForegroundColor Green
    Write-Host "  fleet_report.csv  : $reportCsv" -ForegroundColor Green
    Write-Host "  fleet_report.html : $fleetHtml" -ForegroundColor Green
    Write-Host "  fleet_summary.txt : $summaryTxt" -ForegroundColor Green
    if ($hayOut) { Write-Host "  hayabusa timeline : $hayOut" -ForegroundColor Green }
    Write-Host "================================================================" -ForegroundColor Green
    foreach ($src in $sources) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-FlashTriage {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host ""
    Out-Flash "==============================================================" 'Cyan'
    Out-Flash "  FLASH TRIAGE  -  $Computer  -  $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" 'Cyan'
    Out-Flash "==============================================================" 'Cyan'

    $iocs = Get-IocList
    $iocHits = @()

    $procs = Get-ProcessInventory
    $bad = @($procs | Where-Object { $_.Flags })
    $sigChecked = @()
    if ($bad.Count -gt 0) {
        foreach ($b in $bad) {
            $s = Get-SignatureInfo -Path $b.Path
            $sigChecked += [pscustomobject]@{
                PID = $b.PID; Name = $b.Name; Path = $b.Path; Company = $b.Company
                Flags = $b.Flags; SigStatus = if ($s) { $s.Status } else { 'N/A' }
                Signer = if ($s) { $s.Signer } else { '' }
            }
        }
    }
    if ($iocs -and $iocs.Hashes.Count -gt 0) {
        $paths = @($procs | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) } | Select-Object -ExpandProperty Path -Unique)
        foreach ($p in $paths) {
            try {
                $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
                if ($iocs.Hashes.ContainsKey($h)) {
                    $pn = ($procs | Where-Object { $_.Path -eq $p } | Select-Object -First 1)
                    $iocHits += [pscustomobject]@{ Type = 'SHA256'; Indicator = $h.Substring(0, 16) + '...'; Where = $p; Context = "process PID $($pn.PID)" }
                }
            } catch { }
        }
    }

    $conns = Get-ConnectionTable
    $est = @($conns | Where-Object { $_.Proto -eq 'TCP' -and $_.State -eq 'Established' })
    $ext = @($est | Where-Object { $_.Public })
    if ($iocs -and $iocs.Ips.Count -gt 0) {
        foreach ($c in @($conns | Where-Object { $_.RemoteAddress -and $iocs.Ips.ContainsKey("$($_.RemoteAddress)") })) {
            $iocHits += [pscustomobject]@{ Type = 'IP'; Indicator = "$($c.RemoteAddress)"; Where = "conn PID $($c.PID) $($c.ProcessPath)"; Context = "$($c.RemoteAddress):$($c.RemotePort) $($c.State)" }
        }
    }

    $dns = Get-DnsCacheRows
    if ($iocs -and $iocs.Domains.Count -gt 0) {
        foreach ($d in $dns) {
            if ($d.PSObject.Properties['Entry']) {
                $e = "$($d.Entry)".ToLower()
                foreach ($dom in $iocs.Domains.Keys) {
                    if ($e -eq $dom -or $e.EndsWith("." + $dom)) {
                        $iocHits += [pscustomobject]@{ Type = 'Domain'; Indicator = $dom; Where = "dns cache: $e"; Context = "$($d.Data)" }
                        break
                    }
                }
            }
        }
    }

    $svcPaths = @()
    try { $svcPaths = @(Get-WmiOrCim -Class Win32_Service | ForEach-Object { "$($_.PathName)" }) } catch { }
    $taskActions = @()
    try {
        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
            $taskActions = @(Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ' })
        }
    } catch { }

    $scored = foreach ($b in $sigChecked) {
        $score = 0; $evidence = New-Object System.Collections.Generic.List[string]
        if ($b.Flags -match 'USER-WRITABLE-PATH') { $score += 1; $evidence.Add('runs-from-user-path') }
        if ($b.Flags -match 'NO-COMPANY' -or $b.SigStatus -eq 'NotSigned') { $score += 2; $evidence.Add('unsigned/no-company') }
        if ($b.Flags -match 'BINARY-MISSING') { $score += 3; $evidence.Add('binary-deleted-from-disk') }
        $myExt = @($ext | Where-Object { $_.PID -eq $b.PID })
        if ($myExt.Count -gt 0) { $score += 2; $evidence.Add("public-conn:$($myExt[0].RemoteAddress):$($myExt[0].RemotePort)") }
        if ($iocHits | Where-Object { $_.Where -eq $b.Path }) { $score += 4; $evidence.Add('IOC-HASH-MATCH') }
        $name = Split-Path $b.Path -Leaf -ErrorAction SilentlyContinue
        if ($name) {
            $svcRef = @($svcPaths | Where-Object { $_ -and $_ -match [regex]::Escape($name) })
            if ($svcRef.Count -gt 0) { $score += 2; $evidence.Add("persistence:service($($svcRef.Count))") }
            $taskRef = @($taskActions | Where-Object { $_ -and $_ -match [regex]::Escape($name) })
            if ($taskRef.Count -gt 0) { $score += 2; $evidence.Add("persistence:task($($taskRef.Count))") }
        }
        $iocHit = [bool]($iocHits | Where-Object { $_.Where -eq $b.Path })
        $trustedSigned = ($b.SigStatus -eq 'Valid' -and (Test-TrustedPublisher $b.Signer))
        if ($trustedSigned -and -not $iocHit) {
            $score = [Math]::Min($score, 2)
            $evidence.Add("signed-trusted-publisher:$($b.Signer)")
        } elseif ($trustedSigned -and $iocHit) {
            $evidence.Add("TRUSTED-PUBLISHER-BUT-IOC-HIT")
        }
        $verdict = if ($score -ge 7) { 'HIGH' } elseif ($score -ge 4) { 'MEDIUM' } else { 'LOW' }
        [pscustomobject]@{ PID = $b.PID; Name = $b.Name; Path = $b.Path; Score = $score; Verdict = $verdict; Evidence = ($evidence -join '; '); Flags = $b.Flags; Signer = $b.Signer }
    }

    Out-Flash ("PROCESS ANOMALIES : {0} flagged of {1} processes" -f $sigChecked.Count, $procs.Count) $(if ($sigChecked.Count) { 'Yellow' } else { 'Green' })
    foreach ($s in ($scored | Sort-Object Score -Descending | Select-Object -First 10)) {
        $c = if ($s.Verdict -eq 'HIGH') { 'Red' } elseif ($s.Verdict -eq 'MEDIUM') { 'Yellow' } else { 'DarkYellow' }
        Out-Flash ("    [{0,-6} {1}] {2} (PID {3})  {4}" -f $s.Verdict, $s.Score, $s.Name, $s.PID, $s.Evidence) $c
    }
    if ($sigChecked.Count -gt 10) { Out-Flash "    ... and $($sigChecked.Count - 10) more (see flash_process_scored.csv)" 'DarkGray' }

    Out-Flash ("ESTABLISHED CONNS : {0} total, {1} to PUBLIC IPs" -f $est.Count, $ext.Count) $(if ($ext.Count) { 'Yellow' } else { 'Gray' })
    $shown = @{}
    foreach ($c in ($ext | Sort-Object ProcessPath | Select-Object -First 12)) {
        $key = "$($c.RemoteAddress):$($c.RemotePort)"
        if (-not $shown[$key]) {
            $shown[$key] = $true
            $pname = if ($c.ProcessPath) { Split-Path $c.ProcessPath -Leaf } else { "PID $($c.PID)" }
            Out-Flash "    $key  <- $pname" 'Yellow'
        }
    }

    $suspDns = @($dns | Where-Object { $_.PSObject.Properties['Entry'] -and ($_.Entry.Length -gt 30 -or "$($_.Entry)" -match '^\w{20,}\.') })
    Out-Flash ("DNS CACHE         : {0} entries ({1} long-name suspects)" -f $dns.Count, $suspDns.Count) $(if ($suspDns.Count) { 'Yellow' } else { 'Gray' })

    $arp = Get-ArpRows
    Out-Flash ("ARP NEIGHBORS     : {0} hosts seen at network layer" -f $arp.Count) 'Gray'

    $smbMaps = @(); $smbHosted = @(); $cmdKeys = @()
    try { if (Get-Command Get-SmbMapping -ErrorAction SilentlyContinue) { $smbMaps = @(Get-SmbMapping) } } catch { }
    try { if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { $smbHosted = @(Get-SmbShare) } } catch { }
    $cmdOut = & cmdkey.exe /list 2>$null
    $cmdKeys = @($cmdOut | Select-String -Pattern 'Target:' | ForEach-Object { ($_ -replace '.*Target:\s*', '').Trim() })
    Out-Flash ("SMB               : hosts {0} shares, mounts {1} remote, saved creds: {2}" -f $smbHosted.Count, $smbMaps.Count, $cmdKeys.Count) 'Gray'
    foreach ($k in ($cmdKeys | Select-Object -First 5)) { Out-Flash "    cred: $k" 'DarkYellow' }

    $users = & quser.exe 2>$null
    $uCount = [Math]::Max(0, (@($users | Where-Object { $_ -match '\S' }).Count - 1))
    Out-Flash ("LOGGED-ON USERS   : {0}" -f $uCount) 'Gray'

    $lastDet = ''
    try {
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            $d = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
            if ($d) { $lastDet = $d.InitialDetectionTime }
        }
    } catch { }
    if ($lastDet) {
        Out-Flash ("DEFENDER          : LAST DETECTION $lastDet  <<< INVESTIGATE" ) 'Red'
    } else {
        Out-Flash "DEFENDER          : no detections on record (or service absent)" 'Gray'
    }

    if ($iocs) {
        if ($iocHits.Count -gt 0) {
            Out-Flash ("IOC HITS          : {0} MATCHES !!!" -f $iocHits.Count) 'Red'
            foreach ($h in ($iocHits | Select-Object -First 10)) {
                Out-Flash ("    [{0}] {1}  @  {2}" -f $h.Type, $h.Indicator, $h.Where) 'Red'
            }
        } else {
            Out-Flash ("IOC CHECK         : 0 hits against {0} hashes / {1} IPs / {2} domains" -f $iocs.Hashes.Count, $iocs.Ips.Count, $iocs.Domains.Count) 'Green'
        }
    } else {
        Out-Flash "IOC CHECK         : no iocs.txt in tools\ (add one for instant matching)" 'DarkGray'
    }

    $sw.Stop()
    Out-Flash "==============================================================" 'Cyan'
    Out-Flash ("  Flash complete in {0:N1}s - full data in csv\ + raw\" -f $sw.Elapsed.TotalSeconds) 'Cyan'
    Out-Flash "==============================================================" 'Cyan'

    $flashTxt = Join-Path $CaseDir 'flash_summary.txt'
    $script:FlashLines | Set-Content -LiteralPath $flashTxt -Encoding UTF8
    Save-Rows -Name 'flash_process_scored' -Rows $scored
    Save-Rows -Name 'flash_ioc_hits' -Rows $iocHits
    Save-Rows -Name 'flash_public_connections' -Rows $ext
}

function Get-UserProfileList {
    $rows = @()
    try {
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($k in (Get-ChildItem $pl -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            if ($p.ProfileImagePath -and $k.PSChildName -match '^S-1-5-21-') {
                $rows += [pscustomobject]@{ Sid = $k.PSChildName; Path = "$($p.ProfileImagePath)"; User = (Split-Path "$($p.ProfileImagePath)" -Leaf) }
            }
        }
    } catch { }
    return $rows
}

function ConvertTo-Rot13 {    param([string]$s)
    ($s.ToCharArray() | ForEach-Object {
        $c = [int]$_; $l = $c -band 0x20
        if ((($c -bor $l) -ge 97) -and (($c -bor $l) -le 122)) {
            [char]((($c -band 0x1f) + 12) % 26 + 1 + 96 -bor $l)
        } else { $_ }
    }) -join ''
}

function Get-UserAssistRows {
    $rows = @()
    try {
        $uaGuids = @('CEBFF5CD-ACE2-4F4F-9178-9926F41749EA', 'F4E57C4B-2036-45F0-A9AB-443BCFE33D9F', 'A3D5339B-DEB5-46E8-AAB2-6C05EA7D1FA5', 'B267E3AD-A825-4F92-B35C-9FBF72F7E4D6', 'F2A1CB5A-E3AB-4A3B-9DDC-DF1D2F65C0E1')
        $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
        foreach ($sid in $sids) {
            $user = $sid.PSChildName
            foreach ($g in $uaGuids) {
                $k = "Registry::HKEY_USERS\$user\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\$g\Count"
                if (Test-Path $k) {
                    $prop = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    if ($prop) {
                        foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                            $name = ConvertTo-Rot13 $p.Name
                            $count = ''; $last = ''
                            try {
                                $v = $p.Value
                                if ($v -is [byte[]] -and $v.Length -ge 68) {
                                    $count = [BitConverter]::ToInt32($v, 4)
                                    $ft = [BitConverter]::ToInt64($v, 60)
                                    if ($ft -gt 0) { $last = [DateTime]::FromFileTime($ft) }
                                }
                            } catch { }
                            $rows += [pscustomobject]@{ User = $user; Guid = $g; Entry = $name; RunCount = $count; LastRun = $last }
                        }
                    }
                }
            }
        }
    } catch { }
    return $rows
}

function Invoke-NativeTool {
    param([string]$ExePath, [string[]]$ToolArgs, [string]$WorkingDir = '', [switch]$QuietLog, [switch]$CaptureOut)
    $out = ''; $err = ''
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ExePath
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.Arguments = (@($ToolArgs) | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } }) -join ' '
        if ($WorkingDir) { $psi.WorkingDirectory = $WorkingDir }
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        $null = $p.Start()
        $tOut = $p.StandardOutput.ReadToEndAsync()
        $tErr = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        $out = "$($tOut.Result)"
        $err = "$($tErr.Result)"
        if (-not $QuietLog) {
            foreach ($block in @($out, $err)) {
                if ($block) {
                    ($block -split "`r?`n") | Select-Object -Last 40 | Where-Object { $_ } | ForEach-Object {
                        Write-CaseLog "      $(($_ -replace ([char]27 + '\[[0-9;]*m'), ''))" 'DarkGray'
                    }
                }
            }
        }
        if ($CaptureOut) { return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $out; StdErr = $err } }
        return $p.ExitCode
    } catch {
        Write-CaseLog "      native tool launch failed: $($_.Exception.Message)" 'DarkYellow'
        return -1
    }
}

function Get-DotNetRelease {
    # Endpoint .NET inventory - EZ parsers need .NET 4.x; SQLECmd needs the .NET 9 desktop runtime.
    $parts = @()
    try {
        $r = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction Stop).Release
        $v = '4.6+'
        foreach ($k in @(533320, 528040, 461808, 461308, 460798, 394802)) {
            if ($r -ge $k) { $v = @{ 533320 = '4.8.1'; 528040 = '4.8'; 461808 = '4.7.2'; 461308 = '4.7.1'; 460798 = '4.7'; 394802 = '4.6.2' }[$k]; break }
        }
        $parts += ".NET Framework $v (release $r)"
    } catch { $parts += '.NET Framework: not detected' }
    $nine = $false
    try {
        $dn = Get-Command dotnet.exe -ErrorAction SilentlyContinue
        if ($dn) { $nine = @((& dotnet.exe --list-runtimes 2>$null) | Where-Object { "$_" -match 'WindowsDesktop\.App 9\.' }).Count -gt 0 }
    } catch { }
    $parts += if ($nine) { '.NET 9 desktop runtime: present' } else { '.NET 9 desktop runtime: absent' }
    return ($parts -join '; ')
}

function Invoke-BrowserIocXref {
    # Cross-checks parsed browser history against the IOC domain list (module 8.7 and -Mode Parse).
    $iocs = Get-IocList
    if (-not $iocs -or $iocs.Domains.Count -eq 0) { return }
    $hist = Import-CaseCsv 'browser_history'
    $hits = @()
    foreach ($r in $hist) {
        $u = "$($r.URL)"
        if (-not $u) { continue }
        $hm = [regex]::Match($u, '^(?i)https?://([^/:]+)')
        if (-not $hm.Success) { continue }
        $host2 = $hm.Groups[1].Value.ToLower()
        foreach ($k in $iocs.Domains.Keys) {
            if ($host2 -eq $k -or $host2.EndsWith(".$k")) {
                $hits += [pscustomobject]@{ Indicator = $k; Host = $host2; URL = $u; Title = "$($r.URLTitle)"; Match = 'browser-history' }
                break
            }
        }
    }
    Save-Rows -Name 'ioc_hits_browser' -Rows $hits
    if (@($hits).Count -gt 0) { Write-CaseLog "    BROWSER IOC HITS: $(@($hits).Count) domain(s) from your IOC list in browser history -> csv\ioc_hits_browser.csv" 'Red' }
}

function Get-ParseNeeds {
    # For every expected artifact that is missing, say WHY and how to finish it
    # (endpoint-only source vs analyst-side re-parse via -Mode Parse).
    $dn = Get-DotNetRelease
    $nineOk = "$dn" -match '9 desktop runtime: present'
    $caps = @(
        @{ Artifact = 'amcache.csv';            Parser = 'AmcacheParser'; Net = 'net4'; Input = 'registry\Amcache.hve'; Live = $false }
        @{ Artifact = 'recyclebin.csv';         Parser = 'RBCmd';         Net = 'net4'; Input = 'recyclebin';           Live = $false }
        @{ Artifact = 'prefetch_parsed.csv';    Parser = 'PECmd';         Net = 'net4'; Input = 'prefetch';             Live = $false }
        @{ Artifact = 'lnk_parsed.csv';         Parser = 'LECmd';         Net = 'net4'; Input = 'recent';               Live = $false }
        @{ Artifact = 'jumplist_parsed*.csv';   Parser = 'JLECmd';        Net = 'net4'; Input = 'jumplists';            Live = $false }
        @{ Artifact = 'browser_history.csv';    Parser = 'SQLECmd';       Net = 'net9'; Input = 'browser';              Live = $false }
        @{ Artifact = 'execution_timeline.csv'; Parser = 'chainsaw';      Net = 'none'; Input = 'registry\SYSTEM.hiv';  Live = $false }
        @{ Artifact = 'hayabusa_timeline.csv';  Parser = 'hayabusa';      Net = 'none'; Input = 'evtx';                 Live = $false }
        @{ Artifact = 'shellbags.csv';          Parser = 'SBECmd';        Net = 'net4'; Input = 'live C:\Users';        Live = $true }
        @{ Artifact = 'mft_recent.csv';         Parser = 'MFTECmd';       Net = 'net4'; Input = 'live volume (admin)';  Live = $true }
        @{ Artifact = 'recentfilecache.csv';    Parser = 'AppCompatParser'; Net = 'net4'; Input = 'extras\appcompat';   Live = $false }
    )
    $rows = @()
    foreach ($c in $caps) {
        if (Test-Path (Join-Path $CsvDir $c.Artifact)) { continue }
        if ($c.Live) { $how = 'endpoint-only source - rerun collection elevated on the host' }
        elseif (-not (Test-Path (Join-Path $RawDir $c.Input))) { $how = 'raw evidence not collected (module skipped on endpoint)' }
        elseif ($c.Net -eq 'net9' -and -not $nineOk) { $how = 'endpoint lacks .NET 9 - run on analyst PC: Ophira.ps1 -Mode Parse -Path <case>' }
        else { $how = 'tool was missing on endpoint - run on analyst PC: Ophira.ps1 -Mode Parse -Path <case>' }
        $rows += [pscustomobject]@{ Artifact = $c.Artifact; Parser = $c.Parser; DotNet = $c.Net; RawInput = $c.Input; HowToFinish = $how }
    }
    Save-Rows -Name 'parse_needed' -Rows $rows
    if ($rows.Count -gt 0) { Write-CaseLog "    $($rows.Count) artifact(s) unfinished on endpoint - see csv\parse_needed.csv (-Mode Parse completes most of them analyst-side)" 'Yellow' }
}

$script:SharedFunctions = @(
    'Get-KitRoot', 'Get-ToolsDir', 'Copy-LockedFile', 'Get-LogStart', 'Get-IocList', 'Test-TrustedPublisher',
    'Save-Rows', 'Out-RawText', 'Invoke-ExeCapture', 'Invoke-NativeTool', 'Get-WmiOrCim', 'Convert-WmiDate',
    'Test-IsPublicIp', 'Test-IsUserWritablePath', 'Get-SignatureInfo', 'Get-SysmonState',
    'Get-UserProfileList', 'Get-UserAssistRows', 'ConvertTo-Rot13', 'Get-FilteredEvents', 'Export-Evtx',
    'Import-CaseCsv', 'Invoke-BrowserIocXref', 'Get-EventDataRows', 'Get-IisW3cRows', 'Get-StartupInfoRows', 'Get-WerReportRows'
)

$script:ModuleWorkerText = @'
param($PreambleText, $ModuleDef)
Invoke-Expression $PreambleText
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$err = ''
try {
    $sb = [scriptblock]::Create($ModuleDef.RunText)
    & $sb
} catch { $err = $_.Exception.Message }
$sw.Stop()
return [pscustomobject]@{ Id = $ModuleDef.Id; Name = $ModuleDef.Name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Error = $err }
'@

function New-WorkerPreamble {
    param([string]$WorkerLog)
    $sb = New-Object System.Text.StringBuilder
    foreach ($fn in $script:SharedFunctions) {
        $def = Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue
        if ($def) {
            [void]$sb.AppendLine("function $fn {")
            [void]$sb.AppendLine($def.Definition)
            [void]$sb.AppendLine('}')
            [void]$sb.AppendLine('')
        }
    }
    $seed = @{
        CaseDir  = $CaseDir;  CsvDir = $CsvDir;  RawDir = $RawDir;  MemDir = $MemDir
        Computer = $Computer; Preset = $Preset; KitRoot = (Get-KitRoot)
    }
    foreach ($k in $seed.Keys) {
        $lit = "'" + ("$($seed[$k])" -replace "'", "''") + "'"
        [void]$sb.AppendLine("`$$k = $lit")
    }
    [void]$sb.AppendLine("`$script:LogHours = $($LogHours)")
    [void]$sb.AppendLine("`$script:LogStartDT = $(if ($script:LogStartDT) { "[datetime]'" + $script:LogStartDT.ToString('o') + "'" } else { '$null' })")
    [void]$sb.AppendLine("`$script:LogEndDT = $(if ($script:LogEndDT) { "[datetime]'" + $script:LogEndDT.ToString('o') + "'" } else { '$null' })")
    [void]$sb.AppendLine("`$script:SimpleUI = `$$([bool]$script:SimpleUI)")
    $wl = $WorkerLog -replace "'", "''"
    $override = "function Write-CaseLog { param([string]`$Message,[string]`$Color = 'Gray',[switch]`$NoConsole) Add-Content -LiteralPath '$wl' -Value (`"[{0}] {1}`" -f (Get-Date -Format 'HH:mm:ss'), `$Message) -Encoding UTF8 } "
    [void]$sb.AppendLine($override)
    return $sb.ToString()
}

function Invoke-ModuleBatch {
    param([object[]]$Batch, [int]$Workers = 4)
    $results = @()
    if (-not $Batch -or $Batch.Count -eq 0) { return $results }
    if ($Batch.Count -eq 1 -or $Sequential) {
        foreach ($m in $Batch) {
            $wlog = Join-Path $CaseDir ("worker_{0}.log" -f $m.Id)
            $pre = New-WorkerPreamble -WorkerLog $wlog
            $md = @{ Id = $m.Id; Name = $m.Name; RunText = $m.Run.ToString() }
            $ps = [powershell]::Create()
            $null = $ps.AddScript($script:ModuleWorkerText).AddArgument($pre).AddArgument($md)
            $r = $ps.Invoke() | Select-Object -First 1
            $ps.Dispose()
            if ($r) {
                $results += $r
                if ($r.Error) { Write-CaseLog ("Module {0} ({1}) ERROR: {2}" -f $r.Id, $r.Name, $r.Error) 'Red' }
                else { Write-CaseLog ("Module {0} ({1}) done in {2:N1}s [inline]" -f $r.Id, $r.Name, $r.Seconds) 'DarkGray' -NoConsole }
            }
            Merge-WorkerLog $wlog
        }
        return $results
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, $Workers)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($m in $Batch) {
        $wlog = Join-Path $CaseDir ("worker_{0}.log" -f $m.Id)
        $ps = [powershell]::Create()
        $null = $ps.AddScript($script:ModuleWorkerText).AddArgument((New-WorkerPreamble -WorkerLog $wlog)).AddArgument(@{ Id = $m.Id; Name = $m.Name; RunText = $m.Run.ToString() })
        $ps.RunspacePool = $pool
        $null = $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Module = $m; Log = $wlog })
    }
    while ($jobs.Count -gt 0) {
        $doneIdx = @()
        for ($i = 0; $i -lt $jobs.Count; $i++) {
            if ($jobs[$i].Handle.IsCompleted) { $doneIdx += $i }
        }
        foreach ($i in ($doneIdx | Sort-Object -Descending)) {
            $j = $jobs[$i]
            try {
                $r = @($j.PS.EndInvoke($j.Handle)) | Select-Object -First 1
                if ($r) {
                    $results += $r
                    if ($r.Error) { Write-CaseLog ("Module {0} ({1}) ERROR: {2}" -f $r.Id, $r.Name, $r.Error) 'Red' }
                    else { Write-CaseLog ("Module {0} ({1}) done in {2:N1}s" -f $r.Id, $r.Name, $r.Seconds) 'DarkGray' -NoConsole }
                }
            } catch { Write-CaseLog ("Module {0} worker failed: {1}" -f $j.Module.Id, $_.Exception.Message) 'Red' }
            $j.PS.Dispose()
            Merge-WorkerLog $j.Log
            $jobs.RemoveAt($i)
        }
        if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 300 }
    }
    $pool.Close()
    $pool.Dispose()
    return $results
}

function Merge-WorkerLog {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        try {
            $lines = Get-Content -LiteralPath $Path
            if ($lines) { Add-Content -LiteralPath $CaseLog -Value $lines -Encoding UTF8 }
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        } catch { }
    }
}

$script:Modules = @(
    [pscustomobject]@{ Id = '1.1'; Cat = 'VOLATILE'; Name = 'Processes (path, cmdline, company, parent, flags)'; Default = $true; Quick = $true;
        Run = {
            $rows = Get-ProcessInventory
            Save-Rows -Name 'processes' -Rows $rows
            $flagged = @($rows | Where-Object { $_.Flags })
            Save-Rows -Name 'processes_flagged' -Rows $flagged
        } }
    [pscustomobject]@{ Id = '1.2'; Cat = 'VOLATILE'; Name = 'Full process SHA256 hashing (slower)'; Default = $false; Quick = $false;
        Run = {
            $rows = Get-ProcessInventory | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) } | Select-Object -ExpandProperty Path -Unique
            $hashed = foreach ($p in $rows) {
                try {
                    $h = Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop
                    [pscustomobject]@{ Path = $p; SHA256 = $h.Hash }
                } catch { [pscustomobject]@{ Path = $p; SHA256 = 'ERROR' } }
            }
            Save-Rows -Name 'process_hashes' -Rows $hashed
        } }
    [pscustomobject]@{ Id = '1.3'; Cat = 'VOLATILE'; Name = 'Network connections (TCP/UDP with process map)'; Default = $true; Quick = $true;
        Run = {
            $rows = Get-ConnectionTable
            Save-Rows -Name 'connections' -Rows $rows
            $ext = @($rows | Where-Object { $_.Public -and $_.State -match 'Established|SynSent' })
            Save-Rows -Name 'connections_public_established' -Rows $ext
        } }
    [pscustomobject]@{ Id = '1.4'; Cat = 'VOLATILE'; Name = 'DNS cache + ARP table'; Default = $true; Quick = $true;
        Run = {
            Save-Rows -Name 'dns_cache' -Rows (Get-DnsCacheRows)
            Save-Rows -Name 'arp_table' -Rows (Get-ArpRows)
        } }
    [pscustomobject]@{ Id = '1.5'; Cat = 'VOLATILE'; Name = 'Logon sessions (quser/qwinsta/klist raw)'; Default = $true; Quick = $true;
        Run = {
            Invoke-ExeCapture -SubDir 'sessions' -Name 'quser.txt' -Exe quser.exe -Arguments ''
            Invoke-ExeCapture -SubDir 'sessions' -Name 'qwinsta.txt' -Exe qwinsta.exe -Arguments ''
            Invoke-ExeCapture -SubDir 'sessions' -Name 'klist.txt' -Exe klist.exe -Arguments ''
            $sess = Get-WmiOrCim -Class Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, Authentication
            Save-Rows -Name 'logon_sessions' -Rows $sess
        } }
    [pscustomobject]@{ Id = '1.6'; Cat = 'VOLATILE'; Name = 'Kernel drivers'; Default = $true; Quick = $false;
        Run = {
            $d = Get-WmiOrCim -Class Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, StartMode
            Save-Rows -Name 'drivers' -Rows $d
            Save-Rows -Name 'drivers_flagged' -Rows @($d | Where-Object { Test-IsUserWritablePath "$($_.PathName)" })
            Invoke-ExeCapture -SubDir 'drivers' -Name 'driverquery_v.csv' -Exe driverquery.exe -Arguments '/v /fo csv'
        } }
    [pscustomobject]@{ Id = '1.7'; Cat = 'VOLATILE'; Name = 'Svchost masquerade audit (live -k groups vs registered ServiceDlls)'; Default = $true; Quick = $true;
        Run = {
            # Live svchost -k groups must exist in HKLM:\...\Svchost, and every service in a
            # registered group must carry a ServiceDll. Anything else is a masquerade/persistence
            # tell (svchost.exe is the favorite disguise because it is always running anyway).
            $rows = New-Object System.Collections.Generic.List[object]
            $grpMap = @{}
            $svk = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' -ErrorAction SilentlyContinue
            if ($svk) {
                foreach ($p in ($svk.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                    $grpMap["$($p.Name)"] = @($p.Value)
                }
            }
            $svcDll = @{}
            foreach ($g in @($grpMap.Keys)) {
                foreach ($svc in $grpMap[$g]) {
                    $s = "$svc"
                    if ($s -and -not $svcDll.ContainsKey($s)) {
                        # $null = no Parameters key at all (stock Windows does this, e.g. nsi - not a tell)
                        $dll = $null
                        $parKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$s\Parameters"
                        if (Test-Path -LiteralPath $parKey) {
                            $dll = ''
                            try { $dll = "$((Get-ItemProperty -Path $parKey -Name ServiceDll -ErrorAction Stop).ServiceDll)" } catch { }
                        }
                        $svcDll[$s] = $dll
                    }
                }
            }
            $procs = @()
            try { $procs = @(Get-WmiOrCim -Class Win32_Process | Where-Object { "$($_.Name)" -match '(?i)^svchost\.exe$' }) } catch { }
            $seen = @{}
            foreach ($p in $procs) {
                $grp = ''
                if ("$($p.CommandLine)" -match '\-k\s+(\S+)') { $grp = $Matches[1] }
                if (-not $grp) { continue }
                if (-not $grpMap.ContainsKey($grp)) {
                    $key = "UnregisteredGroup|$grp"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $null = $rows.Add([pscustomobject]@{ Type = 'UnregisteredGroup'; Group = $grp; Service = ''; PID = $p.ProcessId; Path = ''; Detail = "svchost running with -k $grp but that group is not registered in the Svchost registry key (masquerade tell)" })
                    continue
                }
                foreach ($svc in $grpMap[$grp]) {
                    $dll = $svcDll["$svc"]
                    if ($null -eq $dll) { continue }
                    if (-not $dll) {
                        $key = "ServiceDllMissing|$grp|$svc"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        $null = $rows.Add([pscustomobject]@{ Type = 'ServiceDllMissing'; Group = $grp; Service = "$svc"; PID = ''; Path = ''; Detail = "service in group '$grp' has a Parameters key but no ServiceDll value (broken or tampered registration)" })
                        continue
                    }
                    if ("$dll" -notmatch '(?i)\\(System32|SysWOW64)\\') {
                        $key = "OutOfPathServiceDll|$svc"
                        if ($seen.ContainsKey($key)) { continue }
                        $seen[$key] = $true
                        $null = $rows.Add([pscustomobject]@{ Type = 'OutOfPathServiceDll'; Group = $grp; Service = "$svc"; PID = ''; Path = $dll; Detail = "ServiceDll outside System32 - svchost-hosted persistence in a user-writable location" })
                    }
                }
            }
            # unregistered loaded modules (live; needs elevation - degrades silently without)
            $regDlls = @{}
            foreach ($v in $svcDll.Values) {
                if (-not $v) { continue }
                $lf = ''
                try { $lf = (Split-Path "$v" -Leaf).ToLower() } catch { }
                if ($lf) { $regDlls[$lf] = $true }
            }
            foreach ($p in $procs) {
                if (-not $p.ProcessId -or $seen.Count -gt 40) { continue }
                $mods = $null
                try { $mods = (Get-Process -Id $p.ProcessId -ErrorAction Stop).Modules } catch { continue }
                foreach ($m in $mods) {
                    $lf = ''
                    try { $lf = "$($m.FileName)" } catch { continue }
                    if (-not $lf) { continue }
                    $leaf = ''
                    try { $leaf = (Split-Path $lf -Leaf).ToLower() } catch { continue }
                    if (-not $leaf -or $regDlls.ContainsKey($leaf)) { continue }
                    if ("$lf" -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') { continue }
                    $sig = Get-SignatureInfo -Path $lf
                    if ($sig -and "$($sig.Signer)" -match 'Microsoft') { continue }
                    $key = "UnregisteredModule|$lf"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true
                    $null = $rows.Add([pscustomobject]@{ Type = 'UnregisteredModule'; Group = ''; Service = ''; PID = $p.ProcessId; Path = $lf; Detail = "unsigned/non-Microsoft DLL loaded inside svchost that is not a registered ServiceDll" })
                    if ($seen.Count -gt 40) { break }
                }
            }
            Save-Rows -Name 'svchost_audit' -Rows $rows.ToArray()
            $hot = @($rows | Where-Object { "$($_.Type)" -match 'UnregisteredGroup|OutOfPathServiceDll' }).Count
            if ($rows.Count -gt 0) {
                Write-CaseLog "    svchost audit: $($rows.Count) finding(s) ($hot high-tell) -> csv\svchost_audit.csv" $(if ($hot -gt 0) { 'Red' } else { 'Yellow' })
            } else {
                Write-CaseLog '    svchost audit: all live -k groups registered, ServiceDlls in place' 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '2.1'; Cat = 'PERSISTENCE'; Name = 'Autoruns (Run keys + startup folders)'; Default = $true; Quick = $true;
        Run = {
            $rows = @()
            $runPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            )
            foreach ($rp in $runPaths) {
                if (Test-Path $rp) {
                    $prop = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
                    foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $rows += [pscustomobject]@{ Location = $rp; Hive = 'HKLM'; User = ''; Name = $p.Name; Value = "$($p.Value)" }
                    }
                }
            }
            try {
                $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
                foreach ($sid in $sids) {
                    foreach ($sub in @('Run', 'RunOnce')) {
                        $k = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\$sub"
                        if (Test-Path $k) {
                            $prop = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                            foreach ($p in ($prop.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                                $rows += [pscustomobject]@{ Location = $k; Hive = 'HKU'; User = $sid.PSChildName; Name = $p.Name; Value = "$($p.Value)" }
                            }
                        }
                    }
                }
            } catch { }
            Save-Rows -Name 'autoruns_runkeys' -Rows $rows
            $startups = @()
            $dirs = @()
            try {
                $dirs += [Environment]::GetFolderPath('CommonStartup')
                $dirs += [Environment]::GetFolderPath('Startup')
            } catch { }
            foreach ($d in ($dirs | Where-Object { $_ -and (Test-Path $_) })) {
                Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $s = Get-SignatureInfo -Path $_.FullName
                    $startups += [pscustomobject]@{ Folder = $d; File = $_.Name; Created = $_.CreationTime; SigStatus = if ($s) { $s.Status } else { '' }; Signer = if ($s) { $s.Signer } else { '' } }
                }
            }
            Save-Rows -Name 'autoruns_startup_folders' -Rows $startups
        } }
    [pscustomobject]@{ Id = '2.2'; Cat = 'PERSISTENCE'; Name = 'Services (with odd-path flags)'; Default = $true; Quick = $true;
        Run = {
            $s = Get-WmiOrCim -Class Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName, ProcessId
            foreach ($row in $s) {
                $exe = ''
                try { if ($row.PathName) { $exe = ($row.PathName -replace '^"([^"]+)".*$', '$1') -replace '^(\S+\.exe).*$', '$1' } } catch { }
                $row | Add-Member -NotePropertyName Flags -NotePropertyValue ($(if (Test-IsUserWritablePath $row.PathName) { 'USER-WRITABLE-PATH;' }) + $(if ($exe -and (Test-Path -LiteralPath $exe) -eq $false) { 'BINARY-MISSING;' })) -Force
            }
            Save-Rows -Name 'services' -Rows $s
            Save-Rows -Name 'services_flagged' -Rows @($s | Where-Object { $_.Flags })
        } }
    [pscustomobject]@{ Id = '2.3'; Cat = 'PERSISTENCE'; Name = 'Scheduled tasks (non-MS authors flagged)'; Default = $true; Quick = $true;
        Run = {
            if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                Invoke-ExeCapture -SubDir 'tasks' -Name 'schtasks_all.csv' -Exe schtasks.exe -Arguments '/query /fo csv /v'
                return
            }
            $rows = @()
            foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                $actions = ($t.Actions | ForEach-Object { $a = "$($_.Execute) $($_.Arguments)".Trim(); $a }) -join ' || '
                $triggers = (@($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ';')
                $author = ''
                try { $author = $t.Author } catch { }
                $flags = @()
                if ($author -and $author -notmatch '(?i)microsoft') { $flags += 'NON-MS-AUTHOR' }
                if ($actions -match '(?i)powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|curl|wget') { $flags += 'SUSPICIOUS-INTERPRETER' }
                if (Test-IsUserWritablePath $actions) { $flags += 'USER-WRITABLE-PATH' }
                $rows += [pscustomobject]@{
                    Name = $t.TaskName; Path = $t.TaskPath; Author = $author; State = $t.State
                    Actions = $actions; Triggers = $triggers; RunAs = $t.Principal.UserId
                    Flags = ($flags -join ';')
                }
            }
            Save-Rows -Name 'scheduled_tasks' -Rows $rows
            Save-Rows -Name 'scheduled_tasks_flagged' -Rows @($rows | Where-Object { $_.Flags })
        } }
    [pscustomobject]@{ Id = '2.4'; Cat = 'PERSISTENCE'; Name = 'WMI event subscriptions'; Default = $true; Quick = $false;
        Run = {
            $filters = Get-WmiOrCim -Class '__EventFilter' -Namespace 'root\subscription'
            $consumers = @()
            foreach ($cn in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'LogFileEventConsumer')) {
                try {
                    $c = Get-CimInstance -Namespace 'root\subscription' -ClassName $cn -ErrorAction Stop
                    foreach ($x in $c) {
                        $cmd = ''
                        try { $cmd = $x.CommandLineTemplate } catch { }
                        if (-not $cmd) { try { $cmd = $x.ScriptText } catch { } }
                        if (-not $cmd) { try { $cmd = $x.Text } catch { } }
                        $consumers += [pscustomobject]@{ Type = $cn; Name = $x.Name; Payload = $cmd }
                    }
                } catch { }
            }
            $bindings = @()
            try { $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop } catch { }
            Save-Rows -Name 'wmi_event_filters' -Rows $filters
            Save-Rows -Name 'wmi_event_consumers' -Rows $consumers
            Save-Rows -Name 'wmi_bindings' -Rows $bindings
        } }
    [pscustomobject]@{ Id = '2.6'; Cat = 'PERSISTENCE'; Name = 'ASEP deep sweep (IFEO, AppInit, Winlogon, COM hijacks, netsh, LSA, StartupApproved)'; Default = $true; Quick = $false;
        Run = {
            $asepList = New-Object System.Collections.Generic.List[object]
            function Add-Asep([string]$Category, [string]$Location, [string]$Name, [string]$Value, [string[]]$Flags) {
                $asepList.Add([pscustomobject]@{ Category = $Category; Location = $Location; Name = $Name; Value = $Value; Flags = ($Flags -join ';') })
            }
            $flagFor = {
                param([string]$v)
                $f = @()
                if ($v -and (Test-IsUserWritablePath $v)) { $f += 'user-path' }
                return $f
            }
            # IFEO: any Debugger value (incl. accessibility sticky-keys backdoors)
            foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
                if (Test-Path $hive) {
                    foreach ($k in (Get-ChildItem -Path $hive -ErrorAction SilentlyContinue)) {
                        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                        foreach ($vn in @('Debugger', 'GlobalFlag', 'MonitorProcess', 'SilentProcessExit')) {
                            $v = $null; try { $v = $p.$vn } catch { }
                            if ("$v") { Add-Asep 'IFEO' $k.PSPath $vn "$v" (& $flagFor "$v") }
                        }
                    }
                }
            }
            # AppInit_DLLs (32/64)
            foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
                $p = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue
                if ($p) {
                    $v = "$($p.AppInit_DLLs)"
                    if ($v.Trim()) { Add-Asep 'AppInit_DLLs' $hive 'AppInit_DLLs' $v ((& $flagFor $v) + 'nondefault') }
                }
            }
            # Winlogon core values (Shell/Userinit/Taskman/AppSetup replaced or appended)
            $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
            if ($wl) {
                foreach ($vn in @('Shell', 'Userinit', 'Taskman', 'AppSetup')) {
                    $v = $null; try { $v = $wl.$vn } catch { }
                    if (-not "$v") { continue }
                    $ok = $false
                    $entries = @("$v" -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    if ($vn -eq 'Shell') { $ok = ($entries -contains 'explorer.exe') }
                    elseif ($vn -eq 'Userinit') { $ok = (@($entries | Where-Object { $_ -notmatch '(?i)userinit\.exe$' }).Count -eq 0) }
                    $f = @()
                    if (-not $ok) { $f += 'nondefault' }
                    $f += (& $flagFor "$v")
                    if ($f.Count -gt 0) { Add-Asep 'Winlogon' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' $vn "$v" $f }
                }
            }
            # WinlogonNotify DLLs
            $notify = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
            if (Test-Path $notify) {
                foreach ($k in (Get-ChildItem -Path $notify -ErrorAction SilentlyContinue)) {
                    $v = "$((Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue).DLLName)"
                    if ($v) { Add-Asep 'WinlogonNotify' $k.PSPath 'DLLName' $v (& $flagFor $v) }
                }
            }
            # netsh helper DLLs
            $netsh = 'HKLM:\SOFTWARE\Microsoft\Netsh'
            if (Test-Path $netsh) {
                foreach ($k in (Get-ChildItem -Path $netsh -ErrorAction SilentlyContinue)) {
                    $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $v = "$($prop.Value)"
                        if ($v -match '\.dll') { Add-Asep 'NetshHelper' $k.PSPath $prop.Name $v (& $flagFor $v) }
                    }
                }
            }
            # LSA security/authentication packages (DLL list values)
            $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
            if ($lsa) {
                foreach ($vn in @('Security Packages', 'Authentication Packages', 'Notification Packages')) {
                    $v = $null; try { $v = $lsa.$vn } catch { }
                    if ("$v") {
                        $f = @()
                        foreach ($dll in @("$v" -split '[,; ]+' | Where-Object { $_ })) { if (Test-IsUserWritablePath $dll) { $f += "user-path($dll)" } }
                        Add-Asep 'LsaPackages' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' $vn "$v" $f
                    }
                }
            }
            # HKCU COM InprocServer32 entries (per-user COM hijack suspects)
            try {
                $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
                foreach ($sid in $sids) {
                    $clsidRoot = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Classes\CLSID"
                    if (-not (Test-Path $clsidRoot)) { continue }
                    foreach ($clsid in (Get-ChildItem -Path $clsidRoot -ErrorAction SilentlyContinue | Select-Object -First 4000)) {
                        $ips = "$($clsid.PSPath)\InprocServer32"
                        if (Test-Path $ips) {
                            $v = "$((Get-ItemProperty -Path $ips -ErrorAction SilentlyContinue).'(default)')"
                            if ($v -and $v -notmatch '^[Hh]ttp') {
                                $f = & $flagFor $v
                                if ($f) { Add-Asep 'ComHijack-HKCU' $ips "$($clsid.PSChildName)" $v $f }
                            }
                        }
                    }
                }
            } catch { }
            # StartupApproved stamps (enabled/disabled per autorun entry)
            foreach ($root in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved')) {
                if (-not (Test-Path $root)) { continue }
                $hiveName = if ($root -like 'HKCU:*') { 'HKCU' } else { 'HKLM' }
                foreach ($sub in @('Run', 'RunOnce', 'StartupFolder')) {
                    $k = "$root\$sub"
                    if (-not (Test-Path $k)) { continue }
                    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                        $bytes = $null; try { $bytes = $prop.Value } catch { }
                        $state = 'unknown'
                        if ($bytes -is [byte[]] -and $bytes.Count -gt 0) {
                            if (@(2, 3) -contains $bytes[0]) { $state = 'enabled' } elseif (@(6, 7, 13) -contains $bytes[0]) { $state = 'disabled' }
                        }
                        Add-Asep 'StartupApproved' $k $prop.Name $state @()
                    }
                }
            }
            # Custom shim databases (SDB) - classic persistence, rare legit (v2.23 KAPE parity)
            foreach ($sdb in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB', 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom')) {
                if (-not (Test-Path $sdb)) { continue }
                foreach ($k in (Get-ChildItem -Path $sdb -Recurse -ErrorAction SilentlyContinue)) {
                    $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                    $v = ''
                    if ($p -and $p.PSObject.Properties['FullPath']) { $v = "$($p.FullPath)" }
                    if (-not $v) { foreach ($prop in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) { if ("$($prop.Value)" -match '\.sdb$') { $v = "$($prop.Value)"; break } } }
                    if ($v) { Add-Asep 'Sdb' $k.PSPath $k.PSChildName $v (& $flagFor $v) }
                }
            }
            $rows = $asepList.ToArray()
            Save-Rows -Name 'asep_sweep' -Rows $rows
            $hot = @($rows | Where-Object { $_.Flags -match 'user-path|nondefault' })
            if ($hot.Count -gt 0) {
                Write-CaseLog "    ASEP sweep: $($rows.Count) entries, $($hot.Count) UNCOMMON/USER-PATH (IFEO/AppInit/COM/netsh/LSA) -> csv\asep_sweep.csv" 'Red'
                foreach ($h in ($hot | Select-Object -First 5)) { Write-CaseLog "      [$($h.Category)] $($h.Name) = $($h.Value)" 'Red' }
            } else {
                Write-CaseLog "    ASEP sweep: $($rows.Count) entries, none flagged" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '3.1'; Cat = 'NETWORK MAP'; Name = 'Passive map (interfaces, routes, SMB, creds, proxy)'; Default = $true; Quick = $true;
        Run = {
            $net = @()
            try {
                if (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
                    foreach ($i in (Get-NetIPConfiguration)) {
                        $net += [pscustomobject]@{
                            Interface = $i.InterfaceAlias; Description = $i.InterfaceDescription
                            IPv4 = (@($i.IPv4Address | ForEach-Object { $_.IPAddress }) -join ',')
                            Gateway = (@($i.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ',')
                            DNS = (@($i.DNSServer | ForEach-Object { $_.ServerAddresses }) -join ',')
                        }
                    }
                }
            } catch { }
            Save-Rows -Name 'net_interfaces' -Rows $net
            $routes = @()
            try {
                if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
                    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.DestinationPrefix -notmatch '^(127\.|169\.254|224\.|255\.255|0\.0\.0\.0)' } |
                        Select-Object DestinationPrefix, NextHop, RouteMetric, ifIndex -Unique)
                }
            } catch { }
            Save-Rows -Name 'net_reachable_subnets' -Rows $routes
            $hosted = @(); $mounts = @(); $active = @()
            try { if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { $hosted = @(Get-SmbShare | Select-Object Name, Path, Description, ScopeName) } } catch { }
            try { if (Get-Command Get-SmbMapping -ErrorAction SilentlyContinue) { $mounts = @(Get-SmbMapping | Select-Object LocalPath, RemotePath, Status) } } catch { }
            try { if (Get-Command Get-SmbConnection -ErrorAction SilentlyContinue) { $active = @(Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName, ShareName, UserName, NumOpens) } } catch { }
            Save-Rows -Name 'smb_hosted_shares' -Rows $hosted
            Save-Rows -Name 'smb_mounted_shares' -Rows $mounts
            Save-Rows -Name 'smb_active_connections' -Rows $active
            Invoke-ExeCapture -SubDir 'net' -Name 'cmdkey_list.txt' -Exe cmdkey.exe -Arguments '/list'
            $ck = @()
            $raw = & cmdkey.exe /list 2>$null
            $cur = $null
            foreach ($l in ($raw | ForEach-Object { "$_" })) {
                if ($l -match 'Target:(?:(Domain|Legacy)Type=)?(.+)') {
                    if ($cur) { $ck += $cur }
                    $cur = [pscustomobject]@{ Target = ($Matches[2].Trim()); Type = $Matches[1]; User = '' }
                } elseif ($l -match 'User:\s*(.+)' -and $cur) { $cur.User = $Matches[1].Trim() }
            }
            if ($cur) { $ck += $cur }
            Save-Rows -Name 'saved_credentials' -Rows $ck
            Invoke-ExeCapture -SubDir 'net' -Name 'net_use.txt' -Exe net.exe -Arguments 'use'
            Invoke-ExeCapture -SubDir 'net' -Name 'net_share.txt' -Exe net.exe -Arguments 'share'
            Invoke-ExeCapture -SubDir 'net' -Name 'ipconfig_all.txt' -Exe ipconfig.exe -Arguments '/all'
            Invoke-ExeCapture -SubDir 'net' -Name 'route_print.txt' -Exe route.exe -Arguments 'print'
            Invoke-ExeCapture -SubDir 'net' -Name 'arp_a.txt' -Exe arp.exe -Arguments '-a'
            Invoke-ExeCapture -SubDir 'net' -Name 'netstat_ano.txt' -Exe netstat.exe -Arguments '-ano'
            $proxy = @()
            foreach ($hive in @('HKLM', 'HKCU')) {
                foreach ($p in @("${hive}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings")) {
                    try {
                        $v = Get-ItemProperty -Path $p -ErrorAction Stop
                        $proxy += [pscustomobject]@{
                            Key = $hive; ProxyEnable = $v.ProxyEnable; ProxyServer = $v.ProxyServer
                            AutoConfigURL = $v.AutoConfigURL
                        }
                    } catch { }
                }
            }
            Save-Rows -Name 'proxy_settings' -Rows $proxy
            $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            if (Test-Path $hosts) { Out-RawText -SubDir 'net' -Name 'hosts.txt' -Text (Get-Content -LiteralPath $hosts) }
        } }
    [pscustomobject]@{ Id = '3.2'; Cat = 'NETWORK MAP'; Name = 'ACTIVE probes - generates outbound traffic'; Default = $false; Quick = $false;
        Run = {
            $r = @()
            $gw = $null
            try {
                $gws = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
                $gw = $gws.NextHop
            } catch { }
            if ($gw) {
                $ok = $false
                try { $ok = [bool](Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue) } catch { }
                $r += [pscustomobject]@{ Check = 'Gateway'; Target = $gw; Result = $ok }
            }
            foreach ($t in @('1.1.1.1', '8.8.8.8')) {
                $ok = $false
                try { $ok = [bool](Test-Connection -ComputerName $t -Count 1 -Quiet -ErrorAction SilentlyContinue) } catch { }
                $r += [pscustomobject]@{ Check = 'Internet-ICMP'; Target = $t; Result = $ok }
            }
            try {
                $http = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                $r += [pscustomobject]@{ Check = 'Internet-HTTP'; Target = 'msftconnecttest.com'; Result = ($http.StatusCode -eq 200) }
            } catch {
                $r += [pscustomobject]@{ Check = 'Internet-HTTP'; Target = 'msftconnecttest.com'; Result = $false }
            }
            try {
                $dnsr = Resolve-DnsName -Name 'www.microsoft.com' -ErrorAction Stop | Select-Object -First 1
                $r += [pscustomobject]@{ Check = 'DNS-Resolve'; Target = 'www.microsoft.com'; Result = ($null -ne $dnsr) }
            } catch {
                $r += [pscustomobject]@{ Check = 'DNS-Resolve'; Target = 'www.microsoft.com'; Result = $false }
            }
            Save-Rows -Name 'net_active_probes' -Rows $r
        } }
    [pscustomobject]@{ Id = '3.3'; Cat = 'NETWORK MAP'; Name = 'Firewall profiles + firewall log copy'; Default = $true; Quick = $false;
        Run = {
            $prof = @()
            try {
                if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
                    foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                        $prof += [pscustomobject]@{
                            Profile = $p.Name; Enabled = $p.Enabled
                            InboundDefault = $p.DefaultInboundAction; OutboundDefault = $p.DefaultOutboundAction
                            LogFileName = "$($p.LogFileName)"; LogMaxKB = $p.LogMaxSizeKilobytes
                        }
                    }
                } else {
                    $raw = (& netsh.exe advfirewall show allprofiles 2>$null | Where-Object { $_ }) -join "`r`n"
                    if ($raw) { Out-RawText -SubDir 'net' -Name 'firewall_profiles_netsh.txt' -Text $raw }
                }
            } catch { }
            Save-Rows -Name 'firewall_profiles' -Rows $prof
            $dst = Join-Path $RawDir 'firewall'
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            $copied = 0
            foreach ($logPath in @("$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log", "$env:SystemRoot\System32\LogFiles\Firewall\domainfw.log", "$env:SystemRoot\System32\LogFiles\Firewall\privatefw.log", "$env:SystemRoot\System32\LogFiles\Firewall\publicfw.log")) {
                if (Test-Path -LiteralPath $logPath) {
                    try { Copy-Item -LiteralPath $logPath -Destination $dst -Force -ErrorAction Stop; $copied++ } catch { }
                }
            }
            Write-CaseLog "    firewall: $($prof.Count) profile row(s), $copied log file(s) -> raw\firewall\" 'Gray'
        } }
    [pscustomobject]@{ Id = '4.1'; Cat = 'LOGS'; Name = 'Security log (auth events + evtx export)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ids = @(4624, 4625, 4648, 4672, 4720, 4722, 4724, 4726, 4728, 4732, 4735, 4756, 4688, 4698, 5140, 5145, 1102)
            $ev = Get-FilteredEvents -LogName 'Security' -Ids $ids -Start $start
            Save-Rows -Name 'security_events' -Rows $ev
            $auth = @($ev | Where-Object { @(4624, 4625) -contains $_.Id } | ForEach-Object {
                $msg = "$($_.Message)"
                # 4624/4625: the logon account/session live in the New Logon section - anchor after it
                # (Subject Logon ID is the caller's, and a Linked Logon ID may trail New Logon)
                $nlIdx = $msg.IndexOf('New Logon')
                $after = if ($nlIdx -ge 0) { $msg.Substring($nlIdx) } else { $msg }
                $names = [regex]::Matches($msg, 'Account Name:\s+([^\r\n]+)')
                $nlNames = [regex]::Matches($after, 'Account Name:\s+([^\r\n]+)')
                $acct = if ($nlNames.Count -gt 0) { $nlNames[0].Groups[1].Value.Trim() } elseif ($names.Count -gt 0) { $names[0].Groups[1].Value.Trim() } else { '' }
                $subject = if ($names.Count -gt 0) { $names[0].Groups[1].Value.Trim() } else { '' }
                $ip = if ($msg -match 'Source Network Address:\s+(\S+)') { $Matches[1] } else { '' }
                $lt = if ($msg -match 'Logon Type:\s+(\d+)') { $Matches[1] } else { '' }
                $lids = [regex]::Matches($after, 'Logon ID:\s+(0x[0-9A-Fa-f]+)')
                $lid = if ($lids.Count -gt 0) { $lids[0].Groups[1].Value.Trim() } else { '' }
                [pscustomobject]@{ Time = $_.TimeCreated; EventId = $_.Id; Account = $acct; SubjectAccount = $subject; SourceIp = $ip; LogonType = $lt; LogonId = $lid }
            })
            # account management EIDs (R6 account lifecycle) - TargetUserName-style EventData
            $acctEv = Get-EventDataRows -LogName 'Security' -Id @(4720, 4722, 4724, 4726, 4728, 4732, 4735, 4756) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'TargetUserName'; SourceIp = 'IpAddress'; LogonType = ''; LogonId = '' })
            $auth = @($auth + $acctEv)
            Save-Rows -Name 'security_auth_events' -Rows $auth
            $brute = @($auth | Where-Object { $_.EventId -eq 4625 } | Group-Object SourceIp |
                Where-Object { $_.Count -ge 5 } | Sort-Object Count -Descending |
                ForEach-Object { [pscustomobject]@{ SourceIp = $_.Name; FailedLogons = $_.Count } })
            Save-Rows -Name 'security_bruteforce_candidates' -Rows $brute
            $sum = @($auth | Group-Object Account, SourceIp | Sort-Object Count -Descending | Select-Object -First 100 |
                ForEach-Object { [pscustomobject]@{ AccountSource = $_.Name; Count = $_.Count } })
            Save-Rows -Name 'security_auth_summary' -Rows $sum
            # v2.20 structured parses (fields need audit policy: 4688 cmdline needs "Include Command Line")
            $procEv = Get-EventDataRows -LogName 'Security' -Id @(4688) -Start $start -Cap 4000 -Fields ([ordered]@{ Account = 'SubjectUserName'; LogonId = 'SubjectLogonId'; NewProcess = 'NewProcessName'; CommandLine = 'CommandLine'; ParentProcess = 'ParentProcessName' })
            Save-Rows -Name 'security_proc_events' -Rows $procEv
            if ($procEv.Count -gt 0) { Write-CaseLog "    4688 process creations: $($procEv.Count) (empty CommandLine = cmdline audit off)" 'Gray' }
            $taskEv = Get-EventDataRows -LogName 'Security' -Id @(4698) -Start $start -Cap 500 -Fields ([ordered]@{ Account = 'SubjectUserName'; TaskName = 'TaskName'; TaskContent = 'TaskContent' })
            foreach ($t in $taskEv) {
                $cmd = ''
                if ("$($t.TaskContent)" -match '<Command>([^<]+)</Command>') { $cmd = $Matches[1] }
                $t | Add-Member -NotePropertyName Command -NotePropertyValue $cmd -Force
                $t.PSObject.Properties.Remove('TaskContent')
            }
            Save-Rows -Name 'security_task_install' -Rows $taskEv
            if ($taskEv.Count -gt 0) { Write-CaseLog "    4698 scheduled task installs: $($taskEv.Count)" 'Gray' }
            $shareEv = Get-EventDataRows -LogName 'Security' -Id @(5140, 5145) -Start $start -Cap 8000 -Fields ([ordered]@{ Account = 'SubjectUserName'; LogonId = 'SubjectLogonId'; ShareName = 'ShareName'; RelativeTargetName = 'RelativeTargetName'; SourceIp = 'IpAddress'; AccessList = 'AccessList' })
            Save-Rows -Name 'security_share_access' -Rows $shareEv
            if ($shareEv.Count -ge 8000) { Write-CaseLog "    share access: capped at 8000 rows - wide file-share activity (file server?)" 'DarkGray' }
            Export-Evtx -LogName 'Security' -FileName 'Security.evtx'
        } }
    [pscustomobject]@{ Id = '4.2'; Cat = 'LOGS'; Name = 'PowerShell operational log (4104 script blocks)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4104, 400, 600) -Start $start -MaxMsg 2000
            Save-Rows -Name 'powershell_events' -Rows $ev
            Export-Evtx -LogName 'Microsoft-Windows-PowerShell/Operational' -FileName 'PowerShell_Operational.evtx'
        } }
    [pscustomobject]@{ Id = '4.3'; Cat = 'LOGS'; Name = 'Sysmon logs (auto-skips if not installed)'; Default = $true; Quick = $false;
        Run = {
            if (-not (Get-SysmonState)) { Write-CaseLog "    Sysmon not present - skipping" 'DarkGray'; return }
            $start = Get-LogStart
            $ids = @(1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 20, 21, 22, 23, 25)
            $ev = Get-FilteredEvents -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids $ids -Start $start
            Save-Rows -Name 'sysmon_events' -Rows $ev
            $net = @()
            try {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3 }
                if ($start) { $filter.StartTime = $start }
                $raw = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                foreach ($e in $raw) {
                    $x = [xml]$e.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                    $net += [pscustomobject]@{
                        Time = $e.TimeCreated; Image = $d['Image']; DestIp = $d['DestinationIp']
                        DestPort = $d['DestinationPort']; Protocol = $d['Protocol']
                    }
                }
            } catch { }
            Save-Rows -Name 'sysmon_network' -Rows $net
            $dns = @()
            try {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 22 }
                if ($start) { $filter.StartTime = $start }
                $rawD = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                foreach ($e in $rawD) {
                    $x = [xml]$e.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                    $dns += [pscustomobject]@{
                        Time = $e.TimeCreated; Image = $d['Image']; QueryName = $d['QueryName']
                        QueryResults = $d['QueryResults']; ProcessId = $d['ProcessId']
                    }
                }
            } catch { }
            Save-Rows -Name 'sysmon_dns' -Rows $dns
            # EID 7: image loads - the DLL side-load data source
            $img = @()
            try {
                $filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 7 }
                if ($start) { $filter.StartTime = $start }
                $rawI = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                foreach ($e in ($rawI | Select-Object -First 3000)) {
                    $x = [xml]$e.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
                    $img += [pscustomobject]@{
                        Time = $e.TimeCreated; Process = $d['Image']; Dll = $d['ImageLoaded']
                        Signed = $d['Signed']; Signature = $d['Signature']; Company = $d['Company']; Description = $d['Description']
                    }
                }
            } catch { }
            Save-Rows -Name 'sysmon_image_load' -Rows $img
            if ($img.Count -gt 0) { Write-CaseLog "    sysmon image loads: $($img.Count) (DLL side-load data source)" 'Gray' }
            # v2.20: EID 10 process access (LSASS-access data source), EID 13 registry (UAC-bypass/persistence), EID 2 file time (timestomping)
            $pa = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(10) -Start $start -Cap 3000 -Fields ([ordered]@{ SourceImage = 'SourceImage'; TargetImage = 'TargetImage'; GrantedAccess = 'GrantedAccess'; CallTrace = 'CallTrace' })
            Save-Rows -Name 'sysmon_process_access' -Rows $pa
            if ($pa.Count -ge 3000) { Write-CaseLog "    EID 10 process access: capped at 3000 - widen the Sysmon ProcessAccess filter" 'DarkGray' }
            $reg = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(13) -Start $start -Cap 5000 -Fields ([ordered]@{ EventType = 'EventType'; TargetObject = 'TargetObject'; Image = 'Image' })
            Save-Rows -Name 'sysmon_registry' -Rows $reg
            $ft = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(2) -Start $start -Cap 1000 -Fields ([ordered]@{ Image = 'Image'; TargetFilename = 'TargetFilename'; CreationUtcTime = 'CreationUtcTime'; PreviousCreationUtcTime = 'PreviousCreationUtcTime' })
            Save-Rows -Name 'sysmon_file_time' -Rows $ft
            if ($ft.Count -gt 0) { Write-CaseLog "    EID 2 file creation-time changes: $($ft.Count) (timestomping data source)" 'Yellow' }
            # v2.27: EID 1 process create - OriginalFileName vs Image feeds the renamed-LOLBIN at-rest rule
            $pc = Get-EventDataRows -LogName 'Microsoft-Windows-Sysmon/Operational' -Id @(1) -Start $start -Cap 5000 -Fields ([ordered]@{ Image = 'Image'; OriginalFileName = 'OriginalFileName'; CommandLine = 'CommandLine'; User = 'User' })
            Save-Rows -Name 'sysmon_proc_create' -Rows $pc
            Export-Evtx -LogName 'Microsoft-Windows-Sysmon/Operational' -FileName 'Sysmon_Operational.evtx'
        } }
    [pscustomobject]@{ Id = '4.4'; Cat = 'LOGS'; Name = 'RDP logs (LocalSessionManager + ConnectionManager)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev1 = Get-FilteredEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Ids @(21, 22, 24, 25, 39, 40) -Start $start -MaxMsg 300
            Save-Rows -Name 'rdp_localsession' -Rows $ev1
            Export-Evtx -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -FileName 'RDP_LocalSessionManager.evtx'
            $ev2 = Get-FilteredEvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Ids @(1149) -Start $start -MaxMsg 300
            Save-Rows -Name 'rdp_connections' -Rows $ev2
            Export-Evtx -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FileName 'RDP_ConnectionManager.evtx'
            # v2.30: RDP bitmap cache - screen fragments of what INBOUND RDP sessions displayed
            $rcSrc = Join-Path $env:LOCALAPPDATA 'Microsoft\Terminal Server Client\Cache'
            if (Test-Path $rcSrc) {
                $rcDst = Join-Path $RawDir 'rdp_cache'
                New-Item -ItemType Directory -Path $rcDst -Force | Out-Null
                $nBmc = 0
                foreach ($f in @(Get-ChildItem -LiteralPath $rcSrc -Filter '*.bmc' -File -ErrorAction SilentlyContinue)) {
                    try { Copy-Item -LiteralPath $f.FullName -Destination $rcDst -Force -ErrorAction Stop; $nBmc++ } catch { }
                }
                if ($nBmc -gt 0) { Write-CaseLog "    RDP bitmap cache: $nBmc file(s) -> raw\rdp_cache (screen fragments of inbound RDP sessions; view with RdpCacheStudio)" 'Gray' }
            }
        } }
    [pscustomobject]@{ Id = '4.5'; Cat = 'LOGS'; Name = 'System log (service installs 7045, changes 7040)'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'System' -Ids @(7045, 7040, 104, 6005, 6006) -Start $start
            Save-Rows -Name 'system_events' -Rows $ev
            $svc = @($ev | Where-Object { $_.Id -eq 7045 } | ForEach-Object {
                $msg = "$($_.Message)"
                $name = if ($msg -match 'Service Name:\s+(.+)') { $Matches[1].Split("`n")[0].Trim() } else { '' }
                $file = if ($msg -match 'File Name:\s+(.+)') { $Matches[1].Split("`n")[0].Trim() } else { '' }
                [pscustomobject]@{ Time = $_.TimeCreated; Service = $name; Binary = $file; Type = 'NewService' }
            })
            Save-Rows -Name 'system_new_services' -Rows $svc
        } }
    [pscustomobject]@{ Id = '4.6'; Cat = 'LOGS'; Name = 'Detection pack: hayabusa Sigma timeline + logon summary (needs tools\hayabusa)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $h = $null
            if ($tDir) { $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1 }
            if (-not $h) { Write-CaseLog "    hayabusa not in tools\ - skipping (or run: -Mode Setup / -Mode Links)" 'DarkGray'; return }
            $evtxDir = Join-Path $RawDir 'evtx'
            if (-not (Test-Path $evtxDir)) { Write-CaseLog "    no evtx exported - skipping" 'DarkGray'; return }
            $out = Join-Path $CsvDir 'hayabusa_timeline.csv'
            $html = Join-Path $CsvDir 'hayabusa_report.html'
            $hayArgs = @('dfir-timeline', '-p', 'verbose', '-d', "$evtxDir", '-o', "$out", '-H', "$html", '-q', '-w', '-U', '-C', '-K', '-m', 'low', '-E')
            $huntNote = 'full range'
            if ($script:LogStartDT) {
                $hayArgs += @('--start-timeline', $script:LogStartDT.ToString('yyyy-MM-dd HH:mm:ss'))
                if ($script:LogEndDT) { $hayArgs += @('--end-timeline', $script:LogEndDT.ToString('yyyy-MM-dd HH:mm:ss')) }
                $huntNote = "from $($script:LogStartDT.ToString('yyyy-MM-dd HH:mm'))$(if ($script:LogEndDT) { " to $($script:LogEndDT.ToString('yyyy-MM-dd HH:mm'))" })"
            } elseif ($LogHours -gt 0) { $hayArgs += @('--time-offset', "$($LogHours)h"); $huntNote = "last $($LogHours)h" }
            Write-CaseLog "    hayabusa dfir-timeline Sigma hunt ($huntNote)..." 'Cyan'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs $hayArgs -WorkingDirectory $h.DirectoryName
            if (Test-Path $out) {
                $n = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
                Write-CaseLog "    hayabusa: $n timeline rows (level>=low) in csv\hayabusa_timeline.csv" $(if ($n -gt 0) { 'Yellow' } else { 'Gray' })
            } else { Write-CaseLog "    hayabusa timeline produced no output" 'DarkYellow' }
            Write-CaseLog "    hayabusa logon-summary..." 'Cyan'
            $lsPrefix = Join-Path $CsvDir 'logon_summary'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs @('logon-summary', '-d', "$evtxDir", '-o', "$lsPrefix", '-q', '-C', '-K') -WorkingDirectory $h.DirectoryName
            $ps64 = Join-Path $CsvDir 'ps_decoded_commands.csv'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs @('extract-base64', '-d', "$evtxDir", '-o', "$ps64", '-q', '-C', '-K', '-U') -WorkingDirectory $h.DirectoryName
            if (Test-Path $ps64) {
                $n64 = @(Get-Content -LiteralPath $ps64 | Select-Object -Skip 1).Count
                if ($n64 -gt 0) { Write-CaseLog "    extract-base64: $n64 encoded/obfuscated command(s) recovered -> csv\ps_decoded_commands.csv" 'Yellow' }
                else { Remove-Item -LiteralPath $ps64 -Force -ErrorAction SilentlyContinue }
            }
        } }
    [pscustomobject]@{ Id = '4.7'; Cat = 'LOGS'; Name = 'YARA scan of flagged/user-path binaries (needs tools\yara)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $yr = $null
            if ($tDir) { $yr = Get-ChildItem -Path $tDir -Recurse -Filter 'yr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if (-not $yr) { Write-CaseLog "    yr.exe not in tools\ - skipping (run Setup, tool 'yara')" 'DarkGray'; return }
            $rulesDir = Join-Path $yr.DirectoryName 'rules'
            if (-not (Test-Path -LiteralPath $rulesDir)) { Write-CaseLog "    no rules\ folder next to yr.exe - skipping" 'DarkGray'; return }
            $ruleFiles = @(Get-ChildItem -LiteralPath $rulesDir -Recurse -File -Include '*.yar', '*.yara' -ErrorAction SilentlyContinue)
            if ($ruleFiles.Count -eq 0) { Write-CaseLog "    rules\ contains no .yar files - skipping" 'DarkGray'; return }

            $seen = @{}
            $targets = New-Object System.Collections.Generic.List[string]
            foreach ($src in @('flash_process_scored', 'processes_flagged', 'services_flagged', 'scheduled_tasks_flagged', 'autoruns_runkeys', 'autoruns_startup_folders', 'drivers_flagged', 'amcache')) {
                $f = Join-Path $CsvDir "$src.csv"
                if (-not (Test-Path -LiteralPath $f)) { continue }
                try { $rows = @(Import-Csv -LiteralPath $f -ErrorAction Stop) } catch { continue }
                foreach ($r in $rows) {
                    $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
                    foreach ($mm in [regex]::Matches($line, '(?i)(?:[a-z]:\\|\\\\)[^\s'',\|]+\.(?:exe|dll|scr|com|ps1|bat|cmd|vbs|js|hta|jar)')) {
                        $p2 = $mm.Value
                        if (-not $seen.ContainsKey($p2.ToLower())) {
                            $seen[$p2.ToLower()] = $true
                            if (Test-Path -LiteralPath $p2 -PathType Leaf) { $targets.Add($p2) }
                        }
                    }
                }
            }
            $maxScan = 200
            if ($targets.Count -eq 0) { Write-CaseLog "    no on-disk candidate files found - nothing to scan" 'Gray'; Save-Rows -Name 'yara_hits' -Rows @(); Save-Rows -Name 'yara_scanned' -Rows @(); return }
            $scanList = @($targets | Select-Object -First $maxScan)
            Write-CaseLog "    yara: scanning $($scanList.Count) candidate file(s) with $($ruleFiles.Count) rule file(s)..." 'Cyan'
            if ($targets.Count -gt $maxScan) { Write-CaseLog "    (capped at $maxScan of $($targets.Count) candidates)" 'DarkYellow' }

            $hits = New-Object System.Collections.Generic.List[object]
            $scanned = New-Object System.Collections.Generic.List[object]
            $failed = 0
            foreach ($f2 in $scanList) {
                $res = Invoke-NativeTool -ExePath $yr.FullName -ToolArgs @('scan', '-m', '--output-format=ndjson', $rulesDir, $f2) -WorkingDirectory $yr.DirectoryName -QuietLog -CaptureOut
                if ($res -isnot [pscustomobject] -or $res.ExitCode -ne 0) {
                    $failed++
                    if ($failed -eq 1 -and $res -is [pscustomobject] -and $res.StdErr) { Write-CaseLog "    yr.exe error: $(($res.StdErr -split '\r?\n' | Where-Object { $_ } | Select-Object -First 1))" 'DarkYellow' }
                    continue
                }
                $hitRules = @()
                if ($res.StdOut) {
                    foreach ($ln in ($res.StdOut -split "`r?`n" | Where-Object { $_ -match '^\s*\{' })) {
                        try { $j = $ln | ConvertFrom-Json } catch { continue }
                        if (@($j.rules).Count -gt 0) {
                            foreach ($ru in @($j.rules)) {
                                $meta = @{}
                                if ($ru.meta) { foreach ($kv in @($ru.meta)) { $meta["$($kv[0])"] = "$($kv[1])" } }
                                $sev = if ($meta['severity']) { $meta['severity'] } else { 'unknown' }
                                $hits.Add([pscustomobject]@{
                                    Severity = $sev
                                    Rule = "$($ru.identifier)"
                                    Description = "$($meta['description'])"
                                    File = $f2
                                })
                                $hitRules += "$($ru.identifier)"
                            }
                        }
                    }
                }
                $sha = ''
                try { $fi = Get-Item -LiteralPath $f2 -ErrorAction Stop; if ($fi.Length -lt 200MB) { $sha = (Get-FileHash -LiteralPath $f2 -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } } catch { }
                $scanned.Add([pscustomobject]@{ File = $f2; SHA256 = $sha; Hits = $hitRules.Count; Rules = ($hitRules -join ';') })
            }
            Save-Rows -Name 'yara_hits' -Rows $hits.ToArray()
            Save-Rows -Name 'yara_scanned' -Rows $scanned.ToArray()
            $hitArr = $hits.ToArray()
            $hi = @($hitArr | Where-Object { "$($_.Severity)" -match '^(?i)(high|critical)$' }).Count
            if ($hitArr.Count -gt 0) {
                Write-CaseLog "    YARA: $($hitArr.Count) hit(s) on $($scanned.Count) scanned file(s) ($hi high/crit) - csv\yara_hits.csv" $(if ($hi -gt 0) { 'Red' } else { 'Yellow' })
                foreach ($h2 in ($hitArr | Select-Object -First 10)) {
                    Write-CaseLog ("      [{0}] {1}  {2}" -f $h2.Severity, $h2.Rule, $h2.File) $(if ("$($h2.Severity)" -match '^(?i)(high|critical)$') { 'Red' } else { 'Yellow' })
                }
            } else {
                Write-CaseLog "    yara: no hits on $($scanned.Count) scanned file(s)$(if ($failed) { " ($failed scan failures)" } else { '' })" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '4.8'; Cat = 'LOGS'; Name = 'C2 beaconing analysis (needs Sysmon network events)'; Default = $true; Quick = $false;
        Run = {
            $f = Join-Path $CsvDir 'sysmon_network.csv'
            $fd = Join-Path $CsvDir 'sysmon_dns.csv'
            if (-not (Test-Path -LiteralPath $f) -and -not (Test-Path -LiteralPath $fd)) { Write-CaseLog "    no sysmon_network.csv / sysmon_dns.csv (no Sysmon / module 4.3 skipped) - beaconing not analyzable" 'DarkGray'; return }
            $all = @()
            try {
                foreach ($r in @(Import-Csv -LiteralPath $f -ErrorAction Stop)) {
                    $t = $null
                    try { $t = [datetime]"$($r.Time)" } catch { }
                    if ($t) { $all += [pscustomobject]@{ T = $t; Kind = 'net'; Key = "net|$($r.Image)|$($r.DestIp)|$($r.DestPort)"; Image = "$($r.Image)"; Ip = "$($r.DestIp)"; Port = "$($r.DestPort)"; Domain = '' } }
                }
            } catch { }
            try {
                foreach ($r in @(Import-Csv -LiteralPath $fd -ErrorAction Stop)) {
                    $t = $null
                    try { $t = [datetime]"$($r.Time)" } catch { }
                    if ($t) {
                        $dom = ("$($r.QueryName)" -replace '\.$', '').ToLower()
                        $rip = ''
                        foreach ($m in [regex]::Matches("$($r.QueryResults)", '\b\d{1,3}(\.\d{1,3}){3}\b')) { if (Test-IsPublicIp $m.Value) { $rip = $m.Value; break } }
                        $all += [pscustomobject]@{ T = $t; Kind = 'dns'; Key = "dns|$($r.Image)|$dom"; Image = "$($r.Image)"; Ip = $rip; Port = ''; Domain = $dom }
                    }
                }
            } catch { }
            if ($all.Count -lt 15) { Write-CaseLog "    too few Sysmon network/DNS events ($($all.Count)) for beaconing analysis" 'Gray'; Save-Rows -Name 'beacon_candidates' -Rows @(); Save-Rows -Name 'dns_beacon_candidates' -Rows @(); return }
            $flagged = @{}
            $fps = Join-Path $CsvDir 'flash_process_scored.csv'
            if (Test-Path -LiteralPath $fps) {
                try { foreach ($fr in @(Import-Csv -LiteralPath $fps)) { if ("$($fr.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($fr.Path)") { $flagged["$($fr.Path)".ToLower()] = $true } } } catch { }
            }
            $out = @()
            $outDns = @()
            foreach ($g in ($all | Group-Object Key)) {
                if ($g.Count -lt 15) { continue }
                $ev = @($g.Group | Sort-Object T)
                $span = ($ev[-1].T - $ev[0].T).TotalMinutes
                if ($span -lt 15) { continue }
                $deltas = @()
                for ($i = 1; $i -lt $ev.Count; $i++) {
                    $d = ($ev[$i].T - $ev[$i - 1].T).TotalSeconds
                    if ($d -gt 0 -and $d -le 3600) { $deltas += $d }
                }
                if ($deltas.Count -lt 10) { continue }
                $sortedD = @($deltas | Sort-Object)
                $median = $sortedD[[int][math]::Floor($sortedD.Count / 2)]
                $mean = ($deltas | Measure-Object -Average).Average
                $variance = (($deltas | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum) / $deltas.Count
                $jitter = if ($mean -gt 0) { [math]::Round([math]::Sqrt($variance) / $mean, 2) } else { 9.99 }
                $inBand = @($deltas | Where-Object { $_ -ge ($median * 0.5) -and $_ -le ($median * 1.5) }).Count
                $reg = [math]::Round($inBand / $deltas.Count, 2)
                if ($reg -lt 0.6) { continue }
                $img = "$($ev[0].Image)"; $ip = "$($ev[0].Ip)"
                $isPub = Test-IsPublicIp $ip
                $flags = @()
                if ($isPub) { $flags += 'public-ip' }
                if (Test-IsUserWritablePath $img) { $flags += 'user-path' }
                if ($flagged.ContainsKey($img.ToLower())) { $flags += 'flagged-process' }
                $sev = 'low'; $rk = 1
                if ($reg -ge 0.7 -and ($isPub -or ($flags -contains 'user-path'))) { $sev = 'medium'; $rk = 2 }
                if ($reg -ge 0.85 -and $g.Count -ge 30 -and $isPub) { $sev = 'high'; $rk = 3 }
                if ($ev[0].Kind -eq 'dns') {
                    $outDns += [pscustomobject]@{
                        Severity = $sev; Rank = $rk; Process = $img; Domain = $ev[0].Domain; ResolvedIp = $ip
                        Events = $g.Count; SpanMin = [math]::Round($span, 0); MedianIntervalSec = [math]::Round($median, 0)
                        Jitter = $jitter; Regularity = $reg; Flags = ($flags -join ';')
                    }
                } else {
                    $out += [pscustomobject]@{
                        Severity = $sev; Rank = $rk; Process = $img; RemoteIp = $ip; Port = "$($ev[0].Port)"
                        Events = $g.Count; SpanMin = [math]::Round($span, 0); MedianIntervalSec = [math]::Round($median, 0)
                        Jitter = $jitter; Regularity = $reg; Flags = ($flags -join ';')
                    }
                }
            }
            $out2 = @($out | Sort-Object Rank, Regularity -Descending)
            Save-Rows -Name 'beacon_candidates' -Rows $out2
            $outD2 = @($outDns | Sort-Object Rank, Regularity -Descending)
            Save-Rows -Name 'dns_beacon_candidates' -Rows $outD2
            $bh = @($out2 | Where-Object { "$($_.Severity)" -eq 'high' }).Count
            $bm = @($out2 | Where-Object { "$($_.Severity)" -eq 'medium' }).Count
            $dh = @($outD2 | Where-Object { "$($_.Severity)" -eq 'high' }).Count
            $dm = @($outD2 | Where-Object { "$($_.Severity)" -eq 'medium' }).Count
            if ($out2.Count -gt 0 -or $outD2.Count -gt 0) {
                Write-CaseLog "    beaconing: $($out2.Count) connection pattern(s) ($bh high, $bm medium), $($outD2.Count) DNS pattern(s) ($dh high, $dm medium)" $(if ($bh + $dh -gt 0) { 'Red' } else { 'Yellow' })
                foreach ($b in ($out2 | Select-Object -First 4)) {
                    Write-CaseLog ("      [{0}] {1} -> {2}:{3} every ~{4}s x{5} (reg {6}, jitter {7}) {8}" -f $b.Severity, (Split-Path $b.Process -Leaf), $b.RemoteIp, $b.Port, $b.MedianIntervalSec, $b.Events, $b.Regularity, $b.Jitter, $b.Flags) $(if ("$($b.Severity)" -eq 'high') { 'Red' } else { 'Yellow' })
                }
                foreach ($b in ($outD2 | Select-Object -First 4)) {
                    Write-CaseLog ("      [{0}] {1} -> DNS {2} every ~{3}s x{4} (reg {5}) {6}" -f $b.Severity, (Split-Path $b.Process -Leaf), $b.Domain, $b.MedianIntervalSec, $b.Events, $b.Regularity, $b.Flags) $(if ("$($b.Severity)" -eq 'high') { 'Red' } else { 'Yellow' })
                }
            } else {
                Write-CaseLog "    beaconing: no periodic outbound patterns detected in Sysmon network/DNS events" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '4.9'; Cat = 'LOGS'; Name = 'Kerberos + directory events (DC: 4768/4769/4771/4776, 4662 DCSync, 5136 changes)'; Default = $false; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ker = @()
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4768) -Start $start -Cap 3000 -Fields ([ordered]@{ Account = 'TargetUserName'; Service = 'ServiceName'; IpAddress = 'IpAddress'; PreAuth = 'PreAuthType'; Status = 'Status' })
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4769) -Start $start -Cap 3000 -Fields ([ordered]@{ Account = 'TargetUserName'; Service = 'ServiceName'; IpAddress = 'IpAddress'; TicketEnc = 'TicketEncryptionType'; Status = 'Status' })
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4771) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'TargetUserName'; IpAddress = 'IpAddress'; Status = 'Status' })
            $ker += Get-EventDataRows -LogName 'Security' -Id @(4776) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'TargetUserName'; Workstation = 'WorkstationName' })
            Save-Rows -Name 'security_kerberos' -Rows $ker
            $ds = @()
            $ds += Get-EventDataRows -LogName 'Security' -Id @(4662) -Start $start -Cap 3000 -Fields ([ordered]@{ Account = 'SubjectUserName'; Object = 'ObjectName'; OpType = 'OperationType'; Properties = 'Properties' })
            $ds += Get-EventDataRows -LogName 'Security' -Id @(5136) -Start $start -Cap 2000 -Fields ([ordered]@{ Account = 'SubjectUserName'; ObjectDN = 'ObjectDN'; OpType = 'OperationType'; Attribute = 'AttributeLDAPDisplayName'; Value = 'AttributeValue' })
            Save-Rows -Name 'security_ds_access' -Rows $ds
            if ($ker.Count -eq 0 -and $ds.Count -eq 0) {
                Write-CaseLog "    no Kerberos/DS events - not a DC, or 'Audit Directory Service Access' audit policy off" 'DarkGray'
            } else {
                Write-CaseLog "    Kerberos events: $($ker.Count), directory-service events: $($ds.Count)" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '4.10'; Cat = 'LOGS'; Name = 'Application log (crashes 1000/1001/1002, MSI installs 1033/11707/11724) + evtx export'; Default = $true; Quick = $false;
        Run = {
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'Application' -Ids @(1000, 1001, 1002, 1004, 1033, 11707, 11724) -Start $start -MaxMsg 300
            Save-Rows -Name 'application_events' -Rows $ev
            if ($ev.Count -gt 0) {
                Write-CaseLog "    application events: $($ev.Count) (crashes/installs - crashed attacker tools show up here) -> csv\application_events.csv" 'Gray'
            }
            Export-Evtx -LogName 'Application' -FileName 'Application.evtx'
        } }
    [pscustomobject]@{ Id = '5.1'; Cat = 'ARTIFACTS'; Name = 'Prefetch files'; Default = $true; Quick = $false;
        Run = {
            $pf = Join-Path $env:SystemRoot 'Prefetch'
            if (-not (Test-Path $pf)) { Write-CaseLog "    Prefetch directory absent (disabled?)" 'DarkGray'; return }
            $files = @(Get-ChildItem -Path $pf -Filter '*.pf' -ErrorAction SilentlyContinue)
            $dest = Join-Path $RawDir 'prefetch'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $copied = 0
            foreach ($f in $files) {
                try { Copy-Item -LiteralPath $f.FullName -Destination $dest -Force -ErrorAction Stop; $copied++ } catch { }
            }
            Save-Rows -Name 'prefetch_index' -Rows ($files | Select-Object Name, Length, CreationTime, LastWriteTime)
            Write-CaseLog "    Copied $copied of $($files.Count) prefetch files" 'Gray'
            $tDir = Get-ToolsDir
            $peExe = $null
            if ($tDir) { $peExe = Get-ChildItem -Path $tDir -Recurse -Filter 'PECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if ($peExe -and $copied -gt 0) {
                Write-CaseLog "    PECmd: parsing prefetch (run counts + times)..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $peExe.FullName -ToolArgs @('-d', $dest, '--csv', $CsvDir, '--csvf', 'prefetch_parsed.csv')
                $pp = Join-Path $CsvDir 'prefetch_parsed.csv'
                if (Test-Path -LiteralPath $pp) {
                    $n = @(Get-Content -LiteralPath $pp | Select-Object -Skip 1).Count
                    Write-CaseLog "    prefetch parsed: $n entries -> csv\prefetch_parsed.csv" 'Gray'
                } else { Write-CaseLog "    PECmd produced no output" 'DarkYellow' }
            }
        } }
    [pscustomobject]@{ Id = '5.2'; Cat = 'ARTIFACTS'; Name = 'Registry hives (SYSTEM/SOFTWARE/SAM/SECURITY/Amcache) + UserAssist'; Default = $true; Quick = $false;
        Run = {
            $dest = Join-Path $RawDir 'registry'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            foreach ($hive in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY')) {
                $out = Join-Path $dest "$hive.hiv"
                & reg.exe save "HKLM\$hive" "$out" /y 2>&1 | Out-Null
                $saved = Test-Path $out
                if ($saved) { $saved = ((Get-Item $out -ErrorAction SilentlyContinue).Length -gt 0) }
                if ($LASTEXITCODE -ne 0 -or -not $saved) {
                    if (Test-Path $out) { Remove-Item $out -Force -ErrorAction SilentlyContinue }
                    Write-CaseLog "    reg save $hive failed (admin needed)" 'DarkYellow'
                }
            }
            $amc = Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
            if (Test-Path $amc) {
                $out = Join-Path $dest 'Amcache.hve'
                try { Copy-Item -LiteralPath $amc -Destination $out -Force -ErrorAction Stop }
                catch { & esentutl.exe /y "$amc" /d "$out" 2>&1 | Out-Null }
            }
            Save-Rows -Name 'userassist' -Rows (Get-UserAssistRows)
        } }
    [pscustomobject]@{ Id = '5.3'; Cat = 'ARTIFACTS'; Name = 'SRUM database (larger, uses VSS copy)'; Default = $false; Quick = $false;
        Run = {
            $sru = Join-Path $env:SystemRoot 'System32\sru\SRUDB.dat'
            if (-not (Test-Path $sru)) { return }
            $dest = Join-Path $RawDir 'sru'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $out = Join-Path $dest 'SRUDB.dat'
            $null = Copy-LockedFile -Source $sru -Dest $out
        } }
    [pscustomobject]@{ Id = '5.4'; Cat = 'ARTIFACTS'; Name = 'Execution history (chainsaw: shimcache+amcache timeline, SRUM, evtx gaps)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $cs = $null
            if ($tDir) { $cs = Get-ChildItem -Path $tDir -Recurse -Filter 'chainsaw*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if (-not $cs) { Write-CaseLog "    chainsaw not in tools\ - skipping (or run: -Mode Setup / -Mode Links)" 'DarkGray'; return }
            $regDir = Join-Path $RawDir 'registry'
            $sys = Join-Path $regDir 'SYSTEM.hiv'
            $amc = Join-Path $regDir 'Amcache.hve'
            $sft = Join-Path $regDir 'SOFTWARE.hiv'
            if (-not (Test-Path $sys)) { Write-CaseLog "    registry hives not saved (enable module 5.2) - skipping" 'DarkGray'; return }
            $out = Join-Path $CsvDir 'execution_timeline.csv'
            $amArgs = @()
            if (Test-Path $amc) { $amArgs = @('-a', $amc) }
            Write-CaseLog "    chainsaw: shimcache/amcache execution timeline..." 'Cyan'
            $null = Invoke-NativeTool -ExePath $cs.FullName -ToolArgs (@('analyse', 'shimcache', $sys) + $amArgs + @('-o', $out))
            if (Test-Path $out) {
                $n = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
                Write-CaseLog "    execution timeline: $n entries in csv\execution_timeline.csv" 'Gray'
            } else { Write-CaseLog "    chainsaw shimcache analysis failed" 'DarkYellow' }
            $sruCopy = Join-Path $RawDir 'sru\SRUDB.dat'
            if ((Test-Path $sruCopy) -and (Test-Path $sft)) {
                Write-CaseLog "    chainsaw: SRUM usage analysis..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $cs.FullName -ToolArgs @('analyse', 'srum', '-s', $sft, $sruCopy, '-o', (Join-Path $CsvDir 'srum_usage.csv'), '-q')
            }
            $evtxDir = Join-Path $RawDir 'evtx'
            if (Test-Path $evtxDir) {
                $anDir = Join-Path $RawDir 'analysis'
                if (-not (Test-Path $anDir)) { New-Item -ItemType Directory -Path $anDir -Force | Out-Null }
                Write-CaseLog "    chainsaw: evtx gap detection (tamper check)..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $cs.FullName -ToolArgs @('analyse', 'gaps', $evtxDir, '-q', '-o', (Join-Path $anDir 'evtx_gaps.txt'))
            }
        } }
    [pscustomobject]@{ Id = '5.5'; Cat = 'ARTIFACTS'; Name = 'NTFS forensics: MFT recent-file inventory + USN write bursts (needs tools\MFTECmd + admin)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            if (-not $tDir) { Write-CaseLog "    no tools\ - skipping" 'DarkGray'; return }
            $mftExe = Get-ChildItem -Path $tDir -Recurse -Filter 'MFTECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $mftExe) { Write-CaseLog "    MFTECmd not in tools\ - skipping (run Setup)" 'DarkGray'; return }
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_ntfs_" + (Get-Date -Format 'HHmmss'))
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            try {
                $exeExt = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jar', '.hta', '.scr', '.msi', '.py', '.wsf', '.lnk')
                $cutoff = (Get-Date).AddDays(-30)   # ponytail: fixed 30-day recency ($LogHours is not seeded into worker runspaces)
                $ransomExt = @('.locked', '.locky', '.crypt', '.crypto', '.enc', '.encrypted', '.enc1', '.cry', '.cerber', '.wallet', '.onion', '.aes', '.rsa', '.mallox', '.pha', '.devos', '.mkp', '.faust', '.elh', '.ransom', '.payform', '.locked1')
                $keepFull = {
                    # Full preset only: preserve the unfiltered parser output for analyst-side work (skips when disk is tight).
                    param($srcCsv, $outName)
                    $root = [IO.Path]::GetPathRoot($CaseDir).TrimEnd('\')
                    $free = 0
                    try { $free = (Get-PSDrive -Name ($root.TrimEnd(':')) -ErrorAction Stop).Free } catch { }
                    if ($free -lt 10GB) { Write-CaseLog "    Full preset: under 10GB free on $root - skipping full NTFS preservation" 'DarkYellow'; return }
                    $an = Join-Path $RawDir 'analysis'
                    if (-not (Test-Path $an)) { New-Item -ItemType Directory -Path $an -Force | Out-Null }
                    Copy-Item -LiteralPath $srcCsv -Destination (Join-Path $an $outName) -Force
                    Write-CaseLog "    Full preset: preserved $outName -> raw\analysis\ (full $([math]::Round((Get-Item -LiteralPath $srcCsv).Length / 1MB, 1)) MB)" 'Gray'
                }
                $keep = New-Object System.Collections.Generic.List[object]
                $mftTotal = 0
                $bursts = @()
                $drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Free -ne $null })
                foreach ($d in $drives) {
                    $dl = "$($d.Name):"
                    $isNtfs = $true
                    try { $v = Get-Volume -DriveLetter $d.Name -ErrorAction Stop; if ("$($v.FileSystem)" -and "$($v.FileSystem)" -ne 'NTFS') { $isNtfs = $false } } catch { }
                    if (-not $isNtfs) { Write-CaseLog "    drive $dl not NTFS - skipped" 'DarkGray'; continue }
                    $dlLower = $d.Name.ToLower()

                    # ---- $MFT per drive: keep only executable-ish files in user paths or created recently ----
                    Write-CaseLog "    MFTECmd: parsing live `$MFT on $dl..." 'Cyan'
                    $null = Invoke-NativeTool -ExePath $mftExe.FullName -ToolArgs @('-f', "$($d.Root)`$MFT", '--csv', $tmp, '--csvf', "mft_full.csv")
                    $mftFull = Join-Path $tmp 'mft_full.csv'
                    if (Test-Path -LiteralPath $mftFull) {
                        $hdr = @((Get-Content -LiteralPath $mftFull -First 1) -split ',' | ForEach-Object { $_.Trim(' "') })
                        $colOf = {
                            param([string]$pattern)
                            @($hdr | Where-Object { $_ -match $pattern } | Select-Object -First 1)[0]
                        }
                        $cName = & $colOf '^FileName$'; $cParent = & $colOf 'ParentPath'; $cExt = & $colOf '^Extension$'
                        $cCreated = & $colOf 'Created'; $cMod = & $colOf 'LastModified'; $cSize = & $colOf 'FileSize'; $cEntry = & $colOf 'EntryNumber'
                        $cCreated30 = & $colOf 'Created0x30'
                        Import-Csv -LiteralPath $mftFull | ForEach-Object {
                            $mftTotal++
                            $name = "$($_.$cName)"
                            if (-not $name) { return }
                            $ext = ("$($_.$cExt)").ToLower()
                            if ($exeExt -notcontains $ext) { return }
                            $parent = "$($_.$cParent)"
                            $path = if ($parent) { "$dl$parent\$name" } else { "$dl\$name" }
                            $userPath = Test-IsUserWritablePath $path
                            $created = $null; try { $created = [datetime]"$($_.$cCreated)" } catch { }
                            $recent = ($created -and $created -ge $cutoff)
                            if (-not ($userPath -or $recent)) { return }
                            $flags = @('exec'); if ($userPath) { $flags += 'user-path' }; if ($recent) { $flags += 'recent' }
                            $keep.Add([pscustomobject]@{ Drive = $dl; Entry = "$($_.$cEntry)"; Created = "$($_.$cCreated)"; CreatedFN = $(if ($cCreated30) { "$($_.$cCreated30)" } else { '' }); LastModified = "$($_.$cMod)"; Size = "$($_.$cSize)"; Name = $name; Path = $path; Flags = ($flags -join ';') })
                        }
                        if ("$Preset" -eq 'Full') { & $keepFull $mftFull "mft_full_$($d.Name).csv" }
                        Remove-Item -LiteralPath $mftFull -Force -ErrorAction SilentlyContinue
                    } else { Write-CaseLog "    MFT parse on $dl produced no output (not elevated?)" 'DarkYellow' }

                    # ---- USN journal per drive: per-minute write bursts + ransomware-extension check ----
                    Write-CaseLog "    MFTECmd: reading live USN journal on $dl..." 'Cyan'
                    $null = Invoke-NativeTool -ExePath $mftExe.FullName -ToolArgs @('-f', "$($d.Root)`$Extend\`$J", '--csv', $tmp, '--csvf', 'usn_full.csv')
                    $usnFull = Join-Path $tmp 'usn_full.csv'
                    if (Test-Path -LiteralPath $usnFull) {
                        $uHdr = @((Get-Content -LiteralPath $usnFull -First 1) -split ',' | ForEach-Object { $_.Trim(' "') })
                        $uCol = {
                            param([string]$pattern)
                            @($uHdr | Where-Object { $_ -match $pattern } | Select-Object -First 1)[0]
                        }
                        $tCol = & $uCol 'time'; $rCol = & $uCol 'reason'; $nCol = & $uCol 'sourcefile|^file'
                        if ($tCol -and $rCol) {
                            # ponytail: >=1000 write-reason events/min across >=100 distinct files = burst window (heuristic; big installs/updates can trigger too)
                            $min = @{}
                            Import-Csv -LiteralPath $usnFull | ForEach-Object {
                                $reason = "$($_.$rCol)"
                                $isWrite = ($reason -match 'DataExtend|Truncate|BasicInfoChange')
                                $isNew = ($reason -match 'FileCreate|RenameNewName')
                                if (-not $isWrite -and -not $isNew) { return }
                                $t = $null; try { $t = [datetime]"$($_.$tCol)" } catch { }
                                if (-not $t) { return }
                                $k = $t.ToString('yyyy-MM-dd HH:mm')
                                if (-not $min.ContainsKey($k)) { $min[$k] = @{ Events = 0; Files = @{}; Ext = @{} } }
                                if ($isWrite) { $min[$k].Events++ }
                                if ($nCol) {
                                    $f = "$($_.$nCol)"
                                    if ($f) {
                                        if (-not $min[$k].Files.ContainsKey($f)) { $min[$k].Files[$f] = $true }
                                        if ($isNew) {
                                            $fe = [IO.Path]::GetExtension($f).ToLower()
                                            if ($fe -and $ransomExt -contains $fe) { $min[$k].Ext[$fe] = $true }
                                        }
                                    }
                                }
                            }
                            foreach ($k in @($min.Keys | Sort-Object)) {
                                if ($min[$k].Events -ge 1000 -and $min[$k].Files.Count -ge 100) {
                                    $bursts += [pscustomobject]@{ WindowStart = $k; Drive = $dl; WriteEvents = $min[$k].Events; DistinctFiles = $min[$k].Files.Count; RansomExt = (($min[$k].Ext.Keys | Sort-Object) -join ';') }
                                }
                            }
                        }
                        if ("$Preset" -eq 'Full') { & $keepFull $usnFull "usn_full_$($d.Name).csv" }
                        Remove-Item -LiteralPath $usnFull -Force -ErrorAction SilentlyContinue
                    }
                }
                $out5 = $keep.ToArray()
                if ($out5.Count -gt 5000) { $out5 = $out5[0..4999] }
                Save-Rows -Name 'mft_recent' -Rows $out5
                Write-CaseLog "    MFT: $mftTotal entries scanned across $($drives.Count) drive(s), $($keep.Count) executable/user-path/recent kept -> csv\mft_recent.csv" 'Gray'
                Save-Rows -Name 'usn_write_bursts' -Rows $bursts
                if (@($bursts).Count -gt 0) {
                    Write-CaseLog "    USN: $(@($bursts).Count) mass-modification window(s) >=1000 writes/min - POSSIBLE RANSOMWARE -> csv\usn_write_bursts.csv" 'Red'
                    foreach ($b in @($bursts | Select-Object -First 5)) { Write-CaseLog "      $($b.WindowStart) [$($b.Drive)]: $($b.WriteEvents) writes over $($b.DistinctFiles) files$(if ("$($b.RansomExt)") { " RANSOM-EXT: $($b.RansomExt)" })" 'Red' }
                } else { Write-CaseLog "    USN journal analyzed - no mass-modification windows" 'Gray' }
            } finally {
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        } }
    [pscustomobject]@{ Id = '6.1'; Cat = 'DEFENDER'; Name = 'Defender detections, exclusions, status'; Default = $true; Quick = $true;
        Run = {
            $status = @(); $threats = @(); $prefs = @()
            try {
                if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                    $s = Get-MpComputerStatus -ErrorAction Stop
                    $status += [pscustomobject]@{
                        AMServiceEnabled = $s.AMServiceEnabled; AntispywareEnabled = $s.AntispywareEnabled
                        RealTimeProtection = $s.RealTimeProtectionEnabled; IOfficeAntiVirus = $s.IoavProtectionEnabled
                        AntivirusSigAgeDays = if ($s.AntivirusSignatureAge -ne $null) { $s.AntivirusSignatureAge } else { '' }
                        QuickScanAge = $s.QuickScanAge; FullScanAge = $s.FullScanAge; LastQuickScan = $s.QuickScanStartTime
                    }
                }
            } catch { }
            try {
                if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
                    $threats = @(Get-MpThreat -ErrorAction Stop | Select-Object ThreatName, SeverityID, IsActive, Resources)
                }
            } catch { }
            try {
                if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
                    $p = Get-MpPreference -ErrorAction Stop
                    $prefs += [pscustomobject]@{
                        ExclusionPath = (@($p.ExclusionPath) -join ';')
                        ExclusionProcess = (@($p.ExclusionProcess) -join ';')
                        ExclusionExtension = (@($p.ExclusionExtension) -join ';')
                        DisableRealtime = $p.DisableRealtimeMonitoring
                        SubmitSamplesConsent = $p.SubmitSamplesConsent
                    }
                }
            } catch { }
            Save-Rows -Name 'defender_status' -Rows $status
            Save-Rows -Name 'defender_threats' -Rows $threats
            Save-Rows -Name 'defender_preferences' -Rows $prefs
            $start = Get-LogStart
            $ev = Get-FilteredEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' -Ids @(1116, 1117, 5001, 5007) -Start $start -MaxMsg 500
            Save-Rows -Name 'defender_events' -Rows $ev
            $dconf = @($ev | Where-Object { @(5001, 5007) -contains $_.Id } | ForEach-Object {
                [pscustomobject]@{ Time = $_.TimeCreated; EventId = $_.Id; Detail = ("$($_.Message)" -replace '\s+', ' ').Trim() }
            })
            Save-Rows -Name 'defender_config_events' -Rows $dconf
            Export-Evtx -LogName 'Microsoft-Windows-Windows Defender/Operational' -FileName 'Defender_Operational.evtx'
        } }
    [pscustomobject]@{ Id = '7.1'; Cat = 'MEMORY'; Name = 'RAM capture via winpmem (needs tools\winpmem, LARGE output)'; Default = $false; Quick = $false;
        Run = {
            $tool = $null
            $tDir = Get-ToolsDir
            if ($tDir) {
                $tool = Get-ChildItem -Path $tDir -Recurse -Filter '*winpmem*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            }
            if (-not $tool) {
                Write-CaseLog "    winpmem not found in tools\ folder" 'Yellow'
                $url = Read-Host "    Paste winpmem download URL (or press Enter to skip)"
                if ($url) {
                    try {
                        $tDir = Join-Path $BaseDir 'tools'
                        New-Item -ItemType Directory -Path $tDir -Force | Out-Null
                        $dest = Join-Path $tDir 'winpmem_downloaded.exe'
                        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
                        $tool = Get-Item $dest
                    } catch { Write-CaseLog "    Download failed: $($_.Exception.Message)" 'Red'; return }
                } else { return }
            }
            $confirm = Read-Host "    Capture full RAM to disk? This can take several minutes and RAM-size disk space [y/N]"
            if ($confirm -notmatch '^[Yy]') { Write-CaseLog "    Memory capture skipped by user" 'Gray'; return }
            New-Item -ItemType Directory -Path $MemDir -Force | Out-Null
            $dump = Join-Path $MemDir 'physmem.raw'
            Write-CaseLog "    Capturing memory with $($tool.Name) ..." 'Cyan'
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            & $tool.FullName "$dump" 2>&1 | ForEach-Object { Write-CaseLog "      $_" 'DarkGray' }
            $sw.Stop()
            if (Test-Path $dump) {
                $gb = [math]::Round((Get-Item $dump).Length / 1GB, 1)
                Write-CaseLog "    Memory captured: $gb GB in $([int]$sw.Elapsed.TotalSeconds)s" 'Green'
                $vol = Get-ChildItem -Path $tDir -Recurse -Filter 'vol.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($vol) {
                    $anDir = Join-Path $RawDir 'memory-analysis'
                    New-Item -ItemType Directory -Path $anDir -Force | Out-Null
                    foreach ($plugin in @('windows.pslist.PsList', 'windows.cmdline.CmdLine', 'windows.svcscan.SvcScan')) {
                        $pn = ($plugin -split '\.')[-1]
                        Write-CaseLog "    vol3 quick pass: $pn" 'Cyan'
                        & $vol.FullName -f $dump -r json $plugin 2>$null | Set-Content -LiteralPath (Join-Path $anDir "$pn.json") -Encoding UTF8
                    }
                    Write-CaseLog "    vol3: malfind (injected-code regions)..." 'Cyan'
                    $mfCsv = Join-Path $CsvDir 'memory_malfind.csv'
                    & $vol.FullName -f $dump -r csv windows.malfind.Malfind 2>$null | Set-Content -LiteralPath $mfCsv -Encoding UTF8
                    $mfN = 0
                    try { $mfN = @(Import-Csv -LiteralPath $mfCsv -ErrorAction Stop).Count } catch { $mfN = 0 }
                    if ($mfN -gt 0) {
                        Write-CaseLog "    MALFIND: $mfN suspicious memory region(s) -> csv\memory_malfind.csv" 'Red'
                        & $vol.FullName -f $dump -r csv windows.netscan.NetScan 2>$null | Set-Content -LiteralPath (Join-Path $CsvDir 'memory_netscan.csv') -Encoding UTF8
                    } else {
                        Write-CaseLog "    vol3 malfind: no suspicious regions" 'Gray'
                        Remove-Item -LiteralPath $mfCsv -Force -ErrorAction SilentlyContinue
                        "# no entries" | Set-Content -LiteralPath $mfCsv -Encoding UTF8
                    }
                }
            } else {
                Write-CaseLog "    Memory capture FAILED" 'Red'
            }
        } }
    [pscustomobject]@{ Id = '7.2'; Cat = 'MEMORY'; Name = 'Live memory triage - minidumps of flagged processes + YARA (opt-in, admin, budgeted)'; Default = $false; Quick = $false;
        Run = {
            $cands = @()
            foreach ($r in (Import-CaseCsv 'flash_process_scored')) {
                if ("$($r.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($r.Path)" -and "$($r.PID)") { $cands += [pscustomobject]@{ PID = [int]$r.PID; Path = "$($r.Path)"; Name = "$($r.Name)"; Verdict = "$($r.Verdict)" } }
            }
            $cands = @($cands | Sort-Object -Property @{e = { if ($_.Verdict -eq 'HIGH') { 0 } else { 1 } } } | Select-Object -First 10)
            if ($cands.Count -eq 0) { Write-CaseLog '    no flagged processes - live memory triage skipped' 'Gray'; return }
            $root = [IO.Path]::GetPathRoot($CaseDir).TrimEnd('\')
            $free = 0
            try { $free = (Get-PSDrive -Name ($root.TrimEnd(':')) -ErrorAction Stop).Free } catch { }
            if ($free -lt 10GB) { Write-CaseLog "    under 10GB free on $root - live memory triage skipped" 'Yellow'; return }
            $tDir = Get-ToolsDir
            $yr = $null
            $rulesDir = $null
            if ($tDir) {
                $yr = Get-ChildItem -Path $tDir -Recurse -Filter 'yr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
                $rulesDir = Join-Path $tDir 'yara\rules'
            }
            $dmpDir = Join-Path $RawDir 'minidumps'
            New-Item -ItemType Directory -Path $dmpDir -Force | Out-Null
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class OphiraDump {
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);
}
'@ -ErrorAction SilentlyContinue
            $critical = @('lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'svchost', 'windefend', 'msmpeng')
            $rows = @()
            $used = 0L
            foreach ($c in $cands) {
                if ($used -ge 2GB) { Write-CaseLog '    dump budget (2GB) reached - stopping' 'Yellow'; break }
                $pn = ($c.Name -replace '\.exe$', '').ToLower()
                if ($critical -contains $pn) { Write-CaseLog "    skip $($c.Name) (security-critical process)" 'DarkYellow'; continue }
                try {
                    $proc = Get-Process -Id $c.PID -ErrorAction Stop
                    if ($proc.PrivateMemorySize64 -gt 1.5GB) { Write-CaseLog "    skip $($c.Name) (private memory > 1.5GB)" 'DarkYellow'; continue }
                    $outFile = Join-Path $dmpDir "$($c.Name)_$($c.PID).dmp"
                    $ok = $false
                    $fs = [IO.File]::Create($outFile)
                    try {
                        $ok = [OphiraDump]::MiniDumpWriteDump($proc.Handle, [uint32]$c.PID, $fs.SafeFileHandle.DangerousGetHandle(), [uint32]0x26, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
                    } finally { $fs.Close() }
                    if (-not $ok -or -not (Test-Path -LiteralPath $outFile)) { Write-CaseLog "    dump failed: $($c.Name)" 'DarkYellow'; continue }
                    $used += (Get-Item -LiteralPath $outFile).Length
                    $hits = ''
                    if ($yr -and (Test-Path $rulesDir)) {
                        $res = Invoke-NativeTool -ExePath $yr.FullName -ToolArgs @('scan', '-m', '--output-format=ndjson', $rulesDir, $outFile) -WorkingDirectory $yr.DirectoryName -CaptureOut
                        if ($res -and $res.ExitCode -eq 0 -and $res.StdOut) {
                            $hits = (@($res.StdOut | ForEach-Object { try { ($_ | ConvertFrom-Json).rule } catch { } }) | Where-Object { $_ } | Sort-Object -Unique) -join ';'
                        }
                    }
                    $rows += [pscustomobject]@{ Process = $c.Name; PID = $c.PID; Path = $c.Path; Verdict = $c.Verdict; Dump = "raw\minidumps\$([IO.Path]::GetFileName($outFile))"; DumpMB = [math]::Round((Get-Item -LiteralPath $outFile).Length / 1MB, 1); YaraHits = $hits }
                    Write-CaseLog "    minidump: $($c.Name) ($([math]::Round((Get-Item -LiteralPath $outFile).Length / 1MB, 1)) MB)$(if ($hits) { " YARA: $hits" })" $(if ($hits) { 'Red' } else { 'Gray' })
                } catch { Write-CaseLog "    cannot dump $($c.Name): $($_.Exception.Message)" 'DarkYellow' }
            }
            Save-Rows -Name 'memory_live_scan' -Rows $rows
            if ($rows.Count -gt 0) { Write-CaseLog "    live memory triage: $($rows.Count) dump(s), $([math]::Round($used / 1MB, 0)) MB total -> raw\minidumps + csv\memory_live_scan.csv" 'Cyan' }
        } }
[pscustomobject]@{ Id = '8.1'; Cat = 'CONTEXT'; Name = 'Attacker activity (console history, RDP targets, recycle bin)'; Default = $true; Quick = $true;
        Run = {
            $profiles = Get-UserProfileList
            $dest = Join-Path $RawDir 'useractivity'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $hist = @()
            foreach ($p in $profiles) {
                foreach ($rel in @('AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt')) {
                    $f = Join-Path $p.Path $rel
                    if (Test-Path -LiteralPath $f) {
                        $udir = Join-Path $dest $p.User
                        if (-not (Test-Path $udir)) { New-Item -ItemType Directory -Path $udir -Force | Out-Null }
                        try { Copy-Item -LiteralPath $f -Destination (Join-Path $udir 'ConsoleHost_history.txt') -Force -ErrorAction Stop } catch { }
                        $hist += [pscustomobject]@{ User = $p.User; File = $f; KB = [math]::Round((Get-Item -LiteralPath $f).Length / 1KB, 1); LastWrite = (Get-Item -LiteralPath $f).LastWriteTime }
                    }
                }
            }
            Save-Rows -Name 'powershell_console_history' -Rows $hist
            foreach ($h in $hist) { Write-CaseLog "    history: $($h.User) ($($h.KB) KB, $($h.LastWrite))" 'Gray' }
            $rdp = @()
            try {
                foreach ($sid in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' })) {
                    $base = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Terminal Server Client\Servers"
                    if (Test-Path $base) {
                        foreach ($srv in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                            $hint = (Get-ItemProperty -Path $srv.PSPath -ErrorAction SilentlyContinue).UsernameHint
                            $rdp += [pscustomobject]@{ User = $sid.PSChildName; TargetServer = $srv.PSChildName; UsernameHint = "$hint"; LastWrite = $srv.Name -replace '.*\\', '' }
                        }
                    }
                }
            } catch { }
            Save-Rows -Name 'rdp_client_targets' -Rows $rdp
            $rbRows = @()
            $rbDest = Join-Path $RawDir 'recyclebin'
            New-Item -ItemType Directory -Path $rbDest -Force | Out-Null
            foreach ($drv in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Free -ne $null })) {
                $rb = Join-Path $drv.Root '$Recycle.Bin'
                if (Test-Path -LiteralPath $rb) {
                    $files = Get-ChildItem -LiteralPath $rb -Recurse -Filter '$I*' -File -ErrorAction SilentlyContinue
                    foreach ($f in $files) {
                        $sidDir = Split-Path $f.DirectoryName -Leaf
                        $rbRows += [pscustomobject]@{ Drive = $drv.Name; OwnerSid = $sidDir; File = $f.Name; Bytes = $f.Length; Deleted = $f.LastWriteTime }
                        $sub = Join-Path $rbDest "$($drv.Name)_$sidDir"
                        if (-not (Test-Path $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
                        try { Copy-Item -LiteralPath $f.FullName -Destination $sub -Force -ErrorAction Stop } catch { }
                    }
                }
            }
            Save-Rows -Name 'recyclebin_index' -Rows $rbRows
        } }
    [pscustomobject]@{ Id = '8.2'; Cat = 'CONTEXT'; Name = 'User registry saves (NTUSER.DAT + UsrClass.dat, all profiles)'; Default = $true; Quick = $false;
        Run = {
            $dest = Join-Path $RawDir 'registry\users'
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            $saved = 0
            foreach ($p in (Get-UserProfileList)) {
                $nt = Join-Path $p.Path 'NTUSER.DAT'
                $uc = Join-Path $p.Path 'AppData\Local\Microsoft\Windows\UsrClass.dat'
                $loaded = Test-Path "Registry::HKEY_USERS\$($p.Sid)"
                $loadedCls = Test-Path "Registry::HKEY_USERS\$($p.Sid)_Classes"
                if (Test-Path -LiteralPath $nt) {
                    $out = Join-Path $dest "$($p.User)_NTUSER.DAT"
                    $ok = $false
                    if ($loaded) { & reg.exe save "HKU\$($p.Sid)" "$out" /y 2>&1 | Out-Null; $ok = ($LASTEXITCODE -eq 0) }
                    if (-not $ok) { try { Copy-Item -LiteralPath $nt -Destination $out -Force -ErrorAction Stop; $ok = $true } catch { } }
                    if ($ok -and (Test-Path $out) -and ((Get-Item $out).Length -gt 0)) { $saved++ } elseif (Test-Path $out) { Remove-Item $out -Force -ErrorAction SilentlyContinue }
                }
                if (Test-Path -LiteralPath $uc) {
                    $out = Join-Path $dest "$($p.User)_UsrClass.dat"
                    $ok = $false
                    if ($loadedCls) { & reg.exe save "HKU\$($p.Sid)_Classes" "$out" /y 2>&1 | Out-Null; $ok = ($LASTEXITCODE -eq 0) }
                    if (-not $ok) { try { Copy-Item -LiteralPath $uc -Destination $out -Force -ErrorAction Stop; $ok = $true } catch { } }
                    if ($ok -and (Test-Path $out) -and ((Get-Item $out).Length -gt 0)) { $saved++ } elseif (Test-Path $out) { Remove-Item $out -Force -ErrorAction SilentlyContinue }
                }
            }
            Write-CaseLog "    saved $saved user hive files to raw\registry\users\" 'Gray'
        } }
    [pscustomobject]@{ Id = '8.3'; Cat = 'CONTEXT'; Name = 'Coverage & context (Sysmon config, task XML, BITS, domain info)'; Default = $true; Quick = $true;
        Run = {
            $cDir = Join-Path $RawDir 'context'
            New-Item -ItemType Directory -Path $cDir -Force | Out-Null
            foreach ($svc in @('Sysmon64', 'Sysmon')) {
                $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Parameters"
                if (Test-Path $k) {
                    & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$svc\Parameters" (Join-Path $cDir "${svc}_Parameters.reg") /y 2>&1 | Out-Null
                    break
                }
            }
            try {
                $tDir = Join-Path $RawDir 'tasks'
                New-Item -ItemType Directory -Path $tDir -Force | Out-Null
                if (Get-Command Export-ScheduledTask -ErrorAction SilentlyContinue) {
                    $n = 0
                    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                        try {
                            $safe = ($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]', '_'
                            if ($safe.Length -gt 150) { $safe = $safe.Substring(0, 150) }
                            Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Set-Content -LiteralPath (Join-Path $tDir "$safe.xml") -Encoding UTF8
                            $n++
                        } catch { }
                    }
                    Write-CaseLog "    exported $n task XMLs to raw\tasks\" 'Gray'
                }
            } catch { }
            $bits = @()
            try {
                if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) {
                    $bits = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName, OwnerAccount, JobState, TransferType, @{n = 'Files'; e = { @($_.Files) -join ';' } })
                }
            } catch { }
            Save-Rows -Name 'bits_jobs' -Rows $bits
            $cs = Get-WmiOrCim -Class Win32_ComputerSystem
            $roleMap = @('Standalone Workstation', 'Member Workstation', 'Standalone Server', 'Member Server', 'Backup Domain Controller', 'Primary Domain Controller')
            $dom = @()
            if ($cs) {
                $dom += [pscustomobject]@{
                    Name = $cs.Name; Domain = $cs.Domain; PartOfDomain = $cs.PartOfDomain
                    DomainRole = if ($cs.DomainRole -ne $null) { $roleMap[[int]$cs.DomainRole] } else { '' }
                    LoggedUser = $cs.UserName
                }
            }
            Save-Rows -Name 'domain_info' -Rows $dom
            # local administrators (account entities + rogue-admin hunting)
            $la = @()
            try {
                $laOut = & net.exe localgroup administrators 2>$null | Where-Object { $_ -match '\S' } | Select-Object -Skip 6
                $laOut = @($laOut | Where-Object { $_ -notmatch 'The command completed' })
                foreach ($member in $laOut) { $la += [pscustomobject]@{ Group = 'Administrators'; Member = "$member".Trim() } }
                if ($la.Count -gt 0) { Write-CaseLog "    local admins: $($la.Count) member(s)" 'Gray' }
            } catch { }
            Save-Rows -Name 'local_admins' -Rows $la
            if ($cs -and $cs.PartOfDomain) {
                Invoke-ExeCapture -SubDir 'context' -Name 'nltest_dsgetdc.txt' -Exe nltest.exe -Arguments "/dsgetdc:$env:USERDOMAIN"
                Invoke-ExeCapture -SubDir 'context' -Name 'nltest_trusts.txt' -Exe nltest.exe -Arguments '/domain_trusts'
            }
        } }
    [pscustomobject]@{ Id = '8.4'; Cat = 'CONTEXT'; Name = 'EZ forensic parsers (AmcacheParser + RBCmd, needs tools\)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            if (-not $tDir) { Write-CaseLog "    no tools\ - skipping" 'DarkGray'; return }
            $amcExe = Get-ChildItem -Path $tDir -Recurse -Filter 'AmcacheParser*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            $rbExe = Get-ChildItem -Path $tDir -Recurse -Filter 'RBCmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            $amcHive = Join-Path $RawDir 'registry\Amcache.hve'
            if ($amcExe -and (Test-Path $amcHive)) {
                Write-CaseLog "    AmcacheParser: historical execution inventory..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $amcExe.FullName -ToolArgs @('-f', $amcHive, '--csv', $CsvDir, '--csvf', 'amcache.csv')
                $amcCsv = Join-Path $CsvDir 'amcache.csv'
                if (-not (Test-Path $amcCsv)) {
                    # AmcacheParser 2026+ writes split CSVs (amcache_UnassociatedFileEntries etc.) - merge the
                    # file-entry family back into amcache.csv so the IOC xref / hunt / timeline consumers work
                    $parts = @(Get-ChildItem -Path $CsvDir -Filter 'amcache_*.csv' -ErrorAction SilentlyContinue | Where-Object { (Get-Content -LiteralPath $_.FullName -First 1) -match '^"?ApplicationName' })
                    if ($parts.Count -eq 0) { $parts = @(Get-ChildItem -Path $CsvDir -Filter 'amcache_DriveBinaries.csv' -File -ErrorAction SilentlyContinue) }
                    if ($parts.Count -gt 0) {
                        try {
                            $rows = @(); foreach ($p in $parts) { $rows += @(Import-Csv -LiteralPath $p.FullName) }
                            $rows | Export-Csv -LiteralPath $amcCsv -NoTypeInformation -Encoding UTF8
                            Write-CaseLog "    amcache: $($rows.Count) entries (merged $($parts.Count) split CSVs)" 'Gray'
                        } catch { Write-CaseLog "    amcache split-CSV merge failed: $($_.Exception.Message)" 'DarkYellow' }
                    }
                }
                if (Test-Path $amcCsv) {
                    $n = @(Get-Content -LiteralPath $amcCsv | Select-Object -Skip 1).Count
                    Write-CaseLog "    amcache: $n entries in csv\amcache.csv" 'Gray'
                    $iocs = Get-IocList
                    if ($iocs -and $iocs.Sha1.Count -gt 0) {
                        try {
                            $rows = Import-Csv -LiteralPath $amcCsv
                            $sha1Col = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match '^sha1$' } | Select-Object -First 1)
                            $nameCol = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match 'ApplicationName|SourceSimpleName|^Name$' } | Select-Object -First 1)
                            $hits = @()
                            foreach ($r in $rows) {
                                $sv = "$($r.$sha1Col)".ToUpper() -replace '[^A-F0-9]', ''
                                if ($sv -and $iocs.Sha1.ContainsKey($sv)) {
                                    $hits += [pscustomobject]@{ Indicator = $sv; Application = "$($r.$nameCol)"; SourceFile = "$($r.SourceFile)"; Match = 'amcache-SHA1' }
                                }
                            }
                            Save-Rows -Name 'ioc_hits_amcache' -Rows $hits
                            if ($hits.Count) { Write-CaseLog "    AMCACHE IOC HITS: $($hits.Count) (csv\ioc_hits_amcache.csv)" 'Red' }
                        } catch { Write-CaseLog "    amcache IOC xref failed: $($_.Exception.Message)" 'DarkYellow' }
                    }
                } else { Write-CaseLog "    AmcacheParser produced no output (and no split CSVs to merge)" 'DarkYellow' }
            }
            $rbSrc = Join-Path $RawDir 'recyclebin'
            if ($rbExe -and (Test-Path $rbSrc) -and @(Get-ChildItem -LiteralPath $rbSrc -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0) {
                Write-CaseLog "    RBCmd: recycle bin parse..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $rbExe.FullName -ToolArgs @('-d', $rbSrc, '-q', '--csv', $CsvDir, '--csvf', 'recyclebin.csv')
            }
        } }
    [pscustomobject]@{ Id = '8.5'; Cat = 'CONTEXT'; Name = 'LNK + Jump Lists (raw save + parse via tools\LECmd/JLECmd)'; Default = $true; Quick = $false;
        Run = {
            $recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
            $recDst = Join-Path $RawDir 'recent'
            New-Item -ItemType Directory -Path $recDst -Force | Out-Null
            $nLnk = 0
            if (Test-Path -LiteralPath $recent) {
                foreach ($f in @(Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -ErrorAction SilentlyContinue)) {
                    try { Copy-Item -LiteralPath $f.FullName -Destination $recDst -Force -ErrorAction Stop; $nLnk++ } catch { }
                }
            }
            $jlDst = Join-Path $RawDir 'jumplists'
            New-Item -ItemType Directory -Path $jlDst -Force | Out-Null
            $nJl = 0
            foreach ($sub in @('AutomaticDestinations', 'CustomDestinations')) {
                $d = Join-Path $recent $sub
                $subDst = Join-Path $jlDst $sub
                New-Item -ItemType Directory -Path $subDst -Force | Out-Null
                if (Test-Path -LiteralPath $d) {
                    foreach ($f in @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)) {
                        try { Copy-Item -LiteralPath $f.FullName -Destination $subDst -Force -ErrorAction Stop; $nJl++ } catch { }
                    }
                }
            }
            Write-CaseLog "    saved $nLnk recent LNK + $nJl jump list files to raw\" 'Gray'
            $tDir = Get-ToolsDir
            if (-not $tDir) { return }
            $leExe = Get-ChildItem -Path $tDir -Recurse -Filter 'LECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            $jlExe = Get-ChildItem -Path $tDir -Recurse -Filter 'JLECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($leExe -and $nLnk -gt 0) {
                Write-CaseLog "    LECmd: parsing recent LNK files..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $leExe.FullName -ToolArgs @('-d', $recDst, '--csv', $CsvDir, '--csvf', 'lnk_parsed.csv')
                $lp = Join-Path $CsvDir 'lnk_parsed.csv'
                if (Test-Path -LiteralPath $lp) { Write-CaseLog "    LNK parsed -> csv\lnk_parsed.csv" 'Gray' } else { Write-CaseLog "    LECmd produced no output" 'DarkYellow' }
            }
            if ($jlExe -and $nJl -gt 0) {
                Write-CaseLog "    JLECmd: parsing jump lists..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $jlExe.FullName -ToolArgs @('-d', $jlDst, '--csv', $CsvDir, '--csvf', 'jumplist_parsed.csv')
                $jlCsv = Get-ChildItem -Path $CsvDir -Filter 'jumplist_parsed*.csv' -ErrorAction SilentlyContinue
                if ($jlCsv) { Write-CaseLog "    jump lists parsed -> $(@($jlCsv | ForEach-Object { $_.Name }) -join ', ')" 'Gray' } else { Write-CaseLog "    JLECmd produced no output" 'DarkYellow' }
            }
        } }
    [pscustomobject]@{ Id = '8.6'; Cat = 'CONTEXT'; Name = 'Certificate store inventory (T1553 root-trust abuse)'; Default = $true; Quick = $false;
        Run = {
            $rows = @()
            $stores = @(
                @{ Path = 'Cert:\LocalMachine\Root'; Store = 'LocalMachine\Root' }
                @{ Path = 'Cert:\LocalMachine\CA'; Store = 'LocalMachine\CA' }
                @{ Path = 'Cert:\LocalMachine\TrustedPublisher'; Store = 'LocalMachine\TrustedPublisher' }
                @{ Path = 'Cert:\CurrentUser\Root'; Store = 'CurrentUser\Root' }
            )
            $cutoff = (Get-Date).AddDays(-90)
            foreach ($st in $stores) {
                try {
                    foreach ($c in (Get-ChildItem -Path $st.Path -ErrorAction SilentlyContinue)) {
                        $flags = @()
                        if ($c.NotBefore -and $c.NotBefore -ge $cutoff) { $flags += 'recently-added' }
                        if ($c.Subject -and $c.Issuer -and ("$($c.Subject)" -eq "$($c.Issuer)")) { $flags += 'self-signed' }
                        if ($st.Store -eq 'CurrentUser\Root') { $flags += 'user-store' }
                        $rows += [pscustomobject]@{
                            Store = $st.Store; Thumbprint = $c.Thumbprint; Subject = "$($c.Subject)"
                            Issuer = "$($c.Issuer)"; NotBefore = $c.NotBefore; NotAfter = $c.NotAfter
                            HasPrivateKey = $c.HasPrivateKey; Flags = ($flags -join ';')
                        }
                    }
                } catch { }
            }
            Save-Rows -Name 'certificates' -Rows $rows
            $hot = @($rows | Where-Object { $_.Flags -match 'recently-added' -and $_.Flags -match 'self-signed' })
            if ($hot.Count -gt 0) {
                Write-CaseLog "    certificates: $($rows.Count) inventoried, $($hot.Count) RECENT + SELF-SIGNED (verify: enterprise root CAs are self-signed by design) -> csv\certificates.csv" 'Yellow'
            } else {
                Write-CaseLog "    certificates: $($rows.Count) inventoried -> csv\certificates.csv" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.7'; Cat = 'CONTEXT'; Name = 'Browser artifacts raw save (Chrome/Edge History + Downloads, per profile)'; Default = $true; Quick = $false;
        Run = {
            $dst = Join-Path $RawDir 'browser'
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            $inv = @()
            $browsers = @(
                @{ Name = 'chrome'; Root = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data' }
                @{ Name = 'edge';   Root = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data' }
            )
            foreach ($b in $browsers) {
                if (-not (Test-Path -LiteralPath $b.Root)) { continue }
                $profileDirs = @()
                $prof = Join-Path $b.Root 'Default'
                if (Test-Path -LiteralPath $prof) { $profileDirs += 'Default' }
                try {
                    $profileDirs += @(Get-ChildItem -LiteralPath $b.Root -Directory -Filter 'Profile *' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
                } catch { }
                foreach ($pd in $profileDirs) {
                    foreach ($file in @('History', 'Downloads', 'Preferences', 'Bookmarks', 'Login Data')) {
                        $src = Join-Path $b.Root "$pd\$file"
                        if (-not (Test-Path -LiteralPath $src)) { continue }
                        $sub = Join-Path $dst "$($b.Name)_$pd"
                    if (-not (Test-Path -LiteralPath $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
                    foreach ($rootFile in @('Local State')) {
                        $rs = Join-Path $b.Root $rootFile
                        if (Test-Path -LiteralPath $rs) { Copy-Item -LiteralPath $rs -Destination (Join-Path $sub $rootFile) -Force -ErrorAction SilentlyContinue }
                    }
                    $outFile = Join-Path $sub $file
                        $ok = $false
                        try { Copy-Item -LiteralPath $src -Destination $outFile -Force -ErrorAction Stop; $ok = $true } catch { }
                        if (-not $ok) { $ok = Copy-LockedFile -Source $src -Dest $outFile }
                        if ($ok) { $inv += [pscustomobject]@{ Browser = $b.Name; Profile = $pd; File = $file; Bytes = (Get-Item -LiteralPath $outFile).Length } }
                    }
                }
            }
            Save-Rows -Name 'browser_files' -Rows $inv
            $mb = [math]::Round((($inv | Measure-Object Bytes -Sum).Sum) / 1MB, 1)
            Write-CaseLog "    browser: $($inv.Count) file(s) ($mb MB) saved to raw\browser\ (SQLite parsed offline)" 'Gray'
            # ---- parse the copied SQLite DBs (SQLECmd; .NET 9 on target needed - degrades gracefully) ----
            $tDir = Get-ToolsDir
            $sqlExe = $null
            if ($tDir) { $sqlExe = Get-ChildItem -Path $tDir -Recurse -Filter 'SQLECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
            if ($sqlExe -and @($inv | Where-Object { $_.File -eq 'History' }).Count -gt 0) {
                Write-CaseLog "    SQLECmd: parsing browser history/downloads..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $sqlExe.FullName -ToolArgs @('-d', $dst, '--csv', $CsvDir)
                $merge = {
                    param([string]$glob, [string]$name)
                    $files = @(Get-ChildItem -Path $CsvDir -Filter $glob -File -ErrorAction SilentlyContinue)
                    $all = @()
                    foreach ($f2 in $files) {
                        try { $all += @(Import-Csv -LiteralPath $f2.FullName -ErrorAction Stop) } catch { }
                    }
                    if ($all.Count -gt 0) { Save-Rows -Name $name -Rows $all }
                    foreach ($f2 in $files) { Remove-Item -LiteralPath $f2.FullName -Force -ErrorAction SilentlyContinue }
                    return $all.Count
                }
                $nH = & $merge '*ChromiumBrowser_HistoryVisits_*.csv' 'browser_history'
                $nD = & $merge '*ChromiumBrowser_Downloads_*.csv' 'browser_downloads'
                $nK = & $merge '*ChromiumBrowser_KeywordSearches_*.csv' 'browser_searches'
                Get-ChildItem -Path $CsvDir -Filter 'SQLite.Interop.dll' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Write-CaseLog "    browser parsed: $nH visits, $nD downloads, $nK searches -> csv\browser_*.csv" 'Gray'
                Invoke-BrowserIocXref
            } elseif (-not $sqlExe) {
                Write-CaseLog "    SQLECmd not in tools\ - browser DBs left as raw copies (parse at HQ or run Setup)" 'DarkGray'
            }
        } }
    [pscustomobject]@{ Id = '8.8'; Cat = 'CONTEXT'; Name = 'ShellBags - folder browsing history (needs tools\SBECmd, admin)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            if (-not $tDir) { Write-CaseLog "    no tools\ - skipping" 'DarkGray'; return }
            $sbe = Get-ChildItem -Path $tDir -Recurse -Filter 'SBECmd*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $sbe) { Write-CaseLog "    SBECmd not in tools\ - skipping (run Setup)" 'DarkGray'; return }
            Write-CaseLog "    SBECmd: parsing ShellBags for all user profiles..." 'Cyan'
            $null = Invoke-NativeTool -ExePath $sbe.FullName -ToolArgs @('-d', "$env:SystemDrive\Users", '--csv', $CsvDir)
            $f = Get-ChildItem -Path $CsvDir -Filter 'shellbags*.csv' -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($f) {
                $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
                Save-Rows -Name 'shellbags' -Rows $rows
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
                Write-CaseLog "    shellbags: $($rows.Count) folder-access entries -> csv\shellbags.csv" 'Gray'
            } else { Write-CaseLog "    SBECmd produced no output (not elevated? no profiles?)" 'DarkYellow' }
        } }
    [pscustomobject]@{ Id = '8.9'; Cat = 'CONTEXT'; Name = 'Security posture audit (LSA, SMBv1, RDP, PS logging, UAC, Defender, BitLocker)'; Default = $true; Quick = $true;
        Run = {
            $rows = New-Object System.Collections.Generic.List[object]
            function Add-Posture([string]$Check, [string]$Status, [string]$Detail) {
                $rows.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
            }
            $rp = {
                param([string]$path, [string]$prop)
                try { $v = (Get-ItemProperty -Path $path -ErrorAction Stop).$prop; if ($null -ne $v) { return "$v" } } catch { }
                return $null
            }
            # LSA Protection (credential theft / mimikatz resistance)
            $ppl = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
            if ($ppl -eq '1') { Add-Posture 'LSA Protection (RunAsPPL)' 'GOOD' 'Credential guard for LSASS enabled' }
            else { Add-Posture 'LSA Protection (RunAsPPL)' 'BAD' 'LSASS runs unprotected - credential dumping (mimikatz) is easier; set RunAsPPL=1' }
            # NTLM LAN Manager auth level
            $lm = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
            if ($null -eq $lm) { Add-Posture 'NTLM compatibility level' 'WARN' 'Default level in place - verify NTLMv1 is rejected (level 5)' }
            elseif ([int]$lm -ge 5) { Add-Posture 'NTLM compatibility level' 'GOOD' "Level $lm - NTLMv1 refused" }
            else { Add-Posture 'NTLM compatibility level' 'BAD' "Level $lm - weak NTLMv1/LM responses allowed" }
            # SMBv1
            $smb1 = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
            $mrx = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10' 'Start'
            if ($smb1 -eq '1' -or $mrx -eq '0') { Add-Posture 'SMBv1 protocol' 'BAD' 'SMBv1 enabled - EternalBlue/WannaCry-class exposure; disable it' }
            else { Add-Posture 'SMBv1 protocol' 'GOOD' 'SMBv1 disabled/absent' }
            # RDP + NLA
            $rdp = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
            if ($rdp -eq '0') {
                $nla = & $rp 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
                if ($nla -eq '0') { Add-Posture 'RDP' 'BAD' 'RDP enabled WITHOUT Network Level Authentication - brute-force friendly' }
                else { Add-Posture 'RDP' 'WARN' "RDP enabled with NLA - verify firewall scope + account lockout" }
            } else { Add-Posture 'RDP' 'GOOD' 'RDP disabled' }
            # PowerShell script-block logging
            $sbl = & $rp 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
            if ($sbl -eq '1') { Add-Posture 'PowerShell script-block logging' 'GOOD' 'EID 4104 capture enabled' }
            else { Add-Posture 'PowerShell script-block logging' 'BAD' 'Script-block logging off - PowerShell attacks leave little evidence; enable via GPO' }
            # UAC
            $lua = & $rp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
            $cpb = & $rp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
            if ($lua -eq '0') { Add-Posture 'UAC' 'BAD' 'UAC disabled entirely' }
            elseif ($cpb -eq '0') { Add-Posture 'UAC' 'WARN' 'UAC elevation without prompt (silent admin)' }
            else { Add-Posture 'UAC' 'GOOD' 'UAC enabled with prompts' }
            # Defender posture
            try {
                if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
                    $mp = Get-MpPreference -ErrorAction Stop
                    $exs = @(@($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ })
                    if (@($exs).Count -gt 0) { Add-Posture 'Defender exclusions' 'WARN' "$(@($exs).Count) exclusion(s) configured - attackers add these; review: $(@($exs | Select-Object -First 3) -join ', ')" }
                    else { Add-Posture 'Defender exclusions' 'GOOD' 'No exclusions' }
                    if ($mp.DisableRealtimeMonitoring) { Add-Posture 'Defender real-time protection' 'BAD' 'Real-time protection DISABLED' }
                }
            } catch { }
            $wd = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
            if ($wd -and $wd.StartType -eq 'Disabled') { Add-Posture 'Defender service' 'BAD' 'WinDefend service is Disabled' }
            # BitLocker (OS volume)
            try {
                $bl = & manage-bde.exe -status C: 2>$null | Where-Object { $_ -match 'Protection Status' } | Select-Object -First 1
                if ("$bl" -match 'On') { Add-Posture 'BitLocker (OS volume)' 'GOOD' 'Protection on' }
                elseif ("$bl" -match 'Off') { Add-Posture 'BitLocker (OS volume)' 'WARN' 'Disk not encrypted - offline tampering/theft exposure' }
            } catch { }
            # audit policy coverage (no auditing = silent intrusion)
            try {
                $ap = & auditpol.exe '/get' '/category:*' '/r' 2>$null | ConvertFrom-Csv
                $badAudit = @($ap | Where-Object { $_.'Inclusion Setting' -match '^(No Auditing)$' })
                if (@($ap).Count -gt 0) {
                    if ($badAudit.Count -ge 6) { Add-Posture 'Audit policy' 'BAD' "$($badAudit.Count) of $($ap.Count) categories have NO auditing - intrusion leaves no trace" }
                    elseif ($badAudit.Count -gt 0) { Add-Posture 'Audit policy' 'WARN' "$($badAudit.Count) categories without auditing: $((@($badAudit | Select-Object -First 4 | ForEach-Object { $_.'Subcategory' })) -join ', ')" }
                    else { Add-Posture 'Audit policy' 'GOOD' 'All categories auditing' }
                }
            } catch { }
            # WinRM trusted hosts
            $th = & $rp 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN' 'TrustedHosts'
            if ("$th" -match '\*' -or "$th" -match '[^0-9a-fA-F:\.].*,.*') { Add-Posture 'WinRM TrustedHosts' 'WARN' "Broad trust list: $th" }
            Save-Rows -Name 'posture' -Rows $rows.ToArray()
            $bad = @($rows.ToArray() | Where-Object { $_.Status -eq 'BAD' }).Count
            $warn = @($rows.ToArray() | Where-Object { $_.Status -eq 'WARN' }).Count
            if ($bad -gt 0) { Write-CaseLog "    posture: $($rows.Count) checks - $bad BAD, $warn WARN -> csv\posture.csv (see report hardening recommendations)" 'Yellow' }
            else { Write-CaseLog "    posture: $($rows.Count) checks - no critical findings, $warn warn -> csv\posture.csv" 'Gray' }
        } }
    [pscustomobject]@{ Id = '8.10'; Cat = 'CONTEXT'; Name = 'LOLDrivers hash check - malicious/vulnerable driver xref (needs tools\loldrivers)'; Default = $true; Quick = $false;
        Run = {
            $lolDir = Join-Path (Get-ToolsDir) 'loldrivers'
            $malFile = Join-Path $lolDir 'samples_malicious.sha256'
            $vulFile = Join-Path $lolDir 'samples_vulnerable.sha256'
            if (-not (Test-Path $malFile) -and -not (Test-Path $vulFile)) { Write-CaseLog "    tools\loldrivers datasets missing - skipping (run: -Mode Setup)" 'DarkGray'; return }
            $malSet = @{}
            if (Test-Path $malFile) { foreach ($h in (Get-Content $malFile -ErrorAction SilentlyContinue)) { $hl = "$h".Trim().ToLower(); if ($hl) { $malSet[$hl] = $true } } }
            $vulSet = @{}
            if (Test-Path $vulFile) { foreach ($h in (Get-Content $vulFile -ErrorAction SilentlyContinue)) { $hl = "$h".Trim().ToLower(); if ($hl) { $vulSet[$hl] = $true } } }
            $drvRows = @(Import-CaseCsv 'drivers')
            if ($drvRows.Count -eq 0) { Write-CaseLog "    no drivers.csv (module 1.6 skipped) - nothing to check" 'DarkGray'; return }
            $hits = @()
            $checked = 0
            foreach ($dr in $drvRows) {
                if ($checked -ge 600) { break }
                $p = "$($dr.PathName)" -replace '^\\{1,2}\?\?\\', ''
                if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
                $hash = $null
                try { $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { continue }
                $checked++
                $status = ''
                if ($malSet.ContainsKey($hash)) { $status = 'malicious' }
                elseif ($vulSet.ContainsKey($hash)) { $status = 'vulnerable' }
                if ($status) { $hits += [pscustomobject]@{ Status = $status; Name = "$($dr.Name)"; DisplayName = "$($dr.DisplayName)"; Path = $p; SHA256 = $hash } }
            }
            Save-Rows -Name 'loldrivers_hits' -Rows $hits
            $mal = @($hits | Where-Object { $_.Status -eq 'malicious' }).Count
            $vul = @($hits | Where-Object { $_.Status -eq 'vulnerable' }).Count
            if ($hits.Count -gt 0) {
                Write-CaseLog "    LOLDrivers: $mal MALICIOUS, $vul vulnerable driver(s) on disk ($checked hashed) -> csv\loldrivers_hits.csv" $(if ($mal -gt 0) { 'Red' } else { 'Yellow' })
            } else {
                Write-CaseLog "    LOLDrivers: $checked drivers hashed - no malicious/vulnerable matches" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.11'; Cat = 'CONTEXT'; Name = 'Host history extras (BAM/DAM last-exec, USB devices, Office MRU, UAL raw)'; Default = $true; Quick = $false;
        Run = {
            # BAM/DAM: per-user background execution tracking (survives Prefetch deletion)
            $bam = @()
            foreach ($svc in @('bam', 'dam')) {
                $base = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$svc\State\UserSettings"
                if (-not (Test-Path $base)) { continue }
                foreach ($sid in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                    $t = $sid.LastWriteTime
                    foreach ($v in (Get-ItemProperty -LiteralPath $sid.PSPath -ErrorAction SilentlyContinue).PSObject.Properties) {
                        if (@('Version', 'SequenceNumber') -contains $v.Name -or $v.Name -match '^PS') { continue }
                        if ("$($v.Value)" -and "$($v.Value)" -notmatch '^(Version|SequenceNumber)$') {
                            $bam += [pscustomobject]@{ Source = $svc.ToUpper(); Sid = $sid.PSChildName; Executable = "$($v.Value)"; LastWrite = $t }
                        }
                    }
                }
            }
            Save-Rows -Name 'bam_lastexec' -Rows $bam
            if ($bam.Count -gt 0) { Write-CaseLog "    BAM/DAM: $($bam.Count) last-exec entries -> csv\bam_lastexec.csv" 'Gray' }
            # USB storage devices (every USB device ever connected)
            $usbs = @()
            $usbBase = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR'
            if (Test-Path $usbBase) {
                foreach ($dev in (Get-ChildItem $usbBase -ErrorAction SilentlyContinue)) {
                    foreach ($inst in (Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue)) {
                        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -ErrorAction SilentlyContinue
                        $usbs += [pscustomobject]@{ DeviceKey = $dev.PSChildName; FriendlyName = "$($ip.FriendlyName)"; Serial = $(if ($ip.ParentIdPrefix) { "$($ip.ParentIdPrefix)" } else { $inst.PSChildName }); LastWrite = $inst.LastWriteTime }
                    }
                }
            }
            Save-Rows -Name 'usb_devices' -Rows $usbs
            $sap = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
            if (Test-Path $sap) {
                $d = Join-Path $RawDir 'usb'
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                Copy-Item -LiteralPath $sap -Destination (Join-Path $d 'setupapi.dev.log') -Force -ErrorAction SilentlyContinue
            }
            if ($usbs.Count -gt 0) { Write-CaseLog "    USB: $($usbs.Count) storage device(s) on record -> csv\usb_devices.csv" 'Gray' }
            # Office File MRU (recent documents per user)
            $mru = @()
            foreach ($sid in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' })) {
                foreach ($ver in @('16.0', '15.0')) {
                    foreach ($app in @('Word', 'Excel', 'PowerPoint')) {
                        $k = "$($sid.PSPath)\Software\Microsoft\Office\$ver\$app\File MRU"
                        if (-not (Test-Path $k)) { continue }
                        $t = (Get-Item $k).LastWriteTime
                        foreach ($v in (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).PSObject.Properties) {
                            if ($v.Name -notmatch '^Item \d+' -or $v.Value -isnot [byte[]]) { continue }
                            $ascii = [Text.Encoding]::ASCII.GetString($v.Value)
                            if ($ascii -match '(?i)([a-z]:\\[^\x00-\x1f]+?\.(docx?|xlsx?|pptx?|pdf|rtf))') {
                                $mru += [pscustomobject]@{ Sid = $sid.PSChildName; App = $app; Document = $Matches[1]; LastWrite = $t }
                            }
                        }
                    }
                }
            }
            Save-Rows -Name 'office_mru' -Rows $mru
            if ($mru.Count -gt 0) { Write-CaseLog "    Office MRU: $($mru.Count) recent document(s)" 'Gray' }
            # User Access Logs (SMB/RDP source history - ESE format, preserved raw for analyst)
            $sum = Join-Path $env:SystemRoot 'System32\LogFiles\Sum'
            if (Test-Path $sum) {
                $d = Join-Path $RawDir 'ual'
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                $mts = @(Get-ChildItem $sum -Filter '*.mts' -File -ErrorAction SilentlyContinue)
                $mts | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
                Save-Rows -Name 'ual_files' -Rows @($mts | Select-Object Name, Length, LastWriteTime)
                Write-CaseLog "    UAL: $($mts.Count) .mts file(s) copied to raw\ual (ESE - analyst-side parse)" 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.12'; Cat = 'CONTEXT'; Name = 'Web server artifacts (IIS/HTTPERR logs raw + W3C parse, app pool config)'; Default = $false; Quick = $false;
        Run = {
            $copied = 0
            foreach ($src in @(@('web\iis', "$env:SystemDrive\inetpub\logs\LogFiles"), @('web\httperr', "$env:SystemRoot\System32\LogFiles\HTTPERR"))) {
                if (-not (Test-Path $src[1])) { continue }
                $d = Join-Path $RawDir $src[0]
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                $logs = @(Get-ChildItem -LiteralPath $src[1] -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20)
                foreach ($f in $logs) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $d $f.Name) -Force -ErrorAction SilentlyContinue; $copied++ }
            }
            $ahc = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
            if (Test-Path $ahc) {
                $d = Join-Path $RawDir 'web'
                if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                Copy-Item -LiteralPath $ahc -Destination (Join-Path $d 'applicationHost.config') -Force -ErrorAction SilentlyContinue
                $copied++
            }
            $req = Get-IisW3cRows -Path "$env:SystemDrive\inetpub\logs\LogFiles" -Cap 10000
            $norm = @($req | Where-Object { "$($_.'cs-method')" } | ForEach-Object {
                [pscustomobject]@{
                    Time = ("$($_.date) $($_.time)").Trim(); Method = "$($_.'cs-method')"; Uri = "$($_.'cs-uri-stem')"
                    Query = "$($_.'cs-uri-query')"; Status = "$($_.'sc-status')"; ClientIp = "$($_.'c-ip')"; UserAgent = "$($_.'cs(User-Agent)')"
                }
            })
            Save-Rows -Name 'iis_requests' -Rows $norm
            $anom = New-Object System.Collections.Generic.List[object]
            foreach ($g in (@($norm | Where-Object { $_.Status -eq '500' } | Group-Object ClientIp | Where-Object { $_.Count -ge 10 }))) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'server-errors'; Detail = "$($g.Count) x HTTP 500 from $($g.Name)"; Sample = ((@($g.Group | Select-Object -First 3 | ForEach-Object { $_.Uri })) -join ' | ') })
            }
            foreach ($r in (@($norm | Where-Object { $_.Uri -match '(?i)(\.\./|%2e%2e|%00|/cmd\.|webshell|\.jsp;|eval\()' }) | Select-Object -First 20)) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'suspicious-uri'; Detail = "$($_.Uri) (status $($_.Status))"; Sample = "query=$($_.Query) ip=$($_.ClientIp) ua=$($_.UserAgent)" })
            }
            foreach ($r in (@($norm | Where-Object { $_.Method -eq 'POST' -and $_.Status -match '^2' -and $_.Uri -match '(?i)(upload|filemanager|editor|import)' }) | Select-Object -First 20)) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'post-to-upload-path'; Detail = "$($_.Uri) (status $($_.Status))"; Sample = "ip=$($_.ClientIp) ua=$($_.UserAgent)" })
            }
            $noUa = @($norm | Where-Object { -not $_.UserAgent -and $_.Method -eq 'POST' })
            if ($noUa.Count -ge 10) {
                $null = $anom.Add([pscustomobject]@{ Kind = 'headless-posts'; Detail = "$($noUa.Count) POST requests with no User-Agent"; Sample = ((@($noUa | Select-Object -First 3 | ForEach-Object { $_.Uri })) -join ' | ') })
            }
            Save-Rows -Name 'iis_anomalies' -Rows $anom.ToArray()
            if ($norm.Count -gt 0) {
                Write-CaseLog "    IIS: $($norm.Count) parsed request(s), $($anom.Count) anomaly row(s), $copied log file(s) -> raw\web\" 'Gray'
            } elseif ($copied -gt 0) {
                Write-CaseLog "    IIS: $copied log file(s) copied raw (no W3C fields parsed - check format)" 'Gray'
            } else {
                Write-CaseLog "    IIS: no logs found (no IIS role or logs elsewhere)" 'DarkGray'
            }
        } }
    [pscustomobject]@{ Id = '8.13'; Cat = 'CONTEXT'; Name = 'Host extras (StartupInfo launches, WER crash reports, QuickAssist, PCA, RecentFileCache, MOF, local GPO, WSL dotfiles)'; Default = $true; Quick = $false;
        Run = {
            $siPath = "$env:SystemRoot\System32\WDI\LogFiles\StartupInfo"
            if (Test-Path $siPath) {
                $si = Get-StartupInfoRows -Path $siPath
                Save-Rows -Name 'startup_info' -Rows $si
                if ($si.Count -gt 0) { Write-CaseLog "    StartupInfo: $($si.Count) app-launch record(s) (per-session, survives Prefetch deletion)" 'Gray' }
                $d = Join-Path $RawDir 'extras\startupinfo'
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                Get-ChildItem -LiteralPath $siPath -Filter '*.xml' -File -ErrorAction SilentlyContinue | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
            }
            $werRows = @()
            foreach ($w in @("$env:ProgramData\Microsoft\Windows\WER")) {
                if (Test-Path $w) { $werRows += @(Get-WerReportRows -Path $w) }
            }
            $udirs = @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Public|Default|Default User|All Users' })
            foreach ($u in $udirs) {
                $w = Join-Path $u.FullName 'AppData\Local\Microsoft\Windows\WER'
                if (Test-Path $w) { $werRows += @(Get-WerReportRows -Path $w) }
            }
            Save-Rows -Name 'wer_reports' -Rows $werRows
            if ($werRows.Count -gt 0) { Write-CaseLog "    WER: $($werRows.Count) crash report(s) -> csv\wer_reports.csv (crashed attacker tools leave these)" 'Gray' }
            $d = Join-Path $RawDir 'extras'
            foreach ($pair in @(@('quickassist', "$env:SystemDrive\Users\*\AppData\Local\Temp\QuickAssist"), @('remotehelp', "$env:SystemDrive\Users\*\AppData\Local\Temp\RemoteHelp"))) {
                $srcs = @(Get-ChildItem -Path $pair[1] -Directory -ErrorAction SilentlyContinue)
                foreach ($s in $srcs) {
                    $dd = Join-Path $d $pair[0]
                    New-Item -ItemType Directory -Path $dd -Force | Out-Null
                    Copy-Item -LiteralPath $s.FullName -Destination (Join-Path $dd $s.Name) -Recurse -Force -ErrorAction SilentlyContinue
                    Write-CaseLog "    $($pair[0]): remote-support session artifacts copied (AitM/scam tradecraft marker) -> raw\extras\$($pair[0])" 'Yellow'
                }
            }
            foreach ($pair in @(@('pca', "$env:SystemRoot\appcompat\pca", '*'), @('mof', "$env:SystemRoot\System32\wbem\MOF", '*.mof'))) {
                if (-not (Test-Path $pair[1])) { continue }
                $dd = Join-Path $d $pair[0]
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                Get-ChildItem -LiteralPath $pair[1] -Filter $pair[2] -File -ErrorAction SilentlyContinue | Copy-Item -Destination $dd -Force -ErrorAction SilentlyContinue
            }
            $rfc = "$env:SystemRoot\AppCompat\Programs\RecentFileCache.bcf"
            if (Test-Path $rfc) {
                $dd = Join-Path $d 'appcompat'
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                Copy-Item -LiteralPath $rfc -Destination $dd -Force -ErrorAction SilentlyContinue
            }
            foreach ($g in @("$env:SystemRoot\System32\GroupPolicy", "$env:SystemRoot\System32\GroupPolicyUsers")) {
                if (-not (Test-Path $g)) { continue }
                $dd = Join-Path $d ("gpo\" + (Split-Path $g -Leaf))
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                $files = @(Get-ChildItem -LiteralPath $g -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 300)
                foreach ($f in $files) {
                    $rel = ''
                    try { $rel = $f.FullName.Substring($g.Length).TrimStart('\') } catch { }
                    $pd = Join-Path $dd $(if ($rel) { Split-Path $rel -Parent } else { '' })
                    if ($pd -and -not (Test-Path $pd)) { New-Item -ItemType Directory -Path $pd -Force | Out-Null }
                    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $pd $f.Name) -Force -ErrorAction SilentlyContinue
                }
            }
            $hist = @(Get-ChildItem -Path "$env:SystemDrive\Users\*\AppData\Local\Packages\*\LocalState\rootfs\home" -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\.(bash_history|sh_history|profile|bashrc)$' } | Select-Object -First 20)
            foreach ($h in $hist) {
                $dd = Join-Path $d 'wsl'
                New-Item -ItemType Directory -Path $dd -Force | Out-Null
                Copy-Item -LiteralPath $h.FullName -Destination (Join-Path $dd ("wsl_" + $h.Name)) -Force -ErrorAction SilentlyContinue
            }
            Write-CaseLog "    host extras copied -> raw\extras\ (startupinfo/wer-source/quickassist/pca/mof/appcompat/gpo/wsl)" 'Gray'
        } }
    [pscustomobject]@{ Id = '8.14'; Cat = 'CONTEXT'; Name = 'Server logs raw (DNS/DHCP audit logs, SYSVOL policies; NTDS.dit VSS copy on Full preset + DC)'; Default = $true; Quick = $false;
        Run = {
            $inv = @()
            foreach ($pair in @(@('dns', "$env:SystemRoot\System32\DNS"), @('dhcp', "$env:SystemRoot\System32\dhcp"))) {
                if (-not (Test-Path $pair[1])) { continue }
                $files = @(Get-ChildItem -LiteralPath $pair[1] -Filter '*.log' -File -ErrorAction SilentlyContinue)
                if ($files.Count -eq 0) { continue }
                $d = Join-Path $RawDir ("server\" + $pair[0])
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                $files | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
                foreach ($f in $files) { $inv += [pscustomobject]@{ Type = $pair[0].ToUpper(); File = $f.Name; SizeMB = [math]::Round($f.Length / 1MB, 2); LastWrite = $f.LastWriteTime } }
                Write-CaseLog "    $($pair[0]): $($files.Count) audit log file(s) -> raw\server\$($pair[0])" 'Gray'
            }
            $sysvol = "$env:SystemRoot\SYSVOL\domain\Policies"
            if (Test-Path $sysvol) {
                $d = Join-Path $RawDir 'server\sysvol'
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                $files = @(Get-ChildItem -LiteralPath $sysvol -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 400)
                foreach ($f in $files) {
                    $rel = ''
                    try { $rel = $f.FullName.Substring($sysvol.Length).TrimStart('\') } catch { }
                    $pd = Join-Path $d $(if ($rel) { Split-Path $rel -Parent } else { '' })
                    if ($pd -and -not (Test-Path $pd)) { New-Item -ItemType Directory -Path $pd -Force | Out-Null }
                    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $pd $f.Name) -Force -ErrorAction SilentlyContinue
                }
                $inv += [pscustomobject]@{ Type = 'SYSVOL'; File = "$($files.Count) policy file(s)"; SizeMB = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1MB, 2); LastWrite = '' }
                Write-CaseLog "    SYSVOL: $($files.Count) policy file(s) (GPO persistence surface) -> raw\server\sysvol" 'Gray'
            }
            $isDc = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
            if ($isDc -and "$Preset" -eq 'Full') {
                $ntds = Join-Path $env:SystemRoot 'NTDS\ntds.dit'
                if (Test-Path $ntds) {
                    $d = Join-Path $RawDir 'server\ntds'
                    New-Item -ItemType Directory -Path $d -Force | Out-Null
                    if (Copy-LockedFile -Source $ntds -Dest (Join-Path $d 'ntds.dit')) {
                        $inv += [pscustomobject]@{ Type = 'NTDS'; File = 'ntds.dit'; SizeMB = [math]::Round((Get-Item (Join-Path $d 'ntds.dit')).Length / 1MB, 2); LastWrite = (Get-Item (Join-Path $d 'ntds.dit')).LastWriteTime }
                        Write-CaseLog '    NTDS.dit VSS-copied (read-only copy; hash extraction is analyst-side only) -> raw\server\ntds' 'Yellow'
                    }
                }
            } elseif ($isDc) {
                Write-CaseLog '    DC detected - NTDS.dit copy available with Full preset (module 8.14)' 'DarkGray'
            }
            Save-Rows -Name 'server_logs' -Rows $inv
        } }
    [pscustomobject]@{ Id = '8.15'; Cat = 'CONTEXT'; Name = 'Credential exposure sweep (auto-logon, WLAN keys, DPAPI vault, LSASS dumps, browser Login Data)'; Default = $true; Quick = $false;
        Run = {
            $rows = @()
            # auto-logon: user name + whether a plaintext password value exists (value itself NOT copied to csv)
            $wl = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
            if ($wl -and "$($wl.DefaultUserName)") {
                $hasPw = -not [string]::IsNullOrEmpty("$($wl.DefaultPassword)")
                $rows += [pscustomobject]@{ Item = 'Auto-logon (Winlogon)'; Detail = "user '$($wl.DefaultUserName)', cached password: $(if ($hasPw) { 'PRESENT' } else { 'absent' })"; Risk = $(if ($hasPw) { 'HIGH' } else { 'LOW' }) }
            }
            # WLAN profiles - keys captured into raw\wifi (evidence, analyst material)
            $wifiProfiles = @()
            try {
                foreach ($l in (& netsh.exe wlan show profiles 2>$null | ForEach-Object { "$_" })) {
                    if ($l -match 'All User Profile\s*:\s*(.+)$') { $wifiProfiles += $Matches[1].Trim() }
                }
            } catch { }
            foreach ($p in $wifiProfiles) {
                try {
                    $d = (& netsh.exe wlan show profile name="$p" key=clear 2>$null | ForEach-Object { "$_" }) -join "`n"
                    $auth = ''; if ($d -match 'Authentication\s*:\s*(\S+)') { $auth = $Matches[1] }
                    $hasKey = $d -match 'Key Content\s*:\s*(\S)'
                    Out-RawText -SubDir 'wifi' -Name ("wlan_" + ($p -replace '[^\w\.-]', '_') + ".txt") -Text ($d -split "`n")
                    $rows += [pscustomobject]@{ Item = "WLAN profile '$p'"; Detail = "auth $auth, key $(if ($hasKey) { 'CAPTURED -> raw\wifi' } else { 'not stored' })"; Risk = $(if ($hasKey) { 'MEDIUM' } else { 'LOW' }) }
                } catch { }
            }
            # DPAPI vault + protect blobs (analyst-side decryption) per user
            $vaultCount = 0
            foreach ($u in (@(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Public|Default|All Users' }))) {
                foreach ($sub in @('AppData\Local\Microsoft\Credentials', 'AppData\Roaming\Microsoft\Credentials', 'AppData\Local\Microsoft\Protect')) {
                    $src = Join-Path $u.FullName $sub
                    if (-not (Test-Path $src)) { continue }
                    $files = @(Get-ChildItem -LiteralPath $src -Recurse -File -ErrorAction SilentlyContinue)
                    if ($files.Count -eq 0) { continue }
                    $d = Join-Path $RawDir "vault\$($u.Name)\$([IO.Path]::GetFileName($sub))"
                    New-Item -ItemType Directory -Path $d -Force | Out-Null
                    $files | Copy-Item -Destination $d -Force -ErrorAction SilentlyContinue
                    $vaultCount += $files.Count
                }
            }
            if ($vaultCount -gt 0) { $rows += [pscustomobject]@{ Item = 'DPAPI vault blobs'; Detail = "$vaultCount credential/protect blob(s) -> raw\vault (analyst-side decrypt)"; Risk = 'MEDIUM' } }
            # LSASS dump hunt - shallow, fast, well-known drop spots (recorded, never copied)
            $dmpRoots = @("$env:TEMP", "$env:SystemRoot\Temp", "$env:ProgramData")
            foreach ($u in (@(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Public|Default|All Users' }))) {
                $dmpRoots += @((Join-Path $u.FullName 'AppData\Local\Temp'), (Join-Path $u.FullName 'Documents'), (Join-Path $u.FullName 'Desktop'))
            }
            $dmp = @()
            foreach ($root in $dmpRoots) {
                if (-not $root -or -not (Test-Path $root)) { continue }
                try { $dmp += @(Get-ChildItem -LiteralPath $root -Filter '*.dmp' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)lsass|dump' }) } catch { }
                if (@($dmp).Count -ge 10) { break }
            }
            foreach ($f in (($dmp | Sort-Object FullName -Unique) | Select-Object -First 10)) {
                $rows += [pscustomobject]@{ Item = 'Possible credential dump on disk'; Detail = "$($f.FullName) ($([math]::Round($f.Length / 1MB, 1)) MB)"; Risk = 'HIGH' }
            }
            Save-Rows -Name 'credential_sweep' -Rows $rows
            $hot = @($rows | Where-Object { "$($_.Risk)" -eq 'HIGH' }).Count
            if ($rows.Count -gt 0) {
                Write-CaseLog "    credential sweep: $($rows.Count) finding(s) ($hot HIGH) -> csv\credential_sweep.csv" $(if ($hot -gt 0) { 'Red' } else { 'Gray' })
            } else {
                Write-CaseLog '    credential sweep: no exposure findings (no auto-logon, no WLAN keys, no vault blobs, no dumps)' 'Gray'
            }
        } }
    [pscustomobject]@{ Id = '8.16'; Cat = 'CONTEXT'; Name = 'Remote access sweep (tunnel tools, RA services, RDP ServiceDll, SSH keys, RA logs)'; Default = $true; Quick = $false;
        Run = {
            # Evidence surface for hunt rules R23-R26 (csv\remote_access.csv): tunnels and
            # remote-access tools as services, RDP ServiceDll tamper, SSH authorized_keys,
            # RA tool install/log dirs (logs preserved to raw\ra_logs - vendors rotate them fast).
            $ra = New-Object System.Collections.Generic.List[object]
            # NOTE: keep in sync with $tunPat/$raPat in New-HuntFindings (R23-R26)
            $tunPat = '(?i)(^|[^a-z0-9])(ngrok|cloudflared|tailscaled?|chisel|ligolo|frpc|frps|gost|revsocks)([^a-z0-9]|$)'
            $raPat = '(?i)(^|[^a-z0-9])(anydesk|screenconnect|connectwisecontrol|teamviewer|rustdesk)([^a-z0-9]|$)'

            # 1) one service enumeration: tunnel + RA tool matches, sshd presence
            $svcs = @()
            try { $svcs = @(Get-WmiOrCim -Class Win32_Service) } catch { }
            foreach ($s in $svcs) {
                $blob = "$($s.Name) $($s.DisplayName) $($s.PathName)"
                $kind = ''
                if ($blob -match $tunPat) { $kind = 'Tunnel service' } elseif ($blob -match $raPat) { $kind = 'RA tool service' }
                if (-not $kind) { continue }
                $state = "$($s.State)"
                $null = $ra.Add([pscustomobject]@{
                    Type = $kind; Name = "$($s.Name)"; State = $(if ($state -eq 'Running') { 'running' } else { $state })
                    Path = "$($s.PathName)"; Detail = "display '$($s.DisplayName)' | start $($s.StartMode) | account $($s.StartName)"
                })
            }
            if (@($svcs | Where-Object { "$($_.Name)" -eq 'sshd' }).Count -gt 0) {
                $sshState = "$(@($svcs | Where-Object { "$($_.Name)" -eq 'sshd' })[0].State)"
                $null = $ra.Add([pscustomobject]@{ Type = 'SSH server'; Name = 'sshd'; State = $sshState; Path = "$env:SystemRoot\System32\OpenSSH"; Detail = 'OpenSSH server present - authorized_keys below are live trust anchors' })
            }

            # 2) RDP ServiceDll tamper (RDPWrap-class): the registered DLL must be termsrv.dll
            try {
                $svcDll = "$((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters' -Name ServiceDll -ErrorAction Stop).ServiceDll)"
                if ($svcDll -and $svcDll -notmatch '(?i)\\termsrv\.dll$') {
                    $null = $ra.Add([pscustomobject]@{ Type = 'RDP ServiceDll tamper'; Name = 'TermService'; State = 'tampered'; Path = $svcDll; Detail = 'ServiceDll is not termsrv.dll - RDPWrap-class hijack (multi-session RDP on non-server)' })
                }
            } catch { }

            # 3) authorized_keys: programdata ssh + per-profile .ssh (non-empty = planted trust)
            $akSeen = @()
            $pdSsh = Join-Path $env:ProgramData 'ssh'
            if (Test-Path $pdSsh) { $akSeen += @(Get-ChildItem -LiteralPath $pdSsh -Filter '*authorized_keys*' -File -ErrorAction SilentlyContinue | ForEach-Object { @{ File = $_; Tag = 'programdata' } }) }
            foreach ($u in @(Get-UserProfileList)) {
                $sshDir = Join-Path "$($u.Path)" '.ssh'
                if (Test-Path $sshDir) { $akSeen += @(Get-ChildItem -LiteralPath $sshDir -Filter '*authorized_keys*' -File -ErrorAction SilentlyContinue | ForEach-Object { @{ File = $_; Tag = "$($u.User -replace '[^\w]', '_')" } }) }
            }
            foreach ($ak in $akSeen) {
                $f = $ak.File
                $keyLines = @()
                $readable = $true
                try { $keyLines = @(Get-Content -LiteralPath $f.FullName -ErrorAction Stop | Where-Object { "$($_)" -and "$($_.Trim())" -notmatch '^(#|$)' }) } catch { $readable = $false }
                $sha = ''
                try { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
                $state = if (-not $readable) { 'unreadable (access denied)' } elseif ($keyLines.Count -gt 0) { "populated ($($keyLines.Count) key line(s))" } else { 'empty/comments-only' }
                $null = $ra.Add([pscustomobject]@{
                    Type = 'SSH authorized_keys'; Name = $f.Name; State = $state; Path = $f.FullName
                    Detail = "profile $($ak.Tag)$(if ($sha) { " | sha256 $sha" })$(if ($keyLines.Count -gt 0) { ' | content -> raw\ra_logs' })"
                })
                if ($keyLines.Count -gt 0) {
                    try { Out-RawText -SubDir 'ra_logs' -Name ("authorized_keys_" + $ak.Tag + "_" + $f.Name + ".txt") -Text (@(Get-Content -LiteralPath $f.FullName) | ForEach-Object { "$_" }) } catch { }
                }
            }

            # 4) RA tool data dirs under ProgramData - preserve logs/configs to raw\ra_logs
            foreach ($d in @(Get-ChildItem $env:ProgramData -Directory -ErrorAction SilentlyContinue | Where-Object { "$($_.Name)" -match $raPat })) {
                $files = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 20MB -and "$($_.Name)" -match '(?i)\.(log|trace|txt|xml|conf|config|ad)$|connections' } | Select-Object -First 40)
                if ($files.Count -gt 0) {
                    $dest = Join-Path $RawDir ("ra_logs\" + ($d.Name -replace '[^\w]', '_'))
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                    $files | Copy-Item -Destination $dest -Force -ErrorAction SilentlyContinue
                }
                $null = $ra.Add([pscustomobject]@{
                    Type = 'RA tool data dir'; Name = $d.Name; State = 'present'; Path = $d.FullName
                    Detail = "$(if ($files.Count -gt 0) { "$($files.Count) evidence file(s) -> raw\ra_logs\$($d.Name -replace '[^\w]', '_')" } else { 'no retained logs' })"
                })
            }

            Save-Rows -Name 'remote_access' -Rows $ra.ToArray()
            $notable = @($ra | Where-Object { "$($_.Type)" -match 'Tunnel|tamper|SSH server|authorized_keys' -or "$($_.State)" -match 'running|tampered' }).Count
            if ($ra.Count -gt 0) {
                Write-CaseLog "    remote access sweep: $($ra.Count) row(s) ($notable notable) -> csv\remote_access.csv" $(if ($notable -gt 0) { 'Yellow' } else { 'Gray' })
            } else {
                Write-CaseLog '    remote access sweep: no tunnels, RA tools, RDP tamper or SSH keys found' 'Gray'
            }
        } }
)

function Get-FilteredEvents {
    param([string]$LogName, [int[]]$Ids, $Start, [int]$MaxMsg = 500)
    try {
        $filter = @{ LogName = $LogName; Id = $Ids }
        if ($Start) { $filter.StartTime = $Start }
        if ($script:LogEndDT) { $filter.EndTime = $script:LogEndDT }
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        if (-not $events) { return @() }
        $rows = foreach ($e in $events) {
            $msg = ''
            try { $msg = ($e.Message -replace '\s+', ' '); if ($msg.Length -gt $MaxMsg) { $msg = $msg.Substring(0, $MaxMsg) + '...' } } catch { }
            [pscustomobject]@{ TimeCreated = $e.TimeCreated; Id = $e.Id; Provider = $e.ProviderName; Level = $e.LevelDisplayName; Message = $msg }
        }
        return $rows
    } catch { return @() }
}

function Export-Evtx {
    param([string]$LogName, [string]$FileName)
    try {
        $dir = Join-Path $RawDir 'evtx'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $dest = Join-Path $dir $FileName
        & wevtutil.exe epl $LogName "$dest" /ow:true 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $mb = [math]::Round((Get-Item $dest -ErrorAction SilentlyContinue).Length / 1MB, 1)
            Write-CaseLog "    evtx: $FileName ($mb MB)" 'Gray'
        } else {
            Write-CaseLog "    evtx export failed: $LogName" 'DarkYellow'
        }
    } catch { Write-CaseLog "    evtx export error: $LogName" 'DarkYellow' }
}

function Get-EventDataRows {
    # Structured EventData extraction for security/sysmon event IDs (XML fields, newest-first, capped).
    param([string]$LogName, [int[]]$Id, $Fields, $Start, [int]$Cap = 3000)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $filter = @{ LogName = $LogName; Id = $Id }
        if ($Start) { $filter.StartTime = $Start }
        if ($script:LogEndDT) { $filter.EndTime = $script:LogEndDT }
        $raw = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        if (-not $raw) { return @() }
        foreach ($e in ($raw | Select-Object -First $Cap)) {
            $d = @{}
            try {
                $x = [xml]$e.ToXml()
                $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            } catch { }
            $o = [ordered]@{ Time = $e.TimeCreated; EventId = $e.Id }
            foreach ($k in $Fields.Keys) { $o[$k] = "$($d[$Fields[$k]])" }
            $null = $rows.Add([pscustomobject]$o)
        }
    } catch { }
    return $rows.ToArray()
}

function Get-IisW3cRows {
    # Minimal IIS W3C log parser: fields from the #Fields directive, newest files first, rows capped.
    param([string]$Path, [int]$Cap = 10000)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10)) {
            $fields = $null
            foreach ($line in (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
                if ($line -match '^#Fields:\s*(.+)$') { $fields = ($Matches[1] -split '\s+'); continue }
                if (-not $fields -or $line -match '^#') { continue }
                $p = $line -split ' '
                if ($p.Count -lt $fields.Count) { continue }
                $o = [ordered]@{ }
                for ($i = 0; $i -lt $fields.Count; $i++) { $o[$fields[$i]] = $p[$i] }
                $null = $rows.Add([pscustomobject]$o)
                if ($rows.Count -ge $Cap) { return $rows.ToArray() }
            }
        }
    } catch { }
    return $rows.ToArray()
}

function Get-StartupInfoRows {
    # StartupInfo XMLs (System32\WDI\LogFiles\StartupInfo\*.xml): per-session user app launches.
    param([string]$Path)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter '*.xml' -File -ErrorAction SilentlyContinue)) {
            $x = $null
            try { $x = [xml](Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop) } catch { continue }
            $apps = @()
            try { $apps = @($x.SelectNodes('//*[local-name()="Application"]')) } catch { }
            foreach ($a in $apps) {
                $p2 = $a.Attributes.GetNamedItem('Path')
                if (-not $p2) { continue }
                $cnt = $a.Attributes.GetNamedItem('ExecutionCount')
                $lt = $a.Attributes.GetNamedItem('LastExecutionTime')
                $null = $rows.Add([pscustomobject]@{ File = $f.Name; App = "$($p2.Value)"; Count = $(if ($cnt) { "$($cnt.Value)" } else { '' }); LastRun = $(if ($lt) { "$($lt.Value)" } else { '' }) })
            }
        }
    } catch { }
    return $rows.ToArray()
}

function Get-WerReportRows {
    # Report.wer text files (UTF-16 key=value): faulting app/module + event time (FILETIME ticks).
    param([string]$Path)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter 'Report.wer' -File -Recurse -ErrorAction SilentlyContinue)) {
            $kv = @{}
            try {
                foreach ($line in (Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
                    if ($line -match '^([A-Za-z0-9\[\]\.]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
                }
            } catch { continue }
            $app = ''
            foreach ($k in @('AppPath', 'TargetAppPath', 'Sig[0].Value')) { if ($kv.ContainsKey($k) -and $kv[$k]) { $app = $kv[$k]; break } }
            $mod = ''
            foreach ($k in @('FaultingModule', 'Sig[1].Value', 'Sig[3].Value')) { if ($kv.ContainsKey($k) -and $kv[$k]) { $mod = $kv[$k]; break } }
            $t = ''
            if ($kv.ContainsKey('EventTime') -and $kv['EventTime']) {
                try { $t = [datetime]::FromFileTimeUtc([long]$kv['EventTime']).ToString('s') } catch { }
            }
            $rel = $f.FullName
            try { $rel = $f.FullName.Substring($Path.Length).TrimStart('\') } catch { }
            $null = $rows.Add([pscustomobject]@{ Time = $t; App = $app; Module = $mod; File = $rel })
        }
    } catch { }
    return $rows.ToArray()
}

function Get-PresetSelection {
    param([string]$P)
    $sel = @{}
    foreach ($m in $script:Modules) { $sel[$m.Id] = $false }
    switch ($P) {
        'Flash' { }
        'Quick' { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Quick } }
        'Standard' { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Default } }
        'Full' {
            foreach ($m in $script:Modules) { $sel[$m.Id] = (@('3.2', '7.1') -notcontains $m.Id) }
        }
        default { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Default } }
    }
    if ($IncludeMemory) { $sel['7.1'] = $true }
    # v2.21 role packs: explicit DC/WebServer presets force role modules on; Standard/Full auto-enable on the detected role
    $rolePack = ''
    if ($P -eq 'DC') { $rolePack = '4.9' }
    elseif ($P -eq 'WebServer') { $rolePack = '8.12' }
    elseif (($P -eq 'Standard' -or $P -eq 'Full') -and $script:HostRole -ne 'Workstation') {
        $rolePack = if ($script:HostRole -eq 'DC') { '4.9' } else { '8.12' }
    }
    if ($rolePack -and $sel.ContainsKey($rolePack)) { $sel[$rolePack] = $true }
    return $sel
}

function Show-Menu {
    param([hashtable]$Selection)
    $cats = ($script:Modules | Group-Object Cat | ForEach-Object { $_.Name })
    $range = Get-LogRangeText
    $count = 0
    $byId = @{}
    $script:Modules | ForEach-Object { $byId[$_.Id] = $count; $count++ }
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  OPHIRA v$ScriptVersion   |   $Computer   |   Role: $script:HostRole   |   Log range: $range" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        $n = 0
        foreach ($cat in $cats) {
            Write-Host ""
            Write-Host ("  {0}" -f $cat) -ForegroundColor White
            foreach ($m in ($script:Modules | Where-Object { $_.Cat -eq $cat })) {
                $mark = if ($Selection[$m.Id]) { '[X]' } else { '[ ]' }
                $color = if ($Selection[$m.Id]) { 'Yellow' } else { 'Gray' }
                $note = if (@('3.2') -contains $m.Id) { '  <-- ACTIVE traffic' } elseif ($m.Id -eq '7.1') { '  <-- GB-size' } else { '' }
                Write-Host ("   $mark {0,-4} {1}{2}" -f $m.Id, $m.Name, $note) -ForegroundColor $color
            }
        }
        Write-Host ""
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  <id>  toggle item (e.g. 4.1)   |  <cat#> toggle whole category (e.g. 4)" -ForegroundColor White
        Write-Host "  all | none | T=change log range | R=RUN | Q=quit (no collection)" -ForegroundColor White
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        $inp = Read-Host "  Command"
        switch -Regex ($inp) {
            '^(?i)all$' { foreach ($m in $script:Modules) { $Selection[$m.Id] = $true } }
            '^(?i)none$' { foreach ($m in $script:Modules) { $Selection[$m.Id] = $false } }
            '^(?i)t$' {
                $script:LogStartDT = $null
                $script:LogEndDT = $null
                if ($LogHours -eq 168) { $script:LogHours = 24 }
                elseif ($LogHours -eq 24) { $script:LogHours = 720 }
                elseif ($LogHours -eq 720) { $script:LogHours = 0 }
                else { $script:LogHours = 168 }
                $range = Get-LogRangeText
            }
            '^(?i)r$' { return $Selection }
            '^(?i)q$' { return $null }
            '^(?i)\d+\.\d+$' {
                if ($Selection.ContainsKey($inp.ToUpper())) { $Selection[$inp.ToUpper()] = -not $Selection[$inp.ToUpper()] }
                elseif ($Selection.ContainsKey($inp)) { $Selection[$inp] = -not $Selection[$inp] }
            }
            '^(?i)\d$' {
                foreach ($m in ($script:Modules | Where-Object { $_.Id -like "$inp.*" })) { $Selection[$m.Id] = -not ($Selection[$m.Id]) }
            }
            default { }
        }
    }
}

function Invoke-SelectedModules {
    param([hashtable]$Selection)
    $selected = @($script:Modules | Where-Object { $Selection[$_.Id] })
    $total = $selected.Count
    $done = 0
    $script:ModuleTimings = @()
    $phaseOf = {
        param($m)
        if ($m.Cat -eq 'VOLATILE') { 'A' }
        elseif (@('7.1', '7.2', '4.7', '4.8') -contains $m.Id) { 'CI' }
        elseif (@('4.6', '5.4', '5.5', '8.4') -contains $m.Id) { 'C' }
        else { 'B' }
    }
    $runInline = {
        param($m)
        $script:Progress++
        Write-Host ""
        Write-CaseLog ("[{0}/{1}] Module {2}: {3}" -f $script:Progress, $total, $m.Id, $m.Name) 'Cyan'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            & $m.Run
            $sw.Stop()
            $script:ModuleTimings += [pscustomobject]@{ Id = $m.Id; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Mode = 'inline' }
            Write-CaseLog ("    done in {0:N1}s" -f $sw.Elapsed.TotalSeconds) 'DarkGreen'
        } catch {
            $sw.Stop()
            $script:ModuleTimings += [pscustomobject]@{ Id = $m.Id; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); Mode = 'inline' }
            Write-CaseLog ("    ERROR: {0}" -f $_.Exception.Message) 'Red'
        }
    }
    if ($Sequential -or $script:SimpleUI) {
        $script:Progress = 0
        if ($script:SimpleUI) {
            $friendly = @{
                'VOLATILE'    = 'Checking what is running right now'
                'PERSISTENCE' = 'Checking how malware could survive a reboot'
                'NETWORK MAP' = 'Mapping network connections'
                'LOGS'        = 'Reviewing Windows security logs'
                'ARTIFACTS'   = 'Preserving forensic evidence'
                'CONTEXT'     = 'Collecting attacker activity traces'
                'DEFENDER'    = 'Checking antivirus history'
                'MEMORY'      = 'Capturing memory (the long step)'
            }
            $cats = @($selected | Group-Object Cat | ForEach-Object { $_.Name })
            $step = 0
            $swAll = [System.Diagnostics.Stopwatch]::StartNew()
            foreach ($cat in $cats) {
                $step++
                Write-Host ""
                Write-Host ("  Step {0}/{1}: {2}..." -f $step, $cats.Count, $friendly[$cat]) -ForegroundColor Cyan
                foreach ($m in ($selected | Where-Object { $_.Cat -eq $cat })) { & $runInline $m }
            }
            $swAll.Stop()
            Write-Host ""
            Write-Host ("  All steps finished in {0:N0} seconds. Packaging results..." -f $swAll.Elapsed.TotalSeconds) -ForegroundColor Cyan
        } else {
            foreach ($m in $selected) { & $runInline $m }
        }
        return
    }
    $phases = @{
        A = @($selected | Where-Object { (& $phaseOf $_) -eq 'A' })
        B = @($selected | Where-Object { (& $phaseOf $_) -eq 'B' })
        C = @($selected | Where-Object { (& $phaseOf $_) -eq 'C' })
        CI = @($selected | Where-Object { (& $phaseOf $_) -eq 'CI' })
    }
    $script:Progress = 0
    if ($phases.A.Count -gt 0) {
        Write-Host "`n--- Phase A: volatile (sequential, order of volatility) ---" -ForegroundColor Cyan
        foreach ($m in $phases.A) { & $runInline $m }
    }
    if ($phases.B.Count -gt 0) {
        Write-Host "`n--- Phase B: collection ($(if ($phases.B.Count -gt 1) { 'parallel' } else { 'inline' }): $(($phases.B.Id) -join ' ') ---" -ForegroundColor Cyan
        $script:Progress += 0
        $r = Invoke-ModuleBatch -Batch $phases.B -Workers 4
        foreach ($x in $r) { $script:ModuleTimings += [pscustomobject]@{ Id = $x.Id; Seconds = $x.Seconds; Mode = 'parallel' } }
        $script:Progress += $phases.B.Count
    }
    if ($phases.C.Count -gt 0) {
        Write-Host "`n--- Phase C: heavy analytics ($(if ($phases.C.Count -gt 1) { 'parallel' } else { 'inline' })): $(($phases.C.Id) -join ' ') ---" -ForegroundColor Cyan
        $r = Invoke-ModuleBatch -Batch $phases.C -Workers 4
        foreach ($x in $r) { $script:ModuleTimings += [pscustomobject]@{ Id = $x.Id; Seconds = $x.Seconds; Mode = 'parallel' } }
        $script:Progress += $phases.C.Count
    }
    if ($phases.CI.Count -gt 0) {
        Write-Host "`n--- Phase CI: interactive (memory) ---" -ForegroundColor Cyan
        foreach ($m in $phases.CI) { & $runInline $m }
    }
}

function ConvertTo-HtmlEsc {
    param([string]$s)
    if ($null -eq $s) { return '' }
    return ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

function New-VtLink {
    param([string]$Indicator, [string]$Label = '')
    $i = ConvertTo-HtmlEsc $Indicator
    $lbl = if ($Label) { ConvertTo-HtmlEsc $Label } else { $i }
    if ($Indicator -match '^[a-fA-F0-9]{32,64}$' -or $Indicator -match '^(\d{1,3}\.){3}\d{1,3}$' -or $Indicator -match '\.[a-z]{2,}$') {
        return "<a target='_blank' href='https://www.virustotal.com/gui/search/$i'>VT&nearr;</a>"
    }
    return $lbl
}

function Get-LvlRank {
    # Top-level (was nested in New-HtmlReport): also used by New-SigmaRuleLogs and fleet reporting.
    param([string]$l)
    switch -Regex ("$l") { 'crit' { 5; break } 'high' { 4; break } 'med' { 3; break } 'low' { 2; break } default { 1 } }
}

function Get-TacticLabel {
    param([string]$abbr)
    $tacticNames = @{
        'Recon' = 'Reconnaissance'; 'ResDevDev' = 'Resource Development'; 'InitAccess' = 'Initial Access'
        'Exec' = 'Execution'; 'Persis' = 'Persistence'; 'PrivEsc' = 'Privilege Escalation'
        'DefEvade' = 'Defense Evasion'; 'CredAccess' = 'Credential Access'; 'Disc' = 'Discovery'
        'LatMov' = 'Lateral Movement'; 'Collect' = 'Collection'; 'C2' = 'Command and Control'
        'Exfil' = 'Exfiltration'; 'Impact' = 'Impact'; 'ImpairC2' = 'Impair Command and Control'; 'ImpairProc' = 'Impair Process'
    }
    $a = "$abbr".Trim()
    if ($tacticNames.ContainsKey($a)) { return $tacticNames[$a] }
    return $a
}

function Split-TagList {
    param([string]$s)
    if (-not "$s") { return @() }
    return @([regex]::Split("$s", '[^A-Za-z0-9.\-]+') | Where-Object { $_ -and $_.Length -gt 1 })
}

function Import-CaseCsv {
    param([string]$Name)
    if ($Name -notmatch '\.csv$') { $Name = "$Name.csv" }
    $f = Join-Path $CsvDir $Name
    if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) {
        try { return @(Import-Csv $f) } catch { return @() }
    }
    return @()
}

function New-HtmlReport {
    $scored = @(Import-CaseCsv 'flash_process_scored.csv')
    $iocHits = @(Import-CaseCsv 'flash_ioc_hits.csv')
    $hayRows = @(Import-CaseCsv 'hayabusa_timeline.csv')
    $execRows = @(Import-CaseCsv 'execution_timeline.csv')
    $brute = @(Import-CaseCsv 'security_bruteforce_candidates.csv')
    $pubConns = @(Import-CaseCsv 'flash_public_connections.csv')
    $amcHits = @(Import-CaseCsv 'ioc_hits_amcache.csv')
    $yaraHits = @(Import-CaseCsv 'yara_hits.csv')
    $beacons = @(Import-CaseCsv 'beacon_candidates.csv')
    $dnsBeacons = @(Import-CaseCsv 'dns_beacon_candidates.csv')
    $huntRows = @(Import-CaseCsv 'hunt_findings.csv')
    $liveScan = @(Import-CaseCsv 'memory_live_scan.csv')
    $lolHits = @(Import-CaseCsv 'loldrivers_hits.csv')
    $psCmds = @(Import-CaseCsv 'ps_decoded_commands.csv')
    $entB = @(Import-CaseCsv 'entities_binaries.csv')
    $entA = @(Import-CaseCsv 'entities_accounts.csv')
    $entR = @(Import-CaseCsv 'entities_remotes.csv')
    $srumRows = @(Import-CaseCsv 'srum_usage.csv')
    $usnBursts = @(Import-CaseCsv 'usn_write_bursts.csv')
    $mftRecent = @(Import-CaseCsv 'mft_recent.csv')
    $pfParsed = @(Import-CaseCsv 'prefetch_parsed.csv')
    $authSum = @(Import-CaseCsv 'security_auth_summary.csv')
    $authEv = @(Import-CaseCsv 'security_auth_events.csv')
    $runKeys = @(Import-CaseCsv 'autoruns_runkeys.csv')
    $tasksFlag = @(Import-CaseCsv 'scheduled_tasks_flagged.csv')
    $svcFlag = @(Import-CaseCsv 'services_flagged.csv')
    $wmiBind = @(Import-CaseCsv 'wmi_bindings.csv')
    $deltaRows = @(Import-CaseCsv 'delta_new.csv')
    $gapRows = @(Import-CaseCsv 'logging_gaps.csv')
    $asepRows = @(Import-CaseCsv 'asep_sweep.csv')
    $certs = @(Import-CaseCsv 'certificates.csv')
    $asepHot = @($asepRows | Where-Object { $_.Flags -match 'user-path|nondefault' })
    $defStatus = @(Import-CaseCsv 'defender_status.csv')
    $defThreats = @(Import-CaseCsv 'defender_threats.csv')
    $savedCreds = @(Import-CaseCsv 'saved_credentials.csv')
    $rdpTgt = @(Import-CaseCsv 'rdp_client_targets.csv')
    $bitsJobs = @(Import-CaseCsv 'bits_jobs.csv')
    $posture = @(Import-CaseCsv 'posture.csv')
    $memMfR = @(Import-CaseCsv 'memory_malfind.csv')
    $browserIocR = @(Import-CaseCsv 'ioc_hits_browser.csv')
    $postureBad = @($posture | Where-Object { $_.Status -eq 'BAD' })

    $css = @'
<style>
body{background:#0f1115;color:#d7dce3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 10px;color:#8ab4f8;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
.meta{color:#7d8590;font-size:12px}
.nav{position:sticky;top:0;background:#0f1115ee;border-bottom:1px solid #2a2f3a;padding:8px 0;z-index:9}
.nav a{color:#8ab4f8;font-size:12px;text-decoration:none;margin-right:14px}
.chips{margin:16px 0}.chip{display:inline-block;padding:6px 14px;border-radius:16px;margin-right:8px;font-size:14px;font-weight:600}
.card{background:#181b21;border:1px solid #2a2f3a;border-radius:8px;padding:14px;margin:10px 0}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:700;margin-right:8px}
.HIGH{background:#5c1a1e;color:#ff8789}.MEDIUM{background:#5c470f;color:#ffce6b}.LOW{background:#1d3a26;color:#7ee2a8}.INFO{background:#243447;color:#9ec1f0}
.ev{display:inline-block;background:#232833;border:1px solid #333b49;border-radius:4px;padding:2px 8px;margin:3px 4px 0 0;font-size:11px;color:#aab4c3}
.path{font-family:Consolas,monospace;font-size:12px;color:#8ab4f8;word-break:break-all}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #2a2f3a;padding:6px 10px;text-align:left}
th{background:#1d222c;color:#8ab4f8}tr:nth-child(even){background:#151920}
details{margin:10px 0;padding:6px 10px;background:#151920;border:1px solid #2a2f3a;border-radius:6px}summary{cursor:pointer;padding:4px 0}
.crit{color:#ff8789;font-weight:700}.high{color:#ffb35c}.med{color:#ffce6b}.low{color:#9ec1f0}.info{color:#7d8590}
a{color:#8ab4f8} .foot{margin-top:40px;color:#565e6b;font-size:11px}
.vbanner{border-radius:10px;padding:18px 22px;margin:18px 0;border:2px solid}
.v4{background:#2a0f12;border-color:#a33}.v3{background:#2a150f;border-color:#b33}.v2{background:#2a220f;border-color:#b93}.v1{background:#0f2418;border-color:#3a5}.v0{background:#1c1c22;border-color:#666}
.vtitle{font-size:24px;font-weight:800;margin:0 0 4px}
.vowner{font-size:14px;margin:6px 0 0}
.confwrap{background:#1d222c;border-radius:8px;height:18px;margin-top:12px;position:relative;overflow:hidden}
.confbar{height:18px}
.conftext{position:absolute;left:10px;top:1px;font-size:12px;font-weight:700;color:#d7dce3}
.sig{display:inline-block;background:#232833;border:1px solid #333b49;border-radius:6px;padding:6px 10px;margin:3px 6px 3px 0;font-size:12px}
.cov-ok{color:#7ee2a8}.cov-miss{color:#ff8789}
.tac{display:inline-block;padding:5px 12px;border-radius:14px;margin:3px 6px 3px 0;font-size:12px;font-weight:600;background:#243447;color:#9ec1f0}
.tac.hi{background:#5c1a1e;color:#ff8789}.tac.md{background:#5c470f;color:#ffce6b}
pre.ioc{background:#181b21;border:1px solid #2a2f3a;border-radius:8px;padding:12px;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all}
.rec{background:#181b21;border-left:4px solid #8ab4f8;border-radius:6px;padding:10px 14px;margin:8px 0}
details{margin:6px 0}summary{cursor:pointer;color:#8ab4f8;font-size:13px}
</style>
'@

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira - $Computer</title>$css</head><body>")
    $null = $sb.AppendLine("<h1>OPHIRA COMPROMISE ASSESSMENT REPORT</h1>")
    $null = $sb.AppendLine("<div class='meta'>Host: $Computer &nbsp;|&nbsp; Case: $(ConvertTo-HtmlEsc $script:CurrentCaseID) &nbsp;|&nbsp; Analyst: $(ConvertTo-HtmlEsc $script:CurrentAnalyst) &nbsp;|&nbsp; Collected: $($StartTime.ToString('u')) &nbsp;|&nbsp; Ophira v$ScriptVersion &nbsp;|&nbsp; Sysmon: $(if ($Sysmon) { 'yes' } else { 'no' }) &nbsp;|&nbsp; Elevated: $(if (Test-IsAdmin) { 'yes' } else { 'NO' })</div>")
    $null = $sb.AppendLine("<div class='nav'><a href='#verdict'>Verdict</a><a href='#coverage'>Coverage</a><a href='#attack'>ATT&CK</a><a href='#ioc'>IOCs</a><a href='#tactics'>Findings by tactic</a><a href='#yara'>YARA</a><a href='#processes'>Processes</a><a href='#sigma'>Sigma</a><a href='#logons'>Logons</a><a href='#persistence'>Persistence</a><a href='#filesystem'>File system</a><a href='#beacons'>Beaconing</a><a href='#network'>Network</a><a href='#timeline'>Timeline</a><a href='#snapshot'>Snapshot</a><a href='#drivers'>Drivers</a><a href='#hunt'>Hunt</a><a href='#entities'>Connections</a><a href='#recommendations'>Recommendations</a><a href='#evidence'>Evidence index</a></div>")

    # ---------- verdict banner ----------
    $null = $sb.AppendLine("<a name='verdict'></a><h2>Verdict</h2>")
    if ($script:Verdict) {
        $v = $script:Verdict
        $null = $sb.AppendLine("<div class='vbanner v$($v.LevelRank)'>")
        $null = $sb.AppendLine("<p class='vtitle'>$(ConvertTo-HtmlEsc $v.Level)</p>")
        $null = $sb.AppendLine("<p class='vowner'>$(ConvertTo-HtmlEsc $v.OwnerLine) &nbsp; Confidence: $($v.ConfidencePercent)% (evidence coverage)</p>")
        $null = $sb.AppendLine("<div class='confwrap'><div class='confbar' style='width:$([math]::Min(100, [int]$v.ConfidencePercent))%;background:#b93'></div><div class='conftext'>$($v.ConfidencePercent)% of weighted evidence sources collected</div></div>")
        if (@($v.Signals).Count -gt 0) {
            $null = $sb.AppendLine("<p style='margin-top:12px'><b>Contributing signals</b></p>")
            foreach ($s in @($v.Signals)) {
                $wcol = if ($s.Weight -ge 4) { 'crit' } elseif ($s.Weight -ge 3) { 'high' } elseif ($s.Weight -ge 2) { 'med' } else { 'info' }
                $null = $sb.AppendLine("<div class='sig'><span class='$wcol'>[w$($s.Weight)]</span> $(ConvertTo-HtmlEsc $s.Signal) x$($s.Count) $(if ("$($s.Detail)") { " - <span class='path'>$(ConvertTo-HtmlEsc $s.Detail)</span>" })</div>")
            }
        } else {
            $null = $sb.AppendLine("<p style='margin-top:12px' class='meta'>No compromising signals were observed in the collected evidence.</p>")
        }
        if (@($v.Caveats).Count -gt 0) {
            $null = $sb.AppendLine("<p style='margin-top:12px'><b>What would change this verdict (caveats)</b></p><ul>")
            foreach ($c in @($v.Caveats)) { $null = $sb.AppendLine("<li>$(ConvertTo-HtmlEsc $c)</li>") }
            $null = $sb.AppendLine("</ul>")
        }
        $null = $sb.AppendLine("</div>")
    } else {
        $null = $sb.AppendLine("<div class='vbanner v0'><p class='vtitle'>VERDICT UNAVAILABLE</p><p class='vowner'>The verdict engine did not run - review the raw sections below.</p></div>")
    }
    # ---------- narrative case draft (v2.31) ----------
    try {
        $draft = @(Get-CaseNarrative)
        if ($draft.Count -gt 0) {
            $null = $sb.AppendLine("<a name='draft'></a><h2>Case draft (auto-written - edit before use)</h2><div class='draft'>")
            foreach ($line in $draft) {
                $esc = ConvertTo-HtmlEsc $line
                if ($line -match '^[A-Z][A-Z ]+$') { $null = $sb.AppendLine("<p><b>$esc</b></p>") }
                elseif ($line -match '^ - ') { $null = $sb.AppendLine("<p style='margin:2px 0 2px 18px'>$esc</p>") }
                elseif ($line) { $null = $sb.AppendLine("<p>$esc</p>") }
            }
            $null = $sb.AppendLine("</div><div class='meta'>Plain-text copy: <b>case_draft.txt</b> in the case folder - starting point for your report, not a conclusion.</div>")
        }
    } catch { }

    # ---------- evidence coverage ----------
    $null = $sb.AppendLine("<a name='coverage'></a><h2>Evidence coverage & data quality</h2>")
    if ($script:Verdict -and @($script:Verdict.Coverage).Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Evidence source</th><th>Collected</th><th>Weight</th></tr>")
        foreach ($c in @($script:Verdict.Coverage)) {
            $mark = if ($c.Collected) { "<span class='cov-ok'>yes</span>" } else { "<span class='cov-miss'>NO</span>" }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.Source)</td><td>$mark</td><td>$($c.Weight)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Coverage confidence: $($script:Verdict.ConfidencePercent)% - missing sources narrow what can be ruled out.</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>Coverage data not available.</div>")
    }
    if ($gapRows.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Logging continuity (check for tampering)</h3><table><tr><th>Time</th><th>Event</th><th>Meaning</th></tr>")
        foreach ($g in ($gapRows | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Time)</td><td>$($g.EventId)</td><td>$(ConvertTo-HtmlEsc $g.Meaning)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

    # ---------- summary chips ----------
    $high = @($scored | Where-Object Verdict -eq 'HIGH').Count
    $med = @($scored | Where-Object Verdict -eq 'MEDIUM').Count
    $low = @($scored | Where-Object Verdict -eq 'LOW').Count
    $hayCrit = @($hayRows | Where-Object { "$($_.Level)" -match 'crit' }).Count
    $hayHigh = @($hayRows | Where-Object { "$($_.Level)" -match '^high$' }).Count
    $null = $sb.AppendLine("<div class='chips'>" +
        "<span class='chip HIGH'>Proc HIGH: $high</span><span class='chip MEDIUM'>Proc MED: $med</span><span class='chip LOW'>Proc LOW: $low</span>" +
        "<span class='chip INFO'>IOC hits: $($iocHits.Count)</span><span class='chip INFO'>YARA hits: $($yaraHits.Count)</span><span class='chip INFO'>Sigma rows: $($hayRows.Count) (crit:$hayCrit high:$hayHigh)</span></div>")
    if ($deltaRows.Count -gt 0) {
        $null = $sb.AppendLine("<h2>NEW since previous collection ($(ConvertTo-HtmlEsc $script:DeltaBaseline))</h2><table><tr><th>Type</th><th>Item</th><th>Detail</th></tr>")
        foreach ($d in ($deltaRows | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlEsc $d.Type)</b></td><td>$(ConvertTo-HtmlEsc $d.Item)</td><td class='path'>$(ConvertTo-HtmlEsc $d.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

    # ---------- MITRE ATT&CK ----------
    $null = $sb.AppendLine("<a name='attack'></a><h2>MITRE ATT&CK observed (from Sigma detections)</h2>")
    $techRows = @()
    $tacticCounts = @{}
    $tacticMaxRank = @{}
    foreach ($r in $hayRows) {
        $tacs = @(Split-TagList "$($r.MitreTactics)" | Select-Object -First 1)
        $tags = @(Split-TagList "$($r.MitreTags)")
        $rk = Get-LvlRank "$($r.Level)"
        foreach ($t in $tacs) {
            if (-not $tacticCounts.ContainsKey($t)) { $tacticCounts[$t] = 0; $tacticMaxRank[$t] = 0 }
            $tacticCounts[$t]++
            if ($rk -gt $tacticMaxRank[$t]) { $tacticMaxRank[$t] = $rk }
        }
        foreach ($tg in ($tags | Where-Object { $_ -match '^T\d{4}' })) {
            $techRows += [pscustomobject]@{ Tech = $tg; Tactic = ($tacs -join ','); Rank = $rk; Rule = "$($r.RuleTitle)"; Level = "$($r.Level)"; Last = "$($r.Timestamp)" }
        }
    }
    if ($tacticCounts.Count -gt 0) {
        foreach ($tk in ($tacticCounts.Keys | Sort-Object)) {
            $cls = if ($tacticMaxRank[$tk] -ge 4) { 'hi' } elseif ($tacticMaxRank[$tk] -ge 3) { 'md' } else { '' }
            $null = $sb.AppendLine("<span class='tac $cls'>$(ConvertTo-HtmlEsc (Get-TacticLabel $tk)) : $($tacticCounts[$tk])</span>")
        }
        $null = $sb.AppendLine("")
    }
    $techGroups = @($techRows | Group-Object Tech | ForEach-Object {
        [pscustomobject]@{ Tech = $_.Name; Count = $_.Count; MaxRank = (@($_.Group | ForEach-Object { $_.Rank } | Measure-Object -Maximum).Maximum); Group = $_.Group }
    } | Sort-Object MaxRank, Count -Descending | Select-Object -First 60)
    if ($techGroups.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Technique</th><th>Tactic</th><th>Events</th><th>Max level</th><th>Example alert</th><th>Last seen</th></tr>")
        foreach ($g in $techGroups) {
            $best = @($g.Group | Sort-Object Rank -Descending | Select-Object -First 1)
            $lvlClass = switch -Regex ("$($best.Level)") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
            $tacLbl = (@(Split-TagList $best.Tactic | ForEach-Object { Get-TacticLabel $_ }) -join ', ')
            $null = $sb.AppendLine("<tr><td><b>$($g.Tech)</b></td><td>$(ConvertTo-HtmlEsc $tacLbl)</td><td>$($g.Count)</td><td class='$lvlClass'>$($best.Level)</td><td>$(ConvertTo-HtmlEsc $best.Rule)</td><td>$(ConvertTo-HtmlEsc $best.Last)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Source: csv\hayabusa_timeline.csv (MitreTactics/MitreTags). Reference: <a target='_blank' href='https://attack.mitre.org/techniques/enterprise/'>attack.mitre.org</a></div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No ATT&CK-tagged detections in the analyzed window.</div>")
    }
    $noTelNote = @()
    if (-not (Test-Path (Join-Path $RawDir 'evtx'))) { $noTelNote += 'No event logs exported - Sigma/ATT&CK coverage is nil for this collection.' }
    if (-not $Sysmon) { $noTelNote += 'No Sysmon - injection, image-load and per-process network techniques (e.g. T1055, T1003.001 via Sysmon) are not visible in these logs.' }
    if ($noTelNote.Count -gt 0) {
        $null = $sb.AppendLine("<div class='card'><b>Cannot rule out (telemetry gaps):</b><ul>")
        foreach ($n in $noTelNote) { $null = $sb.AppendLine("<li>$(ConvertTo-HtmlEsc $n)</li>") }
        $null = $sb.AppendLine("</ul></div>")
    }

    # ---------- IOC section ----------
    $null = $sb.AppendLine("<a name='ioc'></a><h2>Indicators of compromise</h2>")
    if ($iocHits.Count -gt 0) {
        $null = $sb.AppendLine("<h3>IOC hits (live system) - investigate first</h3><table><tr><th>Type</th><th>Indicator</th><th>Where</th><th>Context</th><th></th></tr>")
        foreach ($h in $iocHits) {
            $null = $sb.AppendLine("<tr><td><b>$($(ConvertTo-HtmlEsc $h.Type))</b></td><td class='path'>$(ConvertTo-HtmlEsc $h.Indicator)</td><td class='path'>$(ConvertTo-HtmlEsc $h.Where)</td><td>$(ConvertTo-HtmlEsc $h.Context)</td><td>$(New-VtLink $h.Indicator)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($amcHits.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Historical execution IOC hits (amcache SHA1) - near-certain TP evidence</h3><table><tr><th>SHA1</th><th>Application</th><th>Source</th><th></th></tr>")
        foreach ($h in $amcHits) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $h.Indicator)</td><td>$(ConvertTo-HtmlEsc $h.Application)</td><td>$(ConvertTo-HtmlEsc $h.SourceFile)</td><td>$(New-VtLink $h.Indicator)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    $iocBlock = New-Object System.Collections.Generic.List[string]
    foreach ($h in $iocHits) { if ("$($h.Indicator)") { $iocBlock.Add("ioc-$("$($h.Type)".ToLower())  $($h.Indicator)") } }
    foreach ($h in $amcHits) { if ("$($h.Indicator)") { $iocBlock.Add("sha1  $($h.Indicator)") } }
    foreach ($b in $brute) { if ("$($b.SourceIp)") { $iocBlock.Add("ip  $($b.SourceIp)") } }
    foreach ($b in ($beacons | Where-Object { "$($_.Severity)" -match '^(?i)(high|medium)$' -and "$($_.RemoteIp)" })) { $iocBlock.Add("ip  $($b.RemoteIp)") }
    foreach ($b in ($dnsBeacons | Where-Object { "$($_.Severity)" -match '^(?i)(high|medium)$' -and "$($_.Domain)" })) {
        $iocBlock.Add("domain  $($b.Domain)")
        if ("$($b.ResolvedIp)") { $iocBlock.Add("ip  $($b.ResolvedIp)") }
    }
    $yaraScanned = @(Import-CaseCsv 'yara_scanned.csv')
    foreach ($y in ($yaraScanned | Where-Object { "$($_.Hits)" -match '^\d+$' -and [int]$_.Hits -gt 0 -and "$($_.SHA256)" })) { $iocBlock.Add("sha256  $($y.SHA256)") }
    foreach ($h in (Import-CaseCsv 'ioc_hits_dns')) { $iocBlock.Add("domain  $($h.Query)"); if ("$($h.Resolved)") { $iocBlock.Add("ip  $(("$($h.Resolved)" -split '[,;]')[0].Trim())") } }
    foreach ($h in (Import-CaseCsv 'ioc_hits_network')) { $iocBlock.Add("ip  $($h.RemoteIp)") }
    $iocUnique = @($iocBlock.ToArray() | Sort-Object -Unique)
    if ($iocUnique.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Copy-ready indicator list (defanged)</h3><pre class='ioc'>")
        foreach ($l in $iocUnique) {
            $dl = "$l" -replace '(?i)http', 'hxxp'
            if ($dl -notmatch '^(?i)sha') { $dl = $dl -replace '\.', '[.]' }
            $null = $sb.AppendLine((ConvertTo-HtmlEsc $dl))
        }
        $null = $sb.AppendLine("</pre>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No indicators to export.</div>")
    }

    # ---------- findings by tactic (med+ alerts) ----------
    $null = $sb.AppendLine("<a name='tactics'></a><h2>Findings by tactic (med+ Sigma alerts)</h2>")
    $sigAlerts = @($hayRows | Where-Object { (Get-LvlRank "$($_.Level)") -ge 3 })
    if ($sigAlerts.Count -gt 0) {
        $byTactic = @{}
        foreach ($r in $sigAlerts) {
            $tacs = @(Split-TagList "$($r.MitreTactics)")
            if ($tacs.Count -eq 0) { $tacs = @('Other') }
            foreach ($t in ($tacs | Select-Object -First 2)) {
                if (-not $byTactic.ContainsKey($t)) { $byTactic[$t] = New-Object System.Collections.Generic.List[object] }
                $byTactic[$t].Add($r)
            }
        }
        foreach ($tk in ($byTactic.Keys | Sort-Object)) {
            $rows = @($byTactic[$tk])
            $null = $sb.AppendLine("<h3>$(ConvertTo-HtmlEsc (Get-TacticLabel $tk)) ($($rows.Count) events)</h3><details><summary>show alerts</summary><table><tr><th>Alert</th><th>Level</th><th>Hits</th><th>Last seen</th></tr>")
            foreach ($g in @($rows | Group-Object RuleTitle | Sort-Object Count -Descending | Select-Object -First 15)) {
                $best = @($g.Group | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
                $lvlClass = switch -Regex ("$($best.Level)") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $last = (@($g.Group | ForEach-Object { "$($_.Timestamp)" } | Sort-Object -Descending | Select-Object -First 1) -join '')
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td class='$lvlClass'>$($best.Level)</td><td>$($g.Count)</td><td>$(ConvertTo-HtmlEsc $last)</td></tr>")
            }
            $null = $sb.AppendLine("</table></details>")
        }
    } else {
        $null = $sb.AppendLine("<div class='meta'>No medium+ severity Sigma alerts in the analyzed window.</div>")
    }

    # ---------- YARA ----------
    $null = $sb.AppendLine("<a name='yara'></a><h2>YARA findings</h2>")
    if ($yaraHits.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Severity</th><th>Rule</th><th>Description</th><th>File</th></tr>")
        foreach ($y in ($yaraHits | Sort-Object { Get-LvlRank "$($_.Severity)" } -Descending)) {
            $sevCls = switch -Regex ("$($y.Severity)") { 'crit|high' { 'crit'; break } 'med' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $y.Severity)</b></td><td>$(ConvertTo-HtmlEsc $y.Rule)</td><td>$(ConvertTo-HtmlEsc $y.Description)</td><td class='path'>$(ConvertTo-HtmlEsc $y.File)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Scanned binaries: csv\yara_scanned.csv</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No YARA hits (or YARA module not run).</div>")
    }

    # ---------- process verdicts ----------
    $null = $sb.AppendLine("<a name='processes'></a><h2>Process verdicts (correlation scored)</h2>")
    foreach ($p in ($scored | Sort-Object { [int]$_.Score } -Descending | Select-Object -First 30)) {
        $evs = ($p.Evidence -split ';' | Where-Object { $_ }) | ForEach-Object { "<span class='ev'>$(ConvertTo-HtmlEsc $_)</span>" }
        $null = $sb.AppendLine("<div class='card'><span class='badge $($p.Verdict)'>$($p.Verdict) &nbsp;$($p.Score)</span><b>$(ConvertTo-HtmlEsc $p.Name)</b> <span class='meta'>PID $(ConvertTo-HtmlEsc $p.PID)</span> $(New-VtLink $p.Name)<br><span class='path'>$(ConvertTo-HtmlEsc $p.Path)</span><br>$($evs -join ' ')</div>")
    }

    if ($hayRows.Count -gt 0) {
        $alertCol = $null
        foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
            if ($hayRows[0].PSObject.Properties[$cand]) { $alertCol = $cand; break }
        }
        $null = $sb.AppendLine("<a name='sigma'></a><h2>Top Sigma detections (hayabusa)</h2>")
        if ($alertCol) {
            $groups = $hayRows | Group-Object $alertCol | Sort-Object Count -Descending | Select-Object -First 20
            $null = $sb.AppendLine("<table><tr><th>Alert</th><th>Hits</th><th>Max level</th><th>Last seen</th></tr>")
            foreach ($g in $groups) {
                $best = @($g.Group | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
                $lvl = "$($best.Level)"
                $lvlClass = switch -Regex ($lvl) { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $last = (@($g.Group | ForEach-Object { "$($_.Timestamp)" } | Sort-Object -Descending | Select-Object -First 1) -join '')
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td>$($g.Count)</td><td class='$lvlClass'>$lvl</td><td>$(ConvertTo-HtmlEsc $last)</td></tr>")
            }
            $null = $sb.AppendLine("</table>")
        }
        # per-rule drill-down: the actual matched events for the noisiest rules
        if ($hayRows.Count -gt 0) {
            $drill = @($hayRows | Group-Object $alertCol | Sort-Object Count -Descending | Select-Object -First 12)
            foreach ($g in $drill) {
                $best = @($g.Group | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
                $lvl = "$($best.Level)"
                $lvlClass = switch -Regex ($lvl) { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $safe = ("$($g.Name)" -replace '[^A-Za-z0-9\._-]+', '_') -replace '^_+|_+$', ''
                if (-not $safe) { $safe = 'unnamed_rule' }
                if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
                $csvLink = "csv\sigma_rules\$safe.csv"
                $null = $sb.AppendLine("<details><summary><span class='$lvlClass'><b>$(ConvertTo-HtmlEsc $g.Name)</b></span> - $($g.Count) hit(s), max <span class='$lvlClass'>$lvl</span> &nbsp;<span class='meta'>$csvLink</span></summary>")
                $null = $sb.AppendLine("<table><tr><th>Time</th><th>Computer</th><th>EID</th><th>Level</th><th>Event details</th></tr>")
                foreach ($r in (@($g.Group | Sort-Object Timestamp) | Select-Object -First 20)) {
                    $det = ("$($r.Details)") -replace '\s+', ' '
                    if ($det.Length -gt 300) { $det = $det.Substring(0, 300) + '...' }
                    $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $r.Timestamp)</td><td>$(ConvertTo-HtmlEsc $r.Computer)</td><td>$(ConvertTo-HtmlEsc $r.EventID)</td><td class='$lvlClass'>$(ConvertTo-HtmlEsc $r.Level)</td><td class='path'>$(ConvertTo-HtmlEsc $det)</td></tr>")
                }
                $shown = [Math]::Min(20, $g.Count)
                if ($g.Count -gt $shown) { $null = $sb.AppendLine("<tr><td colspan='5' class='meta'>first $shown of $($g.Count) - full log: $csvLink</td></tr>") }
                $null = $sb.AppendLine("</table></details>")
            }
            if ($drill.Count -gt 0) { $null = $sb.AppendLine("<div class='meta'>Expand a rule to see the matched events (time, host, event ID, hayabusa-extracted details). RecordID locates the exact record in the matching evtx under raw\evtx\.</div>") }
        }
        $null = $sb.AppendLine("<div class='meta'>Full timeline: csv\hayabusa_timeline.csv &nbsp;|&nbsp; per-rule event CSVs: csv\sigma_rules\ &nbsp;|&nbsp; hayabusa's own summary: csv\hayabusa_report.html</div>")
    }

    # ---------- recovered attacker commands ----------
    if ($psCmds.Count -gt 0) {
        $null = $sb.AppendLine("<a name='pscmds'></a><h2>Recovered attacker commands (base64/obfuscated PowerShell)</h2>")
        $null = $sb.AppendLine("<table><tr><th>Time</th><th>Source event</th><th>Decoded content</th></tr>")
        foreach ($c in ($psCmds | Select-Object -First 30)) {
            $t = if ($c.PSObject.Properties['Timestamp']) { $c.Timestamp } else { '' }
            $src = if ($c.PSObject.Properties['Channel']) { "$($c.Channel) / $($c.EventID)" } else { '' }
            $txt = ''
            foreach ($p in @('DecodedText', 'Payload', 'Details', 'Message')) {
                if ($c.PSObject.Properties[$p] -and "$($c.$p)") { $txt = "$($c.$p)"; break }
            }
            if (-not $txt) { $txt = ($c.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' ' }
            if ($txt.Length -gt 400) { $txt = $txt.Substring(0, 400) + '...' }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t)</td><td>$(ConvertTo-HtmlEsc $src)</td><td class='path'>$(ConvertTo-HtmlEsc $txt)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>First $($psCmds.Count) recovered commands (hayabusa extract-base64 over the exported PowerShell event logs). Source: csv\ps_decoded_commands.csv</div>")
    }

    # ---------- logon & account analysis ----------
    $null = $sb.AppendLine("<a name='logons'></a><h2>Logon & account activity</h2>")
    $inter = @($authEv | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonType)" -match '^(2|10)$' } | Group-Object Account, SourceIp | Sort-Object Count -Descending | Select-Object -First 15)
    if ($inter.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Interactive / RDP logons</h3><table><tr><th>Account @ Source</th><th>Logons</th></tr>")
        foreach ($g in $inter) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td><b>$($g.Count)</b></td></tr>") }
        $null = $sb.AppendLine("</table>")
    }
    if ($authSum.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Top account/source combinations (all auth events)</h3><details><summary>show top 25</summary><table><tr><th>Account @ Source</th><th>Events</th></tr>")
        foreach ($a in ($authSum | Select-Object -First 25)) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $a.AccountSource)</td><td>$($a.Count)</td></tr>") }
        $null = $sb.AppendLine("</table></details>")
    }
    if ($brute.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Brute-force candidates</h3><table><tr><th>Source IP</th><th>Failed logons</th><th></th></tr>")
        foreach ($b in $brute) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $b.SourceIp)</td><td><b>$($b.FailedLogons)</b></td><td>$(New-VtLink $b.SourceIp)</td></tr>") }
        $null = $sb.AppendLine("</table>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No brute-force candidate sources (threshold: 5+ failed logons). Hayabusa logon summaries: csv\logon_summary* (if module 4.6 ran).</div>")
    }

    # ---------- persistence inventory ----------
    $null = $sb.AppendLine("<a name='persistence'></a><h2>Persistence inventory</h2>")
    $persAny = $false
    if ($tasksFlag.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Flagged scheduled tasks</h3><table><tr><th>Task</th><th>Actions</th><th>Flags</th></tr>")
        foreach ($t in ($tasksFlag | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $t.Actions)</td><td>$(ConvertTo-HtmlEsc $t.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($svcFlag.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Flagged services</h3><table><tr><th>Service</th><th>Binary</th><th>Flags</th></tr>")
        foreach ($s in ($svcFlag | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $s.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $s.PathName)</td><td>$(ConvertTo-HtmlEsc $s.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($wmiBind.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>WMI event subscriptions (rare on clean hosts - review each)</h3><table><tr><th>Binding</th></tr>")
        foreach ($w in ($wmiBind | Select-Object -First 25)) {
            $line = ($w.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' | '
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $line)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($runKeys.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Run keys / startup entries</h3><details><summary>show $($runKeys.Count) entries</summary><table><tr><th>Name</th><th>Command</th></tr>")
        foreach ($r in ($runKeys | Select-Object -First 60)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $r.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $r.Value)</td></tr>")
        }
        $null = $sb.AppendLine("</table></details>")
    }
    if ($asepHot.Count -gt 0) {
        $persAny = $true
        $null = $sb.AppendLine("<h3>Uncommon persistence mechanisms (IFEO / AppInit / Winlogon / netsh / LSA)</h3><table><tr><th>Category</th><th>Target</th><th>Setting</th><th>Value</th><th>Flags</th></tr>")
        foreach ($a in ($asepHot | Select-Object -First 40)) {
            $target = ''
            try { $target = Split-Path "$($a.Location)" -Leaf } catch { }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $a.Category)</td><td>$(ConvertTo-HtmlEsc $target)</td><td>$(ConvertTo-HtmlEsc $a.Name)</td><td class='path'>$(ConvertTo-HtmlEsc $a.Value)</td><td>$(ConvertTo-HtmlEsc $a.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>These autostart extensibility points are rarely used by legitimate software (exception: OEM Winlogon Shell entries). Full inventory incl. per-user COM: csv\asep_sweep.csv</div>")
    }
    if ($certs.Count -gt 0) {
        $certHot = @($certs | Where-Object { $_.Flags -match 'recently-added' -and $_.Flags -match 'self-signed' })
        if ($certHot.Count -gt 0) {
            $persAny = $true
            $null = $sb.AppendLine("<h3>Recently added self-signed certificates (root trust)</h3><table><tr><th>Store</th><th>Subject</th><th>NotBefore</th><th>Flags</th></tr>")
            foreach ($c in ($certHot | Select-Object -First 25)) {
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.Store)</td><td>$(ConvertTo-HtmlEsc $c.Subject)</td><td>$(ConvertTo-HtmlEsc $c.NotBefore)</td><td>$(ConvertTo-HtmlEsc $c.Flags)</td></tr>")
            }
            $null = $sb.AppendLine("</table><div class='meta'>Enterprise root CAs are self-signed by design - verify against the org's PKI. Malware adds root CAs to enable HTTPS interception. Full inventory: csv\certificates.csv</div>")
        }
    }
    if (-not $persAny) { $null = $sb.AppendLine("<div class='meta'>No persistence entries captured (modules not run or nothing found).</div>") }

    # ---------- execution history ----------
    if ($execRows.Count -gt 0) {
        $null = $sb.AppendLine("<h2>Execution history highlights (user-writable paths)</h2><table>")
        $shown = 0
        foreach ($r in $execRows) {
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
            if ($line -match '(?i)\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|\\Downloads\\') {
                $ts = ($r.PSObject.Properties | Select-Object -First 1).Value
                $pathCol = @($r.PSObject.Properties | Where-Object { "$($_.Value)" -match '(?i)\\.*\.(exe|dll|ps1|bat|scr|js|vbs)' } | Select-Object -First 1)
                $pv = if ($pathCol) { "$($pathCol.Value)" } else { $line }
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $ts)</td><td class='path'>$(ConvertTo-HtmlEsc $pv)</td></tr>")
                $shown++
                if ($shown -ge 40) { break }
            }
        }
        $null = $sb.AppendLine("</table><div class='meta'>First $shown of $($execRows.Count) entries - full: csv\execution_timeline.csv</div>")
    }

    # ---------- file system forensics ----------
    $null = $sb.AppendLine("<a name='filesystem'></a><h2>File-system evidence (MFT / USN journal / prefetch)</h2>")
    if ($usnBursts.Count -gt 0) {
        $null = $sb.AppendLine("<div class='sig'><b>Ransomware-style mass file modification detected</b> - $($usnBursts.Count) window(s) with 1000+ write events per minute:</div>")
        $null = $sb.AppendLine("<table><tr><th>Window start</th><th>Write events</th><th>Distinct files</th></tr>")
        foreach ($u in ($usnBursts | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td class='crit'><b>$(ConvertTo-HtmlEsc $u.WindowStart)</b></td><td>$($u.WriteEvents)</td><td>$($u.DistinctFiles)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Legitimate mass changes (system updates, builds, AV signature storms) also trigger this. Cross-check the window against process/Sigma findings. Source: csv\usn_write_bursts.csv</div>")
    }
    if ($pfParsed.Count -gt 0) {
        $rcCol = @($pfParsed[0].PSObject.Properties.Name | Where-Object { $_ -match 'runcount|^run' } | Select-Object -First 1)[0]
        $lrCol = @($pfParsed[0].PSObject.Properties.Name | Where-Object { $_ -match 'lastrun' } | Select-Object -First 1)[0]
        $exCol = @($pfParsed[0].PSObject.Properties.Name | Where-Object { $_ -match 'executable|^name$' } | Select-Object -First 1)[0]
        $null = $sb.AppendLine("<h3>Most-run programs (prefetch)</h3><table><tr><th>Executable</th><th>Run count</th><th>Last run</th></tr>")
        $sorted = $pfParsed
        if ($rcCol) { $sorted = @($pfParsed | Sort-Object @{e = { [int]"$($_.$rcCol)" } } -Descending) }
        foreach ($p in ($sorted | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $p.$exCol)</td><td>$(ConvertTo-HtmlEsc $p.$rcCol)</td><td>$(ConvertTo-HtmlEsc $p.$lrCol)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Prefetch run counts = program execution evidence (Win8+ cap 1024 files). Source: csv\prefetch_parsed.csv</div>")
    }
    if ($mftRecent.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Recently created / user-path executables (MFT)</h3><table><tr><th>Created</th><th>Path</th><th>Size</th><th>Flags</th></tr>")
        $mftSorted = $mftRecent
        try { $mftSorted = @($mftRecent | Sort-Object Created -Descending) } catch { }
        $shownM = 0
        foreach ($mr in $mftSorted) {
            if ("$($mr.Flags)" -notmatch 'user-path') { continue }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $mr.Created)</td><td class='path'>$(ConvertTo-HtmlEsc $mr.Path)</td><td>$(ConvertTo-HtmlEsc $mr.Size)</td><td>$(ConvertTo-HtmlEsc $mr.Flags)</td></tr>")
            $shownM++
            if ($shownM -ge 25) { break }
        }
        $null = $sb.AppendLine("</table><div class='meta'>$($mftRecent.Count) executable/user-path/recent entries kept (user-path ones shown). Source: csv\mft_recent.csv</div>")
    }
    if ($usnBursts.Count -eq 0 -and $pfParsed.Count -eq 0 -and $mftRecent.Count -eq 0) {
        $null = $sb.AppendLine("<div class='meta'>No NTFS forensics data (tools\MFTECmd missing, not elevated, or modules skipped).</div>")
    }

    # ---------- C2 beaconing ----------
    $null = $sb.AppendLine("<a name='beacons'></a><h2>C2 beaconing candidates (periodic outbound patterns)</h2>")
    if ($beacons.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Severity</th><th>Process</th><th>Remote</th><th>Events</th><th>Span</th><th>Interval</th><th>Jitter</th><th>Regularity</th><th>Flags</th></tr>")
        foreach ($b in ($beacons | Select-Object -First 30)) {
            $sevCls = switch -Regex ("$($b.Severity)") { '^high$' { 'crit'; break } '^medium$' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $b.Severity)</b></td><td class='path'>$(ConvertTo-HtmlEsc $b.Process)</td><td>$(New-VtLink $b.RemoteIp):$(ConvertTo-HtmlEsc $b.Port)</td><td>$($b.Events)</td><td>$($b.SpanMin)min</td><td>~$(ConvertTo-HtmlEsc $b.MedianIntervalSec)s</td><td>$(ConvertTo-HtmlEsc $b.Jitter)</td><td>$(ConvertTo-HtmlEsc $b.Regularity)</td><td>$(ConvertTo-HtmlEsc $b.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Regularity = share of inter-arrival times within 0.5x-1.5x of the median. Legitimate updaters/telemetry also beacon - weigh process path, signer and destination. Source: csv\beacon_candidates.csv</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No periodic outbound connection patterns detected (or no Sysmon network events available - requires Sysmon event ID 3).</div>")
    }
    if ($dnsBeacons.Count -gt 0) {
        $null = $sb.AppendLine("<h3>DNS beaconing (periodic domain queries)</h3><table><tr><th>Severity</th><th>Process</th><th>Domain</th><th>Resolved (public)</th><th>Queries</th><th>Span</th><th>Interval</th><th>Regularity</th><th>Flags</th></tr>")
        foreach ($b in ($dnsBeacons | Select-Object -First 30)) {
            $sevCls = switch -Regex ("$($b.Severity)") { '^high$' { 'crit'; break } '^medium$' { 'med'; break } default { 'info' } }
            $ripCell = if ("$($b.ResolvedIp)") { New-VtLink $b.ResolvedIp } else { '-' }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $b.Severity)</b></td><td class='path'>$(ConvertTo-HtmlEsc $b.Process)</td><td>$(ConvertTo-HtmlEsc $b.Domain)</td><td>$ripCell</td><td>$($b.Events)</td><td>$($b.SpanMin)min</td><td>~$(ConvertTo-HtmlEsc $b.MedianIntervalSec)s</td><td>$(ConvertTo-HtmlEsc $b.Regularity)</td><td>$(ConvertTo-HtmlEsc $b.Flags)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Same periodicity math applied to Sysmon DNS queries (event ID 22) - catches C2 that hides behind domains instead of raw IPs. Source: csv\dns_beacon_candidates.csv</div>")
    }

    # ---------- network ----------
    $null = $sb.AppendLine("<a name='network'></a><h2>Public connections (live)</h2>")
    if ($pubConns.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Remote</th><th>State</th><th>PID</th><th>Process</th><th></th></tr>")
        foreach ($c in ($pubConns | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.RemoteAddress):$(ConvertTo-HtmlEsc $c.RemotePort)</td><td>$(ConvertTo-HtmlEsc $c.State)</td><td>$(ConvertTo-HtmlEsc $c.PID)</td><td class='path'>$(ConvertTo-HtmlEsc $c.ProcessPath)</td><td>$(New-VtLink $c.RemoteAddress)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No public IP connections at collection time.</div>")
    }

    # ---------- driver check ----------
    $null = $sb.AppendLine("<a name='drivers'></a><h2>Driver check (LOLDrivers)</h2>")
    if ($lolHits.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Status</th><th>Driver</th><th>Display name</th><th>Path</th><th>SHA256</th></tr>")
        foreach ($l in ($lolHits | Sort-Object { "$($_.Status)" -eq 'malicious' } -Descending | Select-Object -First 25)) {
            $stCls = if ("$($l.Status)" -eq 'malicious') { 'crit' } else { 'med' }
            $null = $sb.AppendLine("<tr><td class='$stCls'><b>$(ConvertTo-HtmlEsc $l.Status)</b></td><td>$(ConvertTo-HtmlEsc $l.Name)</td><td>$(ConvertTo-HtmlEsc $l.DisplayName)</td><td class='path'>$(ConvertTo-HtmlEsc $l.Path)</td><td class='path'>$(ConvertTo-HtmlEsc $l.SHA256)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'><b>malicious</b> = hash matches a driver known to be used in attacks (BYOVD / kernel exploits). <b>vulnerable</b> = known-exploitable driver that attackers can abuse for privilege escalation - replace it. Source: csv\loldrivers_hits.csv (datasets: loldrivers.io)</div>")
    } else {
        $null = $sb.AppendLine("<div class='meta'>No malicious/vulnerable driver matches (or tools\loldrivers datasets missing - run -Mode Setup, needs admin + module 1.6).</div>")
    }

    # ---------- hunt findings ----------
    $null = $sb.AppendLine("<a name='hunt'></a><h2>Hunt findings (technique-based detections)</h2>")
    if ($huntRows.Count -gt 0) {
        $null = $sb.AppendLine("<table><tr><th>Severity</th><th>Rule</th><th>ATT&amp;CK</th><th>Entity</th><th>Evidence</th></tr>")
        foreach ($h2 in ($huntRows | Sort-Object { switch -Regex ("$($_.Severity)") { 'high' { 0 } 'medium' { 1 } default { 2 } } })) {
            $sevCls = switch -Regex ("$($h2.Severity)") { 'high' { 'crit'; break } 'medium' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$sevCls'><b>$(ConvertTo-HtmlEsc $h2.Severity)</b></td><td>$(ConvertTo-HtmlEsc $h2.Rule)</td><td>$(ConvertTo-HtmlEsc $h2.Attck)</td><td class='path'>$(ConvertTo-HtmlEsc $h2.Entity)</td><td class='path'>$(ConvertTo-HtmlEsc $h2.Evidence)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>High-severity hunt rules are high-precision (version-info renames, side-loaded system DLLs, downloaded-then-executed, LSASS access, Office-to-interpreter chains, proxy-execution LOLBin command lines, admin-share staging, Defender tamper, DCSync, password spray, webshell chains) and contribute to the verdict. Medium rules (UAC bypass pattern, discovery storms, timestomping, Kerberoasting/AS-REP patterns, web anomalies, USB/account/RDP anomalies) are report-only leads. Verify against the cited raw evidence. Source: csv\hunt_findings.csv</div>")
        if ($Sysmon -and @(Import-CaseCsv 'sysmon_process_access').Count -eq 0) {
            $null = $sb.AppendLine("<div class='meta'><b>Sysmon config gap:</b> Sysmon is running but no ProcessAccess (EID 10) telemetry arrived - the installed config does not capture it, so the LSASS/registry/Beacon rules above run blind. Deploy <b>tools\sysmon\ophira-sysmon.xml</b> from the kit (<span style='font-family:Consolas,monospace'>sysmon64.exe -accepteula -i ophira-sysmon.xml</span>) and collect again.</div>")
        }
    } else {
        $null = $sb.AppendLine("<div class='meta'>No hunt findings - all techniques clean.</div>")
    }
    if ($liveScan.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Live memory triage (flagged-process minidumps)</h3><table><tr><th>Process</th><th>PID</th><th>Verdict</th><th>Dump</th><th>MB</th><th>YARA hits in memory</th></tr>")
        foreach ($l in $liveScan) {
            $hCls = if ("$($l.YaraHits)") { 'crit' } else { 'info' }
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $l.Process)</td><td>$(ConvertTo-HtmlEsc $l.PID)</td><td>$(ConvertTo-HtmlEsc $l.Verdict)</td><td class='path'>$(ConvertTo-HtmlEsc $l.Dump)</td><td>$($l.DumpMB)</td><td class='$hCls'><b>$(ConvertTo-HtmlEsc $l.YaraHits)</b></td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Minidumps contain unpacked/injected code - YARA hits here mean the pattern lives in MEMORY even if disk scans missed it. Dumps ship in raw\minidumps\ and open in Volatility. Source: csv\memory_live_scan.csv</div>")
    }

    # ---------- connections: correlated entities ----------
    $null = $sb.AppendLine("<a name='entities'></a><h2>Connections - correlated entities</h2>")
    $null = $sb.AppendLine("<div class='meta'>Each entity below joins evidence from multiple independent sources (processes, execution history, persistence, network, SRUM usage, YARA, Sigma...) into one story. More categories touching one binary = stronger signal. Full data: csv\entities_binaries.csv / entities_accounts.csv / entities_remotes.csv</div>")
    $entTop = @($entB | Where-Object { [int]"$($_.CatCount)" -ge 2 } | Select-Object -First 8)
    if ($entTop.Count -gt 0) {
        # master-timeline context for the top cards: rows within +/-15 min of the entity's first seen
        $tlPre = @()
        try {
            $tlPre = @(Import-CaseCsv 'supertimeline' | ForEach-Object { $t = $null; try { $t = [datetime]$_.Timestamp } catch { }; if ($t) { [pscustomobject]@{ T = $t; Row = $_ } } })
        } catch { }
        foreach ($e in $entTop) {
            $vCls = switch -Regex ("$($e.Verdict)") { 'HIGH' { 'crit'; break } 'MEDIUM' { 'med'; break } default { 'info' } }
            $vTxt = if ("$($e.Verdict)") { ", verdict <span class='$vCls'>$($e.Verdict)</span>" } else { '' }
            $null = $sb.AppendLine("<details><summary><b>$(ConvertTo-HtmlEsc $e.Name)</b> - <span class='high'>$($e.CatCount) evidence categories</span>$vTxt</summary>")
            $null = $sb.AppendLine("<table><tr><th>Path</th><th>First seen</th><th>Last seen</th><th>Signer</th><th>Hashes</th></tr>")
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $e.Path)</td><td>$(ConvertTo-HtmlEsc $e.FirstSeen)</td><td>$(ConvertTo-HtmlEsc $e.LastSeen)</td><td>$(ConvertTo-HtmlEsc $e.Signer)</td><td class='path'>$(ConvertTo-HtmlEsc $e.Hashes)</td></tr></table>")
            if ("$($e.Bytes)") { $null = $sb.AppendLine("<div class='meta'>SRUM network usage history: $(ConvertTo-HtmlEsc $e.Bytes)</div>") }
            $null = $sb.AppendLine("<table><tr><th>Source</th><th>Detail</th></tr>")
            foreach ($ev in (("$($e.Evidence)" -split ' \| ') | Select-Object -First 14)) {
                $parts = "$ev" -split ': ', 2
                $null = $sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlEsc $parts[0])</b></td><td class='path'>$(ConvertTo-HtmlEsc ($parts[1..($parts.Length-1)] -join ': '))</td></tr>")
            }
            $null = $sb.AppendLine("</table>")
            # +/-15 min context window around first seen, pulled from the master timeline
            $fs = $null
            try { $fs = ([datetime]$e.FirstSeen).ToUniversalTime() } catch { }
            if ($fs -and $tlPre.Count -gt 0) {
                $lo = $fs.AddMinutes(-15); $hi = $fs.AddMinutes(15)
                $ctx = @($tlPre | Where-Object { $_.T -ge $lo -and $_.T -le $hi } | Select-Object -First 8)
                if ($ctx.Count -gt 0) {
                    $null = $sb.AppendLine("<div class='meta'><b>Context: everything else happening &plusmn;15 min around first seen $($fs.ToString('yyyy-MM-dd HH:mm:ss'))</b> (full window: csv\supertimeline.csv)</div>")
                    $null = $sb.AppendLine("<table><tr><th>Time</th><th>Type</th><th>Actor</th><th>Detail</th></tr>")
                    foreach ($c2 in $ctx) {
                        $r2 = $c2.Row
                        $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $r2.Timestamp)</td><td>$(ConvertTo-HtmlEsc $r2.Type)</td><td>$(ConvertTo-HtmlEsc $r2.Actor)</td><td class='path'>$(ConvertTo-HtmlEsc ("$($r2.Entity) $($r2.Detail)".Trim()))</td></tr>")
                    }
                    $null = $sb.AppendLine("</table>")
                }
            }
            $null = $sb.AppendLine("</details>")
        }
    } else {
        $null = $sb.AppendLine("<div class='meta'>No multi-source binary correlations in this case (a binary must appear in 2+ independent evidence sources to be listed here).</div>")
    }
    if ($entA.Count -gt 0 -and @($entA | Where-Object { [int]$_.Logons -gt 0 -or [int]$_.Failed -gt 0 -or "$($_.RdpOutTargets)" -or [double]"$($_.ConsoleHistoryKB)" -gt 0 }).Count -gt 0) {
        $null = $sb.AppendLine("<h3>Account activity</h3><table><tr><th>Account</th><th>Logons</th><th>Failed</th><th>Logon types</th><th>Source IPs</th><th>RDP out to</th><th>Console hist</th></tr>")
        foreach ($a2 in ($entA | Select-Object -First 10)) {
            $fCls = if ([int]"$($a2.Failed)" -ge 5) { 'crit' } elseif ([int]"$($a2.Failed)" -gt 0) { 'med' } else { 'info' }
            $null = $sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlEsc $a2.Account)</b></td><td>$($a2.Logons)</td><td class='$fCls'>$($a2.Failed)</td><td>$(ConvertTo-HtmlEsc $a2.LogonTypes)</td><td>$(ConvertTo-HtmlEsc $a2.Sources)</td><td class='path'>$(ConvertTo-HtmlEsc $a2.RdpOutTargets)</td><td>$($a2.ConsoleHistoryKB) KB</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($entR.Count -gt 0 -and @($entR | Where-Object { [int]$_.Connections -gt 0 -or "$($_.Beacon)" -or [int]$_.FailedLogons -gt 0 -or [int]$_.RdpOutCount -gt 0 }).Count -gt 0) {
        $null = $sb.AppendLine("<h3>Remote endpoints</h3><table><tr><th>Remote</th><th>Public</th><th>Conns</th><th>Talkers</th><th>Beacon</th><th>Failed logons</th><th>RDP out</th></tr>")
        foreach ($e in ($entR | Select-Object -First 12)) {
            $bCls = switch -Regex ("$($e.Beacon)") { 'high' { 'crit'; break } 'medium' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td>$(New-VtLink $e.Remote)</td><td>$(ConvertTo-HtmlEsc $e.Public)</td><td>$($e.Connections)</td><td class='path'>$(ConvertTo-HtmlEsc $e.Talkers)</td><td class='$bCls'>$(ConvertTo-HtmlEsc $e.Beacon)</td><td class='$(if ([int]"$($e.FailedLogons)" -gt 0) { 'crit' } else { 'info' })'>$($e.FailedLogons)</td><td>$($e.RdpOutCount)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    if ($srumRows.Count -gt 0) {
        $appCol = @($srumRows[0].PSObject.Properties.Name | Where-Object { $_ -match '(?i)^(app|application|path|name|image)' } | Select-Object -First 1)[0]
        $numCols = @($srumRows[0].PSObject.Properties.Name | Where-Object { $_ -match '(?i)byte|sent|recv' })
        if ($appCol -and $numCols.Count -gt 0) {
            $null = $sb.AppendLine("<h3>Top network consumers (SRUM - per-app history)</h3><table><tr><th>Application</th>$((($numCols | Select-Object -First 4) | ForEach-Object { "<th>$(ConvertTo-HtmlEsc $_)</th>" }) -join '')</tr>")
            $srumTop = $srumRows
            try {
                $srumTop = @($srumRows | Sort-Object -Property @{e = { $t = 0L; foreach ($nc in ($numCols | Select-Object -First 4)) { $p2 = $_.PSObject.Properties[$nc]; if ($p2) { $t += [long]"$($p2.Value)" } }; $t }; Descending = $true } | Select-Object -First 12)
            } catch { }
            foreach ($s2 in $srumTop) {
                $cells = ($numCols | Select-Object -First 4) | ForEach-Object { $p2 = $s2.PSObject.Properties[$_]; "<td>$(ConvertTo-HtmlEsc $(if ($p2) { $p2.Value }))</td>" }
                $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $s2.$appCol)</td>$($cells -join '')</tr>")
            }
            $null = $sb.AppendLine("</table><div class='meta'>SRUM records ~30 days of per-application network/resource usage. High sustained upload from a user-path binary = exfiltration candidate. Source: csv\srum_usage.csv</div>")
        }
    }
    # v2.21: process lineage + session-attributed activity
    $chains = @(Import-CaseCsv 'process_chains')
    if ($chains.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Process lineage (how flagged binaries got there)</h3><table><tr><th>Flagged binary</th><th>Hops</th><th>Ancestry chain</th></tr>")
        foreach ($c in ($chains | Sort-Object { [int]"$($_.Steps)" } -Descending | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $c.Entity)</td><td>$($c.Steps)</td><td class='path'><b>$(ConvertTo-HtmlEsc $c.Chain)</b>$(if ("$($c.Evidence)") { "<br>$(ConvertTo-HtmlEsc $c.Evidence)" })</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Rebuilt from 4688 parent-child + live PPID map. A user-path binary whose ancestry runs through office/browser/interpreter processes is a phishing/exploit story; ancestry from services.exe with no matching install event is suspicious. Source: csv\process_chains.csv</div>")
    }
    $sessAct = @(Import-CaseCsv 'session_activity')
    if ($sessAct.Count -gt 0) {
        $null = $sb.AppendLine("<h3>Attributed activity (which session did what)</h3><table><tr><th>Time</th><th>Session account</th><th>Source IP</th><th>Type</th><th>Logon</th><th>Activity</th></tr>")
        foreach ($s2 in ($sessAct | Select-Object -First 30)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $s2.Time)</td><td><b>$(ConvertTo-HtmlEsc $s2.SessionAccount)</b></td><td>$(ConvertTo-HtmlEsc $s2.SourceIp)</td><td>$(ConvertTo-HtmlEsc $s2.Activity)</td><td>$(ConvertTo-HtmlEsc $s2.LogonType)</td><td class='path'>$(ConvertTo-HtmlEsc $s2.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>4624 LogonId joined to 4688/5145 SubjectLogonId: even service/shared accounts are tied back to the interactive/RDP/network session that created them. Source: csv\session_activity.csv</div>")
    }

    # ---------- host snapshot ----------
    $null = $sb.AppendLine("<a name='snapshot'></a><h2>Host snapshot (AV state, stored credentials, outbound RDP)</h2>")
    $snapAny = $false
    if ($defStatus.Count -gt 0) {
        $snapAny = $true
        $d = $defStatus[0]
        $null = $sb.AppendLine("<div>Defender: RealTimeProtection <b>$(ConvertTo-HtmlEsc $d.RealTimeProtection)</b>, AMService <b>$(ConvertTo-HtmlEsc $d.AMServiceEnabled)</b>, signature age <b>$(ConvertTo-HtmlEsc $d.AntivirusSigAgeDays)</b> day(s)</div>")
    }
    if ($defThreats.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Defender detection history</h3><table><tr><th>Threat</th><th>Active</th><th>Resource</th></tr>")
        foreach ($t in ($defThreats | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $t.ThreatName)</td><td>$(ConvertTo-HtmlEsc $t.IsActive)</td><td class='path'>$(ConvertTo-HtmlEsc "$($t.Resources)")</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    $credSweep = @(Import-CaseCsv 'credential_sweep.csv')
    if ($credSweep.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Credential exposure sweep</h3><table><tr><th>Risk</th><th>Item</th><th>Detail</th></tr>")
        foreach ($c3 in ($credSweep | Select-Object -First 12)) {
            $rCls = switch -Regex ("$($c3.Risk)") { 'HIGH' { 'crit'; break } 'MEDIUM' { 'med'; break } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$rCls'><b>$(ConvertTo-HtmlEsc $c3.Risk)</b></td><td>$(ConvertTo-HtmlEsc $c3.Item)</td><td class='path'>$(ConvertTo-HtmlEsc $c3.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>WLAN keys and DPAPI vault blobs ship under raw\ for analyst-side handling only - treat the case folder as sensitive material. Source: csv\credential_sweep.csv</div>")
    }
    if ($savedCreds.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Stored credentials on this host (lateral movement risk)</h3><table><tr><th>Entry</th></tr>")
        foreach ($c in ($savedCreds | Select-Object -First 15)) {
            $line = ($c.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | '
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $line)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Source: csv\saved_credentials.csv</div>")
    }
    if ($rdpTgt.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Outbound RDP targets (where users RDP'd to)</h3><table><tr><th>Entry</th></tr>")
        foreach ($r in ($rdpTgt | Select-Object -First 15)) {
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | '
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $line)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Source: csv\rdp_client_targets.csv - attacker RDP outbound shows lateral movement destinations.</div>")
    }
    if ($bitsJobs.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>BITS transfer jobs</h3><table><tr><th>Name</th><th>Owner</th><th>State</th><th>Files</th></tr>")
        foreach ($b in ($bitsJobs | Select-Object -First 15)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $b.DisplayName)</td><td>$(ConvertTo-HtmlEsc $b.OwnerAccount)</td><td>$(ConvertTo-HtmlEsc $b.JobState)</td><td class='path'>$(ConvertTo-HtmlEsc $b.Files)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>BITS is abused for stealthy persistence/download. Source: csv\bits_jobs.csv</div>")
    }
    if ($memMfR.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Memory analysis: malfind (possible code injection)</h3><table><tr><th>Process</th><th>PID</th><th>Protection</th></tr>")
        foreach ($m in ($memMfR | Select-Object -First 20)) {
            $null = $sb.AppendLine("<tr><td class='crit'>$(ConvertTo-HtmlEsc $m.Process)</td><td>$(ConvertTo-HtmlEsc $m.PID)</td><td>$(ConvertTo-HtmlEsc $m.Protection)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Malfind flags VAD regions with RWX attributes - verify with a full memory workup (false positives possible for legit packed software). Source: csv\memory_malfind.csv</div>")
    }
    if ($browserIocR.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Browser history IOC hits (visited IOC-listed domains)</h3><table><tr><th>Domain</th><th>URL</th><th>Title</th></tr>")
        foreach ($b2 in ($browserIocR | Select-Object -First 20)) {
            $null = $sb.AppendLine("<tr><td class='crit'>$(ConvertTo-HtmlEsc $b2.Indicator)</td><td class='path'>$(ConvertTo-HtmlEsc $b2.URL)</td><td>$(ConvertTo-HtmlEsc $b2.Title)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>A visit is not proof of compromise - but phishing/initial-access often starts here. Source: csv\ioc_hits_browser.csv</div>")
    }
    if ($posture.Count -gt 0) {
        $snapAny = $true
        $null = $sb.AppendLine("<h3>Security posture (hardening audit)</h3><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>")
        $postureSorted = @($posture | Sort-Object @{e = { switch -Regex ("$($_.Status)") { 'BAD' { 0 } 'WARN' { 1 } default { 2 } } } })
        foreach ($p2 in $postureSorted) {
            $stCls = switch ("$($p2.Status)") { 'BAD' { 'crit' } 'WARN' { 'med' } default { 'info' } }
            $null = $sb.AppendLine("<tr><td class='$stCls'><b>$(ConvertTo-HtmlEsc $p2.Status)</b></td><td>$(ConvertTo-HtmlEsc $p2.Check)</td><td>$(ConvertTo-HtmlEsc $p2.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table><div class='meta'>Weak posture = attack path. BAD findings are listed in the recommendations below. Source: csv\posture.csv</div>")
    }
    if (-not $snapAny) { $null = $sb.AppendLine("<div class='meta'>No snapshot data captured (relevant modules skipped).</div>") }

    # ---------- timeline preview (client-side filter over the master timeline) ----------
    $tlAll = @(Import-CaseCsv 'supertimeline.csv')
    $tlRows = @($tlAll | Select-Object -Last 10000)
    $tlSources = @($tlRows | ForEach-Object { "$($_.Source)" } | Sort-Object -Unique)
    $tlParts = New-Object System.Text.StringBuilder
    foreach ($r in $tlRows) {
        try { $null = $tlParts.Append(($r | Select-Object Timestamp, Source, Type, Actor, Entity, Detail | ConvertTo-Json -Compress)).Append(',') } catch { }
    }
    $tlJson = '[' + $tlParts.ToString().TrimEnd(',') + ']'
    $null = $sb.AppendLine("<a name='timeline'></a><h2>Timeline preview (newest $($tlRows.Count) of $($tlAll.Count) rows)</h2>")
    $null = $sb.AppendLine("<div class='meta'>Browse the master chronology without leaving the report. Full chronology: <b>csv\supertimeline.csv</b> (Excel/Timeline Explorer) or <b>-Mode Timeline</b> for windowed CSV exports with per-source summary. Showing the newest 10,000 rows, rendered newest-first, max 1,000 matches.</div>")
    $null = $sb.AppendLine("<div style='margin:10px 0'>")
    $null = $sb.AppendLine("<input id='tlq' type='text' placeholder='text filter (actor/entity/detail)' style='width:280px' oninput='tlDraw()'> ")
    $null = $sb.AppendLine("from <input id='tlf' type='date' onchange='tlDraw()'> to <input id='tlt' type='date' onchange='tlDraw()'> ")
    $srcSel = "source <select id='tlsrc' onchange='tlDraw()'><option value=''>all</option>"
    foreach ($s in $tlSources) { $srcSel += "<option>$(ConvertTo-HtmlEsc $s)</option>" }
    $null = $sb.AppendLine($srcSel + "</select> <span id='tlstat' class='meta'></span></div>")
    $null = $sb.AppendLine("<div id='tlbox'></div>")
    $null = $sb.AppendLine(@"
      <script>
      var TL = $tlJson;
      function tlEsc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
      function tlDraw(){
        var q=document.getElementById('tlq').value.toLowerCase();
        var f=document.getElementById('tlf').value,t=document.getElementById('tlt').value,src=document.getElementById('tlsrc').value;
        var rows=[],n=0;
        for(var i=TL.length-1;i>=0;i--){
          var r=TL[i];
          if(src&&r.Source!==src)continue;
          if(q&&(r.Detail+' '+r.Actor+' '+r.Entity+' '+r.Type).toLowerCase().indexOf(q)<0)continue;
          if(f&&r.Timestamp.substring(0,10)<f)continue;
          if(t&&r.Timestamp.substring(0,10)>t)continue;
          rows.push(r); if(++n>=1000)break;
        }
        var h="<table><tr><th>Timestamp (UTC)</th><th>Source</th><th>Type</th><th>Actor</th><th>Entity</th><th>Detail</th></tr>";
        for(var j=0;j<rows.length;j++){var r2=rows[j];
          h+="<tr><td>"+tlEsc(r2.Timestamp)+"</td><td>"+tlEsc(r2.Source)+"</td><td>"+tlEsc(r2.Type)+"</td><td>"+tlEsc(r2.Actor)+"</td><td class='path'>"+tlEsc(r2.Entity)+"</td><td>"+tlEsc(r2.Detail)+"</td></tr>";
        }
        h+="</table>";
        document.getElementById('tlbox').innerHTML=h;
        document.getElementById('tlstat').textContent=' '+rows.length+' shown'+(rows.length>=500?' (capped)':'')+' / '+TL.length+' loaded';
      }
      tlDraw();
      </script>
"@)

    # ---------- recommendations ----------
    $null = $sb.AppendLine("<a name='recommendations'></a><h2>Recommendations</h2>")
    $recs = New-Object System.Collections.Generic.List[string]
    if ($script:Verdict -and $script:Verdict.LevelRank -ge 3) {
        $recs.Add('Likely/confirmed compromise: preserve evidence (do not wipe yet), isolate the host from the network, and treat credentials used on it as suspect - rotate them.')
    }
    if ($gapRows.Count -gt 0) {
        $recs.Add('Security log clearing/stopping events were observed - determine who/what cleared them and when (csv\logging_gaps.csv, raw evtx).')
    }
    if ($brute.Count -gt 0) {
        $recs.Add('Brute-force sources observed - check whether any 4625 failure was followed by a 4624 success from the same IP (csv\security_auth_events.csv), and enforce account lockout policy.')
    }
    foreach ($pb in $postureBad) {
        $recs.Add("Hardening: $($pb.Check) - $($pb.Detail)")
    }
    if (-not $Sysmon) {
        $recs.Add('Deploy Sysmon with a community configuration (e.g. SwiftOnSecurity) to gain process/network/image-load telemetry needed for ATT&CK-level detection.')
    }
    if (-not (Test-Path (Join-Path $RawDir 'evtx'))) {
        $recs.Add('Event logs were not exported (module 4.x skipped or access denied) - rerun elevated with the Standard preset for Sigma/ATT&CK coverage.')
    }
    if (-not (Test-IsAdmin)) {
        $recs.Add('This collection ran WITHOUT admin rights - rerun elevated to include registry hives, amcache, Security log and other key sources.')
    }
    if ($script:LogStartDT) {
        $recs.Add("Analysis window started at $($script:LogStartDT.ToString('yyyy-MM-dd HH:mm'))$(if ($script:LogEndDT) { " (ends $($script:LogEndDT.ToString('yyyy-MM-dd HH:mm')))" }) - rerun with an earlier -LogStart/-LogWindow if the intrusion may be older.")
    } elseif ($LogHours -gt 0 -and $LogHours -le 168) {
        $recs.Add("Analysis window was only the last $([int]($LogHours/24)) day(s) - rerun with a wider window (e.g. -LogWindow 30d, -LogWindow 3m or 0 = all) if the intrusion may be older.")
    }
    if ($script:Verdict -and $script:Verdict.ConfidencePercent -lt 80) {
        $recs.Add('Evidence coverage was below 80% - address the missing sources in the coverage table before treating a clean verdict as final.')
    }
    if ($recs.Count -eq 0) { $recs.Add('No specific hardening actions indicated by this collection - keep collecting baselines (delta mode) at a regular cadence.') }
    foreach ($r in $recs.ToArray()) { $null = $sb.AppendLine("<div class='rec'>$(ConvertTo-HtmlEsc $r)</div>") }

    # ---------- evidence index ----------
    $null = $sb.AppendLine("<a name='evidence'></a><h2>Evidence index (everything this case contains)</h2>")
    $desc = @{
        'flash_process_scored'            = 'Live processes with anomaly scores - review HIGH verdicts and user-path binaries'
        'flash_ioc_hits'                  = 'Live processes/files matching your IOC list (tools\iocs.txt)'
        'flash_public_connections'        = 'Established connections to public IPs at collection time - map to processes'
        'processes'                       = 'Full live process inventory (parent/PID/command line)'
        'processes_flagged'               = 'Process inventory subset with anomaly flags'
        'process_hashes'                  = 'SHA256 hashes of live process binaries'
        'connections'                     = 'Full connection table (netstat) at collection time'
        'connections_public_established'  = 'ESTABLISHED public-IP connections - C2 candidates'
        'dns_cache'                       = 'DNS resolver cache - look up domains malware resolved recently'
        'arp_table'                       = 'ARP cache - hosts on the local segment'
        'logon_sessions'                  = 'Active logon sessions (who is on the box right now)'
        'drivers'                          = 'Kernel drivers + paths'
        'drivers_flagged'                  = 'Drivers with user-writable binary paths'
        'autoruns_runkeys'                = 'Run/RunOnce/Winlogon autostart commands (all hives)'
        'autoruns_startup_folders'        = 'Startup folder items with signature status'
        'services'                        = 'All services + binary paths'
        'services_flagged'                = 'Services with user-writable or missing binaries'
        'scheduled_tasks'                 = 'All scheduled tasks with actions'
        'scheduled_tasks_flagged'         = 'Tasks with non-Microsoft authors or odd actions'
        'wmi_event_filters'               = 'WMI event filters (rare on clean hosts)'
        'wmi_event_consumers'             = 'WMI event consumers (command/script payloads)'
        'wmi_bindings'                    = 'WMI filter-to-consumer bindings = active WMI persistence'
        'asep_sweep'                      = 'Deep persistence sweep: IFEO/AppInit/Winlogon/COM/netsh/LSA/StartupApproved'
        'certificates'                    = 'Certificate store inventory - check recent self-signed roots (T1553)'
        'firewall_profiles'               = 'Firewall profile state + logging config'
        'net_interfaces'                  = 'Network interfaces + IPs'
        'net_reachable_subnets'           = 'Routes/reachable subnets'
        'smb_hosted_shares'               = 'Shares this host exposes'
        'smb_mounted_shares'              = 'Shares this host has mapped'
        'smb_active_connections'          = 'Live SMB sessions (both directions)'
        'saved_credentials'               = 'Stored credentials (cmdkey) - lateral movement risk'
        'proxy_settings'                  = 'WinHTTP/WinINET proxy + WPAD'
        'net_active_probes'               = 'Opt-in connectivity probes (module 3.2)'
        'security_events'                 = 'Security log events in window (raw)'
        'security_auth_events'            = 'Authentication events (4624/4625/4648...)'
        'security_bruteforce_candidates'  = 'Sources with 5+ failed logons'
        'security_auth_summary'           = 'Logon summary by account/type'
        'powershell_events'               = 'PowerShell 4104 script block logs'
        'sysmon_events'                   = 'Sysmon events in window (raw)'
        'sysmon_network'                  = 'Sysmon EID 3 network events - source for beaconing'
        'rdp_localsession'                = 'Local RDP session events'
        'rdp_connections'                 = 'Inbound RDP connection events'
        'rdp_client_targets'              = 'Outbound RDP destinations (registry MRU)'
        'system_events'                   = 'System log events in window'
        'system_new_services'             = 'EID 7045 service installs - malware installs itself as services'
        'svchost_audit'                   = 'Live svchost -k groups vs registered ServiceDlls (masquerade audit: unregistered group, ServiceDll outside System32, unregistered loaded DLL)'
        'defender_status'                 = 'AV state at collection'
        'defender_threats'                = 'AV detections history'
        'defender_preferences'            = 'AV exclusions - attackers add exclusions'
        'defender_events'                 = 'Defender operational log'
        'powershell_console_history'      = 'Console history files per user - attacker commands'
        'recyclebin_index'                = 'Recycle bin $I files (what was deleted, by whom, when)'
        'bits_jobs'                       = 'BITS transfer jobs (stealth downloads)'
        'domain_info'                     = 'Domain role + logged user'
        'hayabusa_timeline'               = 'Sigma detection timeline with ATT&CK tags'
        'yara_hits'                       = 'YARA rule matches on collected binaries'
        'yara_scanned'                    = 'Which files were YARA-scanned'
        'beacon_candidates'               = 'Periodic outbound patterns (C2 beaconing)'
        'dns_beacon_candidates'           = 'Periodic DNS domain queries (DNS C2 beaconing)'
        'sysmon_dns'                      = 'Sysmon DNS queries (EID 22) - domains each process resolved'
        'loldrivers_hits'                 = 'Driver hashes x LOLDrivers dataset (malicious/vulnerable drivers on disk)'
        'ps_decoded_commands'             = 'Base64/obfuscated PowerShell commands recovered from event logs'
        'execution_timeline'              = 'Shimcache/amcache program execution history'
        'amcache'                         = 'Amcache full parse (installed/executed programs + SHA1)'
        'ioc_hits_amcache'                = 'Amcache SHA1 x IOC list hits (historical execution)'
        'prefetch_index'                  = 'Prefetch files copied (index)'
        'prefetch_parsed'                 = 'Prefetch parse: run counts + last run times'
        'userassist'                      = 'UserAssist GUI programs executed per user'
        'mft_recent'                      = 'MFT: recently created / user-path executables (both birth attributes: $Si Created + FILE_NAME CreatedFN - R22 timestamp-forgery checks)'
        'application_events'              = 'Application log: app crashes (1000/1001/1002) + MSI installs (1033/11707/11724) - crashed attacker tools'
        'startup_info'                    = 'StartupInfo per-session app launches (WDI XMLs) - execution evidence that survives Prefetch deletion'
        'wer_reports'                     = 'Windows Error Reporting crash reports (faulting app/module) - evidence of failed attacker tooling'
        'server_logs'                     = 'Inventory of copied server-role logs (DNS/DHCP audit, SYSVOL policies, NTDS.dit on Full+DC)'
        'registry_recmd'                  = 'RECmd batch registry deep-dive (persistence/execution/lateral keys across all saved hives) - analyst-side enrichment'
        'ioc_hits_dns'                    = 'IOC-listed domains observed in Sysmon DNS queries (feed-attributed)'
        'ioc_hits_network'                = 'IOC-listed IPs observed in historical connections (feed-attributed)'
        'ioc_hits_mft'                    = 'IOC-listed filenames found on disk ($MFT, exact name match)'
        'credential_sweep'                = 'Credential exposure: auto-logon, WLAN keys (raw\wifi), DPAPI vault (raw\vault), LSASS dumps on disk'
        'usn_write_bursts'                = 'USN journal: mass file-modification windows (ransomware)'
        'lnk_parsed'                      = 'LNK parse (Recent docs - what files were opened)'
        'jumplist_parsed*'                = 'Jump List parse (per-app recent files)'
        'shellbags'                       = 'ShellBags folder-browsing history - folder access incl. deleted/network/USB locations'
        'browser_history'                 = 'Parsed browser history (URLs, titles, visit times)'
        'browser_downloads'               = 'Parsed browser downloads (files, sources, times)'
        'browser_searches'                = 'Browser search keywords'
        'ioc_hits_browser'                = 'IOC-listed domains observed in browser data'
        'posture'                         = 'Security hardening audit (LSA/SMBv1/RDP/PS logging/UAC/Defender/BitLocker)'
        'memory_malfind'                  = 'Volatility malfind - hidden/injected memory regions'
        'memory_netscan'                  = 'Volatility netscan - network artifacts found in RAM'
        'recyclebin'                      = 'RBCmd recycle bin parse (original paths + delete times)'
        'srum_usage'                      = 'SRUM: per-app resource/network usage over weeks'
        'logging_gaps'                    = 'Log clear/stop events + evtx coverage gaps'
        'parse_needed'                    = 'Artifacts not finished on the endpoint + exactly how to finish them (-Mode Parse)'
        'hunt_findings'                   = 'Technique-based hunt detections (renamed binaries, side-loads, download-exec, LSASS access, Office chains, proxy-exec, share staging, UAC bypass, discovery storms, Defender tamper, timestomping, DCSync, Kerberoasting, spray, webshells)'
        'security_proc_events'            = '4688 process creations with parent + command line (needs cmdline audit) - Office chains, proxy-exec, discovery storms'
        'security_task_install'           = '4698 scheduled task installs with the task action - remote/atexec-style persistence'
        'security_share_access'           = '5140/5145 share access incl. admin-share writes - lateral movement + staging data source'
        'sysmon_process_access'           = 'Sysmon EID 10 ProcessAccess - LSASS credential-dump data source'
        'sysmon_proc_create'              = 'Sysmon EID 1 process create with OriginalFileName - renamed-binary at-rest evidence'
        'sysmon_registry'                 = 'Sysmon EID 13 RegistryEvent - UAC bypass / persistence data source'
        'sysmon_file_time'                = 'Sysmon EID 2 file creation-time changes - timestomping evidence'
        'defender_config_events'          = 'Defender 5001/5007 - real-time protection disabled / exclusion changes (tamper)'
        'security_kerberos'               = 'Kerberos events (DC: 4768/4769/4771/4776) - Kerberoasting/spray/AS-REP data source'
        'security_ds_access'              = 'Directory-service access (DC: 4662/5136) - DCSync + AD object changes'
        'iis_requests'                    = 'Parsed IIS W3C requests (web role) - what hit this server'
        'iis_anomalies'                   = 'IIS anomalies: error bursts, suspicious URIs, POSTs to upload paths, headless POSTs'
        'session_activity'                = '4624 LogonId x 4688/5145 joins - which logon session (human/IP) did what'
        'process_chains'                  = 'Ancestry chains for flagged binaries (4688 lineage + live PPID) - how it got there'
        'memory_live_scan'                = 'Flagged-process minidumps + YARA hits found in live memory'
        'sysmon_image_load'               = 'Sysmon DLL loads (EID 7) - side-load data source'
        'bam_lastexec'                    = 'BAM/DAM last-execution per user (survives Prefetch deletion)'
        'usb_devices'                     = 'Every USB storage device ever connected (serials + dates)'
        'office_mru'                      = 'Office recent documents per user'
        'ual_files'                       = 'User Access Logs copied raw (SMB/RDP source history - ESE)'
        'local_admins'                    = 'Local Administrators group members'
        'entities_binaries'               = 'Binaries joined across ALL evidence sources (execution/persistence/network/verdict...) with category counts'
        'entities_accounts'               = 'Accounts joined across logons/RDP/console history with failure counts'
        'entities_remotes'                = 'Remote endpoints joined across connections/beacons/brute-force/RDP targets'
        'delta_new'                       = 'Findings NEW since the previous collection'
        'supertimeline'                   = 'MASTER TIMELINE: every artifact source woven chronologically (logons, 4688/5145, Kerberos, Sysmon, prefetch, $MFT births, browser, WER, StartupInfo, hunt findings...) with Timestamp/Source/Type/Actor/Entity/Detail - filter to any timeframe in Excel/Timeline Explorer'
    }
    $null = $sb.AppendLine("<table><tr><th>Artifact</th><th>Rows</th><th>What it is / what to look for</th></tr>")
    foreach ($f in @(Get-ChildItem -Path $CsvDir -Filter '*.csv' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $rows = 0
        try {
            $first = Get-Content -LiteralPath $f.FullName -First 1
            if ($first -and $first -notmatch '^#') { $rows = @(Get-Content -LiteralPath $f.FullName | Select-Object -Skip 1).Count }
        } catch { }
        $base = $f.BaseName
        $d = if ($desc.ContainsKey($base)) { $desc[$base] } elseif ($base -match '^jumplist_parsed') { $desc['jumplist_parsed*'] } else { '' }
        $null = $sb.AppendLine("<tr><td>csv\$(ConvertTo-HtmlEsc $f.Name)</td><td>$rows</td><td>$(ConvertTo-HtmlEsc $d)</td></tr>")
    }
    $null = $sb.AppendLine("</table>")
    $null = $sb.AppendLine("<div class='meta'>Also in the case: <b>supertimeline.csv</b> (MASTER chronology - every artifact, filter by time), <b>csv\evtx_ecmd\</b> (full event-log CSVs for deep-dives, when EvtxECmd ran in Parse mode), <b>siem_export.ndjson</b> (Splunk/Elastic-ready records), <b>case_draft.txt</b> (auto-written executive draft - edit into your report), <b>verdict.json</b>, <b>attack_layer.json</b> (MITRE ATT&amp;CK Navigator layer - load at navigator.mitre.org), <b>case.json</b> (run metadata + module timings), raw evidence under <b>raw\</b> (evtx, registry hives, prefetch, recent/jumplists, browser DBs, firewall log, RDP bitmap cache tiles in <b>raw\rdp_cache</b> - reconstruct what inbound RDP sessions displayed with RdpCacheStudio), collection.log</div>")

    $null = $sb.AppendLine("<div class='foot'>Generated $(Get-Date -Format u) by Ophira v$ScriptVersion - all verdicts are correlation heuristics; verify against raw CSV/evtx evidence before acting.</div>")
    $null = $sb.AppendLine("</body></html>")
    $reportPath = Join-Path $CaseDir 'report.html'
    $sb.ToString() | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-CaseLog "    report: $reportPath" 'Cyan'
    return $reportPath
}

function New-SuperTimeline {
    # v2.24 MASTER TIMELINE: every artifact source woven into ONE chronological CSV with a
    # normalized schema (Timestamp, Source, Type, Actor, Entity, Detail) so the analyst can
    # open a single file and filter to any timeframe ("weird activity at 14:00" checks).
    # Per-source caps + a total cap keep the file bounded; hayabusa sort-csv dedupes overlaps.
    $rows = New-Object System.Collections.Generic.List[object]
    $add = {
        param($ts, [string]$source, [string]$type, [string]$actor, [string]$entity, [string]$detail)
        if (-not $ts) { return }
        $iso = "$ts"
        try { $iso = ([datetime]$ts).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch { }
        $d = ("$detail" -replace '\s+', ' ').Trim()
        if ($d.Length -gt 240) { $d = $d.Substring(0, 240) + '...' }
        $null = $rows.Add([pscustomobject]@{ Timestamp = $iso; Source = $source; Type = "$type"; Actor = "$actor"; Entity = "$entity"; Detail = $d })
    }
    $weave = {
        param([string]$name, [int]$cap, [scriptblock]$map)
        $n = 0
        foreach ($r in (Import-CaseCsv $name)) {
            if ($n -ge $cap) { break }
            $m = $null
            try { $m = & $map $r } catch { }
            if ($m -and "$($m[0])") { $n++; & $add $m[0] $name $m[1] $m[2] $m[3] $m[4] }
        }
    }
    $leaf = { param($p) try { if ("$p") { (Split-Path "$p" -Leaf) } else { '' } } catch { "$p" } }

    # generic event-log CSVs (Get-FilteredEvents shape: TimeCreated/Id/Message)
    foreach ($name in @('security_events', 'powershell_events', 'sysmon_events', 'system_events', 'defender_events', 'rdp_localsession', 'rdp_connections', 'application_events')) {
        $n = 0
        foreach ($r in (Import-CaseCsv $name)) {
            if ($n -ge 5000 -or -not $r.PSObject.Properties['TimeCreated']) { continue }
            $n++
            & $add $r.TimeCreated $name "EID $($r.Id)" '' '' $r.Message
        }
    }
    # structured security telemetry
    & $weave 'security_auth_events' 5000 { param($r) $t = $(if ("$($r.EventId)" -eq '4625') { 'failed logon' } else { 'logon' }); if ("$($r.LogonType)") { $t = "$t (type $($r.LogonType))" } @("$($r.Time)", $t, "$($r.Account)", "$($r.SourceIp)", "LogonId $($r.LogonId)") }
    & $weave 'security_proc_events' 5000 { param($r) @("$($r.Time)", 'process created (4688)', "$($r.Account)", (& $leaf $r.NewProcess), "parent $(& $leaf $r.ParentProcess) | $($r.CommandLine)") }
    & $weave 'security_share_access' 5000 { param($r) @("$($r.Time)", "share access (EID $($r.EventId))", "$($r.Account)", "$("$($r.ShareName)" -replace '^[\*\\\s]+', '')\$("$($r.RelativeTargetName)" -replace '\\', '/')", "from $($r.SourceIp) [$(("$($r.AccessList)" -replace '%%', ''))]") }
    & $weave 'security_task_install' 500 { param($r) @("$($r.Time)", 'scheduled task installed (4698)', "$($r.Account)", "$($r.TaskName)", "$($r.Command)") }
    & $weave 'security_kerberos' 3000 { param($r) @("$($r.Time)", "kerberos (EID $($r.EventId))", "$($r.Account)", "$($r.IpAddress)", "svc=$($r.Service) enc=$($r.TicketEnc) preauth=$($r.PreAuth)") }
    & $weave 'security_ds_access' 3000 { param($r) @("$($r.Time)", "directory service (EID $($r.EventId))", "$($r.Account)", "$($r.Object)$("$($r.ObjectDN)")", "$("$($r.Properties)" -replace '\s+', ' ') | $($r.Attribute)=$($r.Value)") }
    & $weave 'defender_config_events' 500 { param($r) @("$($r.Time)", "defender config (EID $($r.EventId))", '', '', "$($r.Detail)") }
    # sysmon structured
    & $weave 'sysmon_network' 5000 { param($r) @("$($r.Time)", 'network connection (Sysmon 3)', (& $leaf $r.Image), "$($r.DestIp):$($r.DestPort)", "proto $($r.Protocol)") }
    & $weave 'sysmon_dns' 5000 { param($r) @("$($r.Time)", 'DNS query (Sysmon 22)', (& $leaf $r.Image), "$($r.QueryName)", "resolved $($r.QueryResults)") }
    & $weave 'sysmon_image_load' 3000 { param($r) @("$($r.Time)", 'image load (Sysmon 7)', (& $leaf $r.Process), (& $leaf $r.Dll), "signed=$($r.Signed) $($r.Signature)") }
    & $weave 'sysmon_proc_create' 5000 { param($r) @("$($r.Time)", 'process create (Sysmon 1)', (& $leaf $r.Image), '', $(if ("$($r.OriginalFileName)" -and ((Split-Path "$($r.Image)" -Leaf) -ne "$($r.OriginalFileName)")) { "ORIGINAL NAME: $($r.OriginalFileName) | $($r.CommandLine)" } else { "$($r.CommandLine)" })) }
    & $weave 'sysmon_process_access' 3000 { param($r) @("$($r.Time)", 'process access (Sysmon 10)', (& $leaf $r.SourceImage), (& $leaf $r.TargetImage), "granted=$($r.GrantedAccess) trace=$(("$($r.CallTrace)" -replace '\+.*', ''))") }
    & $weave 'sysmon_registry' 3000 { param($r) @("$($r.Time)", "registry event (Sysmon 13)", (& $leaf $r.Image), "$($r.TargetObject)", "$($r.EventType)") }
    & $weave 'sysmon_file_time' 1000 { param($r) @("$($r.Time)", 'file creation time changed (Sysmon 2)', (& $leaf $r.Image), (& $leaf $r.TargetFilename), "$($r.PreviousCreationUtcTime) -> $($r.CreationUtcTime)") }
    # execution evidence
    & $weave 'hayabusa_timeline' 5000 { param($r) @("$($r.Timestamp)", "$($r.Level): $(if ($r.PSObject.Properties['RuleTitle']) { $r.RuleTitle } elseif ($r.PSObject.Properties['Alert']) { $r.Alert } else { $r.RuleFile })", '', '', "$($r.Details)") }
    $exec = Import-CaseCsv 'execution_timeline'
    if ($exec.Count -gt 0) {
        $tCol = ($exec[0].PSObject.Properties.Name | Select-Object -First 1)
        $n = 0
        foreach ($r in $exec) {
            if ($n -ge 3000) { break }
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
            $n++
            & $add $r.$tCol 'execution_timeline' 'shimcache/amcache entry' '' '' $line
        }
    }
    $pfT = { param($r) $c = @($r.PSObject.Properties.Name | Where-Object { $_ -match '(?i)lastrun' } | Select-Object -First 1)[0]; if ($c) { "$($r.$c)" } else { '' } }
    $pfE = { param($r) $c = @($r.PSObject.Properties.Name | Where-Object { $_ -match '(?i)executable|^name$' } | Select-Object -First 1)[0]; if ($c) { "$($r.$c)" } else { '' } }
    & $weave 'prefetch_parsed' 2000 { param($r) $rc = ''; foreach ($pn in @($r.PSObject.Properties.Name)) { if ($pn -match '(?i)runcount|^run') { $rc = "$($r.$pn)"; break } } @((& $pfT $r), 'prefetch run', (& $leaf (& $pfE $r)), (& $pfE $r), "run count $rc") }
    & $weave 'amcache' 2000 {
        param($r)
        $t = $null
        foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)timestamp|time$' })) {
            try { $t2 = [datetime]"$($r.$pn)"; if ($t2 -and (-not $t -or $t2 -lt $t)) { $t = $t2 } } catch { }
        }
        $nm = ''; foreach ($pn in @('Name', 'ApplicationName', 'SourceSimpleName')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)") { $nm = "$($p2.Value)"; break } }
        @($(if ($t) { $t.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }), 'amcache entry', $nm, $nm, "source $($r.SourceFile)")
    }
    & $weave 'mft_recent' 3000 { param($r) @("$($r.Created)", 'file created ($MFT $Si)', '', "$($r.Path)", "FILE_NAME birth $($r.CreatedFN) | $($r.Flags)") }
    & $weave 'usn_write_bursts' 200 { param($r) @("$($r.WindowStart)", 'mass file modification (USN burst)', '', "$($r.Drive)", "$($r.WriteEvents) writes / $($r.DistinctFiles) files$(if ("$($r.RansomExt)") { " RANSOM-EXT $($r.RansomExt)" })") }
    & $weave 'bam_lastexec' 2000 { param($r) @("$($r.LastWrite)", "last exec ($($r.Source))", (& $leaf $r.Executable), "$($r.Executable)", "sid $($r.Sid)") }
    & $weave 'startup_info' 1000 { param($r) @("$($r.LastRun)", 'app launch (StartupInfo)', (& $leaf $r.App), "$($r.App)", "count $($r.Count)") }
    & $weave 'wer_reports' 1000 { param($r) @("$($r.Time)", 'app crash (WER)', "$($r.App)", "$($r.Module)", "$($r.File)") }
    & $weave 'session_activity' 3000 { param($r) @("$($r.Time)", "session activity [$($r.Activity)]", "$($r.SessionAccount)", "$($r.SourceIp)", "$($r.Detail)") }
    & $weave 'office_mru' 500 { param($r) @("$($r.LastWrite)", 'office document (MRU)', "$($r.App)", (& $leaf $r.Document), "$($r.Document)") }
    $anyT = {
        param($r, $fallback)
        foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)time|date' })) {
            if ("$($r.$pn)") { return "$($r.$pn)" }
        }
        $fallback
    }
    & $weave 'lnk_parsed' 1000 { param($r) @((& $anyT $r ''), 'LNK opened', '', (& $leaf $r.Target), "$($r.Path) -> $($r.Target)") }
    & $weave 'shellbags' 1000 { param($r) @((& $anyT $r ''), 'folder accessed (ShellBag)', '', (& $leaf ($r.PSObject.Properties['Path'].Value)), "$($r.PSObject.Properties['Path'].Value)") }
    & $weave 'recyclebin_index' 1000 { param($r) @((& $anyT $r ''), 'file deleted (recycle bin)', '', (& $leaf ($r.PSObject.Properties['OriginalPath'].Value)), "$($r.PSObject.Properties['OriginalPath'].Value)") }
    & $weave 'browser_history' 2000 {
        param($r)
        $u = ''; foreach ($pn in @('URL', 'Url', 'url')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)") { $u = "$($p2.Value)"; break } }
        @((& $anyT $r ''), 'browser visit', '', $u, ("$($r.PSObject.Properties['Title'].Value)"))
    }
    & $weave 'browser_downloads' 1000 {
        param($r)
        $tp = ''; foreach ($pn in @('TargetFilePath', 'TargetPath', 'DownloadPath', 'FullPath', 'Path')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)") { $tp = "$($p2.Value)"; break } }
        @((& $anyT $r ''), 'browser download', '', (& $leaf $tp), "$($r.PSObject.Properties['URL'].Value)")
    }
    & $weave 'iis_requests' 1000 { param($r) @("$($r.Time)", "web request (IIS) $("$($r.Method)")", '', "$($r.ClientIp) -> $("$($r.Uri)")", "status $($r.Status) ua=$("$($r.UserAgent)")") }
    & $weave 'hunt_findings' 500 { param($r) @("$($r.Found)", "hunt finding [$($r.Severity)]", '', "$($r.Entity)", "$($r.Rule): $($r.Evidence) ($($r.Attck))") }
    & $weave 'logging_gaps' 100 { param($r) @("$($r.Time)", 'logging gap', '', "$($r.Source)", "$($r.Meaning) $($r.Message)") }

    if ($rows.Count -eq 0) { return }
    $sorted = @($rows | Sort-Object { $t = [datetime]::MinValue; try { $t = [datetime]::Parse($_.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture) } catch { }; $t })
    if ($sorted.Count -gt 120000) { $sorted = @($sorted | Select-Object -Last 120000) }
    $out = Join-Path $CsvDir 'supertimeline.csv'
    $sorted | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    # hayabusa sort-csv: dedupe same-event rows coming from overlapping/backup evtx (PS sort above already orders by time)
    $hS = Get-HayabusaExe
    if ($hS) { $null = Invoke-NativeTool -ExePath $hS.FullName -ToolArgs @('sort-csv', '-f', $out, '-o', $out, '-C', '-q', '-K') -WorkingDirectory $hS.DirectoryName -QuietLog }
    $nFinal = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
    Write-CaseLog "    MASTER TIMELINE: $($sorted.Count) events from every artifact source, $nFinal after dedupe -> csv\supertimeline.csv (filter by Timestamp in Excel/Timeline Explorer)" 'DarkGray'
}

function New-SigmaRuleLogs {
    # Per-rule rawlog CSVs: one file per matched Sigma rule under csv\sigma_rules\ (+ index.csv).
    $hay = Import-CaseCsv 'hayabusa_timeline'
    if ($hay.Count -eq 0) { return }
    $nameCol = if ($hay[0].PSObject.Properties['RuleTitle']) { 'RuleTitle' } elseif ($hay[0].PSObject.Properties['Alert']) { 'Alert' } else { return }
    $dir = Join-Path $CsvDir 'sigma_rules'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $index = @()
    foreach ($g in ($hay | Group-Object $nameCol)) {
        $safe = ("$($g.Name)" -replace '[^A-Za-z0-9\._-]+', '_') -replace '^_+|_+$', ''
        if (-not $safe) { $safe = 'unnamed_rule' }
        if ($safe.Length -gt 80) { $safe = $safe.Substring(0, 80) }
        $rows = @($g.Group | Sort-Object Timestamp)
        $rows | Select-Object Timestamp, Level, Computer, Channel, EventID, RecordID, RuleID, Details, ExtraFieldInfo |
            Export-Csv -LiteralPath (Join-Path $dir "$safe.csv") -NoTypeInformation -Encoding UTF8
        $best = @($rows | Sort-Object { Get-LvlRank "$($_.Level)" } -Descending | Select-Object -First 1)
        $index += [pscustomobject]@{
            Rule = "$($g.Name)"
            Hits = $rows.Count
            MaxLevel = "$($best.Level)"
            LogCsv = "csv\sigma_rules\$safe.csv"
        }
    }
    $index | Sort-Object { Get-LvlRank "$($_.MaxLevel)" } -Descending |
        Export-Csv -LiteralPath (Join-Path $dir 'index.csv') -NoTypeInformation -Encoding UTF8
    Write-CaseLog "    sigma rule logs: $($index.Count) rule(s) -> csv\sigma_rules\ (per-rule event CSVs + index.csv)" 'DarkGray'
}

function New-EntityCorrelation {
    # Cross-source entity correlation (report-only): joins binaries, accounts and remote
    # endpoints across the case CSVs so one entity's story is readable in one place.
    # Missing sources contribute nothing - graceful by design.
    $CAP = 2000
    $rowsOf = {
        param([string]$name)
        try { return @((Import-CaseCsv $name) | Select-Object -First $CAP) } catch { return @() }
    }

    # ---------- binaries: keyed by full path, name fallback ----------
    $binsByPath = @{}
    $binsByName = @{}
    $binNew = {
        param([string]$raw)
        $p = ("$raw").Trim().Trim('"')
        # SRUM reports device-style paths - normalize to the drive letter (best effort: volume 3 is C: on the vast majority of systems)
        # ponytail: fixed harddiskvolume->C: mapping; per-volume letter resolution needs the mounteddevices hive
        $p = $p -replace '(?i)^\\device\\harddiskvolume\d+\\', 'C:\'
        if (-not $p) { return $null }
        $lk = $p.ToLower()
        $nk = Split-Path $lk -Leaf
        if (-not $nk) { $nk = $lk }
        if ($p.Contains('\') -and $binsByPath.ContainsKey($lk)) { return $binsByPath[$lk] }
        if (-not $p.Contains('\') -and $binsByName.ContainsKey($nk)) { return $binsByName[$nk] }
        $b = [pscustomobject]@{
            Path = $(if ($p.Contains('\')) { $p } else { "(name-only) $p" })
            Name = $nk
            Cats = New-Object System.Collections.Generic.List[string]
            Evidence = New-Object System.Collections.Generic.List[string]
            Hashes = New-Object System.Collections.Generic.List[string]
            Verdict = ''; Signer = ''; FirstSeen = ''; LastSeen = ''; Bytes = ''
        }
        $binsByPath[$lk] = $b
        if (-not $binsByName.ContainsKey($nk)) { $binsByName[$nk] = $b }
        return $b
    }
    $binAdd = {
        param($b, [string]$cat, [string]$detail, [string]$when)
        if (-not $b) { return }
        if ($b.Cats -notcontains $cat) { $b.Cats.Add($cat) }
        if ($detail) {
            $line = "$cat`: $detail"
            if ($b.Evidence.Count -lt 14 -and -not $b.Evidence.Contains($line)) { $b.Evidence.Add($line.Substring(0, [Math]::Min(220, $line.Length))) }
        }
        if ($when) {
            $t = $null
            try { $t = [datetime]$when } catch { }
            if ($t) {
                if (-not $b.FirstSeen -or $t -lt [datetime]$b.FirstSeen) { $b.FirstSeen = "$t" }
                if (-not $b.LastSeen -or $t -gt [datetime]$b.LastSeen) { $b.LastSeen = "$t" }
            }
        }
    }
    $binFromRow = {
        param($r)
        foreach ($pn in @('Binary', 'Image', 'ProcessPath', 'Process', 'Executable', 'Application', 'AppPath', 'App', 'NewProcess')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { return (& $binNew $p2.Value) }
        }
        # 'Path'/'PathName' are only trusted when they name a real binary (service/task rows abuse these for names)
        foreach ($pn in @('PathName', 'SourceFile', 'Path')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)" -match '\.(exe|dll|sys|ps1|bat|js|vbs|hta|com|ocx|drv)$') { return (& $binNew $p2.Value) }
        }
        foreach ($pn in @('Actions', 'Value', 'Details', 'Command')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)" -match '(?i)([a-z]:\\[^\s"|]+\.(exe|dll|sys|ps1|bat|js|vbs|hta))') { return (& $binNew $Matches[1]) }
        }
        foreach ($pn in @('Name', 'ExecutableName', 'FileName')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)" -match '\.(exe|dll|sys|ps1|bat|js|vbs|hta)$') { return (& $binNew $p2.Value) }
        }
        return $null
    }

    foreach ($r in (& $rowsOf 'flash_process_scored')) {
        $b = & $binFromRow $r
        if ($b) { $b.Verdict = "$($r.Verdict)"; $b.Signer = "$($r.Signer)"; & $binAdd $b 'verdict' "[$($r.Verdict) $($r.Score)] $($r.Evidence)" '' }
    }
    foreach ($r in (& $rowsOf 'processes')) { & $binAdd (& $binFromRow $r) 'running' "PID $($r.PID)" '' }
    foreach ($r in (& $rowsOf 'process_hashes')) { $b = & $binFromRow $r; if ($b) { $null = $b.Hashes.Add("$($r.SHA256)"); & $binAdd $b 'hash' "$($r.SHA256)" '' } }
    foreach ($src in @('services', 'services_flagged')) {
        foreach ($r in (& $rowsOf $src)) {
            $b = & $binFromRow $r
            $svcName = if ($r.PSObject.Properties['Service']) { "$($r.Service)" } elseif ($r.PSObject.Properties['Name']) { "$($r.Name)" } else { '' }
            & $binAdd $b 'svc-persist' "service $svcName" ''
        }
    }
    foreach ($r in (& $rowsOf 'scheduled_tasks_flagged')) { & $binAdd (& $binFromRow $r) 'task-persist' "task $($r.Name) (runas $($r.RunAs)) flags $($r.Flags)" '' }
    foreach ($src in @('autoruns_runkeys', 'asep_sweep')) {
        foreach ($r in (& $rowsOf $src)) { & $binAdd (& $binFromRow $r) 'autorun-persist' "$($r.Location) / $($r.Name)" '' }
    }
    foreach ($r in (& $rowsOf 'sysmon_network')) { & $binAdd (& $binFromRow $r) 'conn' "$($r.DestIp):$($r.DestPort)" "$($r.Time)" }
    foreach ($r in (& $rowsOf 'flash_public_connections')) { & $binAdd (& $binFromRow $r) 'conn' "public $($r.RemoteAddress):$($r.RemotePort)" '' }
    foreach ($r in (& $rowsOf 'beacon_candidates')) { & $binAdd (& $binFromRow $r) 'beacon' "[$($r.Severity)] -> $($r.RemoteIp):$($r.Port) every ~$($r.MedianIntervalSec)s" '' }
    foreach ($r in (& $rowsOf 'dns_beacon_candidates')) { & $binAdd (& $binFromRow $r) 'beacon' "[$($r.Severity)] DNS $($r.Domain) every ~$($r.MedianIntervalSec)s" '' }
    foreach ($r in (& $rowsOf 'srum_usage')) {
        $b = & $binFromRow $r
        if ($b) {
            $bt = (@($r.PSObject.Properties | Where-Object { $_.Name -match '(?i)byte|sent|recv|duration' } | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ')
            if ($bt) { $b.Bytes = if ($b.Bytes) { "$($b.Bytes); $bt" } else { $bt }
                if ($b.Bytes.Length -gt 300) { $b.Bytes = $b.Bytes.Substring(0, 300) + '...' } }
            & $binAdd $b 'srum-usage' $bt ''
        }
    }
    foreach ($r in (& $rowsOf 'yara_hits')) { & $binAdd (& $binFromRow $r) 'yara' "$($r.Rule)" '' }
    foreach ($r in (& $rowsOf 'loldrivers_hits')) { & $binAdd (& $binFromRow $r) 'loldriver' "$($r.Status)" '' }
    foreach ($r in (& $rowsOf 'mft_recent')) { & $binAdd (& $binFromRow $r) 'mft-created' $r.Created "$($r.Created)" }
    foreach ($r in (& $rowsOf 'ioc_hits_amcache')) { & $binAdd (& $binFromRow $r) 'ioc' "$($r.Indicator) (amcache $($r.SourceFile))" '' }
    foreach ($r in ((& $rowsOf 'hayabusa_timeline') | Where-Object { (Get-LvlRank "$($_.Level)") -ge 3 })) {
        if ("$($r.Details)" -match '(?i)([a-z0-9_\-]+\.(exe|dll|ps1|js|vbs|hta))') { & $binAdd (& $binNew $Matches[1]) 'sigma' "[$($r.Level)] $($r.RuleTitle)" "$($r.Timestamp)" }
    }
    # v2.21 structured telemetry joins: 4688 execution, admin-share staging, IIS anomalies
    foreach ($r in (& $rowsOf 'security_proc_events')) { & $binAdd (& $binFromRow $r) '4688-exec' "child of $($r.ParentProcess)" "$($r.Time)" }
    foreach ($r in (& $rowsOf 'security_share_access')) {
        $tn = "$($r.RelativeTargetName)"
        if ($tn -match '\.(exe|dll|ps1|bat|js|vbs|hta|msi)$') { & $binAdd (& $binNew $tn) 'share-staging' "$("$($r.ShareName)" -replace '^[\*\\\s]+', '') by $($r.Account) from $($r.SourceIp)" '' }
    }
    foreach ($r in (& $rowsOf 'iis_anomalies')) {
        if ("$($r.Sample)" -match '(?i)([a-z]:\\[^\s"|]+\.(exe|dll|ps1|aspx|jsp|ashx))') { & $binAdd (& $binNew $Matches[1]) 'web-anomaly' "[$($r.Kind)] $($r.Detail)" '' }
    }

    # ---------- accounts ----------
    $accts = @{}
    $acctGet = {
        param([string]$name)
        $a2 = ("$name").Trim()
        if (-not $a2 -or $a2 -match '^(-|\$|DWM-|UMFD-)$' -or @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON') -contains $a2) { return $null }
        $lk = $a2.ToLower()
        if (-not $accts.ContainsKey($lk)) {
            $accts[$lk] = [pscustomobject]@{
                Account = $a2; Logons = 0; Failed = 0
                Types = New-Object System.Collections.Generic.List[string]
                Sources = New-Object System.Collections.Generic.List[string]
                RdpTargets = New-Object System.Collections.Generic.List[string]
                ConsoleKB = 0.0; Created = ''
                Evidence = New-Object System.Collections.Generic.List[string]
            }
        }
        return $accts[$lk]
    }
    $acctFromRow = {
        param($r)
        foreach ($pn in @('Account', 'User', 'UserName', 'TargetUserName', 'SubjectUserName', 'RunAs')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { return (& $acctGet $p2.Value) }
        }
        return $null
    }
    $logonTypeNames = @{ 2 = 'interactive'; 3 = 'network'; 4 = 'batch'; 5 = 'service'; 7 = 'unlock'; 8 = 'net-cleartext'; 9 = 'new-creds'; 10 = 'rdp'; 11 = 'cached' }
    foreach ($r in (& $rowsOf 'security_auth_events')) {
        $a2 = & $acctFromRow $r
        if (-not $a2) { continue }
        if ("$($r.EventId)" -eq '4624') {
            $a2.Logons++
            $lt = $null
            try { $lt = [int]"$($r.LogonType)" } catch { }
            $tn = if ($lt -and $logonTypeNames.ContainsKey($lt)) { $logonTypeNames[$lt] } else { '' }
            if ($tn -and $a2.Types -notcontains $tn) { $null = $a2.Types.Add($tn) }
            if ($tn -eq 'rdp') { if ($a2.Evidence.Count -lt 14) { $a2.Evidence.Add("rdp-in logon at $($r.Time)") | Out-Null } }
        }
        if ("$($r.EventId)" -eq '4625') { $a2.Failed++; if ("$($r.SourceIp)" -and -not $a2.Sources.Contains("$($r.SourceIp)")) { $null = $a2.Sources.Add("$($r.SourceIp)") } }
    }
    foreach ($r in (& $rowsOf 'rdp_localsession')) {
        $a2 = & $acctFromRow $r
        if ($a2 -and $a2.Evidence.Count -lt 14 -and -not ($a2.Evidence | Where-Object { $_ -match '^rdp-session' })) { $a2.Evidence.Add("rdp-session: $($r.TimeCreated)") | Out-Null }
    }
    foreach ($r in (& $rowsOf 'rdp_client_targets')) {
        $a2 = & $acctFromRow $r
        if ($a2) {
            if (-not $a2.RdpTargets.Contains("$($r.TargetServer)")) { $null = $a2.RdpTargets.Add("$($r.TargetServer)") }
            $a2.Evidence.Add("rdp-out: $($r.TargetServer) (hint $($r.UsernameHint))") | Out-Null
        }
    }
    foreach ($r in (& $rowsOf 'powershell_console_history')) {
        $a2 = & $acctFromRow $r
        if ($a2) { $a2.ConsoleKB = [math]::Round($a2.ConsoleKB + [double]"$($r.KB)", 1); $a2.Evidence.Add("console history: $($r.KB) KB (raw\useractivity\$($a2.Account))") | Out-Null }
    }
    # v2.21: Kerberos + directory-service + session-attributed activity evidence
    foreach ($r in (& $rowsOf 'security_kerberos')) {
        $a2 = & $acctFromRow $r
        if (-not $a2 -or $a2.Evidence.Count -ge 14) { continue }
        if ("$($r.EventId)" -eq '4769') { $null = $a2.Evidence.Add("kerberos TGS for $($r.Service) from $($r.IpAddress) (enc $($r.TicketEnc))") }
        elseif ("$($r.EventId)" -eq '4771') { $null = $a2.Evidence.Add("kerberos pre-auth FAILED from $($r.IpAddress)") }
    }
    foreach ($r in (& $rowsOf 'security_ds_access')) {
        $a2 = & $acctFromRow $r
        if ($a2 -and $a2.Evidence.Count -lt 14 -and "$($r.Properties)" -match '(?i)e3514235|1131f6a') { $null = $a2.Evidence.Add("directory replication access (4662 Get-Changes) on $($r.Object)") }
    }
    foreach ($r in (& $rowsOf 'session_activity')) {
        $pn = $r.PSObject.Properties['SessionAccount']
        if (-not $pn -or -not "$($pn.Value)") { continue }
        $a2 = & $acctGet "$($pn.Value)"
        if ($a2 -and $a2.Evidence.Count -lt 14) { $null = $a2.Evidence.Add("session activity [$($r.Activity)]: $($r.Detail)$(if ("$($r.SourceIp)") { " from $($r.SourceIp)" })") }
    }

    # ---------- remote endpoints ----------
    $rem = @{}
    $remGet = {
        param([string]$ip)
        $k = ("$ip").Trim().ToLower()
        if (-not $k) { return $null }
        if (-not $rem.ContainsKey($k)) {
            $rem[$k] = [pscustomobject]@{
                Remote = "$ip"; Public = (Test-IsPublicIp $ip); Conns = 0
                Talkers = New-Object System.Collections.Generic.List[string]
                Beacon = ''; Brute = 0; RdpOut = 0
                Evidence = New-Object System.Collections.Generic.List[string]
            }
        }
        return $rem[$k]
    }
    foreach ($r in (& $rowsOf 'sysmon_network')) {
        $e = & $remGet $r.DestIp
        if ($e) {
            $e.Conns++
            if ("$($r.Image)") { $leaf = Split-Path "$($r.Image)" -Leaf; if ($leaf -and -not $e.Talkers.Contains($leaf)) { $null = $e.Talkers.Add($leaf) } }
        }
    }
    foreach ($r in (& $rowsOf 'flash_public_connections')) {
        $e = & $remGet $r.RemoteAddress
        if ($e) {
            $e.Conns++
            if ("$($r.ProcessPath)") { $leaf = Split-Path "$($r.ProcessPath)" -Leaf; if ($leaf -and -not $e.Talkers.Contains($leaf)) { $null = $e.Talkers.Add($leaf) } }
        }
    }
    foreach ($r in (& $rowsOf 'beacon_candidates')) { $e = & $remGet $r.RemoteIp; if ($e) { $e.Beacon = "$($r.Severity)"; $e.Evidence.Add("beacon $($r.Severity) from $($r.Process)") | Out-Null } }
    foreach ($r in (& $rowsOf 'dns_beacon_candidates')) { $e = & $remGet $r.ResolvedIp; if ($e) { if (-not $e.Beacon) { $e.Beacon = "$($r.Severity)" }; $e.Evidence.Add("dns-beacon $($r.Severity) for $($r.Domain)") | Out-Null } }
    foreach ($r in (& $rowsOf 'security_bruteforce_candidates')) { $e = & $remGet $r.SourceIp; if ($e) { $e.Brute = [int]"$($r.FailedLogons)"; $e.Evidence.Add("brute-force: $($r.FailedLogons) failed logons") | Out-Null } }
    foreach ($r in (& $rowsOf 'rdp_client_targets')) { $e = & $remGet $r.TargetServer; if ($e) { $e.RdpOut++; $e.Evidence.Add("rdp-out target (hint $($r.UsernameHint))") | Out-Null } }

    foreach ($r in (& $rowsOf 'hunt_findings')) {
        $ent = "$($r.Entity)"
        $b = $null
        if ($ent -match '^[a-z]:\\') { $b = & $binNew $ent } else { $b = & $binFromRow $r }
        if ($b) { & $binAdd $b 'hunt' "[$($r.Severity)] $($r.Rule): $($r.Evidence)" '' }
    }

    # ---------- emit ----------
    if ($env:OPHIRA_DBG_ENT) { foreach ($kv in $binsByPath.GetEnumerator()) { Write-Host ("DBG bin: {0} -> [{1}]" -f $kv.Key, ($kv.Value.Cats -join ",")) } }
    if ($env:OPHIRA_DBG_ENT) { foreach ($a2 in $accts.Values) { Write-Host ("DBG acct: {0} logons={1} failed={2}" -f $a2.Account, $a2.Logons, $a2.Failed) } }
    $binRows = @($binsByPath.Values | ForEach-Object {
        [pscustomobject]@{
            Categories = ($_.Cats -join ';'); CatCount = $_.Cats.Count; Name = $_.Name; Path = $_.Path
            Verdict = $_.Verdict; Signer = $_.Signer; FirstSeen = $_.FirstSeen; LastSeen = $_.LastSeen
            Hashes = (($_.Hashes | Select-Object -Unique | Select-Object -First 4) -join ';'); Bytes = $_.Bytes
            Evidence = ($_.Evidence -join ' | ')
        }
    } | Sort-Object @{e = 'CatCount'; Descending = $true }, @{e = { if ("$($_.Verdict)" -match 'HIGH') { 2 } elseif ("$($_.Verdict)" -match 'MEDIUM') { 1 } else { 0 } }; Descending = $true })
    Save-Rows -Name 'entities_binaries' -Rows $binRows

    $acctRows = @($accts.Values | ForEach-Object {
        $ev = ($_.Evidence | Select-Object -Unique | Select-Object -First 12) -join ' | '
        [pscustomobject]@{
            Account = $_.Account; Logons = $_.Logons; Failed = $_.Failed; LogonTypes = ($_.Types -join ';')
            Sources = ($_.Sources | Select-Object -Unique) -join ';'; RdpOutTargets = ($_.RdpTargets | Select-Object -Unique) -join ';'
            ConsoleHistoryKB = $_.ConsoleKB; Evidence = $ev
        }
    } | Sort-Object @{e = 'Failed'; Descending = $true }, @{e = 'Logons'; Descending = $true })
    Save-Rows -Name 'entities_accounts' -Rows $acctRows

    $remRows = @($rem.Values | ForEach-Object {
        [pscustomobject]@{
            Remote = $_.Remote; Public = $_.Public; Connections = $_.Conns
            Talkers = (($_.Talkers | Select-Object -Unique | Select-Object -First 6) -join ';')
            Beacon = $_.Beacon; FailedLogons = $_.Brute; RdpOutCount = $_.RdpOut
            Evidence = (($_.Evidence | Select-Object -Unique | Select-Object -First 10) -join ' | ')
        }
    } | Sort-Object @{e = 'Beacon'; Descending = $true }, @{e = 'FailedLogons'; Descending = $true }, @{e = 'Connections'; Descending = $true })
    Save-Rows -Name 'entities_remotes' -Rows $remRows

    $multi = @($binRows | Where-Object { $_.CatCount -ge 2 }).Count
    Write-CaseLog "    entity correlation: $($binRows.Count) binaries ($multi multi-source), $($acctRows.Count) accounts, $($remRows.Count) remotes -> csv\entities_*.csv" 'DarkGray'
}

function New-SessionAttribution {
    # v2.21: join 4624 logon sessions (LogonId -> account/source IP/logon type) to 4688/5140/5145
    # SubjectLogonId - attributes process creations and share writes to the human session that made them.
    $sess = @{}
    foreach ($r in ((Import-CaseCsv 'security_auth_events') | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonId)" })) {
        $sess["$($r.LogonId)"] = $r
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $s = $sess["$($r.LogonId)"]
        if (-not $s) { continue }
        $cmd = "$($r.CommandLine)"; if ($cmd.Length -gt 160) { $cmd = $cmd.Substring(0, 160) + '...' }
        $null = $out.Add([pscustomobject]@{ Time = $r.Time; SessionAccount = "$($s.Account)"; SourceIp = "$($s.SourceIp)"; LogonType = "$($s.LogonType)"; Activity = 'process'; Detail = "$($r.NewProcess) $cmd".Trim() })
    }
    foreach ($r in (Import-CaseCsv 'security_share_access')) {
        $s = $sess["$($r.LogonId)"]
        if (-not $s) { continue }
        $sh = "$($r.ShareName)" -replace '^[\*\\\s]+', ''
        $srcIp = "$($r.SourceIp)"
        if (-not $srcIp -or $srcIp -eq '-') { $srcIp = "$($s.SourceIp)" }
        $null = $out.Add([pscustomobject]@{ Time = $r.Time; SessionAccount = "$($s.Account)"; SourceIp = $srcIp; LogonType = "$($s.LogonType)"; Activity = 'share'; Detail = "$sh -> $($r.RelativeTargetName)" })
    }
    $rows = @($out.ToArray() | Sort-Object Time)
    Save-Rows -Name 'session_activity' -Rows $rows
    $n = $rows.Count
    if ($n -gt 0) {
        Write-CaseLog "    session attribution: $n activity row(s) joined to logon sessions (4624 LogonId x 4688/5145) -> csv\session_activity.csv" 'Gray'
    } else {
        Write-CaseLog "    session attribution: no joins (4624 without LogonId in this case, or no 4688/5145 activity)" 'DarkGray'
    }
}

function New-ProcessChains {
    # v2.21: reconstruct parent->child ancestry for flagged processes from 4688 lineage + live PPID map.
    # Chains answer "how did this get here": explorer.exe -> winword.exe -> powershell.exe -> beacon.exe.
    $edges = @{}
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $c = ''; $p = ''
        try { $c = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        try { $p = (Split-Path "$($r.ParentProcess)" -Leaf).ToLower() } catch { }
        if (-not $c -or -not $p -or $c -eq $p) { continue }
        if (-not $edges.ContainsKey($c)) { $edges[$c] = New-Object System.Collections.Generic.List[object] }
        $null = $edges[$c].Add([pscustomobject]@{ Parent = $p; ParentPath = "$($r.ParentProcess)"; Time = "$($r.Time)"; Cmd = "$($r.CommandLine)"; Src = '4688' })
    }
    $pidMap = @{}
    $live = @(Import-CaseCsv 'processes')
    foreach ($r in $live) { if ("$($r.PID)") { $pidMap["$($r.PID)"] = $r } }
    foreach ($r in $live) {
        $c = ''
        try { $c = (Split-Path "$($r.Path)" -Leaf).ToLower() } catch { }
        if (-not $c -or -not "$($r.PPID)" -or -not $pidMap.ContainsKey("$($r.PPID)")) { continue }
        $par = $pidMap["$($r.PPID)"]
        $p = ''
        try { $p = (Split-Path "$($par.Path)" -Leaf).ToLower() } catch { }
        if (-not $p -or $c -eq $p) { continue }
        if (-not $edges.ContainsKey($c)) { $edges[$c] = New-Object System.Collections.Generic.List[object] }
        $null = $edges[$c].Add([pscustomobject]@{ Parent = $p; ParentPath = "$($par.Path)"; Time = ''; Cmd = "$($par.Path)"; Src = 'live' })
    }
    if ($edges.Count -eq 0) { Write-CaseLog '    process lineage: no parent-child edges (4688 off, no live map)' 'DarkGray'; return }

    $flagged = New-Object System.Collections.Generic.List[string]
    foreach ($r in ((Import-CaseCsv 'flash_process_scored') | Where-Object { "$($_.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($_.Path)" })) {
        $null = $flagged.Add("$($r.Path)")
    }
    foreach ($r in ((Import-CaseCsv 'hunt_findings') | Where-Object { "$($_.Severity)" -eq 'high' })) {
        $e = "$($r.Entity)"
        if ($e -match '^[a-z]:\\' -or $e -match '\.(exe|dll|ps1|bat|js|vbs)$') { $null = $flagged.Add($e) }
    }
    $out = New-Object System.Collections.Generic.List[object]
    $seenChains = @{}
    foreach ($f in (@($flagged | Select-Object -Unique) | Select-Object -First 40)) {
        $leaf = ''
        try { $leaf = (Split-Path $f -Leaf).ToLower() } catch { }
        if (-not $leaf -or -not $edges.ContainsKey($leaf)) { continue }
        # walk ancestors, widest evidence per hop, cap depth 8
        $steps = New-Object System.Collections.Generic.List[string]
        $notes = New-Object System.Collections.Generic.List[string]
        $cur = $leaf
        $depth = 0
        $visited = @{}
        while ($edges.ContainsKey($cur) -and $depth -lt 8) {
            if ($visited.ContainsKey($cur)) { break }
            $visited[$cur] = $true
            $e = $edges[$cur][0]
            $null = $steps.Insert(0, $e.Parent)
            if ("$($e.Cmd)" -or "$($e.Time)") { $null = $notes.Insert(0, "$($e.Parent): $(if ("$($e.Cmd)") { "$($e.Cmd)" } else { '?' })$(if ("$($e.Time)") { " @ $($e.Time)" })") }
            $cur = $e.Parent
            $depth++
        }
        $null = $steps.Add($leaf)
        $chain = $steps -join ' -> '
        if ($steps.Count -lt 2 -or $seenChains.ContainsKey($chain)) { continue }
        $seenChains[$chain] = $true
        $null = $out.Add([pscustomobject]@{ Entity = $f; Steps = $steps.Count; Chain = $chain; Evidence = (($notes | Select-Object -First 8) -join ' | ') })
    }
    Save-Rows -Name 'process_chains' -Rows $out.ToArray()
    if ($out.Count -gt 0) {
        Write-CaseLog "    process lineage: $($out.Count) ancestry chain(s) for flagged binaries -> csv\process_chains.csv" 'Gray'
    } else {
        Write-CaseLog '    process lineage: flagged binaries have no parent edges in this case' 'DarkGray'
    }
}

function New-IocHits {
    # v2.26: xref the structured case telemetry against the IOC feeds (iocs.txt + tools\iocs\).
    # Historical DNS queries + network connections + $MFT dropped-filename exact matches.
    $iocs = Get-IocList
    if (-not $iocs) { return }
    $feedOf = { param($k) $f = $iocs.Feed[$k]; if ($f) { $f } else { 'iocs.txt' } }
    $dns = @()
    foreach ($r in (Import-CaseCsv 'sysmon_dns')) {
        $q = "$($r.QueryName)".ToLower()
        if (-not $q) { continue }
        foreach ($k in $iocs.Domains.Keys) {
            if ($q -eq $k -or $q.EndsWith(".$k")) {
                $dns += [pscustomobject]@{ Indicator = $k; Feed = (& $feedOf $k); Query = $q; Process = "$($r.Image)"; Resolved = "$($r.QueryResults)"; Match = 'dns-query' }
                break
            }
        }
    }
    Save-Rows -Name 'ioc_hits_dns' -Rows $dns
    if (@($dns).Count -gt 0) { Write-CaseLog "    DNS IOC HITS: $(@($dns).Count) query/queries to known-bad domain(s) -> csv\ioc_hits_dns.csv" 'Red' }
    $net = @()
    foreach ($r in (Import-CaseCsv 'sysmon_network')) {
        $ip = "$($r.DestIp)"
        if (-not $ip -or -not $iocs.Ips.ContainsKey($ip)) { continue }
        $net += [pscustomobject]@{ Indicator = $ip; Feed = (& $feedOf $ip); RemoteIp = $ip; Port = "$($r.DestPort)"; Process = "$($r.Image)"; Match = 'network-connection' }
    }
    Save-Rows -Name 'ioc_hits_network' -Rows $net
    if (@($net).Count -gt 0) { Write-CaseLog "    NETWORK IOC HITS: $(@($net).Count) connection(s) to known-bad IP(s) -> csv\ioc_hits_network.csv" 'Red' }
    $mft = @()
    if ($iocs.Names.Count -gt 0) {
        foreach ($r in (Import-CaseCsv 'mft_recent')) {
            $nm = "$($r.Name)".ToLower()
            if (-not $nm -or -not $iocs.Names.ContainsKey($nm)) { continue }
            $mft += [pscustomobject]@{ Indicator = $nm; Feed = (& $feedOf $nm); Path = "$($r.Path)"; Created = "$($r.Created)"; Match = 'mft-filename' }
        }
    }
    Save-Rows -Name 'ioc_hits_mft' -Rows $mft
    if (@($mft).Count -gt 0) { Write-CaseLog "    FILENAME IOC HITS: $($mft.Count) known-bad filename(s) on disk -> csv\ioc_hits_mft.csv" 'Red' }
}

function New-HuntFindings {
    # Hunt techniques ported from Velociraptor-style detection logic + APT TTPs.
    # Findings feed the report, entity correlation and (R1-R4) the verdict.
    $out = New-Object System.Collections.Generic.List[object]
    $find = {
        param([string]$rule, [string]$sev, [string]$entity, [string]$evidence, [string]$attack)
        $null = $out.Add([pscustomobject]@{ Found = (Get-Date).ToUniversalTime().ToString('o'); Rule = $rule; Severity = $sev; Entity = $entity; Attck = $attack; Evidence = $evidence })
    }

    # ---------- R1: renamed LOLBin (version-info identity vs filename, BinaryRename port) ----------
    $lolBins = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'wmic.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe', 'bitsadmin.exe', 'net.exe', 'net1.exe', 'netsh.exe', 'wevtutil.exe', 'psexec.exe', 'psexec64.exe', 'msiexec.exe', 'installutil.exe', 'schtasks.exe', 'curl.exe', 'wget.exe', '7z.exe', 'winrar.exe')
    $r1Seen = @{}
    foreach ($r in ((Import-CaseCsv 'processes') | Select-Object -First 400)) {
        $p = "$($r.Path)"
        if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $leaf = $null
        try { $leaf = (Split-Path $p -Leaf).ToLower() } catch { continue }
        if (-not $leaf -or $r1Seen.ContainsKey($p.ToLower())) { continue }
        $r1Seen[$p.ToLower()] = $true
        $vi = $null
        try { $vi = (Get-Item -LiteralPath $p -ErrorAction Stop).VersionInfo } catch { continue }
        $internal = "$($vi.InternalName)"; $original = "$($vi.OriginalFilename)"
        $identities = @($internal, $original) | Where-Object { $_ } | ForEach-Object { (($_ -replace '\.mui$', '') -replace '\.exe$', '').ToLower().Trim() }
        $idHit = @($identities | Where-Object { $lolBins -contains ($_ + '.exe') })
        if ($idHit.Count -gt 0 -and ($leaf -replace '\.exe$', '') -ne $idHit[0]) {
            & $find 'Renamed LOLBin (version-info mismatch)' 'high' $p "file '$leaf' but embedded identity '$($idHit[0])' (internal=$internal; original=$original)" 'T1036.003'
        }
    }

    # ---------- R1b: renamed LOLBin at rest - Sysmon EID1 OriginalFileName vs executed Image name ----------
    # catches copies that already exited (live R1 only sees running processes); winupd.exe-class
    $r1bSeen = @{}
    foreach ($r in (Import-CaseCsv 'sysmon_proc_create')) {
        $orig = "$($r.OriginalFileName)".ToLower().Trim()
        if (-not $orig) { continue }
        $img = "$($r.Image)"
        $leaf = ''
        try { $leaf = (Split-Path $img -Leaf).ToLower() } catch { continue }
        if (-not $leaf) { continue }
        $origBase = $orig -replace '\.exe$', ''
        $leafBase = $leaf -replace '\.exe$', ''
        if ($lolBins -notcontains "$origBase.exe" -or $leafBase -eq $origBase) { continue }
        $key = "$leaf|$origBase"
        if ($r1bSeen.ContainsKey($key)) { continue }
        $r1bSeen[$key] = $true
        $cmd = "$($r.CommandLine)"
        if ($cmd.Length -gt 120) { $cmd = $cmd.Substring(0, 120) + '...' }
        & $find 'Renamed LOLBin at rest (Sysmon identity mismatch)' 'high' $img "executed as '$leaf' but embedded identity '$origBase'$(if ($cmd) { " | cmd: $cmd" })" 'T1036.003'
    }

    # ---------- R2: DLL side-load live - proxy DLL loaded from user-writable path (Sysmon EID 7) ----------
    $proxyDlls = @('version.dll', 'winmm.dll', 'dbghelp.dll', 'd3d9.dll', 'd3d10.dll', 'd3d11.dll', 'dxgi.dll', 'cryptsp.dll', 'winhttp.dll', 'ualapi.dll', 'wlanapi.dll', 'wbemcomn.dll', 'actxprxy.dll', 'msdtcprx.dll', 'tspkg.dll', 'ntlmshared.dll', 'mfc42.dll', 'msvcp60.dll')
    foreach ($r in (Import-CaseCsv 'sysmon_image_load')) {
        $dll = "$($r.Dll)"
        if (-not $dll) { continue }
        $leaf = ''
        try { $leaf = (Split-Path $dll -Leaf).ToLower() } catch { continue }
        if (-not $leaf) { continue }
        if ($proxyDlls -contains $leaf -and (Test-IsUserWritablePath $dll)) {
            & $find 'DLL side-load - proxy DLL in user-writable path' 'high' $dll "loaded by $($r.Process) (signed=$($r.Signed); sig=$($r.Signature))" 'T1574.002'
        } elseif ($proxyDlls -contains $leaf -and "$($r.Signed)" -eq 'false' -and $dll -notmatch '(?i)\\windows\\') {
            & $find 'DLL side-load - unsigned proxy DLL outside Windows' 'medium' $dll "loaded by $($r.Process) from $dll" 'T1574.002'
        }
    }

    # ---------- R3: same proxy-DLL/binary name in system dir AND user dir (static side-load) ----------
    $namePaths = @{}
    foreach ($src in @('amcache', 'mft_recent', 'sysmon_image_load')) {
        foreach ($r in (Import-CaseCsv $src)) {
            $p = $null
            if ($src -eq 'sysmon_image_load') { $p = "$($r.Dll)" } else {
                foreach ($pn in @('Path', 'Name')) { $p2 = $r.PSObject.Properties[$pn]; if ($p2 -and "$($p2.Value)" -match '\.(dll|exe)$') { $p = "$($p2.Value)"; break } }
            }
            if (-not $p) { continue }
            $leaf = ''
            try { $leaf = (Split-Path $p -Leaf).ToLower() } catch { continue }
            if (-not $leaf -or $proxyDlls -notcontains $leaf) { continue }
            if (-not $namePaths.ContainsKey($leaf)) { $namePaths[$leaf] = New-Object System.Collections.Generic.List[string] }
            $null = $namePaths[$leaf].Add($p)
        }
    }
    foreach ($kv in $namePaths.GetEnumerator()) {
        $inSys = @($kv.Value | Where-Object { $_ -match '(?i)^c:\\windows\\(system32|syswow64|sysnative)\\' })
        $inUser = @($kv.Value | Where-Object { Test-IsUserWritablePath $_ })
        if ($inSys.Count -gt 0 -and $inUser.Count -gt 0) {
            & $find 'DLL side-load - planted system DLL name in user path' 'high' $kv.Key "system: $($inSys[0]) | user: $($inUser[0])$(if ($inUser.Count -gt 1) { ' (+' + ($inUser.Count - 1) + ' more)' })" 'T1574.002'
        }
    }

    # ---------- R4: downloaded then executed ----------
    $execNames = @{}
    foreach ($src in @('amcache', 'prefetch_parsed', 'execution_timeline', 'processes')) {
        foreach ($r in (Import-CaseCsv $src)) {
            foreach ($pn in @('Path', 'Executable', 'Name', 'App')) {
                $p2 = $r.PSObject.Properties[$pn]
                if ($p2 -and "$($p2.Value)") {
                    $n = ''
                    try { $n = (Split-Path "$($p2.Value)" -Leaf).ToLower() } catch { $n = "$($p2.Value)".ToLower() }
                    if ($n -match '\.(exe|dll|ps1|bat|js|hta|scr|msi|lnk|vbs)$') { $execNames[$n] = $true }
                    break
                }
            }
        }
    }
    foreach ($r in (Import-CaseCsv 'browser_downloads')) {
        $tp = ''
        foreach ($pn in @('TargetFilePath', 'TargetPath', 'DownloadPath', 'FullPath', 'Path', 'URL')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $tp = "$($p2.Value)"; break }
        }
        if (-not $tp) { continue }
        $n = ''
        try { $n = (Split-Path $tp -Leaf).ToLower() } catch { $n = $tp.ToLower() }
        if ($n -and $n -match '\.(exe|dll|ps1|bat|js|hta|scr|msi|lnk|vbs)$' -and $execNames.ContainsKey($n)) {
            & $find 'Downloaded then executed' 'high' $tp "'$n' downloaded via browser and later appears in execution evidence" 'T1105/T1204.002'
        }
    }

    # ---------- R5: USB execution trail (report-only) ----------
    $usb = @(Import-CaseCsv 'usb_devices')
    if ($usb.Count -gt 0) {
        $nonC = @()
        foreach ($src in @('lnk_parsed', 'shellbags')) {
            foreach ($r in (Import-CaseCsv $src)) {
                foreach ($p2 in $r.PSObject.Properties) {
                    $v = "$($p2.Value)"
                    if ($v -match '(?i)^([d-z]):\\' -and $Matches[1].ToUpper() -ne 'C:') { $nonC += "$($src.Substring(0, 3))/$($p2.Name): $v"; break }
                }
                if ($nonC.Count -ge 3) { break }
            }
            if ($nonC.Count -ge 3) { break }
        }
        if ($nonC.Count -gt 0) {
            & $find 'USB execution trail' 'info' "$($usb.Count) USB device(s) on record" "non-C: drive references: $(($nonC | Select-Object -First 3) -join ' | ')" 'T1091'
        }
    }

    # ---------- R6: account created + privileged group change in window (report-only) ----------
    $auth = Import-CaseCsv 'security_auth_events'
    $created = @($auth | Where-Object { "$($_.EventId)" -eq '4720' } | ForEach-Object { "$($_.Account)" } | Sort-Object -Unique)
    $grpAdds = @($auth | Where-Object { @('4728', '4732', '4756') -contains "$($_.EventId)" })
    if ($created.Count -gt 0 -and $grpAdds.Count -gt 0) {
        & $find 'Account lifecycle - created + group change' 'info' (($created | Select-Object -First 5) -join ', ') "$($created.Count) account creation(s) + $($grpAdds.Count) privileged-group change(s) in window" 'T1136/T1098'
    }

    # ---------- R7: RDP logon from public internet IP (report-only) ----------
    $rdpPub = @($auth | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonType)" -eq '10' -and (Test-IsPublicIp "$($_.SourceIp)") })
    foreach ($g in ($rdpPub | Group-Object SourceIp)) {
        $accts = (@($g.Group | ForEach-Object { "$($_.Account)" } | Sort-Object -Unique | Select-Object -First 4)) -join ', '
        & $find 'RDP logon from public internet IP' 'medium' "$($g.Name)" "$($g.Count) RDP logon(s): $accts" 'T1021.001'
    }

    # ---------- R8: LSASS access - non-system process opened lsass.exe (Sysmon EID 10) ----------
    $lsassOk = @('csrss.exe', 'lsm.exe', 'smss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'svchost.exe', 'lsass.exe', 'lsaiso.exe', 'msmpeng.exe', 'nissrv.exe', 'mssense.exe', 'sense.exe', 'sgrmbroker.exe', 'wmiprvse.exe', 'vssvc.exe', 'dfsr.exe', 'dfsrs.exe', 'taskhostw.exe', 'sihost.exe', 'spoolsv.exe')
    $lsassHits = @{}
    foreach ($r in (Import-CaseCsv 'sysmon_process_access')) {
        $tgt = "$($r.TargetImage)"
        if ($tgt -notmatch '(?i)\\lsass\.exe$') { continue }
        $src = "$($r.SourceImage)"
        $leaf = ''
        try { $leaf = (Split-Path $src -Leaf).ToLower() } catch { }
        if (-not $leaf -or $lsassOk -contains $leaf) { continue }
        if (-not $lsassHits.ContainsKey($src)) { $lsassHits[$src] = New-Object System.Collections.Generic.List[string] }
        $null = $lsassHits[$src].Add("granted=$($r.GrantedAccess) @ $($r.Time)")
    }
    foreach ($kv in ($lsassHits.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 10)) {
        & $find 'LSASS access - non-system process opened lsass.exe' 'high' $kv.Key "$($kv.Value.Count) handle event(s): $($kv.Value[0])" 'T1003.001'
    }

    # ---------- R9: Office app spawned interpreter (4688 parent-child chain) ----------
    $officeApps = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'mspub.exe', 'onenote.exe', 'onenotem.exe')
    $interpreters = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msbuild.exe', 'installutil.exe', 'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'msxsl.exe')
    $r9Seen = @{}
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $par = ''; $kid = ''
        try { $par = (Split-Path "$($r.ParentProcess)" -Leaf).ToLower() } catch { }
        try { $kid = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        if (-not $par -or -not $kid -or $officeApps -notcontains $par -or $interpreters -notcontains $kid) { continue }
        $k = "$par>$kid"
        if ($r9Seen.ContainsKey($k)) { $r9Seen[$k]++ ; continue }
        $r9Seen[$k] = 1
        $cmd = "$($r.CommandLine)"; if ($cmd.Length -gt 200) { $cmd = $cmd.Substring(0, 200) + '...' }
        & $find 'Office app spawned interpreter' 'high' "$par -> $kid" "$($r.Time): $cmd" 'T1566.001/T1059'
    }

    # ---------- R10: proxy-execution LOLBin command lines (4688 CommandLine; needs cmdline audit) ----------
    $r10Seen = @{}
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $cmd = "$($r.CommandLine)".Trim()
        if ($cmd.Length -lt 8) { continue }
        $low = $cmd.ToLower()
        $hit = ''
        $sev = 'high'
        if ($low -match '(-enc\b|-encodedcommand\b|frombase64string)') { $hit = 'encoded command' }
        elseif ($low -match 'certutil\.exe.+\s(-urlcache|-decode|-decodehex)') { $hit = 'certutil download/decode' }
        elseif ($low -match 'mshta\.exe.*(https?://|vbscript:|javascript:)') { $hit = 'mshta remote/script URL' }
        elseif ($low -match 'rundll32\.exe.*(javascript:|comsvcs\.dll,?\s*minidump)') { $hit = 'rundll32 script/minidump' }
        elseif ($low -match 'regsvr32(\.exe)?\s+/i:/?(https?|file):') { $hit = 'regsvr32 remote scriplet' }
        elseif ($low -match 'bitsadmin(\.exe)?\s+(/transfer|/create)') { $hit = 'bitsadmin download'; $sev = 'medium' }
        elseif ($low -match 'msiexec(\.exe)?.*https?://') { $hit = 'msiexec remote package'; $sev = 'medium' }
        elseif ($low -match 'wmic(\.exe)?.*\sprocess\s+call\s+create') { $hit = 'wmic process create'; $sev = 'medium' }
        if (-not $hit) { continue }
        $key = "$hit|$low"
        if ($r10Seen.ContainsKey($key)) { continue }
        $r10Seen[$key] = $true
        if ($r10Seen.Count -gt 20) { break }
        & $find "LOLBin proxy-execution - $hit" $sev "$($r.NewProcess)" "$($r.Time): $(if ($cmd.Length -gt 220) { $cmd.Substring(0, 220) + '...' } else { $cmd })" 'T1218'
    }

    # ---------- R11: UAC bypass pattern - ms-settings shell\open\command writes (Sysmon EID 13) ----------
    $r11Seen = @{}
    foreach ($r in (Import-CaseCsv 'sysmon_registry')) {
        $to = "$($r.TargetObject)"
        if ($to -notmatch '(?i)\\ms-settings\\shell\\open\\command') { continue }
        $k = $to -replace '^HKEY_USERS\\[^\\]+', 'HKCU'
        if ($r11Seen.ContainsKey($k)) { continue }
        $r11Seen[$k] = $true
        & $find 'UAC bypass pattern - ms-settings command hijack' 'medium' $to "registry write by $($r.Image) (fodhelper/eventvwr technique)" 'T1548.002'
    }

    # ---------- R12: executable written via admin share (5145 WriteData/Append on ADMIN$/x$) ----------
    $r12Seen = @{}
    foreach ($r in (Import-CaseCsv 'security_share_access')) {
        if ("$($r.EventId)" -ne '5145') { continue }
        $share = ("$($r.ShareName)" -replace '^[\*\\\s]+', '')
        if ($share -notmatch '(?i)^admin\$' -and $share -notmatch '(?i)^[a-z]\$$') { continue }
        $tn = "$($r.RelativeTargetName)"
        if ($tn -notmatch '(?i)\.(exe|dll|ps1|bat|cmd|hta|js|vbs|vbe|jse|scr|psm1|jar|msi)$') { continue }
        if ("$($r.AccessList)" -notmatch '%%4415|%%4416') { continue }
        $k = "$($r.Account)|$share|$tn"
        if ($r12Seen.ContainsKey($k)) { continue }
        $r12Seen[$k] = $true
        & $find 'Admin-share executable staging' 'high' "$($r.SourceIp)" "'$tn' written on \\$share by $($r.Account) at $($r.Time)" 'T1021.002'
    }

    # ---------- R13: discovery command storm (4688 recon-tool burst per account) ----------
    $discBins = @('whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'systeminfo.exe', 'ipconfig.exe', 'quser.exe', 'qwinsta.exe', 'tasklist.exe', 'netstat.exe', 'nslookup.exe', 'arp.exe', 'route.exe', 'klist.exe', 'wmic.exe', 'dsquery.exe', 'adfind.exe', 'csvde.exe', 'ldifde.exe', 'tree.exe')
    $discByAcct = @{}
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $leaf = ''
        try { $leaf = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        if ($discBins -notcontains $leaf) { continue }
        $a = "$($r.Account)"; if (-not $a) { $a = '(unknown)' }
        if (-not $discByAcct.ContainsKey($a)) { $discByAcct[$a] = New-Object System.Collections.Generic.List[string] }
        $null = $discByAcct[$a].Add($leaf)
    }
    foreach ($kv in ($discByAcct.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 5)) {
        $distinct = @($kv.Value | Sort-Object -Unique).Count
        if ($kv.Value.Count -lt 15 -and $distinct -lt 6) { continue }
        $tools = ($kv.Value | Sort-Object -Unique | Select-Object -First 8) -join ', '
        & $find 'Discovery command storm' 'medium' $kv.Key "$($kv.Value.Count) recon commands ($distinct distinct): $tools" 'T1087/T1082'
    }

    # ---------- R14: Defender tamper - real-time protection off / exclusion change (5001/5007) ----------
    $dcfg = @(Import-CaseCsv 'defender_config_events')
    $rtOff = @($dcfg | Where-Object { "$($_.EventId)" -eq '5001' })
    if ($rtOff.Count -gt 0) {
        & $find 'Defender real-time protection DISABLED' 'high' $Computer "$($rtOff.Count) disable event(s), last at $($rtOff[-1].Time) - tamper or manual change" 'T1562.001'
    }
    foreach ($e in (@($dcfg | Where-Object { "$($_.EventId)" -eq '5007' -and "$($_.Detail)" -match '(?i)exclusion' }) | Select-Object -First 3)) {
        & $find 'Defender exclusion configuration changed' 'high' $Computer "$($e.Time): $($e.Detail)" 'T1562.001'
    }

    # ---------- R15: timestomping - creation time changed (Sysmon EID 2) ----------
    foreach ($r in ((Import-CaseCsv 'sysmon_file_time') | Select-Object -First 10)) {
        & $find 'File creation time changed (timestomping candidate)' 'medium' "$($r.TargetFilename)" "by $($r.Image): $($r.PreviousCreationUtcTime) -> $($r.CreationUtcTime)" 'T1070.006'
    }

    # ---------- R16: DCSync - replication Get-Changes by a user account (4662) ----------
    $dcSeen = @{}
    foreach ($r in (@(Import-CaseCsv 'security_ds_access') | Where-Object { "$($_.Properties)" -match '(?i)e3514235-4b06-11d1-ab04-00c04fc2dcd2|1131f6a[ad]-' -and "$($_.Account)" -notmatch '\$$' })) {
        $a = "$($r.Account)"
        if (-not $a -or $dcSeen.ContainsKey($a)) { continue }
        $dcSeen[$a] = $true
        if ($dcSeen.Count -gt 10) { break }
        & $find 'DCSync - replication access by user account' 'high' $a "4662 Get-Changes on $($r.Object) at $($r.Time)" 'T1003.006'
    }

    # ---------- R17: Kerberoasting pattern - RC4 TGS burst per source (4769) ----------
    $ker = @(Import-CaseCsv 'security_kerberos')
    $tgs = @($ker | Where-Object { "$($_.EventId)" -eq '4769' -and "$($_.TicketEnc)" -eq '0x17' })
    foreach ($g in ($tgs | Group-Object IpAddress)) {
        $svc = @(@($g.Group | ForEach-Object { "$($_.Service)" }) | Sort-Object -Unique)
        if ($svc.Count -ge 10) {
            & $find 'Kerberoasting pattern - RC4 TGS burst' 'medium' "$($g.Name)" "$($g.Count) TGS requests for $($svc.Count) distinct SPNs over RC4" 'T1558.003'
        }
    }

    # ---------- R18: AS-REP roast pattern - TGT without pre-auth (4768 PreAuthType 0) ----------
    $asrepSeen = @{}
    foreach ($r in (@($ker | Where-Object { "$($_.EventId)" -eq '4768' -and "$($_.PreAuth)" -eq '0' }) | Select-Object -First 5)) {
        $a = "$($r.Account)"
        if ($asrepSeen.ContainsKey($a)) { continue }
        $asrepSeen[$a] = $true
        & $find 'AS-REP roast pattern - TGT requested without pre-auth' 'medium' $a "from $($r.IpAddress) at $($r.Time)" 'T1558.004'
    }

    # ---------- R19: password spray - many distinct accounts failing from one source (4771/4625) ----------
    $sprayFails = @()
    $sprayFails += (@($ker | Where-Object { "$($_.EventId)" -eq '4771' }) | ForEach-Object { [pscustomobject]@{ Account = "$($_.Account)"; Ip = "$($_.IpAddress)" } })
    $sprayFails += (@(Import-CaseCsv 'security_auth_events') | Where-Object { "$($_.EventId)" -eq '4625' } | ForEach-Object { [pscustomobject]@{ Account = "$($_.Account)"; Ip = "$($_.SourceIp)" } })
    foreach ($g in ($sprayFails | Where-Object { $_.Ip -and $_.Ip -ne '-' -and $_.Ip -ne '::1' -and $_.Account } | Group-Object Ip)) {
        $accts = @(@($g.Group | ForEach-Object { $_.Account }) | Sort-Object -Unique)
        if ($accts.Count -ge 10) {
            & $find 'Password spray - many accounts from one source' 'high' "$($g.Name)" "$($g.Count) failures across $($accts.Count) accounts: $(($accts | Select-Object -First 5) -join ', ')" 'T1110.003'
        }
    }

    # ---------- R20: web server spawned interpreter (4688: w3wp/tomcat/httpd parent) ----------
    $webParents = @('w3wp.exe', 'tomcat8.exe', 'tomcat9.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe')
    $webKids = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'csc.exe', 'vbc.exe', 'msbuild.exe', 'curl.exe', 'net.exe')
    $r20Seen = @{}
    foreach ($r in (Import-CaseCsv 'security_proc_events')) {
        $par = ''; $kid = ''
        try { $par = (Split-Path "$($r.ParentProcess)" -Leaf).ToLower() } catch { }
        try { $kid = (Split-Path "$($r.NewProcess)" -Leaf).ToLower() } catch { }
        if (-not $par -or -not $kid -or $webParents -notcontains $par -or $webKids -notcontains $kid) { continue }
        $k = "$par>$kid"
        if ($r20Seen.ContainsKey($k)) { $r20Seen[$k]++ ; continue }
        $r20Seen[$k] = 1
        $cmd = "$($r.CommandLine)"; if ($cmd.Length -gt 200) { $cmd = $cmd.Substring(0, 200) + '...' }
        & $find 'Web server spawned interpreter' 'high' "$par -> $kid" "$($r.Time): $cmd" 'T1505.003'
    }

    # ---------- R21: web traffic anomalies (report-only leads from the IIS parse) ----------
    foreach ($r in ((@(Import-CaseCsv 'iis_anomalies') | Where-Object { @('suspicious-uri', 'post-to-upload-path', 'headless-posts') -contains $_.Kind }) | Select-Object -First 5)) {
        & $find 'Web traffic anomaly' 'medium' "$($r.Kind)" "$($r.Detail) - $($r.Sample)" 'T1190'
    }

    # ---------- R22: timestamp forgery indicators (MFT birth attributes x execution evidence) ----------
    # Scans every executable in mft_recent (checks are O(1) per row):
    #   future-birth    - $MFT $Si birth after collection time (+1d margin)
    #   ran-before-born - amcache evidence predates the claimed birth by >24h
    #   0x10-vs-0x30    - $Si and FILE_NAME birth attributes disagree by >90 days
    # Sysmon EID 2 events for the same file are cited as corroboration. Medium, report-only.
    $mftByLeaf = @{}
    foreach ($r in (Import-CaseCsv 'mft_recent')) {
        $lf = ''
        try { $lf = (Split-Path "$($r.Path)" -Leaf).ToLower() } catch { }
        if ($lf -and -not $mftByLeaf.ContainsKey($lf)) { $mftByLeaf[$lf] = $r }
    }
    $amcByLeaf = @{}
    foreach ($r in (Import-CaseCsv 'amcache')) {
        $lf = ''
        foreach ($pn in @('Name', 'ApplicationName', 'SourceSimpleName')) {
            $p2 = $r.PSObject.Properties[$pn]
            if ($p2 -and "$($p2.Value)") { $lf = "$($p2.Value)".ToLower(); break }
        }
        if (-not $lf) { continue }
        $t = $null
        foreach ($pn in (@($r.PSObject.Properties.Name) | Where-Object { $_ -match '(?i)timestamp|time$' })) {
            try { $t2 = [datetime]"$($r.$pn)"; if ($t2 -and (-not $t -or $t2 -lt $t)) { $t = $t2 } } catch { }
        }
        if (-not $amcByLeaf.ContainsKey($lf) -or ($t -and $amcByLeaf[$lf].T -and $t -lt $amcByLeaf[$lf].T)) { $amcByLeaf[$lf] = @{ T = $t; Src = 'amcache' } }
    }
    $eid2ByLeaf = @{}
    foreach ($r in (Import-CaseCsv 'sysmon_file_time')) {
        $lf = ''
        try { $lf = (Split-Path "$($r.TargetFilename)" -Leaf).ToLower() } catch { }
        if ($lf) { $eid2ByLeaf[$lf] = $true }
    }
    $now = (Get-Date).ToUniversalTime()
    $tfSeen = @{}
    foreach ($m in (@($mftByLeaf.Values) | Select-Object -First 200)) {
        $lf = ''
        try { $lf = (Split-Path "$($m.Path)" -Leaf).ToLower() } catch { }
        if (-not $lf -or $tfSeen.ContainsKey($lf)) { continue }
        $birth = $null; try { $birth = [datetime]"$($m.Created)" } catch { }
        if (-not $birth) { continue }
        $checks = New-Object System.Collections.Generic.List[string]
        if (($birth - $now).TotalDays -gt 1) {
            $null = $checks.Add("birth '$($m.Created)' is in the future (backdated or clock-skewed)")
        }
        if ("$($m.CreatedFN)") {
            $bfn = $null; try { $bfn = [datetime]"$($m.CreatedFN)" } catch { }
            if ($bfn -and ([math]::Abs(($birth - $bfn).TotalDays) -gt 90)) {
                $null = $checks.Add("birth attributes disagree: `$Si $($m.Created) vs FILE_NAME $($m.CreatedFN) ($([math]::Abs([math]::Round(($birth - $bfn).TotalDays))) day skew - classic backdated `$Si)")
            }
        }
        $am = $amcByLeaf[$lf]
        if ($am -and $am.T -and (($birth - $am.T).TotalDays -gt 1)) {
            $null = $checks.Add("execution evidence ($($am.Src)) at $($am.T.ToString('s')) predates claimed birth $($m.Created) (ran before it existed)")
        }
        if ($checks.Count -eq 0) { continue }
        $tfSeen[$lf] = $true
        if ($tfSeen.Count -gt 40) { break }
        if ($eid2ByLeaf.ContainsKey($lf)) { $null = $checks.Add('Sysmon EID 2 file-creation-time changes observed for this file') }
        & $find 'Timestamp forgery indicators' 'medium' "$($m.Path)" (($checks | Select-Object -First 4) -join ' | ') 'T1070.006'
    }

    # ---------- R23-R26: tunnel & remote-access pack (csv\remote_access.csv + collected sources) ----------
    # R23 tunnel binary active - high when running/installed/service-installed, medium when only on disk
    # R24 RA-tool service - medium (dual-use: legitimate remote support is common)
    # R25 RDP ServiceDll tamper - high (RDPWrap-class)
    # R26 non-empty authorized_keys - high (planted SSH trust anchor)
    # NOTE: keep $tunPat/$raPat in sync with module 8.16
    $tunPat = '(?i)(^|[^a-z0-9])(ngrok|cloudflared|tailscaled?|chisel|ligolo|frpc|frps|gost|revsocks)([^a-z0-9]|$)'
    $raPat = '(?i)(^|[^a-z0-9])(anydesk|screenconnect|connectwisecontrol|teamviewer|rustdesk)([^a-z0-9]|$)'
    $raActive = @{}
    foreach ($r in (Import-CaseCsv 'processes')) {
        $leaf = ''
        try { $leaf = (Split-Path "$($r.Path)" -Leaf) } catch { continue }
        if (-not $leaf -or "$leaf" -notmatch $tunPat) { continue }
        $key = "$leaf".ToLower()
        if ($raActive.ContainsKey($key)) { continue }
        $raActive[$key] = $true
        & $find 'Remote-access tunnel binary active' 'high' "$($r.Path)" "tunnel tool running as process '$leaf' (pid $($r.PID))" 'T1572'
        if ($raActive.Count -gt 10) { break }
    }
    foreach ($r in (Import-CaseCsv 'services')) {
        $blob = "$($r.Name) $($r.DisplayName) $($r.PathName)"
        if ("$blob" -notmatch $tunPat) { continue }
        $key = "$($r.Name)".ToLower()
        if ($raActive.ContainsKey($key)) { continue }
        $raActive[$key] = $true
        & $find 'Remote-access tunnel binary active' 'high' "$($r.PathName)" "tunnel tool installed as service '$($r.Name)' (state $($r.State))" 'T1572'
        if ($raActive.Count -gt 10) { break }
    }
    foreach ($r in (Import-CaseCsv 'system_new_services')) {
        $blob = "$($r.Service) $($r.Binary)"
        if ("$blob" -notmatch $tunPat) { continue }
        $key = "$($r.Service)".ToLower()
        if ($raActive.ContainsKey($key)) { continue }
        $raActive[$key] = $true
        & $find 'Remote-access tunnel binary active' 'high' "$($r.Binary)" "tunnel tool service '$($r.Service)' installed at $($r.Time) (7045)" 'T1543.003'
        if ($raActive.Count -gt 10) { break }
    }
    foreach ($src in @('mft_recent', 'amcache')) {
        foreach ($r in (Import-CaseCsv $src)) {
            $lf = ''
            foreach ($pn in @('Path', 'Name', 'ApplicationName')) {
                $p2 = $r.PSObject.Properties[$pn]
                if ($p2 -and "$($p2.Value)") { try { $lf = (Split-Path "$($p2.Value)" -Leaf) } catch { $lf = "$($p2.Value)" }; break }
            }
            if (-not $lf -or "$lf" -notmatch $tunPat) { continue }
            $key = "$lf".ToLower()
            if ($raActive.ContainsKey($key)) { continue }
            $raActive[$key] = $true
            & $find 'Remote-access tunnel tool on disk' 'medium' "$lf" "tunnel tool name present in $src (file evidence only - not seen running/installed)" 'T1572'
            if ($raActive.Count -gt 20) { break }
        }
    }
    $raSvcSeen = @{}
    foreach ($r in (Import-CaseCsv 'services')) {
        $blob = "$($r.Name) $($r.DisplayName) $($r.PathName)"
        if ("$blob" -notmatch $raPat) { continue }
        $key = "$($r.Name)".ToLower()
        if ($raSvcSeen.ContainsKey($key)) { continue }
        $raSvcSeen[$key] = $true
        & $find 'Remote-access tool present' 'medium' "$($r.PathName)" "remote-access tool installed as service '$($r.Name)' (state $($r.State)) - dual-use, verify support expectation" 'T1219'
        if ($raSvcSeen.Count -gt 10) { break }
    }
    foreach ($r in (Import-CaseCsv 'remote_access')) {
        if ("$($r.Type)" -eq 'RA tool service' -or "$($r.Type)" -eq 'RA tool data dir') {
            $key = "$($r.Name)".ToLower()
            if (-not $raSvcSeen.ContainsKey($key)) {
                $raSvcSeen[$key] = $true
                & $find 'Remote-access tool present' 'medium' "$($r.Path)" "remote-access tool $($r.Type.ToLower()) '$($r.Name)' ($($r.State)) - dual-use, verify support expectation" 'T1219'
            }
        }
        if ("$($r.Type)" -eq 'RDP ServiceDll tamper') {
            & $find 'RDP ServiceDll tamper' 'high' "$($r.Path)" "TermService ServiceDll replaced: $($r.Path) - $($r.Detail)" 'T1112'
        }
        if ("$($r.Type)" -eq 'SSH authorized_keys' -and "$($r.State)" -match 'populated') {
            & $find 'SSH authorized_keys present' 'high' "$($r.Path)" "$($r.Name) is $($r.State) - planted SSH trust anchor ($($r.Detail))" 'T1098.004'
        }
    }

    # ---------- R27: svchost masquerade (module 1.7 audit xref) ----------
    $svchN = 0
    foreach ($r in (Import-CaseCsv 'svchost_audit')) {
        $sev = if ("$($r.Type)" -match 'UnregisteredGroup|OutOfPathServiceDll') { 'high' } else { 'medium' }
        $ent = if ("$($r.Path)") { "$($r.Path)" } elseif ("$($r.Service)") { "svchost -k $($r.Group) / $($r.Service)" } else { "svchost -k $($r.Group)" }
        & $find 'Svchost masquerade indicator' $sev $ent "$($r.Type): $($r.Detail)" 'T1036.005'
        $svchN++
        if ($svchN -ge 20) { break }
    }

    Save-Rows -Name 'hunt_findings' -Rows $out.ToArray()
    $hi = @($out | Where-Object { $_.Severity -eq 'high' }).Count
    if ($out.Count -gt 0) {
        Write-CaseLog "    hunt findings: $($out.Count) ($hi high) -> csv\hunt_findings.csv" $(if ($hi -gt 0) { 'Red' } else { 'Yellow' })
        foreach ($f in ($out | Where-Object { $_.Severity -eq 'high' } | Select-Object -First 4)) { Write-CaseLog "      [$($f.Severity)] $($f.Rule) - $($f.Entity)" 'Red' }
    } else {
        Write-CaseLog '    hunt findings: none - all techniques clean' 'Gray'
    }
}

function New-LoggingGaps {
    $rows = @()
    $meanings = @{ 6005 = 'Event logging STARTED'; 6006 = 'Event logging STOPPED (shutdown)'; 104 = 'Event log CLEARED'; 1102 = 'Security audit log CLEARED' }
    foreach ($name in @('system_events', 'security_events')) {
        foreach ($r in (Import-CaseCsv $name)) {
            if (@(6005, 6006, 104, 1102) -contains $r.Id) {
                $rows += [pscustomobject]@{ Time = $r.TimeCreated; EventId = $r.Id; Meaning = $meanings[[int]$r.Id]; Source = $name; Message = $r.Message }
            }
        }
    }
    $gapsFile = Join-Path $RawDir 'analysis\evtx_gaps.txt'
    if ((Test-Path $gapsFile) -and (Get-Item $gapsFile).Length -gt 0) {
        $rows += [pscustomobject]@{ Time = ''; EventId = ''; Meaning = 'chronological gaps detected in evtx (see raw\analysis\evtx_gaps.txt)'; Source = 'chainsaw'; Message = '' }
    }
    Save-Rows -Name 'logging_gaps' -Rows $rows
    $bad = @($rows | Where-Object { @(104, 1102) -contains $_.EventId })
    if ($bad.Count -gt 0) { Write-CaseLog "    LOGGING GAPS: $($bad.Count) clear/down events - check csv\logging_gaps.csv" 'Red' }
}

function New-SiemExport {
    $lines = New-Object System.Collections.Generic.List[string]
    $base = @{ host = $Computer; tool = "Ophira v$ScriptVersion"; caseid = $script:CurrentCaseID }
    foreach ($p in (Import-CaseCsv 'flash_process_scored')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'proc_verdict'; $o['host'] = $base.host; $o['name'] = $p.Name; $o['verdict'] = $p.Verdict; $o['score'] = [int]$p.Score; $o['path'] = $p.Path; $o['evidence'] = $p.Evidence; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($h in ((Import-CaseCsv 'flash_ioc_hits') + (Import-CaseCsv 'ioc_hits_amcache'))) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'ioc_hit'; $o['host'] = $base.host; $o['type'] = $h.Type; $o['indicator'] = $h.Indicator; $o['where'] = $h.Where; $o['application'] = $h.Application; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'security_bruteforce_candidates')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'bruteforce'; $o['host'] = $base.host; $o['src_ip'] = $b.SourceIp; $o['failures'] = [int]$b.FailedLogons; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
        if ("$($r.Level)" -match 'crit|^high$') {
            $rule = if ($r.PSObject.Properties['RuleTitle']) { $r.RuleTitle } else { $r.Alert }
            $o = [ordered]@{}; $o['ts'] = "$($r.Timestamp)"; $o['kind'] = 'sigma_alert'; $o['host'] = $base.host; $o['level'] = $r.Level; $o['rule'] = $rule; $o['eventid'] = $r.EventID; $o['details'] = $r.Details; $o['caseid'] = $base.caseid
            $lines.Add(($o | ConvertTo-Json -Compress))
        }
    }
    foreach ($d in (Import-CaseCsv 'delta_new')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'delta_new'; $o['host'] = $base.host; $o['type'] = $d.Type; $o['item'] = $d.Item; $o['detail'] = $d.Detail; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'beacon_candidates')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'beacon'; $o['host'] = $base.host; $o['severity'] = $b.Severity; $o['process'] = $b.Process; $o['dest_ip'] = $b.RemoteIp; $o['dest_port'] = $b.Port; $o['interval_sec'] = $b.MedianIntervalSec; $o['regularity'] = $b.Regularity; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'dns_beacon_candidates')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'dns_beacon'; $o['host'] = $base.host; $o['severity'] = $b.Severity; $o['process'] = $b.Process; $o['domain'] = $b.Domain; $o['resolved_ip'] = $b.ResolvedIp; $o['interval_sec'] = $b.MedianIntervalSec; $o['regularity'] = $b.Regularity; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($l in (Import-CaseCsv 'loldrivers_hits')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'loldriver'; $o['host'] = $base.host; $o['status'] = $l.Status; $o['driver'] = $l.Name; $o['path'] = $l.Path; $o['sha256'] = $l.SHA256; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($u in (Import-CaseCsv 'usn_write_bursts')) {
        $o = [ordered]@{}; $o['ts'] = "$($u.WindowStart)"; $o['kind'] = 'mass_modification'; $o['host'] = $base.host; $o['write_events'] = [int]"$($u.WriteEvents)"; $o['distinct_files'] = [int]"$($u.DistinctFiles)"; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($m in (Import-CaseCsv 'memory_malfind')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'malfind'; $o['host'] = $base.host; $o['process'] = $m.Process; $o['pid'] = $m.PID; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($b in (Import-CaseCsv 'ioc_hits_browser')) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'browser_ioc'; $o['host'] = $base.host; $o['indicator'] = $b.Indicator; $o['url'] = $b.URL; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    foreach ($h in (Import-CaseCsv 'hunt_findings')) {
        if (@('high', 'medium') -notcontains "$($h.Severity)") { continue }
        $o = [ordered]@{}; $o['ts'] = "$($h.Found)"; $o['kind'] = 'hunt_finding'; $o['host'] = $base.host; $o['severity'] = $h.Severity; $o['rule'] = $h.Rule; $o['entity'] = $h.Entity; $o['attack'] = $h.Attck; $o['evidence'] = $h.Evidence; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    if ($script:Verdict) {
        $o = [ordered]@{}; $o['ts'] = "$($StartTime.ToString('o'))"; $o['kind'] = 'verdict'; $o['host'] = $base.host; $o['level'] = $script:Verdict.Level; $o['rank'] = $script:Verdict.LevelRank; $o['confidence'] = $script:Verdict.ConfidencePercent; $o['signals'] = @($script:Verdict.Signals).Count; $o['caseid'] = $base.caseid
        $lines.Add(($o | ConvertTo-Json -Compress))
    }
    if ($lines.Count -eq 0) { return }
    $out = Join-Path $CaseDir 'siem_export.ndjson'
    $lines | Set-Content -LiteralPath $out -Encoding UTF8
    Write-CaseLog "    siem export: $($lines.Count) records -> siem_export.ndjson" 'DarkGray'
}

function New-AttackLayer {
    # MITRE ATT&CK Navigator layer (https://navigator.mitre.org) from hayabusa MitreTags
    $tech = @{}
    foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
        foreach ($m in [regex]::Matches("$($r.MitreTags)", 'T\d{4}(?:\.\d{3})?')) {
            $k = $m.Value
            if (-not $tech.ContainsKey($k)) { $tech[$k] = 0 }
            $tech[$k]++
        }
    }
    if ($tech.Count -eq 0) { return }
    $techniques = @($tech.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ techniqueID = $_; score = $tech[$_]; comment = "$($tech[$_]) Sigma detection(s)" } })
    $layer = [pscustomobject]@{
        name        = "Ophira - $Computer$(if ($script:CurrentCaseID) { " ($($script:CurrentCaseID))" })"
        domain      = 'enterprise-attack'
        description = "Ophira v$ScriptVersion Sigma detections (hayabusa MitreTags)"
        versions    = @{ navigator = '4.9'; layer = '4.5' }
        techniques  = $techniques
        layout      = @{ layout = 'side'; aggregateFunction = 'sum' }
    }
    $layer | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'attack_layer.json') -Encoding UTF8
    Write-CaseLog "    ATT&CK Navigator layer: $($tech.Count) techniques -> attack_layer.json" 'DarkGray'
}

function Invoke-DeltaCompare {
    param([string]$Path)
    $baseline = $null
    if ($Path) {
        if (Test-Path -LiteralPath $Path) { $baseline = Get-Item -LiteralPath $Path }
        else { Write-CaseLog "    delta: -DeltaPath not found ($Path)" 'DarkYellow'; return }
    } else {
        $root = Get-KitRoot
        $cands = @(Get-ChildItem -Path $root -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $StartTime.AddSeconds(-5) } | Sort-Object LastWriteTime -Descending)
        if ($cands.Count -eq 0) {
            $cands = @(Get-ChildItem -Path $root -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $CaseName -and (Test-Path (Join-Path $_.FullName 'case.json')) } | Sort-Object LastWriteTime -Descending)
        }
        if ($cands.Count -gt 0) { $baseline = $cands[0] }
    }
    if (-not $baseline) { Write-CaseLog "    delta: no previous collection found - this run becomes the baseline for next time" 'DarkGray'; return }
    $prevDir = $baseline.FullName
    $tmp = $null
    if ($baseline -is [System.IO.FileInfo]) {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("delta_" + $baseline.BaseName)
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($baseline.FullName, $tmp)
            $prevDir = $tmp
        } catch { Write-CaseLog "    delta: cannot extract baseline" 'DarkYellow'; return }
    }
    $prevCsv = {
        param($n)
        $f = Join-Path $prevDir "csv\$n"
        if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) { try { return @(Import-Csv $f) } catch { return @() } }
        return @()
    }
    $prevCutoff = $null
    $prevCaseJson = Join-Path $prevDir 'case.json'
    if (Test-Path $prevCaseJson) { try { $pc = Get-Content $prevCaseJson -Raw | ConvertFrom-Json; $prevCutoff = [datetime]$pc.StartedUTC } catch { } }
    $new = @()
    $prevProcPaths = @{}
    foreach ($r in (& $prevCsv 'processes.csv')) { if ($r.Path) { $prevProcPaths["$($r.Path)".ToLower()] = $true } }
    foreach ($r in (Import-CaseCsv 'processes_flagged')) {
        if ($r.Path -and -not $prevProcPaths.ContainsKey("$($r.Path)".ToLower())) {
            $new += [pscustomobject]@{ Type = 'NewFlaggedProcess'; Item = $r.Name; Detail = "$($r.Path) [$($r.Flags)]" }
        }
    }
    $prevTasks = @{}
    foreach ($r in (& $prevCsv 'scheduled_tasks.csv')) { $prevTasks["$($r.Path)$($r.Name)"] = $true }
    foreach ($r in (Import-CaseCsv 'scheduled_tasks_flagged')) {
        if (-not $prevTasks.ContainsKey("$($r.Path)$($r.Name)")) { $new += [pscustomobject]@{ Type = 'NewFlaggedTask'; Item = $r.Name; Detail = "$($r.Actions)" } }
    }
    $prevSvc = @{}
    foreach ($r in (& $prevCsv 'services.csv')) { $prevSvc["$($r.Name)"] = $true }
    foreach ($r in (Import-CaseCsv 'services_flagged')) {
        if (-not $prevSvc.ContainsKey("$($r.Name)")) { $new += [pscustomobject]@{ Type = 'NewFlaggedService'; Item = $r.Name; Detail = "$($r.PathName)" } }
    }
    $prevAuto = @{}
    foreach ($r in (& $prevCsv 'autoruns_runkeys.csv')) { $prevAuto["$($r.Name)=$($r.Value)"] = $true }
    foreach ($r in (Import-CaseCsv 'autoruns_runkeys')) {
        if (-not $prevAuto.ContainsKey("$($r.Name)=$($r.Value)")) { $new += [pscustomobject]@{ Type = 'NewAutorun'; Item = $r.Name; Detail = "$($r.Value)" } }
    }
    if ($prevCutoff) {
        foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
            if ("$($r.Level)" -match 'crit|^high$') {
                $ts = $null
                try { $ts = [datetime]::Parse("$($r.Timestamp)", [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
                if ($ts -and $ts -gt $prevCutoff) {
                    $rule = if ($r.PSObject.Properties['RuleTitle']) { $r.RuleTitle } else { $r.Alert }
                    $new += [pscustomobject]@{ Type = 'NewSigmaAlert'; Item = "$rule"; Detail = "$($r.Timestamp) [$($r.Level)]" }
                }
            }
        }
    }
    Save-Rows -Name 'delta_new' -Rows $new
    $script:DeltaCount = $new.Count
    $script:DeltaBaseline = $baseline.Name
    Write-CaseLog "    delta: $($new.Count) NEW findings vs $($baseline.Name)" $(if ($new.Count -gt 0) { 'Yellow' } else { 'Gray' })
    if ($tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-CompromiseVerdict {
    # Correlates all case findings into one verdict + coverage-weighted confidence.
    # Levels (rank): 4=COMPROMISED 3=LIKELY COMPROMISED 2=SUSPICIOUS 1=NO EVIDENCE OF COMPROMISE 0=INCONCLUSIVE
    $iocLive = Import-CaseCsv 'flash_ioc_hits'
    $iocAmc = Import-CaseCsv 'ioc_hits_amcache'
    $yara = Import-CaseCsv 'yara_hits'
    $hay = Import-CaseCsv 'hayabusa_timeline'
    $proc = Import-CaseCsv 'flash_process_scored'
    $def = Import-CaseCsv 'defender_threats'
    $gaps = Import-CaseCsv 'logging_gaps'
    $brute = Import-CaseCsv 'security_bruteforce_candidates'
    $beacons = Import-CaseCsv 'beacon_candidates'
    $dnsBeacons = Import-CaseCsv 'dns_beacon_candidates'
    $lol = Import-CaseCsv 'loldrivers_hits'
    $usnBursts = Import-CaseCsv 'usn_write_bursts'
    $asep = Import-CaseCsv 'asep_sweep'
    $memMf = Import-CaseCsv 'memory_malfind'
    $browserIoc = Import-CaseCsv 'ioc_hits_browser'

    $levelNames = @{ 4 = 'COMPROMISED'; 3 = 'LIKELY COMPROMISED'; 2 = 'SUSPICIOUS'; 1 = 'NO EVIDENCE OF COMPROMISE'; 0 = 'INCONCLUSIVE' }

    $signals = New-Object System.Collections.Generic.List[object]
    function Add-Signal([string]$name, [int]$floor, [int]$count, [string]$detail) {
        if ($count -gt 0) { $signals.Add([pscustomobject]@{ Signal = $name; Weight = $floor; Count = $count; Detail = $detail }) }
    }

    $hayCrit = @($hay | Where-Object { "$($_.Level)" -match 'crit' }).Count
    $hayHigh = @($hay | Where-Object { "$($_.Level)" -match '^high$' }).Count
    $hayHighRules = @($hay | Where-Object { "$($_.Level)" -match '^high$' } | Group-Object RuleTitle).Count
    $procHigh = @($proc | Where-Object { "$($_.Verdict)" -eq 'HIGH' }).Count
    $procMed = @($proc | Where-Object { "$($_.Verdict)" -eq 'MEDIUM' }).Count
    $yaraHi = @($yara | Where-Object { "$($_.Severity)" -match '^(?i)(high|critical)$' }).Count
    $yaraMed = @($yara | Where-Object { "$($_.Severity)" -match '^(?i)medium$' }).Count
    $gapTamper = @($gaps | Where-Object { "$($_.EventId)" -match '^(1102|104)$' -or "$($_.Meaning)" -match 'clear|stop' }).Count
    $beaconHi = @($beacons | Where-Object { "$($_.Severity)" -match '^(?i)high$' }).Count
    $beaconMed = @($beacons | Where-Object { "$($_.Severity)" -match '^(?i)medium$' }).Count
    $dnsHi = @($dnsBeacons | Where-Object { "$($_.Severity)" -match '^(?i)high$' }).Count
    $dnsMed = @($dnsBeacons | Where-Object { "$($_.Severity)" -match '^(?i)medium$' }).Count
    $lolMal = @($lol | Where-Object { $_.Status -eq 'malicious' }).Count
    $hunt = Import-CaseCsv 'hunt_findings'
    $huntHi = @($hunt | Where-Object { "$($_.Severity)" -eq 'high' -and "$($_.Rule)" -match 'Renamed LOLBin|side-load|Downloaded then executed|LSASS access|Office app spawned|proxy-execution|Admin-share staging|Defender (real-time|exclusion)|DCSync|Password spray|Web server spawned|Remote-access tunnel|ServiceDll tamper|authorized_keys|Svchost masquerade' })
    $usnBurstN = @($usnBursts).Count
    $rExt = ((@($usnBursts) | Where-Object { "$($_.RansomExt)" } | ForEach-Object { "$($_.RansomExt)" } | Sort-Object -Unique) -join ',')
    # ponytail: COM hijacks + StartupApproved excluded from the signal (per-user COM has many legit users, e.g. Teams/OneDrive); they stay report-visible
    $asepHotN = @($asep | Where-Object { $_.Flags -match 'user-path|nondefault' -and "$($_.Category)" -notmatch 'ComHijack|StartupApproved' }).Count

    Add-Signal 'IOC hit - historical execution (amcache SHA1)' 4 @($iocAmc).Count "near-certain true positive evidence"
    Add-Signal 'YARA hit - high/critical rule' 4 $yaraHi (($yara | Where-Object { "$($_.Severity)" -match '^(?i)(high|critical)$' } | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'C2 beaconing - highly regular callbacks' 3 $beaconHi (($beacons | Where-Object { "$($_.Severity)" -match '^(?i)high$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.RemoteIp):$($_.Port) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'C2 DNS beaconing - highly regular domain queries' 3 $dnsHi (($dnsBeacons | Where-Object { "$($_.Severity)" -match '^(?i)high$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.Domain) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'Known-malicious driver on disk (LOLDrivers)' 2 $lolMal (($lol | Where-Object { $_.Status -eq 'malicious' } | Select-Object -First 3 | ForEach-Object { "$($_.Name): $($_.Path)" }) -join '; ')
    Add-Signal 'Hunt technique - renamed binary / side-load / download-exec / LSASS access / Office chain / proxy-exec / share staging / Defender tamper / DCSync / spray / webshell / tunnel / RDP hijack / SSH keys / svchost masquerade' 2 $huntHi.Count (($huntHi | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'Ransomware-like mass file modification (USN journal)' 3 $usnBurstN ((($usnBursts | Select-Object -First 3 | ForEach-Object { "$($_.WindowStart): $($_.WriteEvents) writes / $($_.DistinctFiles) files" }) -join '; ') + $(if ($rExt) { " - RANSOM EXTENSIONS: $rExt" }))
    Add-Signal 'Uncommon persistence mechanism (IFEO/AppInit/Winlogon/netsh/LSA)' 2 $asepHotN (($asep | Where-Object { $_.Flags -match 'user-path|nondefault' -and "$($_.Category)" -notmatch 'ComHijack|StartupApproved' } | Select-Object -First 3 | ForEach-Object { "$($_.Category): $($_.Name) = $($_.Value)" }) -join '; ')
    Add-Signal 'Memory malfind indicators (injected code regions)' 2 @($memMf).Count (($memMf | Select-Object -First 3 | ForEach-Object { "$($_.Process)($($_.PID))" }) -join '; ')
    Add-Signal 'IOC domain observed in browser history' 2 @($browserIoc).Count (($browserIoc | Select-Object -First 3 | ForEach-Object { $_.Indicator }) -join '; ')
    $dnsIoc = @(Import-CaseCsv 'ioc_hits_dns')
    $netIoc = @(Import-CaseCsv 'ioc_hits_network')
    Add-Signal 'IOC hit - known-bad DNS query / historical connection' 2 ($dnsIoc.Count + $netIoc.Count) ((@($dnsIoc | Select-Object -First 3 | ForEach-Object { $_.Query }) + @($netIoc | Select-Object -First 2 | ForEach-Object { $_.RemoteIp })) -join '; ')
    $mftIoc = @(Import-CaseCsv 'ioc_hits_mft')
    Add-Signal 'IOC hit - known-bad filename on disk ($MFT)' 2 @($mftIoc).Count (($mftIoc | Select-Object -First 3 | ForEach-Object { $_.Path }) -join '; ')
    Add-Signal 'IOC hit - live system' 3 @($iocLive).Count (($iocLive | Select-Object -First 3 | ForEach-Object { $_.Indicator }) -join '; ')
    Add-Signal 'Sigma detection - critical' 3 $hayCrit (($hay | Where-Object { "$($_.Level)" -match 'crit' } | Select-Object -First 3 | ForEach-Object { $_.RuleTitle }) -join '; ')
    Add-Signal 'YARA hit - medium rule' 2 $yaraMed (($yara | Where-Object { "$($_.Severity)" -match '^(?i)medium$' } | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'C2 beaconing - periodic callbacks' 2 $beaconMed (($beacons | Where-Object { "$($_.Severity)" -match '^(?i)medium$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.RemoteIp) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'C2 DNS beaconing - periodic domain queries' 2 $dnsMed (($dnsBeacons | Where-Object { "$($_.Severity)" -match '^(?i)medium$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.Domain) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'Sigma detection - high' 2 $hayHigh "$hayHigh events from $hayHighRules distinct rules"
    Add-Signal 'Process anomaly verdict HIGH' 2 $procHigh (($proc | Where-Object { "$($_.Verdict)" -eq 'HIGH' } | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '; ')
    Add-Signal 'Defender detection history' 2 @($def).Count "antivirus detected something during retention window"
    Add-Signal 'Security tooling tampering / log clearing' 2 $gapTamper "log cleared or security service stopped"
    Add-Signal 'Process anomaly verdict MEDIUM' 1 $procMed "unsigned/user-path binaries worth review"
    Add-Signal 'Brute-force source(s) seen' 0 @($brute).Count "failed logon sources - check for follow-up success"

    # coverage: weighted evidence sources actually collected
    $cov = New-Object System.Collections.Generic.List[object]
    function Add-Cov([string]$name, [bool]$present, [int]$weight) {
        $cov.Add([pscustomobject]@{ Source = $name; Collected = $present; Weight = $weight })
    }
    $evtxDir = Join-Path $RawDir 'evtx'
    Add-Cov 'Volatile process inventory' (Test-Path (Join-Path $CsvDir 'flash_process_scored.csv')) 12
    Add-Cov 'Live network connections' (Test-Path (Join-Path $CsvDir 'flash_public_connections.csv')) 8
    $pers = (Test-Path (Join-Path $CsvDir 'autoruns_runkeys.csv')) -or (Test-Path (Join-Path $CsvDir 'services.csv')) -or (Test-Path (Join-Path $CsvDir 'scheduled_tasks.csv'))
    Add-Cov 'Persistence surface (autoruns/services/tasks)' $pers 15
    Add-Cov 'Event log export' (Test-Path $evtxDir) 20
    Add-Cov 'Sigma detection timeline' (Test-Path (Join-Path $CsvDir 'hayabusa_timeline.csv')) 10
    Add-Cov 'Historical execution (amcache)' (Test-Path (Join-Path $CsvDir 'amcache.csv')) 12
    Add-Cov 'Prefetch execution history' (Test-Path (Join-Path $CsvDir 'prefetch_index.csv')) 8
    Add-Cov 'USN journal (file modification history)' (Test-Path (Join-Path $CsvDir 'usn_write_bursts.csv')) 10
    Add-Cov 'MFT file timeline (filtered)' (Test-Path (Join-Path $CsvDir 'mft_recent.csv')) 8
    Add-Cov 'ASEP deep sweep (IFEO/AppInit/COM/netsh/LSA)' (Test-Path (Join-Path $CsvDir 'asep_sweep.csv')) 5
    Add-Cov 'Browser history artifacts' (Test-Path (Join-Path $CsvDir 'browser_files.csv')) 4
    Add-Cov 'Defender status' (Test-Path (Join-Path $CsvDir 'defender_status.csv')) 5
    Add-Cov 'YARA binary scan' (Test-Path (Join-Path $CsvDir 'yara_scanned.csv')) 5
    Add-Cov 'DNS query telemetry (Sysmon EID 22)' (Test-Path (Join-Path $CsvDir 'sysmon_dns.csv')) 4
    Add-Cov 'Entity correlation' (Test-Path (Join-Path $CsvDir 'entities_binaries.csv')) 3
    Add-Cov 'Hunt rules' (Test-Path (Join-Path $CsvDir 'hunt_findings.csv')) 3
    Add-Cov 'Svchost masquerade audit' (Test-Path (Join-Path $CsvDir 'svchost_audit.csv')) 2
    Add-Cov 'Remote access sweep (tunnels/RA tools/SSH keys)' (Test-Path (Join-Path $CsvDir 'remote_access.csv')) 2
    Add-Cov 'Structured telemetry (4688 / Sysmon 10-13)' ((Test-Path (Join-Path $CsvDir 'security_proc_events.csv')) -or (Test-Path (Join-Path $CsvDir 'sysmon_process_access.csv'))) 3
    Add-Cov 'Kerberos/DS telemetry (DC role)' ((Test-Path (Join-Path $CsvDir 'security_kerberos.csv')) -or (Test-Path (Join-Path $CsvDir 'security_ds_access.csv'))) 3
    Add-Cov 'Web telemetry (IIS)' (Test-Path (Join-Path $CsvDir 'iis_requests.csv')) 2
    Add-Cov 'Session attribution + process lineage' ((Test-Path (Join-Path $CsvDir 'session_activity.csv')) -or (Test-Path (Join-Path $CsvDir 'process_chains.csv'))) 2
    Add-Cov 'Host extras (WER/StartupInfo/QuickAssist/GPO)' ((Test-Path (Join-Path $CsvDir 'wer_reports.csv')) -or (Test-Path (Join-Path $CsvDir 'startup_info.csv'))) 2
    $iocsLoaded = $false
    try { $iocsLoaded = ($null -ne (Get-IocList)) } catch { }
    Add-Cov 'IOC feeds loaded (iocs.txt/STIX/MISP)' $iocsLoaded 2
    Add-Cov 'LOLDrivers driver hash check' (Test-Path (Join-Path $CsvDir 'loldrivers_hits.csv')) 3
    Add-Cov 'Sysmon telemetry (bonus)' ([bool]$Sysmon) 5
    Add-Cov 'RAM capture (bonus)' (Test-Path $MemDir) 3
    $coverageRaw = 0
    foreach ($c in $cov) { if ($c.Collected) { $coverageRaw += $c.Weight } }
    $isAdminRun = if ($null -ne $script:EndpointAdmin) { [bool]$script:EndpointAdmin } else { Test-IsAdmin }
    if (-not $isAdminRun) { $coverageRaw -= 15 }
    if ($coverageRaw -gt 100) { $coverageRaw = 100 }
    if ($coverageRaw -lt 0) { $coverageRaw = 0 }

    # verdict level
    $rank = 0
    foreach ($s in $signals) { if ($s.Weight -gt $rank) { $rank = $s.Weight } }
    $distinctStrong = @($signals | Where-Object { $_.Weight -ge 2 }).Count
    if ($rank -eq 2 -and $distinctStrong -ge 2) { $rank = 3 }
    if ($rank -eq 0) {
        if ($coverageRaw -lt 40) { $rank = 0 } else { $rank = 1 }
    }

    # caveats = what would change this verdict
    $caveats = New-Object System.Collections.Generic.List[string]
    if (-not $isAdminRun) { $caveats.Add('Run was NOT elevated - several sources are incomplete or missing') }
    if (-not $Sysmon) { $caveats.Add('No Sysmon on host - process injection / image-load / per-process network telemetry were not available') }
    if (Test-Path $evtxDir) {
        if ($script:LogStartDT) { $caveats.Add("Event-log analysis covered $(Get-LogRangeText) only - activity outside that window not assessed") }
        elseif ($LogHours -gt 0) { $caveats.Add("Event-log analysis covered only the last $([int]($LogHours/24)) days - older activity not assessed") }
    }
    if (-not (Test-Path $MemDir)) { $caveats.Add('No RAM capture - fileless / in-memory-only malware is not covered') }
    if (-not (Test-Path (Join-Path $CsvDir 'prefetch_index.csv'))) { $caveats.Add('Prefetch unavailable - program execution history limited') }
    if (-not (Test-Path (Join-Path $CsvDir 'amcache.csv'))) { $caveats.Add('Amcache unavailable - historical execution inventory missing') }
    if (-not (Test-Path $evtxDir)) { $caveats.Add('Event logs not exported - Sigma detection could not run') }
    if ($rank -eq 0) { $caveats.Add('Too little evidence was collected to draw a conclusion') }

    $ownerLines = @{
        4 = 'Strong signs of MALICIOUS ACTIVITY were found on this computer.'
        3 = 'Several suspicious findings - malicious activity is LIKELY.'
        2 = 'Some SUSPICIOUS items were found - the security team will check them.'
        1 = 'No signs of compromise were found.'
        0 = 'Not enough data could be collected to tell for sure.'
    }

    $counts = [pscustomobject]@{
        IocLive = @($iocLive).Count; IocAmcache = @($iocAmc).Count; YaraHigh = $yaraHi; YaraMedium = $yaraMed
        SigmaCritical = $hayCrit; SigmaHigh = $hayHigh; ProcessHigh = $procHigh; ProcessMedium = $procMed
        DefenderDetections = @($def).Count; TamperEvents = $gapTamper; BruteForceSources = @($brute).Count
        BeaconHigh = $beaconHi; BeaconMedium = $beaconMed
        DnsBeaconHigh = $dnsHi; DnsBeaconMedium = $dnsMed; LolDriversMalicious = $lolMal
        HuntHighPrecision = $huntHi.Count; HuntTotal = @($hunt).Count
    }

    return [pscustomobject]@{
        Level = $levelNames[$rank]
        LevelRank = $rank
        ConfidencePercent = $coverageRaw
        OwnerLine = $ownerLines[$rank]
        Signals = $signals.ToArray()
        Caveats = $caveats.ToArray()
        Coverage = $cov.ToArray()
        CoveragePercentUnadjusted = $coverageRaw
        Counts = $counts
        GeneratedUTC = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-CaseNarrative {
    # Plain-language executive draft built from the verdict + hunt findings (v2.31).
    # Written to case_draft.txt and rendered under the verdict in report.html - a starting
    # draft for the analyst's report, not a conclusion. Deterministic template, no filler.
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("CASE DRAFT - $Computer ($script:HostRole) - collected $($StartTime.ToString('yyyy-MM-dd HH:mm')) local, Ophira v$ScriptVersion")
    $L.Add("")
    if (-not $script:Verdict) { $L.Add("The verdict engine did not run - this draft has no assessment. Review the evidence sections."); return $L.ToArray() }
    $v = $script:Verdict
    $L.Add("ASSESSMENT: $($v.Level) (confidence $($v.ConfidencePercent)% of expected evidence collected). $($v.OwnerLine)")
    $L.Add("")
    $strong = @($v.Signals | Where-Object { $_.Weight -ge 3 })
    $notable = @($v.Signals | Where-Object { $_.Weight -eq 2 })
    if ($strong.Count -gt 0 -or $notable.Count -gt 0) {
        $L.Add("WHAT THE EVIDENCE SHOWS")
        foreach ($s in $strong) {
            $d = if ("$($s.Detail)") { " ($($s.Detail))" } else { '' }
            $L.Add(" - $($s.Signal) x$($s.Count)$d")
        }
        foreach ($s in $notable) {
            $d = if ("$($s.Detail)") { " ($($s.Detail))" } else { '' }
            $L.Add(" - Also seen: $($s.Signal) x$($s.Count)$d")
        }
    } else {
        $L.Add("WHAT THE EVIDENCE SHOWS: no compromising signals in the collected evidence.")
    }
    $L.Add("")
    $leads = @(Import-CaseCsv 'hunt_findings' | Where-Object { "$($_.Severity)" -eq 'high' } | Select-Object -First 5)
    if ($leads.Count -gt 0) {
        $L.Add("BEST LEADS (high-severity hunt detections - verify against cited evidence)")
        foreach ($f in $leads) { $L.Add(" - [$($f.Attck)] $($f.Rule) on $($f.Entity): $($f.Evidence)") }
        $L.Add("")
    }
    $missing = @($v.Coverage | Where-Object { -not $_.Collected })
    if ($missing.Count -gt 0) {
        $L.Add("WHAT THIS ASSESSMENT COULD NOT SEE")
        $L.Add(" - Evidence sources not collected: " + (($missing | ForEach-Object { $_.Source }) -join ', '))
        $L.Add(" - Absence of findings in these areas is NOT proof of absence.")
        $L.Add("")
    }
    if (@($v.Caveats).Count -gt 0) {
        $L.Add("CAVEATS")
        foreach ($c in @($v.Caveats)) { $L.Add(" - $c") }
        $L.Add("")
    }
    $L.Add("(Machine-generated starting draft - verify every lead against the cited evidence, then rewrite in your own words.)")
    return $L.ToArray()
}

function Invoke-RegenerateOutputs {
    # Shared by New-Package and -Mode Parse: rebuilds every derived artifact from csv\
    # (supertimeline, gaps, parse_needed, verdict.json, SIEM export, ATT&CK layer, report.html).
    param([pscustomobject]$Case)
    try { New-SuperTimeline } catch { Write-CaseLog "    supertimeline failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-SigmaRuleLogs } catch { Write-CaseLog "    sigma rule logs failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-HuntFindings } catch { Write-CaseLog "    hunt findings failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-IocHits } catch { Write-CaseLog "    IOC xref failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-EntityCorrelation } catch { Write-CaseLog "    entity correlation failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-SessionAttribution } catch { Write-CaseLog "    session attribution failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-ProcessChains } catch { Write-CaseLog "    process lineage failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-LoggingGaps } catch { Write-CaseLog "    logging gaps failed: $($_.Exception.Message)" 'DarkYellow' }
    try { Get-ParseNeeds } catch { Write-CaseLog "    parse-needed check failed: $($_.Exception.Message)" 'DarkYellow' }
    $script:Verdict = $null
    try {
        $script:Verdict = Get-CompromiseVerdict
        if ($script:Verdict) {
            $script:Verdict | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'verdict.json') -Encoding UTF8
            if ($Case) {
                $Case | Add-Member -NotePropertyName Verdict -NotePropertyValue ([pscustomobject]@{
                    Level = $script:Verdict.Level
                    ConfidencePercent = $script:Verdict.ConfidencePercent
                    SignalCount = $script:Verdict.Signals.Count
                    CaveatCount = $script:Verdict.Caveats.Count
                }) -Force
            }
            $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
            Write-CaseLog "    VERDICT: $($script:Verdict.Level) (confidence $($script:Verdict.ConfidencePercent)%) - $($script:Verdict.Signals.Count) signal(s), $($script:Verdict.Caveats.Count) caveat(s) -> verdict.json" $vColor
        }
    } catch { Write-CaseLog "    verdict engine failed: $($_.Exception.Message)" 'DarkYellow' }
    try { Get-CaseNarrative | Set-Content -LiteralPath (Join-Path $CaseDir 'case_draft.txt') -Encoding UTF8 } catch { Write-CaseLog "    case draft failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-SiemExport } catch { Write-CaseLog "    siem export failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-AttackLayer } catch { Write-CaseLog "    ATT&CK layer failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-HtmlReport | Out-Null } catch { Write-CaseLog "    report generation failed: $($_.Exception.Message)" 'DarkYellow' }
}

function New-Package {
    Write-Host ""
    Write-CaseLog "Packaging case folder..." 'Cyan'
    $os = Get-WmiOrCim -Class Win32_OperatingSystem
    $case = [pscustomobject]@{
        Tool = "Ophira v$ScriptVersion"
        CaseID = $script:CurrentCaseID
        Analyst = $script:CurrentAnalyst
        Computer = $Computer
        Preset = $Preset
        StartedUTC = $StartTime.ToUniversalTime().ToString('o')
        Role = $script:HostRole
        FinishedUTC = (Get-Date).ToUniversalTime().ToString('o')
        OS = if ($os) { $os.Caption + ' ' + $os.Version } else { '' }
        Owner = $env:USERNAME
        AdminElevated = (Test-IsAdmin)
        SysmonPresent = (Get-SysmonState)
        LogHours = $LogHours
        LogStart = $(if ($script:LogStartDT) { $script:LogStartDT.ToUniversalTime().ToString('o') } else { '' })
        LogEnd = $(if ($script:LogEndDT) { $script:LogEndDT.ToUniversalTime().ToString('o') } else { '' })
        DotNet = (Get-DotNetRelease)
        OutputFolder = $CaseDir
    }
    if ($script:ModuleTimings) {
        $case | Add-Member -NotePropertyName ModuleTimings -NotePropertyValue $script:ModuleTimings -Force
        $case | Add-Member -NotePropertyName ModuleSecondsTotal -NotePropertyValue ([math]::Round((($script:ModuleTimings | Measure-Object Seconds -Sum).Sum), 1)) -Force
    }
    $case | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8

    try { Invoke-DeltaCompare -Path $DeltaPath } catch { Write-CaseLog "    delta failed: $($_.Exception.Message)" 'DarkYellow' }
    Invoke-RegenerateOutputs -Case $case
    if ($script:Verdict) { $case | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8 }

    $manifest = @()
    $manifest += "Ophira v$ScriptVersion evidence manifest + chain of custody"
    $manifest += "CaseID: $($script:CurrentCaseID)  Analyst: $($script:CurrentAnalyst)"
    $manifest += "Host: $Computer  Collected: $($StartTime.ToString('u'))  Packaged: $((Get-Date).ToUniversalTime().ToString('u'))"
    $manifest += "Scope: every file in this folder is SHA256-hashed below (the manifest itself excepted - hash it after zip)."
    $manifest += "Custody: the case zip is the evidence unit; keep the hash of the zip with your case notes."
    $manifest += ""
    try {
        $selfHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        $manifest += "SCRIPT: Ophira v$ScriptVersion  SHA256: $selfHash"
    } catch { $manifest += "SCRIPT: Ophira v$ScriptVersion  (self-hash unavailable)" }
    $tDirM = Get-ToolsDir
    if ($tDirM) {
        $toolExes = Get-ChildItem -Path $tDirM -Recurse -File -Include 'hayabusa*.exe', 'chainsaw*.exe', 'vol.exe', '*winpmem*.exe', 'AmcacheParser*.exe', 'RBCmd*.exe', 'yr.exe' -ErrorAction SilentlyContinue
        if ($toolExes) {
            $manifest += "TOOLS AVAILABLE:"
            foreach ($exe in $toolExes) {
                $th = ''
                try { $th = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.Substring(0, 16) } catch { }
                $manifest += "  $($exe.Name)  [$th...]"
            }
        }
    }
    $manifest += ""
    $manifest += "{0,-70} {1,12} SHA256" -f "File", "SizeBytes"
    $files = Get-ChildItem -LiteralPath $CaseDir -Recurse -File | Where-Object { $_.Name -ne 'manifest.txt' -and $_.Name -notmatch '\.zip$' }
    foreach ($f in ($files | Sort-Object FullName)) {
        $h = ''
        try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch { $h = 'HASH-ERROR' }
        $rel = $f.FullName.Substring($CaseDir.Length + 1)
        $manifest += "{0,-70} {1,12} {2}" -f $rel, $f.Length, $h
    }
    $manifest | Set-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8

    $zipPath = "$CaseDir.zip"
    $zipped = $false
    try {
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            $items = Get-ChildItem -LiteralPath $CaseDir | Where-Object { $_.Name -ne 'memory' } | ForEach-Object { $_.FullName }
            if ($items) {
                Compress-Archive -Path $items -DestinationPath $zipPath -CompressionLevel Fastest -Force
                $zipped = $true
            }
        }
    } catch { Write-CaseLog "Zip failed: $($_.Exception.Message)" 'Yellow' }

    $zipHash = ''
    if ($zipped -and (Test-Path $zipPath)) {
        $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value ""
        Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "PACKAGE SHA256 ($([IO.Path]::GetFileName($zipPath))): $zipHash"
    }
    if (Test-Path $MemDir) {
        Get-ChildItem -LiteralPath $MemDir -Recurse -File | ForEach-Object {
            $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "MEMORY SHA256 ($($_.Name)): $h"
        }
    }

    $shareResult = ''
    $script:ShareOk = $false
    if ($SharePath -and $zipped -and (Test-Path $zipPath)) {
        try {
            if (-not (Test-Path $SharePath)) { throw "share path not reachable: $SharePath" }
            Copy-Item -LiteralPath $zipPath -Destination $SharePath -Force -ErrorAction Stop
            $shareResult = "copied to $SharePath"
            $script:ShareOk = $true
            Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "UPLOADED TO: $SharePath at $(Get-Date -Format u)"
        } catch { $shareResult = "SHARE COPY FAILED: $($_.Exception.Message)" }
    }
    $script:FinalZipPath = if ($zipped -and (Test-Path $zipPath)) { $zipPath } else { (Join-Path $CaseDir 'report.html') }

    $sizeAll = [math]::Round((Get-ChildItem -LiteralPath $CaseDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
    $zipSize = if ($zipped) { [math]::Round((Get-Item $zipPath).Length / 1MB, 1) } else { 0 }
    if (-not $script:SimpleUI) {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  COLLECTION COMPLETE" -ForegroundColor Green
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  Case folder : $CaseDir  ($sizeAll MB)"
        if (Test-Path (Join-Path $CaseDir 'report.html')) { Write-Host "  Report      : $CaseDir\report.html  <-- open this first" -ForegroundColor Cyan }
        if ($zipped) { Write-Host "  Package     : $zipPath  ($zipSize MB)" -ForegroundColor White }
        if ($zipHash) { Write-Host "  Zip SHA256  : $zipHash" -ForegroundColor White }
        if ($shareResult) { Write-Host "  Share copy  : $shareResult" -ForegroundColor $(if ($shareResult -match 'FAILED') { 'Red' } else { 'Green' }) }
        Write-Host "  Memory dump : $(if (Test-Path $MemDir) { "$MemDir (NOT in zip - send separately)" } else { 'not captured' })"
        if ($script:Verdict) {
            $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
            Write-Host "  VERDICT     : $($script:Verdict.Level)  (confidence $($script:Verdict.ConfidencePercent)%)  - details: report.html / verdict.json" $vColor
        }
        Write-Host ""
        Write-Host "  Send the ZIP file (and memory dump if captured) to the analyst." -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Green
    }
}

function Show-RoleGate {
    if ($script:OphiraRole -eq 'responder') { return 'responder' }
    if ($script:OphiraRole -eq 'owner') { return 'owner' }
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "   ___  ___  ___ _  _ ___ _____ _   ___ ___   " -ForegroundColor Cyan
        Write-Host "  | _ \/ _ \| __| \| | _ \_   _/_\ | _ \ _ \ " -ForegroundColor Cyan
        Write-Host "  |  _/ (_) | _|| .\` |  _/ | |/ _ \|   /  _/" -ForegroundColor Cyan
        Write-Host "  |_|  \___/|___|_|\_|_|   |_/_/ \_\_|_\_|_\ " -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  Ophira v$ScriptVersion  -  single-script Windows IR toolkit" -ForegroundColor White
        Write-Host "  READ-ONLY: collects evidence, never changes the system" -ForegroundColor DarkGray
        Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Who is using this tool?" -ForegroundColor White
        Write-Host ""
        Write-Host "   [1]  I am on the security / incident response team" -ForegroundColor Yellow
        Write-Host "        Full menu: collect, push & run on remote PCs, analyze." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "   [2]  The security team asked me to run this" -ForegroundColor Yellow
        Write-Host "        Guided automatic collection - nothing to decide." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        $inp = Read-Host "  Choose 1 or 2"
        switch -Regex ($inp) {
            '^1$' { return 'responder' }
            '^2$' { return 'owner' }
            default { }
        }
    }
}

function Show-TaskMenu {
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  OPHIRA v$ScriptVersion   |   $($env:COMPUTERNAME)   |   RESPONDER" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  What do you want to do?" -ForegroundColor White
        Write-Host ""
        Write-Host "   [1]  Collect evidence on THIS PC" -ForegroundColor Yellow
        Write-Host "   [2]  Push & run on REMOTE PCs (WinRM)" -ForegroundColor Yellow
        Write-Host "   [3]  Analyze collected results (fleet report)" -ForegroundColor Yellow
        Write-Host "   [4]  Setup / download companion tools" -ForegroundColor Yellow
        Write-Host "   [5]  Update detection rules (hayabusa)" -ForegroundColor Yellow
        Write-Host "   [6]  Tune Sigma rules (reduce false positives)" -ForegroundColor Yellow
        Write-Host "   [7]  Tool links" -ForegroundColor Yellow
        Write-Host "   [8]  Finish a collected case (parse evidence analyst-side)" -ForegroundColor Yellow
        Write-Host "   [9]  Analyze a single process (pivot on a case)" -ForegroundColor Yellow
        Write-Host "   [C]  Detection canary (self-test the pipeline on this PC)" -ForegroundColor Yellow
        Write-Host "   [T]  Timeline pivot (filter the master timeline to a window)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "   [Q]  Quit" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
        $inp = Read-Host "  Command"
        switch -Regex ($inp) {
            '^(?i)1$' { return 'Collect' }
            '^(?i)2$' { return 'Deploy' }
            '^(?i)3$' { return 'Analyze' }
            '^(?i)4$' { return 'Setup' }
            '^(?i)5$' { return 'UpdateRules' }
            '^(?i)6$' { return 'Tune' }
            '^(?i)7$' { return 'Links' }
            '^(?i)8$' { return 'Parse' }
            '^(?i)9$' { return 'Process' }
            '^(?i)c$' { return 'Canary' }
            '^(?i)t$' { return 'Timeline' }
            '^(?i)q$' { return $null }
            default { }
        }
    }
}

function Invoke-SetupWizard {
    Write-Host ""
    Write-Host "=== Setup companion tools ===" -ForegroundColor Cyan
    Write-Host "Tools live in tools\ subfolders. Available:" -ForegroundColor Gray
    Write-Host "  winpmem  hayabusa  volatility3  chainsaw  AmcacheParser  RBCmd  MFTECmd  PECmd  LECmd  JLECmd  SBECmd  SQLECmd  loldrivers  yara" -ForegroundColor White
    Write-Host "  plus tools\sysmon\ophira-sysmon.xml - recommended Sysmon config for full hunt-rule telemetry (deploy yourself, see README 'Deploy Sysmon')" -ForegroundColor Gray
    Write-Host "ENTER = walk through all tools (confirm each download)," 
    Write-Host "or give a comma-separated list (e.g. hayabusa,winpmem)."
    $inp = (Read-Host "Tools [all]").Trim()
    $wanted = $null
    if ($inp) { $wanted = $inp }
    Invoke-SetupMode -Wanted $wanted
}

function Invoke-UpdateRulesMode {
    $tDir = Get-ToolsDir
    $h = $null
    if ($tDir) { $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1 }
    if (-not $h) { Write-Host "hayabusa not found in tools\ - run Setup first" -ForegroundColor Red; return $false }
    $rulesDir = Join-Path $h.DirectoryName 'rules'
    $confirm = Read-Host "Replace hayabusa detection rules with the latest from hayabusa-rules? [Y/n]"
    if ($confirm -match '^[Nn]') { return $true }
    $bak = $null
    if (Test-Path $rulesDir) {
        $bak = "$rulesDir.bak"
        if (Test-Path $bak) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
        Move-Item -LiteralPath $rulesDir -Destination $bak -Force
    }
    try {
        Write-Host "Downloading latest rules from hayabusa-rules..." -ForegroundColor Cyan
        $zip = Join-Path ([IO.Path]::GetTempPath()) 'hayabusa-rules.zip'
        Invoke-WebRequest -Uri 'https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.zip' -OutFile $zip -UseBasicParsing -ErrorAction Stop
        $ex = Join-Path ([IO.Path]::GetTempPath()) 'hayabusa-rules-extract'
        if (Test-Path $ex) { Remove-Item $ex -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $ex -Force -ErrorAction Stop
        $inner = Get-ChildItem $ex -Directory | Select-Object -First 1
        if (-not $inner) { throw 'archive layout unexpected' }
        Move-Item -LiteralPath $inner.FullName -Destination $rulesDir -Force -ErrorAction Stop
        Remove-Item $zip, $ex -Recurse -Force -ErrorAction SilentlyContinue
        $n = @(Get-ChildItem $rulesDir -Recurse -Filter '*.yml' -ErrorAction SilentlyContinue).Count
        if ($n -eq 0) { throw 'no rule files found after extract' }
        if ($bak -and (Test-Path $bak)) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Host "Rules updated ($n rule files). (Chainsaw Sigma rules: git pull in tools\chainsaw\sigma)" -ForegroundColor Green
        return $true
    } catch {
        if ($bak -and (Test-Path $bak)) { Move-Item -LiteralPath $bak -Destination $rulesDir -Force }
        Write-Host "Rules update FAILED ($($_.Exception.Message)) - previous rules restored." -ForegroundColor Red
        return $false
    }
}

function Find-SigmaRuleFile {
    # Locates a rule's .yml in the bundled hayabusa rules by its RuleID GUID (first match wins).
    param([string]$RuleId, $HayabusaExe)
    if (-not $RuleId -or -not $HayabusaExe) { return $null }
    $rulesDir = Join-Path $HayabusaExe.DirectoryName 'rules'
    if (-not (Test-Path $rulesDir)) { return $null }
    $hit = Get-ChildItem -Path $rulesDir -Recurse -Filter '*.yml' -File -ErrorAction SilentlyContinue |
        Select-String -Pattern ([regex]::Escape($RuleId)) -List -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.Path }
    return $null
}

function Invoke-TuneMode {
    # Sigma FP feedback loop: shows top-hit rules from the most recent case timeline,
    # writes picks into hayabusa's native exclude_rules.txt / level_tuning.txt.
    $h = Get-HayabusaExe
    if (-not $h) { Write-Host "hayabusa not found in tools\ - run Setup first" -ForegroundColor Red; return $false }
    $cfgDir = Join-Path $h.DirectoryName 'rules\config'
    if (-not (Test-Path $cfgDir)) { Write-Host "hayabusa rule config not found: $cfgDir" -ForegroundColor Red; return $false }
    $kit = Get-KitRoot
    $cand = @(Get-ChildItem -Path $kit -Recurse -Filter 'hayabusa_timeline.csv' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $tl = $null
    if ($cand.Count -eq 1) { $tl = $cand[0].FullName }
    elseif ($cand.Count -gt 1) {
        Write-Host ""
        Write-Host "  Found $($cand.Count) hayabusa timelines (newest first):" -ForegroundColor White
        for ($i = 0; $i -lt [Math]::Min(9, $cand.Count); $i++) { Write-Host ("   [{0}] {1}" -f ($i + 1), $cand[$i].FullName) }
        $sel = (Read-Host "  Which case? [1]").Trim()
        if (-not $sel) { $sel = '1' }
        if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le [Math]::Min(9, $cand.Count)) { $tl = $cand[[int]$sel - 1].FullName }
    }
    if (-not $tl) { $tl = (Read-Host "  Path to hayabusa_timeline.csv").Trim(' " ') }
    if (-not $tl -or -not (Test-Path -LiteralPath $tl)) { Write-Host "No timeline available - run a collection first (or enter a path)." -ForegroundColor Red; return $false }
    Write-Host "  Loading $([IO.Path]::GetFileName($tl)) ..." -ForegroundColor Gray
    $rows = @(Import-Csv -LiteralPath $tl)
    if ($rows.Count -eq 0) { Write-Host "Timeline is empty - nothing to tune." -ForegroundColor Yellow; return $true }
    $groups = @($rows | Group-Object RuleID, RuleTitle, Level | Sort-Object Count -Descending | Select-Object -First 25)
    Write-Host ""
    Write-Host "  Top noisy rules (by hit count):" -ForegroundColor White
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $g = $groups[$i]
        Write-Host ("   [{0,2}] x{1,-7} {2,-14} {3}" -f ($i + 1), $g.Count, "$($g.Group[0].Level)", "$($g.Group[0].RuleTitle)")
    }
    Write-Host ""
    Write-Host "  E = exclude (rule never fires again)   D = demote to informational (stays visible, loses verdict weight)" -ForegroundColor DarkGray
    Write-Host "  V = view the rule's .yml in Notepad    ED = edit the rule's .yml in Notepad (changes apply on the next run)" -ForegroundColor DarkGray
    $pick = (Read-Host "  Rule numbers to tune (comma-separated), A = all shown, ENTER = cancel").Trim()
    if (-not $pick) { Write-Host "Cancelled." -ForegroundColor Gray; return $true }
    $idx = @()
    if ($pick -match '^(?i)a$') { $idx = @(1..$groups.Count) }
    else { foreach ($p in ($pick -split ',')) { $pt = $p.Trim(); if ($pt -match '^\d+$' -and [int]$pt -ge 1 -and [int]$pt -le $groups.Count) { $idx += [int]$pt } } }
    if ($idx.Count -eq 0) { Write-Host "No valid selection." -ForegroundColor Yellow; return $true }
    $exPath = Join-Path $cfgDir 'exclude_rules.txt'
    $lvPath = Join-Path $cfgDir 'level_tuning.txt'
    $nEx = 0
    $nLv = 0
    foreach ($i in $idx) {
        $g = $groups[$i - 1]
        $rid = "$($g.Group[0].RuleID)"
        $title = "$($g.Group[0].RuleTitle)"
        $lvl = "$($g.Group[0].Level)"
        $act = (Read-Host "  [$title - $lvl] E / D / V=iew rule / ED=it rule / S=kip").Trim()
        if (-not $rid) { continue }
        if ($act -match '^(?i)e$') {
            Add-Content -LiteralPath $exPath -Value ("{0} # `"{1}`" (Ophira Tune {2})" -f $rid, $title, (Get-Date -Format 'yyyy-MM-dd')) -Encoding UTF8
            $nEx++
        } elseif ($act -match '^(?i)d$') {
            if (-not (Test-Path $lvPath)) { Set-Content -LiteralPath $lvPath -Value 'id,new_level' -Encoding UTF8 }
            Add-Content -LiteralPath $lvPath -Value ("{0},informational # `"{1}`" - Originally {2} (Ophira Tune {3})" -f $rid, $title, $lvl, (Get-Date -Format 'yyyy-MM-dd')) -Encoding UTF8
            $nLv++
        } elseif ($act -match '^(?i)(v|ed)$') {
            Write-Host "  locating rule file (searching bundled rules for RuleID)..." -ForegroundColor Gray
            $rf = Find-SigmaRuleFile -RuleId $rid -HayabusaExe $h
            if (-not $rf) {
                Write-Host "  rule file not found in tools\hayabusa\rules - bundled rules may predate this rule (try -Mode UpdateRules)" -ForegroundColor Yellow
            } elseif ($act -match '^(?i)ed$') {
                Write-Host "  $rf" -ForegroundColor Gray
                Write-Host "  Notepad will open - save your edit and close it to continue." -ForegroundColor Yellow
                Write-Host "  NOTE: manual rule edits are discarded when rules are refreshed via -Mode UpdateRules." -ForegroundColor Yellow
                Start-Process notepad.exe $rf -Wait | Out-Null
                Write-Host "  edit saved (applies on the next collection/run)" -ForegroundColor Green
            } else {
                Start-Process notepad.exe $rf | Out-Null
                Write-Host "  opened in Notepad: $rf" -ForegroundColor Gray
            }
        }
    }
    Write-Host ""
    Write-Host "Tune done: $nEx excluded, $nLv demoted (written into tools\hayabusa rules\config)." -ForegroundColor $(if ($nEx + $nLv -gt 0) { 'Green' } else { 'Gray' })
    Write-Host "These settings travel with Deploy (-PushTools) to every host. Re-run a collection to see the effect." -ForegroundColor Gray
    return $true
}

function Open-CaseSession {
    # Loads a case folder/zip and adopts its identity into $script: session vars
    # (shared by -Mode Parse and -Mode Process). Returns the case metadata or $null.
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { Write-Host "  Path not found: $Path" -ForegroundColor Red; return $null }
    $tmp = $null
    $caseDirP = $Path
    if ((Test-Path -LiteralPath $Path -PathType Leaf) -and $Path -match '\.zip$') {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ophira_open_" + (Get-Date -Format 'HHmmss'))
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [IO.Compression.ZipFile]::ExtractToDirectory($Path, $tmp)
        } catch { Write-Host "  cannot extract zip: $($_.Exception.Message)" -ForegroundColor Red; return $null }
        $caseDirP = $tmp
    }
    $meta = $null
    $cj = Join-Path $caseDirP 'case.json'
    if (Test-Path $cj) { try { $meta = Get-Content $cj -Raw | ConvertFrom-Json } catch { } }
    if (-not $meta) { Write-Host "  case.json not found - not an Ophira case folder?" -ForegroundColor Red; if ($tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }; return $null }
    $script:CaseDir = $caseDirP
    $script:CsvDir = Join-Path $caseDirP 'csv'
    $script:RawDir = Join-Path $caseDirP 'raw'
    $script:MemDir = Join-Path $caseDirP 'memory'
    $script:CaseLog = Join-Path $caseDirP 'collection.log'
    $script:Computer = "$($meta.Computer)"
    $script:CurrentCaseID = "$($meta.CaseID)"
    $script:CurrentAnalyst = "$($meta.Analyst)"
    $script:LogHours = $(if ($meta.LogHours) { [int]$meta.LogHours } else { 168 })
    $script:LogStartDT = $null
    $script:LogEndDT = $null
    try { if ("$($meta.LogStart)") { $script:LogStartDT = [datetime]$meta.LogStart } } catch { }
    try { if ("$($meta.LogEnd)") { $script:LogEndDT = [datetime]$meta.LogEnd } } catch { }
    $script:Sysmon = [bool]$meta.SysmonPresent
    $script:EndpointAdmin = [bool]$meta.AdminElevated
    $st = $null
    try { $st = [datetime]"$($meta.StartedUTC)" } catch { }
    if (-not $st) { $st = Get-Date }
    $script:StartTime = $st
    $script:OpenCaseTmp = $tmp
    return $meta
}

function Invoke-ParseMode {
    # Analyst-side completion: run THIS kit's parsers over a case's raw\ evidence and
    # regenerate everything the endpoint couldn't finish (tool missing, .NET gap, skipped module).
    # Only reads raw\ inputs - never touches the analyst's own system state as evidence.
    param([string]$Path)
    Write-Host ""
    Write-Host "=== Finish a collected case (analyst-side parsing) ===" -ForegroundColor Cyan
    if (-not $Path) { $Path = (Read-Host "  Case folder or OPHIRA_*.zip path").Trim(' "') }
    $meta = Open-CaseSession -Path $Path
    if (-not $meta) { return $false }
    $caseDirP = $script:CaseDir
    $tmp = $script:OpenCaseTmp
    $cj = Join-Path $caseDirP 'case.json'
    Add-Content -LiteralPath $script:CaseLog -Encoding UTF8 -Value ("[{0}] === analyst parse session (Ophira v{1}) ===" -f (Get-Date -Format 'HH:mm:ss'), $ScriptVersion)
    Write-Host "  Case: $($meta.Computer)  collected $($meta.StartedUTC)  ($($meta.Tool))" -ForegroundColor Gray
    $before = @(Get-ChildItem -LiteralPath $script:CsvDir -Filter '*.csv' -File -ErrorAction SilentlyContinue).Count

    # 1) modules that read ONLY raw\ evidence - reuse the real module code verbatim
    foreach ($id in @('4.6', '5.4', '8.4')) {
        $m = $script:Modules | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if ($m) {
            Write-Host "  module ${id}: $($m.Name)" -ForegroundColor Cyan
            try { & $m.Run } catch { Write-Host "    failed: $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }

    # 2) parse-only halves of the copy+parse modules (their raw inputs ship inside the zip)
    $tDir = Get-ToolsDir
    $findTool = {
        param($filter)
        if ($tDir) { Get-ChildItem -Path $tDir -Recurse -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
    }
    $runTool = {
        param($exe, $toolArgs, $label)
        if (-not $exe) { Write-Host "  $label - tool not in tools\ (run -Mode Setup)" -ForegroundColor DarkYellow; return }
        Write-Host "  $label..." -ForegroundColor Cyan
        $null = Invoke-NativeTool -ExePath $exe.FullName -ToolArgs $toolArgs -WorkingDirectory $exe.DirectoryName
    }
    $pfDst = Join-Path $script:RawDir 'prefetch'
    if ((Test-Path $pfDst) -and -not (Test-Path (Join-Path $script:CsvDir 'prefetch_parsed.csv'))) {
        & $runTool (& $findTool 'PECmd*.exe') @('-d', $pfDst, '--csv', $script:CsvDir, '--csvf', 'prefetch_parsed.csv') 'PECmd: prefetch run counts'
    }
    $recDst = Join-Path $script:RawDir 'recent'
    if ((Test-Path $recDst) -and -not (Test-Path (Join-Path $script:CsvDir 'lnk_parsed.csv'))) {
        & $runTool (& $findTool 'LECmd*.exe') @('-d', $recDst, '--csv', $script:CsvDir, '--csvf', 'lnk_parsed.csv') 'LECmd: recent LNK files'
    }
    $jlDst = Join-Path $script:RawDir 'jumplists'
    if ((Test-Path $jlDst) -and -not (Test-Path (Join-Path $script:CsvDir 'jumplist_parsed*.csv'))) {
        & $runTool (& $findTool 'JLECmd*.exe') @('-d', $jlDst, '--csv', $script:CsvDir, '--csvf', 'jumplist_parsed.csv') 'JLECmd: jump lists'
    }
    $brDst = Join-Path $script:RawDir 'browser'
    if ((Test-Path $brDst) -and -not (Test-Path (Join-Path $script:CsvDir 'browser_history.csv'))) {
        $sqlExe = & $findTool 'SQLECmd*.exe'
        if ($sqlExe) {
            & $runTool $sqlExe @('-d', $brDst, '--csv', $script:CsvDir) 'SQLECmd: browser history/downloads'
            $merge = {
                param([string]$glob, [string]$name)
                $files = @(Get-ChildItem -Path $script:CsvDir -Filter $glob -File -ErrorAction SilentlyContinue)
                $all = @()
                foreach ($f2 in $files) { try { $all += @(Import-Csv -LiteralPath $f2.FullName -ErrorAction Stop) } catch { } }
                if ($all.Count -gt 0) { Save-Rows -Name $name -Rows $all }
                foreach ($f2 in $files) { Remove-Item -LiteralPath $f2.FullName -Force -ErrorAction SilentlyContinue }
            }
            & $merge '*ChromiumBrowser_HistoryVisits_*.csv' 'browser_history'
            & $merge '*ChromiumBrowser_Downloads_*.csv' 'browser_downloads'
            & $merge '*ChromiumBrowser_KeywordSearches_*.csv' 'browser_searches'
            Get-ChildItem -Path $script:CsvDir -Filter 'SQLite.Interop.dll' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            Invoke-BrowserIocXref
        }
    }
    # RECmd batch registry deep-dive over saved hives (v2.25: bundled ophira-registry.bn)
    $regDir2 = Join-Path $script:RawDir 'registry'
    if (Test-Path $regDir2) {
        $reExe = & $findTool 'RECmd*.exe'
        $bn = $null
        try { $bn = Join-Path (Get-KitRoot) 'tools\recmd\ophira-registry.bn' } catch { }
        if ($reExe -and $bn -and (Test-Path $bn) -and -not (Test-Path (Join-Path $script:CsvDir 'registry_recmd.csv'))) {
            Write-Host "  RECmd: batch registry deep-dive..." -ForegroundColor Cyan
            $outDir = Join-Path $script:CsvDir 'recmd_out'
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            $hives = @(Get-ChildItem -LiteralPath $regDir2 -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(hiv|hive|dat)$' })
            foreach ($h in $hives) {
                $null = Invoke-NativeTool -ExePath $reExe.FullName -ToolArgs @('--bn', $bn, '-f', $h.FullName, '--csv', $outDir, '--csvf', "$($h.BaseName).csv") -WorkingDirectory $reExe.DirectoryName
            }
            $all = @()
            foreach ($f2 in @(Get-ChildItem -Path $outDir -Filter '*.csv' -File -ErrorAction SilentlyContinue)) {
                try { $rows2 = @(Import-Csv -LiteralPath $f2.FullName -ErrorAction Stop) } catch { continue }
                foreach ($r2 in $rows2) {
                    $all += [pscustomobject]@{ Hive = $f2.BaseName; KeyPath = "$($r2.'Key Path')"; ValueName = "$($r2.'Value Name')"; ValueType = "$($r2.'Value Type')"; Value = ("$($r2.'Value')" -replace '\s+', ' '); LastWrite = "$($r2.'Last Write Timestamp')" }
                }
            }
            Save-Rows -Name 'registry_recmd' -Rows $all
            Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
            if ($all.Count -gt 0) { Write-Host "  RECmd: $($all.Count) registry value(s) via batch -> csv\registry_recmd.csv" -ForegroundColor Gray }
        }
    }
    # EvtxECmd: FULL evtx->CSV conversion for timeframe deep-dives (v2.25)
    $evSrc = Join-Path $script:RawDir 'evtx'
    if (Test-Path $evSrc) {
        $evExe = & $findTool 'EvtxECmd*.exe'
        if ($evExe -and -not (Test-Path (Join-Path $script:CsvDir 'evtx_ecmd'))) {
            Write-Host "  EvtxECmd: full evtx->CSV conversion..." -ForegroundColor Cyan
            $outDir = Join-Path $script:CsvDir 'evtx_ecmd'
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            $n2 = 0
            foreach ($ev in @(Get-ChildItem -LiteralPath $evSrc -Filter '*.evtx' -File -ErrorAction SilentlyContinue)) {
                $null = Invoke-NativeTool -ExePath $evExe.FullName -ToolArgs @('-f', $ev.FullName, '--csv', $outDir, '--csvf', "$($ev.BaseName).csv") -WorkingDirectory $evExe.DirectoryName
                $n2++
            }
            if ($n2 -gt 0) { Write-Host "  EvtxECmd: $n2 log file(s) fully converted -> csv\evtx_ecmd\ (filter EventTime for deep-dives)" -ForegroundColor Gray }
        }
    }

    # 3) regenerate everything derived from csv\
    Invoke-RegenerateOutputs -Case $meta
    try {
        $meta | Add-Member -NotePropertyName AnalystParsedUTC -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
        $meta | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $cj -Encoding UTF8
    } catch { }

    $after = @(Get-ChildItem -LiteralPath $script:CsvDir -Filter '*.csv' -File -ErrorAction SilentlyContinue).Count
    Write-Host ""
    Write-Host "Done: $before -> $after CSVs. Regenerated report.html / verdict.json / supertimeline.csv / siem_export.ndjson." -ForegroundColor Green
    Write-Host "csv\parse_needed.csv lists anything that still needs the ORIGINAL endpoint (live-only sources)." -ForegroundColor Gray

    # 4) re-pack if the input was a zip
    if ($tmp) {
        try {
            $items = Get-ChildItem -LiteralPath $caseDirP | Where-Object { $_.Name -ne 'memory' } | ForEach-Object { $_.FullName }
            Compress-Archive -Path $items -DestinationPath $Path -CompressionLevel Fastest -Force
            Write-Host "Repacked: $Path" -ForegroundColor Green
        } catch { Write-Host "repack failed ($($_.Exception.Message)) - parsed files remain in $caseDirP" -ForegroundColor Yellow }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $true
}

function Invoke-ProcessPivot {
    # Analyst-side single-process analysis: search every CSV in a collected case for one
    # indicator (name, path fragment or hash) and group what the evidence says about it.
    param([string]$Path, [string]$Indicator)
    Write-Host ""
    Write-Host "=== Analyze a single process (case pivot) ===" -ForegroundColor Cyan
    if (-not $Path) { $Path = (Read-Host "  Case folder or OPHIRA_*.zip path").Trim(' "') }
    $meta = Open-CaseSession -Path $Path
    if (-not $meta) { return $false }
    if (-not $Indicator) { $Indicator = (Read-Host "  Process name, path fragment or hash (sha256/sha1/md5)").Trim() }
    if (-not $Indicator) { Write-Host "  no indicator given" -ForegroundColor Red; return $false }
    $ind = $Indicator.ToLower()
    $isHash = $ind -match '^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$'
    Write-Host "  Case: $($meta.Computer)  indicator: $Indicator" -ForegroundColor Gray

    $scan = {
        param([string]$term)
        $found = New-Object System.Collections.Generic.List[object]
        foreach ($f in @(Get-ChildItem -LiteralPath $script:CsvDir -Filter '*.csv' -File -ErrorAction SilentlyContinue | Where-Object { @('process_pivot.csv', 'supertimeline.csv') -notcontains $_.Name } | Sort-Object Name)) {
            $src = $f.BaseName
            $rr = $null
            try { $rr = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { continue }
            foreach ($r in $rr) {
                $matchProps = @()
                $pivotVals = @()
                foreach ($p in $r.PSObject.Properties) {
                    $v = "$($p.Value)"
                    if ($v -and $v.ToLower().Contains($term)) { $matchProps += "$($p.Name)=$v" }
                    if ($v -and $p.Name -match '^(?i)(Name|Path|Application|Process|Image)$') { $pivotVals += $v }
                }
                if ($matchProps.Count -gt 0) {
                    $detail = ($matchProps -join ' | ')
                    if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + '...' }
                    $found.Add([pscustomobject]@{ Indicator = $Indicator; Source = $src; Detail = $detail; Pivot = (($pivotVals | Select-Object -First 4) -join '|') })
                }
            }
        }
        return $found
    }

    $hits = [System.Collections.Generic.List[object]]@(& $scan $ind)
    # hash given -> also pivot on the matching binary's name/path so one hash pulls the whole story
    if ($isHash -and $hits.Count -gt 0) {
        $extra = @()
        foreach ($h in $hits) {
            foreach ($v in (@("$($h.Pivot)" -split '\|') | Where-Object { $_ })) {
                $vl = $v.ToLower()
                if ($vl.Length -ge 4 -and $vl -ne $ind -and $extra -notcontains $vl) { $extra += $vl }
            }
        }
        foreach ($term in (@($extra | Select-Object -First 3))) {
            foreach ($h2 in (& $scan $term)) {
                if (@($hits | Where-Object { $_.Source -eq $h2.Source -and $_.Detail -eq $h2.Detail }).Count -eq 0) { $hits.Add($h2) }
            }
        }
    }

    Save-Rows -Name 'process_pivot' -Rows @($hits)
    Write-Host ""
    if ($hits.Count -eq 0) {
        Write-Host "No evidence found for '$Indicator' in this case." -ForegroundColor Yellow
        return $true
    }
    Write-Host "EVIDENCE FOR '$Indicator' - $($hits.Count) row(s) across $($hits | Group-Object Source | Select-Object -ExpandProperty Count) artifact(s):" -ForegroundColor Cyan
    foreach ($g in ($hits | Group-Object Source | Sort-Object Count -Descending)) {
        Write-Host ("  {0,-32} x{1}" -f $g.Name, $g.Count) -ForegroundColor White
        foreach ($h in ($g.Group | Select-Object -First 2)) {
            $d = $h.Detail
            if ($d.Length -gt 160) { $d = $d.Substring(0, 160) + '...' }
            Write-Host "      $d" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    Write-Host "Full pivot -> csv\process_pivot.csv (in the case folder). Timeline view: csv\supertimeline.csv" -ForegroundColor Gray
    return $true
}

function Invoke-TimelineMode {
    # v2.25 analyst-side timeframe pivot: filter the case's MASTER TIMELINE to a window and
    # summarize what happened - the "someone reported weird activity around 14:00" workflow.
    # Timestamps in supertimeline.csv are UTC; enter the window in UTC.
    param([string]$Path, [string]$Start, [string]$End)
    Write-Host ""
    Write-Host "=== Timeline pivot (filter the master timeline to a window) ===" -ForegroundColor Cyan
    if (-not $Path) { $Path = (Read-Host "  Case folder or OPHIRA_*.zip path").Trim(' "') }
    $meta = Open-CaseSession -Path $Path
    if (-not $meta) { return $false }
    if (-not $Start) { $Start = (Read-Host "  Window START (yyyy-MM-dd HH:mm, UTC)").Trim() }
    if (-not $End) { $End = (Read-Host "  Window END   (yyyy-MM-dd HH:mm, UTC)").Trim() }
    $t0 = $null; $t1 = $null
    try { $t0 = [datetime]$Start } catch { }
    try { $t1 = [datetime]$End } catch { }
    if (-not $t0 -or -not $t1 -or ($t1 -eq [datetime]::MinValue)) { Write-Host "  invalid start/end - use 'yyyy-MM-dd HH:mm'" -ForegroundColor Red; return $false }
    if ($t1 -lt $t0) { $tmp = $t0; $t0 = $t1; $t1 = $tmp }
    $tlPath = Join-Path $script:CsvDir 'supertimeline.csv'
    if (-not (Test-Path $tlPath)) { Write-Host "  no supertimeline.csv in this case (collect first, or run -Mode Parse)" -ForegroundColor Red; return $false }
    $tl = @(Import-Csv -LiteralPath $tlPath -ErrorAction SilentlyContinue)
    $sel = New-Object System.Collections.Generic.List[object]
    foreach ($r in $tl) {
        $t = $null
        try { $t = [datetime]$r.Timestamp } catch { }
        if ($t -and $t -ge $t0 -and $t -le $t1) { $null = $sel.Add($r) }
    }
    if ($sel.Count -eq 0) {
        Write-Host "  no rows in $t0 -> $t1 UTC. Timeline coverage: $(@($tl)[0].Timestamp) -> $(@($tl)[-1].Timestamp)" -ForegroundColor Yellow
        return $true
    }
    $out = Join-Path $script:CsvDir ("timeline_" + $t0.ToString('yyyyMMdd_HHmm') + "_" + $t1.ToString('yyyyMMdd_HHmm') + ".csv")
    $sel.ToArray() | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "  Window: $t0 -> $t1 UTC   rows: $($sel.Count) of $($tl.Count)  ->  $(Split-Path $out -Leaf)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  By source:" -ForegroundColor White
    foreach ($g in (@($sel | Group-Object Source | Sort-Object Count -Descending))) { Write-Host ("    {0,-28} x{1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Busiest minutes:" -ForegroundColor White
    foreach ($g in (@($sel | Group-Object { "$($_.Timestamp)".PadRight(16).Substring(0, 16) } | Sort-Object Count -Descending | Select-Object -First 5))) { Write-Host ("    {0}  x{1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Top actors:" -ForegroundColor White
    foreach ($g in (@($sel | Where-Object { "$($_.Actor)" } | Group-Object Actor | Sort-Object Count -Descending | Select-Object -First 5))) { Write-Host ("    {0,-24} x{1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    Write-Host ""
    Write-Host "  Open the CSV in Excel/Timeline Explorer (sorted, filterable). Report refresh: -Mode Parse." -ForegroundColor Gray
    return $true
}

function Invoke-CanaryMode {
    # Detection self-test: plant safe, self-labeled test activity, enable the logging the
    # hunt rules need, run a collection, then score which detections fired. With -Target,
    # also exercises the cross-host story (lateral SMB touch as canary_test -> R12/attribution).
    # The ONLY mode that changes endpoint state (audit policy + registry + test artifacts) -
    # audit changes are restored afterwards unless -KeepLogging.
    param([switch]$KeepLogging, [string]$Target, [string]$TargetUser)
    Write-Host ""
    Write-Host "=== Detection canary (validate the pipeline end-to-end) ===" -ForegroundColor Cyan
    if (-not (Test-IsAdmin)) {
        Write-Host "  Needs an elevated shell (audit policy + registry changes). Relaunching..." -ForegroundColor Yellow
        $argStr = Get-ArgString
        try { Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $argStr"; return } catch { Write-Host "  Elevation declined - canary needs admin." -ForegroundColor Red; return $false }
    }
    if ($script:SimpleUI) { Write-Host "  Canary is a responder tool - not available in the simple owner UI." -ForegroundColor Yellow; return $false }
    if (-not $Target) { $Target = (Read-Host "  Lateral target PC (IP/name, ENTER = single-host canary)").Trim() }
    Write-Host ""
    Write-Host "  This will, on THIS PC:" -ForegroundColor Yellow
    Write-Host "   - enable Process Creation + cmdline + scriptblock logging (restored after, unless -KeepLogging)"
    Write-Host "   - plant self-labeled test activity: renamed cmd copies (one kept alive as a fake tunnel tool),"
    Write-Host "     canary_test user (created + deleted), recon command burst, certutil fetch of a benign file,"
    Write-Host "     canary_tunneld service (registered + immediately removed - the 7045 event remains),"
    Write-Host "     one labeled line in administrators_authorized_keys (file removed/restored after)"
    Write-Host "   - run a Standard collection and score which hunt rules fired"
    if ($Target) {
        Write-Host "  And on TARGET '$Target':" -ForegroundColor Yellow
        Write-Host "   - enable the same audits (+ Detailed File Share) - restored after"
        Write-Host "   - receive an SMB session + a labeled file write to its admin share (canary_lateral.exe)"
        Write-Host "   - receive its own collection, scored for the cross-host detections"
        Write-Host "  The target must be domain-joined and reachable (this account needs remote-admin rights on it)." -ForegroundColor Yellow
        Write-Host "  Targeting by IP also needs this host's WinRM TrustedHosts to include the target." -ForegroundColor Yellow
    }
    Write-Host "  Lab / validation use only - never run it as part of a live investigation." -ForegroundColor Yellow
    $go = (Read-Host "  Run the canary here? [y/N]").Trim()
    if ($go -notmatch '^(?i)y') { Write-Host "  Cancelled." -ForegroundColor Gray; return $false }
    # remote actions need EXPLICIT credentials when this process itself sits in a remoting session
    # (network token cannot authenticate a second hop) - prompt, or read the lab-automation override
    $tCred = $null
    if ($Target) {
        if (-not $TargetUser) { $TargetUser = (Read-Host "  Target admin account (ENTER = current account)").Trim() }
        if ($TargetUser) {
            if ($env:OPHIRA_CANARY_TARGET_PASS) {
                $tpw = ConvertTo-SecureString $env:OPHIRA_CANARY_TARGET_PASS -AsPlainText -Force
                $tCred = New-Object PSCredential($TargetUser, $tpw)
                Write-Host "  Target credentials: $TargetUser (from OPHIRA_CANARY_TARGET_PASS)" -ForegroundColor DarkGray
            } else { $tCred = Get-Credential -UserName $TargetUser -Message "Password for target $Target" }
            if (-not $tCred) { $TargetUser = '' }
        }
        if (-not $TargetUser) { Write-Host "  No target credentials - remote leg uses the current account (works only from a locally-launched, interactive session)." -ForegroundColor DarkYellow }
    }

    # ---- phase 1: enable logging (capturing prior state for restore) ----
    Write-Host ""
    Write-Host "  [1/4] Enabling logging..." -ForegroundColor Cyan
    $undo = New-Object System.Collections.Generic.List[string]
    foreach ($sub in @('Process Creation', 'User Account Management', 'Security Group Management')) {
        $before = (& auditpol.exe /get /subcategory:"$sub" 2>$null | Out-String)
        if ($before -match '(?i)Success') { Write-Host "    $sub - already on" -ForegroundColor DarkGray; continue }
        $null = & auditpol.exe /set /subcategory:"$sub" /success:enable 2>&1
        $undo.Add("auditpol|$sub")
        Write-Host "    $sub - enabled" -ForegroundColor Gray
    }
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $cmdHad = (Get-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    if ("$cmdHad" -ne '1') {
        if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
        if ($null -eq $cmdHad) { New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -Force | Out-Null; $undo.Add("regdel|$auditKey|ProcessCreationIncludeCmdLine_Enabled") }
        else { Set-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Force; $undo.Add("regset|$auditKey|ProcessCreationIncludeCmdLine_Enabled|$cmdHad") }
        Write-Host "    4688 command line - enabled" -ForegroundColor Gray
    } else { Write-Host "    4688 command line - already on" -ForegroundColor DarkGray }
    $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $sbHad = (Get-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    if ("$sbHad" -ne '1') {
        if (-not (Test-Path $psKey)) { New-Item -Path $psKey -Force | Out-Null }
        if ($null -eq $sbHad) { New-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force | Out-Null; $undo.Add("regdel|$psKey|EnableScriptBlockLogging") }
        else { Set-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -Value 1 -Force; $undo.Add("regset|$psKey|EnableScriptBlockLogging|$sbHad") }
        Write-Host "    PowerShell script block logging - enabled" -ForegroundColor Gray
    } else { Write-Host "    PowerShell script block logging - already on" -ForegroundColor DarkGray }
    $bUndo = @()
    if ($Target) {
        Write-Host "    target ${Target}: enabling audits..." -ForegroundColor Gray
        try {
            $rc = @{ ComputerName = $Target; ErrorAction = 'Stop' }
            if ($tCred) { $rc.Credential = $tCred }
            $bUndo = @(Invoke-Command @rc -ScriptBlock {
                param([string[]]$Subs)
                $undo = @()
                foreach ($sub in $Subs) {
                    $before = (& auditpol.exe /get /subcategory:"$sub" 2>$null | Out-String)
                    if ($before -match '(?i)Success') { continue }
                    $null = & auditpol.exe /set /subcategory:"$sub" /success:enable 2>&1
                    $undo += "auditpol|$sub"
                }
                return $undo
            } -ArgumentList (, @('Process Creation', 'User Account Management', 'Security Group Management', 'Detailed File Share')))
            Write-Host "    target ${Target}: audits ready ($(@($bUndo).Count) newly enabled)" -ForegroundColor Gray
        } catch {
            Write-Host "    target unreachable/forbidden ($($_.Exception.Message)) - continuing single-host" -ForegroundColor DarkYellow
            $Target = ''
        }
    }

    # ---- phase 2: plant the battery (everything self-labeled 'canary') ----
    Write-Host "  [2/4] Planting test activity..." -ForegroundColor Cyan
    $canExe = Join-Path $env:PUBLIC 'canary_renamed.exe'
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $canExe -Force
    $null = & $canExe /c "echo canary > `"$env:TEMP\canary_out.txt`"" 2>&1
    Write-Host "    renamed cmd copy run (canary_renamed.exe)" -ForegroundColor Gray
    # tunnel-tool plant: named for a tunnel binary + kept alive so it is RUNNING at collect time
    # (fires R23 via the live process and R1/R1b via the cmd identity; killed in cleanup)
    $ngProc = $null
    $canNgrok = Join-Path $env:PUBLIC 'canary_ngrok.exe'
    try {
        Copy-Item "$env:SystemRoot\System32\cmd.exe" $canNgrok -Force -ErrorAction Stop
        $ngProc = Start-Process -FilePath $canNgrok -ArgumentList '/c', 'ping -n 400 127.0.0.1 > nul' -WindowStyle Hidden -PassThru -ErrorAction Stop
        Write-Host "    canary_ngrok.exe running (kept alive through collection)" -ForegroundColor Gray
    } catch { Write-Host "    canary_ngrok plant failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    # service-install plant: registered + immediately removed - only the 7045 event remains
    if ($ngProc) {
        $null = & sc.exe create canary_tunneld binPath= "$canNgrok" start= demand 2>&1
        $null = & sc.exe delete canary_tunneld 2>&1
        Write-Host "    canary_tunneld service registered + removed (7045 evidence remains)" -ForegroundColor Gray
    }
    # SSH trust plant: one labeled key line (prior file state captured; restored/removed in cleanup)
    $akFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $akPrev = $null
    $akCreated = $false
    $akOk = $false
    try {
        if (Test-Path -LiteralPath $akFile) { $akPrev = @(Get-Content -LiteralPath $akFile -ErrorAction Stop | ForEach-Object { "$_" }) }
        else {
            $akDir = Split-Path $akFile -Parent
            if (-not (Test-Path $akDir)) { New-Item -ItemType Directory -Path $akDir -Force | Out-Null }
            $akCreated = $true
        }
        Add-Content -LiteralPath $akFile -Value 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICANARYKEYLINE canary@ophira-selftest' -ErrorAction Stop
        $akOk = $true
        Write-Host "    labeled line planted in administrators_authorized_keys" -ForegroundColor Gray
    } catch { Write-Host "    authorized_keys plant skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    $canPass = 'Canary!2026'
    $null = & net.exe user canary_test $canPass /add 2>&1
    $null = & net.exe localgroup administrators canary_test /add 2>&1
    Write-Host "    canary_test user created + added to Administrators (kept alive for the lateral leg)" -ForegroundColor Gray
    if ($Target) {
        $lateralOk = $false
        $null = & net.exe use "\\$Target\C$" /delete 2>&1
        # authenticate as the TARGET ADMIN when we have those credentials (R12 needs the admin
        # share anyway; canary_test exercises account lifecycle locally, not this leg)
        $useUser = "$env:USERDOMAIN\canary_test"; $usePass = $canPass
        if ($tCred) { $useUser = $tCred.UserName; $usePass = $tCred.GetNetworkCredential().Password }
        $nu = & net.exe use "\\$Target\C$" $usePass /user:"$useUser" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $null = & cmd.exe /c "dir \\$Target\C$\Users\Public > nul" 2>&1
            try {
                Copy-Item $canExe "\\$Target\C$\Users\Public\canary_lateral.exe" -Force -ErrorAction Stop
                $lateralOk = $true
                Write-Host "    lateral: SMB session as $useUser + canary_lateral.exe written to target admin share" -ForegroundColor Gray
            } catch { Write-Host "    lateral write failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
            $null = & net.exe use "\\$Target\C$" /delete 2>&1
        } else {
            Write-Host "    lateral SMB failed (exit $LASTEXITCODE): $(($nu | Where-Object { "$_" } | Select-Object -Last 1))" -ForegroundColor DarkYellow
            Write-Host "    B-side checks will be BLIND" -ForegroundColor DarkYellow
        }
    }
    $recon = @(
        { & whoami.exe 2>&1 }, { & net.exe user 2>&1 }, { & net.exe localgroup administrators 2>&1 },
        { & nltest.exe /dclist:"$env:USERDOMAIN" 2>&1 }, { & systeminfo.exe 2>&1 }, { & ipconfig.exe /all 2>&1 },
        { & quser.exe 2>&1 }, { & tasklist.exe 2>&1 }, { & klist.exe 2>&1 }, { & netstat.exe -an 2>&1 }
    )
    foreach ($rcmd in $recon) { $null = & $rcmd }
    Write-Host "    discovery burst (10 recon tools)" -ForegroundColor Gray
    try {
        $null = & certutil.exe -urlcache -f 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/README.md' "$env:TEMP\canary_dl.bin" 2>&1
        Write-Host "    certutil benign fetch" -ForegroundColor Gray
    } catch { Write-Host "    certutil fetch skipped (offline?)" -ForegroundColor DarkYellow }
    $null = & net.exe localgroup administrators canary_test /delete 2>&1
    $null = & net.exe user canary_test /delete 2>&1
    if ($Target) { $null = Invoke-Command @rc -ScriptBlock { Remove-Item C:\Users\Public\canary_lateral.exe -Force -ErrorAction SilentlyContinue } }
    Write-Host "    canary_test removed (all planted artifacts are self-labeled)" -ForegroundColor Gray

    # ---- phase 3: collection (Standard: Quick excludes the 4688/auth parses the scorecard reads) ----
    Write-Host "  [3/4] Collecting (Standard preset, ~3-5 min)..." -ForegroundColor Cyan
    $kit = Get-KitRoot
    $before = @(Get-ChildItem -Path $kit -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue)
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode Collect -NoMenu -NoElevate -Preset Standard -CaseID CANARY -OutputPath `"$kit`""
    $null = Start-Process -FilePath 'powershell.exe' -ArgumentList $cmd -Wait -WindowStyle Hidden
    $case = @(Get-ChildItem -Path $kit -Directory -Filter 'OPHIRA_*' -ErrorAction SilentlyContinue | Where-Object { $before -notcontains $_ } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if (-not $case) { Write-Host "  collection produced no case folder - see collection.log" -ForegroundColor Red; return $false }
    $csv = Join-Path $case.FullName 'csv'
    $bZip = $null
    if ($Target) {
        Write-Host "  [3/4] Collecting on target $Target (Standard)..." -ForegroundColor Cyan
        $beforeZips = @(Get-ChildItem -Path (Join-Path $kit 'collections') -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue)
        try {
            Invoke-DeployMode -Targets @($Target) -DeployPreset 'Standard' -Cred $tCred -DeployCaseID 'CANARY' -DeploySharePath '' -Threads 1 -PushBin $false -DeployLogHours 168
            $bZip = Get-ChildItem -Path (Join-Path $kit 'collections') -Filter 'OPHIRA_*.zip' -File -ErrorAction SilentlyContinue | Where-Object { $beforeZips -notcontains $_ } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        } catch { Write-Host "    target collection failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
        if (-not $bZip) { Write-Host "    no result zip from target - B-side checks will be BLIND" -ForegroundColor DarkYellow }
    }

    # ---- phase 4: scorecard ----
    Write-Host ""
    Write-Host "  [4/4] Scorecard - case: $(Split-Path $case.FullName -Leaf)" -ForegroundColor Cyan
    Write-Host ""
    $hf = @(Import-Csv -LiteralPath (Join-Path $csv 'hunt_findings.csv') -ErrorAction SilentlyContinue)
    $procRows = @(Import-Csv -LiteralPath (Join-Path $csv 'security_proc_events.csv') -ErrorAction SilentlyContinue)
    $authRows = @(Import-Csv -LiteralPath (Join-Path $csv 'security_auth_events.csv') -ErrorAction SilentlyContinue)
    $pcRows = @(Import-Csv -LiteralPath (Join-Path $csv 'sysmon_proc_create.csv') -ErrorAction SilentlyContinue)
    $raRows = @(Import-Csv -LiteralPath (Join-Path $csv 'remote_access.csv') -ErrorAction SilentlyContinue)
    $sysSvcRows = @(Import-Csv -LiteralPath (Join-Path $csv 'system_new_services.csv') -ErrorAction SilentlyContinue)
    $score = 0; $possible = 0
    $c4720 = @($authRows | Where-Object { "$($_.EventId)" -eq '4720' }).Count
    $c4732 = @($authRows | Where-Object { @('4728', '4732', '4756') -contains "$($_.EventId)" }).Count
    $r6Why = if ($c4720 -eq 0 -and $c4732 -eq 0) { 'User Account Management audit not active' } elseif ($c4732 -eq 0) { 'Security Group Management audit not active (4720 seen, no group change)' } else { 'auth telemetry missing' }
    $checks = @(
        @{ L = 'R1b  renamed LOLBin at rest';      Hit = @($hf | Where-Object { $_.Rule -match 'Renamed LOLBin at rest' }).Count;        Data = @($pcRows | Where-Object { $_ -match 'canary_renamed' }).Count;  DataWhy = 'Sysmon not present or EID 1 not captured' }
        @{ L = 'R6   account lifecycle';           Hit = @($hf | Where-Object { $_.Rule -match 'Account lifecycle' }).Count;              Data = ($c4720 + $c4732); DataWhy = $r6Why }
        @{ L = 'R10  proxy-execution (certutil)';  Hit = @($hf | Where-Object { $_.Rule -match 'proxy-execution' }).Count;                Data = @($procRows | Where-Object { $_ -match 'canary|certutil' }).Count; DataWhy = '4688/cmdline audit not active at plant time' }
        @{ L = 'R13  discovery command storm';     Hit = @($hf | Where-Object { $_.Rule -match 'Discovery command storm' }).Count;        Data = @($procRows | Where-Object { $_ -match 'whoami|systeminfo|nltest' }).Count; DataWhy = '4688 audit not active at plant time' }
        @{ L = 'R23  remote-access tunnel (canary_ngrok)'; Hit = @($hf | Where-Object { $_.Rule -match 'Remote-access tunnel' }).Count; Data = @($raRows | Where-Object { $_ -match 'canary_ngrok' }).Count + @($sysSvcRows | Where-Object { $_ -match 'canary_ngrok|canary_tunneld' }).Count; DataWhy = 'module 8.16 + processes missing (Standard preset required)' }
        @{ L = 'RA   service-install telemetry (7045 canary_tunneld)'; Hit = @($sysSvcRows | Where-Object { $_ -match 'canary_tunneld' }).Count; Data = @($sysSvcRows).Count; DataWhy = 'System log module (4.5) did not run - no 7045 rows' }
        @{ L = 'R26  SSH authorized_keys plant';   Hit = @($hf | Where-Object { $_.Rule -match 'authorized_keys' }).Count;                Data = @($raRows | Where-Object { $_ -match 'administrators_authorized_keys' }).Count; DataWhy = 'module 8.16 missing (Standard preset required)' }
    )
    foreach ($c in $checks) {
        $possible++
        if ($c.Hit -gt 0) { $score++; Write-Host ("    {0}  FIRED" -f $c.L) -ForegroundColor Green }
        elseif ($c.Data -gt 0) { Write-Host ("    {0}  MISS - data present (x{1}) but rule silent: file this" -f $c.L, $c.Data) -ForegroundColor Red }
        else { Write-Host ("    {0}  BLIND - no telemetry: {1}" -f $c.L, $c.DataWhy) -ForegroundColor Yellow }
    }
    Write-Host "    R25  RDP ServiceDll tamper  n/a - not planted (TermService tamper too invasive for a canary)" -ForegroundColor DarkGray
    $verdict = $null
    try { $verdict = (Get-Content -LiteralPath (Join-Path $case.FullName 'verdict.json') -Raw | ConvertFrom-Json) } catch { }
    Write-Host ""
    Write-Host ("    Pipeline: {0}/{1} canary detections fired. Case verdict: {2}" -f $score, $possible, $(if ($verdict) { "$($verdict.Level) ($($verdict.ConfidencePercent)%)" })) -ForegroundColor $(if ($score -eq $possible) { 'Green' } elseif ($score -gt 0) { 'Yellow' } else { 'Red' })
    Write-Host "    Report: $((Join-Path $case.FullName 'report.html'))" -ForegroundColor Gray

    # ---- phase 4b: cross-host scorecard (target side) ----
    if ($bZip) {
        Write-Host ""
        Write-Host "  Cross-host scorecard - target case: $($bZip.BaseName)" -ForegroundColor Cyan
        $bDir = Join-Path ([IO.Path]::GetTempPath()) ("canary_b_" + (Get-Date -Format 'HHmmss'))
        try { Expand-Archive -LiteralPath $bZip.FullName -DestinationPath $bDir -Force } catch { Write-Host "    cannot extract target case: $($_.Exception.Message)" -ForegroundColor Red; $bDir = $null }
        if ($bDir) {
            $bcsv = Join-Path $bDir 'csv'
            $bAuth = @(Import-Csv -LiteralPath (Join-Path $bcsv 'security_auth_events.csv') -ErrorAction SilentlyContinue)
            $bShare = @(Import-Csv -LiteralPath (Join-Path $bcsv 'security_share_access.csv') -ErrorAction SilentlyContinue)
            $bSess = @(Import-Csv -LiteralPath (Join-Path $bcsv 'session_activity.csv') -ErrorAction SilentlyContinue)
            $bHf = @(Import-Csv -LiteralPath (Join-Path $bcsv 'hunt_findings.csv') -ErrorAction SilentlyContinue)
            $bAcct = if ($tCred) { ($tCred.UserName -split '\\')[-1] } else { 'canary_test' }
            $c4624 = @($bAuth | Where-Object { "$($_.EventId)" -eq '4624' -and "$($_.LogonType)" -eq '3' -and "$($_.Account)" -match $bAcct }).Count
            $c5145 = @($bShare | Where-Object { $_ -match 'canary|C\$' }).Count
            $cJoin = @($bSess | Where-Object { $_ -match 'canary' }).Count
            $bChecks = @(
                @{ L = "B 4624 type-3 lateral logon ($bAcct)"; Hit = $c4624; Data = $c4624; DataWhy = 'network logon did not arrive (audit off on target, or SMB leg failed)' }
                @{ L = 'B 5145 share access captured';       Hit = $c5145; Data = $c5145;            DataWhy = 'Detailed File Share audit not active at touch time' }
                @{ L = 'B session attribution join';         Hit = $cJoin; Data = $cJoin;                DataWhy = 'no canary share/process activity to attribute' }
                @{ L = 'B R12  admin-share executable staging'; Hit = @($bHf | Where-Object { $_.Rule -match 'Admin-share' }).Count; Data = @($bShare | Where-Object { $_ -match 'canary_lateral\.exe' }).Count; DataWhy = '5145 rows missing (audit off) or write leg failed' }
            )
            $bs = 0
            foreach ($c in $bChecks) {
                if ($c.Hit -gt 0) { $bs++; Write-Host ("    {0}  FIRED" -f $c.L) -ForegroundColor Green }
                elseif ($c.Data -gt 0) { Write-Host ("    {0}  MISS - data present (x{1}) but rule silent: file this" -f $c.L, $c.Data) -ForegroundColor Red }
                else { Write-Host ("    {0}  BLIND - {1}" -f $c.L, $c.DataWhy) -ForegroundColor Yellow }
            }
            Write-Host ("    Cross-host: {0}/{1} fired. Fleet stitch check: .\Ophira.ps1 -Mode Analyze -AnalyzePath <collections>" -f $bs, $bChecks.Count) -ForegroundColor Gray
            Remove-Item $bDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # ---- cleanup + restore ----
    if ($ngProc -and -not $ngProc.HasExited) { $null = Stop-Process -Id $ngProc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $canExe, $canNgrok, "$env:TEMP\canary_out.txt", "$env:TEMP\canary_dl.bin" -Force -ErrorAction SilentlyContinue
    if ($akOk) {
        try {
            if ($akCreated) { Remove-Item -LiteralPath $akFile -Force -ErrorAction Stop }
            else { Set-Content -LiteralPath $akFile -Value $akPrev -ErrorAction Stop }
            Write-Host "  administrators_authorized_keys restored." -ForegroundColor DarkGray
        } catch { Write-Host "  authorized_keys restore FAILED: $akFile - remove the canary line manually" -ForegroundColor Yellow }
    }
    if (-not $KeepLogging -and $undo.Count -gt 0) {
        Write-Host "  Restoring original audit state..." -ForegroundColor DarkGray
        foreach ($u in $undo) {
            $p2 = $u -split '\|'
            switch ($p2[0]) {
                'auditpol' { $null = & auditpol.exe /set /subcategory:"$($p2[1])" /success:disable 2>&1 }
                'regdel' { Remove-ItemProperty -LiteralPath $p2[1] -Name $p2[2] -Force -ErrorAction SilentlyContinue }
                'regset' { Set-ItemProperty -LiteralPath $p2[1] -Name $p2[2] -Value $p2[3] -Force }
            }
        }
        Write-Host "  Restored. Re-run with -KeepLogging to leave logging enabled." -ForegroundColor DarkGray
    } elseif ($KeepLogging) { Write-Host "  Logging left enabled (-KeepLogging)." -ForegroundColor DarkGray }
    if ($Target -and @($bUndo).Count -gt 0 -and -not $KeepLogging) {
        try {
            $null = Invoke-Command @rc -ScriptBlock {
                param([string[]]$Undo)
                foreach ($u in $Undo) { $p2 = $u -split '\|'; $null = & auditpol.exe /set /subcategory:"$($p2[1])" /success:disable 2>&1 }
            } -ArgumentList (, @($bUndo))
            Write-Host "  Target audit state restored." -ForegroundColor DarkGray
        } catch { Write-Host "  Target audit restore failed ($($_.Exception.Message)) - restore manually on ${Target}:" -ForegroundColor Yellow; $bUndo | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } }
    }
    return $true
}

function Read-WizardLine {
    # Prompt helper for multi-step wizards: trims input; 'B'/'back' returns $null so the
    # wizard can redo the previous step (or cancel when on the first one).
    param([string]$Prompt)
    $v = (Read-Host "$Prompt  (B = back)").Trim()
    if ($v -match '^(?i)b(ack)?$') { return $null }
    return $v
}

function Invoke-DeployWizard {
    $kit = Get-KitRoot
    $hostsFile = Join-Path $kit 'hosts.txt'
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  PUSH & RUN ON REMOTE PCS" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Pushes Ophira to remote PCs over WinRM, runs a collection there"
    Write-Host "  and pulls the result ZIPs back to this PC (or uploads to a share)."
    Write-Host "  Needs: WinRM enabled on targets + an admin account on them."
    Write-Host "  Answer 'B' at any question to go back and change the previous one."
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    $defTargets = $script:CfgTargets
    if (-not $defTargets -and (Test-Path -LiteralPath $hostsFile)) { $defTargets = 'hosts.txt' }
    $defPreset = if ($script:CfgDeployPreset) { $script:CfgDeployPreset } else { 'Standard' }
    $pushDef = if ($script:CfgPushTools) { 'Y' } else { 'N' }
    $threads = if ($script:CfgThreads -gt 0) { $script:CfgThreads } else { $MaxThreads }
    $targets = @()
    $targetsIn = ''
    $cred = $null
    $preset = $defPreset
    $push = [bool]$script:CfgPushTools
    $shareIn = ''
    $advLogHours = -1
    $advLogWindow = ''
    $step = 1
    while ($true) {
        switch ($step) {
            1 {
                while ($true) {
                    $prompt = "  Target PCs (comma-separated, or a .txt file path)$(if ($defTargets) { " [$defTargets]" })"
                    $targetsIn = Read-WizardLine $prompt
                    if ($null -eq $targetsIn) { Write-Host "  Deploy cancelled." -ForegroundColor Yellow; return }
                    if (-not $targetsIn -and $defTargets) { $targetsIn = $defTargets.Trim() }
                    if (-not $targetsIn) { Write-Host "  please enter at least one target" -ForegroundColor Red; continue }
                    if ($targetsIn -match '\.txt$') {
                        $tf = $null
                        if (Test-Path -LiteralPath $targetsIn) { $tf = $targetsIn }
                        elseif (Test-Path -LiteralPath (Join-Path $kit $targetsIn)) { $tf = Join-Path $kit $targetsIn }
                        if ($tf) {
                            $targets = @(Get-Content -LiteralPath $tf | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
                            if ($targets.Count -eq 0) { Write-Host "  file has no host entries: $tf" -ForegroundColor Red }
                        } else { Write-Host "  file not found: $targetsIn" -ForegroundColor Red }
                    } else {
                        $targets = @($targetsIn -split '[,;\s]+' | Where-Object { $_ })
                    }
                    if ($targets.Count -gt 0) { break }
                }
                $step = 2
            }
            2 {
                Write-Host ""
                $cIn = Read-WizardLine "  Credentials: ENTER = your current account ($env:USERDOMAIN\$env:USERNAME), or type a username"
                if ($null -eq $cIn) { $step = 1; continue }
                $cred = $null
                if ($cIn) {
                    $cred = Get-Credential -UserName $cIn -Message "Password for remote PCs"
                    if (-not $cred) { Write-Host "  no credentials entered - using current account" -ForegroundColor Yellow; $cred = $null }
                }
                $step = 3
            }
            3 {
                $pIn = Read-WizardLine "  Collection depth: 1=Quick (~1-2 min/PC) or 2=Standard (~3-5 min/PC) [$defPreset]"
                if ($null -eq $pIn) { $step = 2; continue }
                $preset = $defPreset
                if ($pIn -match '^1' -or $pIn -match '^(?i)q(uick)?$') { $preset = 'Quick' }
                elseif ($pIn -match '^2' -or $pIn -match '^(?i)s(tandard)?$') { $preset = 'Standard' }
                $step = 4
            }
            4 {
                $p2In = Read-WizardLine "  Also push hayabusa for on-host Sigma detection (removed after run)? [y/N] (default $pushDef)"
                if ($null -eq $p2In) { $step = 3; continue }
                $push = if ($p2In) { $p2In -match '^(?i)y' } else { [bool]$script:CfgPushTools }
                $step = 5
            }
            5 {
                if ($script:CfgDeployShare) {
                    $shareIn = Read-WizardLine "  Upload results to share (UNC path, 'none' = pull to collections\, ENTER = $($script:CfgDeployShare))"
                    if ($null -eq $shareIn) { $step = 4; continue }
                    if (-not $shareIn) { $shareIn = $script:CfgDeployShare }
                    if ($shareIn -ieq 'none') { $shareIn = '' }
                } else {
                    $shareIn = Read-WizardLine "  Upload results to a central share instead of pulling back? (UNC path, ENTER = pull to collections\)"
                    if ($null -eq $shareIn) { $step = 4; continue }
                }
                if ($shareIn -and -not (Test-Path $shareIn)) {
                    Write-Host "  WARNING: share not reachable right now ($shareIn) - will retry during run" -ForegroundColor Yellow
                }
                $step = 6
            }
            6 {
                $advLogHours = -1
                $advLogWindow = ''
                $advIn = Read-WizardLine "  Advanced options (Full depth, log window, parallelism)? [y/N]"
                if ($null -eq $advIn) { $step = 5; continue }
                if ($advIn -notmatch '^(?i)y') { $step = 7; continue }
                $dIn = Read-WizardLine "  Depth: 1=Quick  2=Standard  3=Full - heaviest, includes SRUM etc. [current: $preset]"
                if ($null -eq $dIn) { $step = 5; continue }
                if ($dIn -match '^3' -or $dIn -match '^(?i)f(ull)?$') { $preset = 'Full' }
                $lhIn = Read-WizardLine "  Log analysis window (168 = hours, 30d, 3m, 0 = all, or start date 2026-09-01) [ENTER = 168 = 7 days]"
                if ($null -eq $lhIn) { $step = 5; continue }
                if ($lhIn) {
                    if ($lhIn -match '^\d+$') { $advLogHours = [int]$lhIn }
                    elseif ($null -eq (ConvertTo-LogStart $lhIn)) { Write-Host "  window not understood - keeping the default 7 days" -ForegroundColor Yellow }
                    else { $advLogWindow = $lhIn }
                }
                $thIn = Read-WizardLine "  Hosts to process in parallel (ENTER = current setting)"
                if ($null -eq $thIn) { $step = 5; continue }
                if ($thIn -match '^\d+$' -and [int]$thIn -gt 0) { $threads = [int]$thIn }
                $step = 7
            }
            7 {
                $shown = ($targets | Select-Object -First 5) -join ', '
                if ($targets.Count -gt 5) { $shown += ", ...($($targets.Count) total)" }
                $credNote = if ($cred) { $cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME (current)" }
                Write-Host ""
                Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
                Write-Host "  Ready to deploy. Please confirm:" -ForegroundColor White
                Write-Host "    Targets   : $shown"
                Write-Host "    Depth     : $preset"
                if ($advLogHours -ge 0) { Write-Host "    Log window: $(if ($advLogHours -eq 0) { 'all available' } else { "$advLogHours hours" })" }
                if ($advLogWindow) { Write-Host "    Log window: from $advLogWindow" }
                Write-Host "    Account   : $credNote"
                Write-Host "    hayabusa  : $(if ($push) { 'push + run + remove' } else { 'not pushed' })"
                Write-Host "    Results   : $(if ($shareIn) { "upload to $shareIn" } else { 'pull to collections\' })"
                if ($CaseID) { Write-Host "    Case ID   : $CaseID" }
                Write-Host "    Parallel  : $threads hosts at once"
                Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
                $go = Read-WizardLine "  Start? [Y/n]"
                if ($null -eq $go) { $step = 6; continue }
                if ($go -match '^[Nn]') { Write-Host "  Deploy cancelled." -ForegroundColor Yellow; return }
                $step = 8
            }
            8 {
                Invoke-DeployMode -Targets $targets -DeployPreset $preset -Cred $cred -DeployCaseID $CaseID -DeploySharePath $shareIn -Threads $threads -PushBin $push -DeployLogHours $advLogHours -DeployLogWindow $advLogWindow
                $rem = Read-WizardLine "  Remember these answers for next time? [y/N]"
                if ($rem -match '^(?i)y') {
                    $vals = @{ TARGETS = $targetsIn; PRESET = $preset; PUSHTOOLS = $(if ($push) { 'yes' } else { 'no' }) }
                    if ($shareIn) { $vals['DEPLOYSHARE'] = $shareIn }
                    if (Save-OphiraConfig -Values $vals) { Write-Host "  Saved to ophira.config.txt" -ForegroundColor Green }
                }
                return
            }
        }
    }
}

function Invoke-AnalyzeWizard {
    $kit = Get-KitRoot
    $def = Join-Path $kit 'collections'
    if (-not (Test-Path -LiteralPath $def)) { $def = $kit }
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  ANALYZE COLLECTED RESULTS" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Merges OPHIRA_*.zip case files in a folder into one fleet report"
    Write-Host "  (deploy pulls results into 'collections' by default)."
    Write-Host "================================================================" -ForegroundColor Cyan
    while ($true) {
        $pIn = (Read-Host "  Folder with case ZIPs [$def]").Trim()
        $path = if ($pIn) { $pIn } else { $def }
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Host "  not found: $path" -ForegroundColor Red
            $retry = (Read-Host "  Enter another path, or press ENTER to cancel").Trim()
            if (-not $retry) { return }
            $def = $retry
            continue
        }
        Invoke-AnalyzeMode -Path $path -HayabusaExe $HayabusaPath
        return
    }
}

$bareLaunch = ($Mode -eq 'Collect' -and -not $PSBoundParameters.ContainsKey('Mode') -and -not $NoMenu -and -not $script:SimpleUI)
if ($bareLaunch -and [Environment]::UserInteractive) {
    $role = Show-RoleGate
    if ($role -eq 'owner') {
        $script:SimpleUI = $true
        $script:ExtraRelaunchArgs += @('-SimpleUI')
    } else {
        while ($true) {
            $chosenTask = Show-TaskMenu
            if (-not $chosenTask) { exit 0 }
            if ($chosenTask -eq 'Collect') {
                $script:ExtraRelaunchArgs += @('-Mode', 'Collect')
                break
            }
            switch ($chosenTask) {
                'Deploy' { Invoke-DeployWizard }
                'Analyze' { Invoke-AnalyzeWizard }
                'Setup' { Invoke-SetupWizard }
        'UpdateRules' { if (-not (Invoke-UpdateRulesMode)) { exit 1 } }
                'Tune' { Invoke-TuneMode | Out-Null }
                'Parse' { Invoke-ParseMode | Out-Null }
                'Process' { Invoke-ProcessPivot | Out-Null }
                'Timeline' { Invoke-TimelineMode | Out-Null }
                'Canary' { Invoke-CanaryMode -KeepLogging:$KeepLogging -Target $CanaryTarget -TargetUser $CanaryTargetUser | Out-Null }
                'Links' { Show-ToolLinks }
            }
            Write-Host ""
            Write-Host "Press any key to return to the menu..." -ForegroundColor DarkGray
            try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
        }
    }
}

if ($Mode -ne 'Collect') {
    switch ($Mode) {
        'Links' { Show-ToolLinks }
        'Setup' { Invoke-SetupMode -Wanted $SetupTools }
        'Analyze' { Invoke-AnalyzeMode -Path $AnalyzePath -HayabusaExe $HayabusaPath }
        'Deploy' {
            if ($TargetsFile -and (Test-Path -LiteralPath $TargetsFile)) {
                $ComputerName += @(Get-Content -LiteralPath $TargetsFile | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
            }
            if (-not $ComputerName) { Write-Host "-ComputerName or -TargetsFile required for Deploy mode" -ForegroundColor Red; exit 1 }
            Invoke-DeployMode -Targets $ComputerName -DeployPreset $Preset -Cred $Credential -DeployCaseID $CaseID -DeploySharePath $SharePath -Threads $MaxThreads -PushBin ([bool]$PushTools) -DeployLogHours $LogHours -DeployLogWindow $LogWindow
        }
        'UpdateRules' { Invoke-UpdateRulesMode }
        'Tune' { Invoke-TuneMode | Out-Null }
        'Parse' { Invoke-ParseMode -Path $ParsePath | Out-Null }
        'Process' { Invoke-ProcessPivot -Path $ParsePath -Indicator $ProcessName | Out-Null }
        'Timeline' { Invoke-TimelineMode -Path $ParsePath -Start $TimelineStart -End $TimelineEnd | Out-Null }
        'Canary' { Invoke-CanaryMode -KeepLogging:$KeepLogging -Target $CanaryTarget -TargetUser $CanaryTargetUser | Out-Null }
    }
    exit 0
}

if (-not (Test-IsAdmin) -and -not $NoElevate) {
    Write-Host "[!] Not elevated. Requesting administrator rights..." -ForegroundColor Yellow
    $argStr = Get-ArgString
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $argStr"
        exit
    } catch {
        Write-Host "[!] Elevation declined. Continuing with LIMITED access (many modules will fail)." -ForegroundColor Red
        try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
    }
}

$Computer = $env:COMPUTERNAME
$StartTime = Get-Date
$Stamp = $StartTime.ToString('yyyyMMdd_HHmmss')
$BaseDir = if ($OutputPath) { $OutputPath } else { Get-KitRoot }
$CaseName = "OPHIRA_${Computer}_${Stamp}"
$CaseDir = Join-Path $BaseDir $CaseName
$CsvDir = Join-Path $CaseDir 'csv'
$RawDir = Join-Path $CaseDir 'raw'
$MemDir = Join-Path $CaseDir 'memory'
$CaseLog = Join-Path $CaseDir 'collection.log'

New-Item -ItemType Directory -Path $CsvDir, $RawDir -Force | Out-Null
$script:FlashLines = New-Object System.Collections.Generic.List[string]
$script:CurrentCaseID = $CaseID
$script:CurrentAnalyst = $Analyst

$IsAdmin = Test-IsAdmin
$Sysmon = Get-SysmonState
Clear-Host
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   ___  ___  ___ _  _ ___ _____ _   ___ ___   " -ForegroundColor Cyan
Write-Host "  | _ \/ _ \| __| \| | _ \_   _/_\ | _ \ _ \ " -ForegroundColor Cyan
Write-Host "  |  _/ (_) | _|| .\` |  _/ | |/ _ \|   /  _/" -ForegroundColor Cyan
Write-Host "  |_|  \___/|___|_|\_|_|   |_/_/ \_\_|_\_|_\ " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Ophira v$ScriptVersion  -  single-script Windows IR toolkit" -ForegroundColor White
Write-Host "  READ-ONLY: collects evidence, never changes the system" -ForegroundColor DarkGray
Write-Host "  Modes: -Mode Collect | Deploy | Analyze | Setup | Links" -ForegroundColor DarkGray
Write-Host "----------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "  Host      : $Computer"
Write-Host "  OS User   : $env:USERNAME"
    Write-Host "  Elevated  : $(if ($IsAdmin) { 'YES - full access' } else { 'NO - LIMITED (many modules will fail)' })" -ForegroundColor $(if ($IsAdmin) { 'Green' } else { 'Red' })
    Write-Host "  Sysmon    : $(if ($Sysmon) { 'DETECTED - logs will be collected' } else { 'not present' })" -ForegroundColor $(if ($Sysmon) { 'Green' } else { 'DarkGray' })
Write-Host "  Output    : $CaseDir"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-CaseLog "Ophira v$ScriptVersion started on $Computer by $env:USERNAME (admin=$IsAdmin, sysmon=$Sysmon)" 'Gray' -NoConsole

Invoke-FlashTriage

$selection = Get-PresetSelection -P $Preset
if ($NoMenu -or $script:SimpleUI) {
    Write-Host ""
    if ($script:SimpleUI) {
        Write-Host "  First quick check done - details are saved for the security team." -ForegroundColor Cyan
        Write-Host "  Now collecting the full evidence. This usually takes 3-5 minutes." -ForegroundColor Cyan
        Write-Host "  Please DO NOT close this window until it says DONE." -ForegroundColor Yellow
        Write-Host ""
    } else {
        if ($script:HostRole -ne 'Workstation') { Write-CaseLog "Host role detected: $script:HostRole (role telemetry enabled in this preset)" 'Cyan' }
        Write-CaseLog "NoMenu mode: running preset '$Preset' ($(@($selection.Values | Where-Object { $_ }).Count) modules)" 'Cyan'
    }
    if ($Preset -eq 'Flash') {
        Write-CaseLog "Flash-only preset: skipping deep modules" 'Gray'
        $selection = @{}
    }
} else {
    $sel = Show-Menu -Selection $selection
    if (-not $sel) {
        Write-Host "Quit before collection. Flash summary saved to:" -ForegroundColor Yellow
        Write-Host "  $CaseDir\flash_summary.txt"
        exit 0
    }
    $selection = $sel
}

if (@($selection.Values | Where-Object { $_ }).Count -gt 0) {
    Invoke-SelectedModules -Selection $selection
}

New-Package

if ($script:SimpleUI) {
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "     DONE! Everything was collected successfully." -ForegroundColor Green
    Write-Host ""
    if ($script:Verdict) {
        $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
        Write-Host "     RESULT: $($script:Verdict.OwnerLine)" $vColor
        Write-Host "     This is an automated first check - please send the file below" -ForegroundColor DarkGray
        Write-Host "     to your security team so they can confirm it." -ForegroundColor DarkGray
        Write-Host ""
    }
    if ($script:DeltaCount -gt 0) {
        Write-Host "     NOTE: $script:DeltaCount NEW items appeared since the last check." -ForegroundColor Yellow
        Write-Host "     Mention this to your security team - they will see the details." -ForegroundColor Yellow
        Write-Host ""
    }
    if ($script:ShareOk) {
        Write-Host "     Your results were uploaded automatically." -ForegroundColor Green
        Write-Host "     Nothing left to do - you can close this window." -ForegroundColor Green
    } else {
        Write-Host "     Please send this file to your security team:" -ForegroundColor White
        Write-Host ""
        Write-Host "     $script:FinalZipPath" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "     The file location is COPIED to your clipboard (Ctrl+V to paste)." -ForegroundColor White
        Write-Host "     A folder window has opened with the file already selected." -ForegroundColor White
        Write-Host "     If some items failed, send the file anyway - it holds everything" -ForegroundColor DarkGray
        Write-Host "     that could be collected." -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor Green
    try { Set-Clipboard -Value $script:FinalZipPath } catch { }
    if ($script:FinalZipPath -and (Test-Path -LiteralPath $script:FinalZipPath)) {
        try { Start-Process explorer.exe -ArgumentList "/select,`"$($script:FinalZipPath)`"" } catch { }
    }
} elseif (-not $NoMenu) {
    Write-Host ""
    Write-Host "Press any key to close..." -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
}







