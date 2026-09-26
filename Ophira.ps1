<#
Ophira v2.12  -  Windows Incident Response Triage Toolkit
READ-ONLY by design: never modifies the system, only reads and copies data
into its own output folder. Intended to be handed to a system owner or run
by a responder during early triage / threat hunting.
#>

[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Deploy', 'Analyze', 'Setup', 'Links', 'UpdateRules')]
    [string]$Mode = 'Collect',
    [string]$CaseID = "",
    [string]$Analyst = "",
    [string]$OutputPath = "",
    [ValidateSet('Flash', 'Quick', 'Standard', 'Full', 'Custom')]
    [string]$Preset = 'Standard',
    [switch]$NoMenu,
    [switch]$SimpleUI,
    [switch]$IncludeMemory,
    [switch]$PushTools,
    [switch]$Sequential,
    [switch]$NoElevate,
    [int]$LogHours = 168,
    [string]$SharePath = "",
    [string[]]$ComputerName,
    [string]$TargetsFile = '',
    [int]$MaxThreads = 8,
    [string]$AnalyzePath = '.',
    [string]$HayabusaPath = '',
    [string]$DeltaPath = '',
    [string[]]$SetupTools,
    [System.Management.Automation.PSCredential]$Credential
)

$ScriptVersion = "2.12"
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

function Get-LogStart {
    if ($script:LogHours -gt 0) { return (Get-Date).AddHours(-1 * $script:LogHours) }
    return $null
}

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
    $tDir = Get-ToolsDir
    if (-not $tDir) { return $null }
    $f = Join-Path $tDir 'iocs.txt'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    $iocs = @{ Hashes = @{}; Sha1 = @{}; Ips = @{}; Domains = @{} }
    foreach ($line in (Get-Content -LiteralPath $f)) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        if ($l -match '^[a-fA-F0-9]{40}$') { $iocs.Sha1[$l.ToUpper()] = $true; $iocs.Hashes[$l.ToUpper()] = $true }
        elseif ($l -match '^[a-fA-F0-9]{32,64}$') { $iocs.Hashes[$l.ToUpper()] = $true }
        elseif ($l -match '^(\d{1,3}\.){3}\d{1,3}$') { $iocs.Ips[$l] = $true }
        else { $iocs.Domains[$l.ToLower()] = $true }
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
        [pscustomobject]@{ Name = 'winpmem';     Repo = 'Velocidex/winpmem';                Pattern = '^go-winpmem_amd64.*signed\.exe$|^winpmem.*x64.*\.exe$'; Zip = $false }
        [pscustomobject]@{ Name = 'hayabusa';    Repo = 'Yamato-Security/hayabusa';         Pattern = '^hayabusa-[\d\.]+-win-x64\.zip$'; Zip = $true }
        [pscustomobject]@{ Name = 'volatility3'; Repo = 'volatilityfoundation/volatility3'; Pattern = '^volatility3-win-exes-.*\.zip$'; Zip = $true }
        [pscustomobject]@{ Name = 'chainsaw';    Repo = 'WithSecureOpenSource/chainsaw';     Pattern = '^chainsaw_all_platforms\+rules\.zip$'; Zip = $true }
        [pscustomobject]@{ Name = 'AmcacheParser'; Direct = 'https://download.ericzimmermanstools.com/AmcacheParser.zip'; Zip = $true }
        [pscustomobject]@{ Name = 'RBCmd';       Direct = 'https://download.ericzimmermanstools.com/RBCmd.zip'; Zip = $true }
        [pscustomobject]@{ Name = 'MFTECmd';     Direct = 'https://download.ericzimmermanstools.com/MFTECmd.zip'; Zip = $true }
        [pscustomobject]@{ Name = 'PECmd';       Direct = 'https://download.ericzimmermanstools.com/PECmd.zip'; Zip = $true }
        [pscustomobject]@{ Name = 'LECmd';       Direct = 'https://download.ericzimmermanstools.com/LECmd.zip'; Zip = $true }
        [pscustomobject]@{ Name = 'JLECmd';      Direct = 'https://download.ericzimmermanstools.com/JLECmd.zip'; Zip = $true }
        [pscustomobject]@{ Name = 'yara';        Repo = 'VirusTotal/yara-x';                 Pattern = '^yara-x-v[\d\.]+-x86_64-pc-windows-msvc\.zip$'; Zip = $true }
    )
    $installed = @()
    foreach ($t in $catalog) {
        if ($Wanted -and $Wanted.Count -gt 0 -and $t.Name -notin $Wanted) { continue }
        Write-Host ""
        Write-Host "=== $($t.Name) ===" -ForegroundColor Cyan
        try {
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
                $dest = Join-Path $toolsDir $t.Name
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
    Write-Host "hayabusa/volatility3/chainsaw live in tools\<name>\ subfolders - Ophira finds them recursively." -ForegroundColor Gray
}

function Invoke-DeployMode {
    param([string[]]$Targets, [string]$DeployPreset, $Cred, [string]$DeployCaseID, [string]$DeploySharePath, [int]$Threads = 8, [bool]$PushBin = $false, [int]$DeployLogHours = 0)

    $kit = Get-KitRoot
    $scriptPath = Join-Path $kit 'Ophira.ps1'
    $tools = Join-Path $kit 'tools'
    $outFolder = Join-Path $kit 'collections'
    if (-not (Test-Path $scriptPath)) { Write-Host "Ophira.ps1 not found in $kit" -ForegroundColor Red; return }
    if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $toolsDir = if (Test-Path $tools) { $tools } else { $null }
    $binZip = $null
    if ($PushBin -and $toolsDir) {
        $hayDir = Join-Path $toolsDir 'hayabusa'
        if (Test-Path $hayDir) {
            try {
                Write-Host "Packaging hayabusa for push (bin push)..." -ForegroundColor Cyan
                $binZip = Join-Path ([IO.Path]::GetTempPath()) 'ophira-bin-hayabusa.zip'
                if (Test-Path $binZip) { Remove-Item $binZip -Force }
                Compress-Archive -Path "$hayDir\*" -DestinationPath $binZip -CompressionLevel Fastest -Force
                Write-Host "  hayabusa packaged ($([math]::Round((Get-Item $binZip).Length / 1MB, 1)) MB) - will be REMOVED from targets after run" -ForegroundColor Gray
            } catch { Write-Host "  bin packaging failed: $($_.Exception.Message) - continuing without on-host Sigma" -ForegroundColor Yellow; $binZip = $null }
        } else { Write-Host "  tools\hayabusa not found - PushTools has nothing to push" -ForegroundColor Yellow }
    }

    $worker = {
        param($c, $scriptPath, $toolsDir, $preset, $caseID, $sharePath, $cred, $outFolder, $binZip, $logHours)
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
                    $null = New-Item -ItemType Directory -Path "$using:remoteDir\tools\hayabusa" -Force
                    Expand-Archive -LiteralPath "$using:remoteDir\bin.zip" -Destination "$using:remoteDir\tools\hayabusa" -Force
                    Remove-Item "$using:remoteDir\bin.zip" -Force -ErrorAction SilentlyContinue
                } -ErrorAction Stop
            }
            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteDir\Ophira.ps1`" -Mode Collect -NoMenu -NoElevate -Preset $preset -OutputPath `"$remoteDir\out`" -CaseID `"$caseID`""
            if ($sharePath) { $cmd += " -SharePath `"$sharePath`"" }
            if ($logHours -ge 0) { $cmd += " -LogHours $logHours" }
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
        $jobs = [System.Collections.ArrayList]::new()
        foreach ($c in $Batch) {
            $ps = [powershell]::Create()
            $null = $ps.AddScript($worker.ToString()).AddArgument($c).AddArgument($scriptPath).AddArgument($toolsDir).AddArgument($DeployPreset).AddArgument($DeployCaseID).AddArgument($DeploySharePath).AddArgument($Cred).AddArgument($outFolder).AddArgument($binZip).AddArgument($DeployLogHours)
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
    $extractJobs = [System.Collections.ArrayList]::new()
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
                        if ($k -eq 'flash_process_scored.csv' -and $r.PSObject.Properties['Signer'] -and "$($r.Signer)") {
                            $signerRows += [pscustomobject]@{ Host = $host_; Signer = "$($r.Signer)"; Name = "$($r.Name)"; Verdict = "$($r.Verdict)" }
                        }
                            if (-not $detail) { $detail = ($r.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' }
                            $findings += [pscustomobject]@{ Host = $host_; Type = $map[$k]; Detail = $detail.Trim(); Source = $k }
                        }
                    } catch { }
                }
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
    $highRisk = @($findings | Where-Object { $_.Type -in @('IOC-HIT', 'AVDetection') })
    if ($highRisk.Count) {
        Write-Host "`n  *** HIGH-PRIORITY (IOC hits / AV detections) ***" -ForegroundColor Red
        $highRisk | Group-Object Host | ForEach-Object { Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor Red }
    }
    $crossHost = @()
    foreach ($g in ($findings | Where-Object { $_.Type -in @('ProcAnomaly', 'IOC-HIT', 'TaskFlagged', 'ServiceFlagged', 'FileHash') } | Group-Object { ($_.Detail -split ' ')[0] })) {
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
            $n = @(Get-Content $hayOut | Select-Object -Skip 1).Count
            Write-Host "    hayabusa: $n detections -> $hayOut" -ForegroundColor Yellow
        }
        Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue
    }
    $reportCsv = Join-Path $OutFolder 'fleet_report.csv'
    $findings | Sort-Object Host, Type | Export-Csv -LiteralPath $reportCsv -NoTypeInformation -Encoding UTF8
    $hostsCsv = Join-Path $OutFolder 'fleet_hosts.csv'
    $hosts | Sort-Object Host | Select-Object Host, Verdict, VerdictRank, Confidence, Signals, Caveats, Collected, Admin, Sysmon, Source, CaseID | Export-Csv -LiteralPath $hostsCsv -NoTypeInformation -Encoding UTF8

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
    $null = $fsb.AppendLine("<h2>Host summary (worst verdict first)</h2><table><tr><th>Host</th><th>Verdict</th><th>Conf</th><th>High-priority</th><th>Proc anomalies</th><th>Brute force</th><th>Collected</th></tr>")
    foreach ($h in ($hosts | Sort-Object -Property @{Expression='VerdictRank';Descending=$true}, 'Host')) {
        $hf = @($findings | Where-Object Host -eq $h.Host)
        $hp = @($hf | Where-Object { $_.Type -in @('IOC-HIT', 'AVDetection') }).Count
        $pa = @($hf | Where-Object { $_.Type -eq 'ProcAnomaly' -and $_.Detail -match '^\[HIGH' }).Count
        $bf = @($hf | Where-Object Type -eq 'BruteForce').Count
        $rowClass = if ($hp -gt 0 -or $pa -gt 0) { 'HIGH' } else { '' }
        $vCell = if ($h.VerdictRank -ge 0) { "<span class='V$($h.VerdictRank)'>$(ConvertTo-HtmlEsc $h.Verdict)</span>" } else { "<span class='VN'>n/a</span>" }
        $cCell = if ($h.VerdictRank -ge 0) { "$($h.Confidence)%" } else { '' }
        $null = $fsb.AppendLine("<tr><td class='$rowClass'>$(ConvertTo-HtmlEsc $h.Host)</td><td>$vCell</td><td>$cCell</td><td>$hp</td><td>$pa</td><td>$bf</td><td>$(ConvertTo-HtmlEsc $h.Collected)</td></tr>")
    }
    $null = $fsb.AppendLine("</table><div class='meta'>Per-host verdict details: each case zip's verdict.json + report.html. Host list CSV: fleet_hosts.csv</div>")
    if ($highRisk.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>High-priority findings (IOC / AV)</h2><table><tr><th>Host</th><th>Type</th><th>Detail</th></tr>")
        foreach ($f in ($highRisk | Sort-Object Host | Select-Object -First 100)) {
            $null = $fsb.AppendLine("<tr><td class='IOC'>$(ConvertTo-HtmlEsc $f.Host)</td><td>$(ConvertTo-HtmlEsc $f.Type)</td><td class='path'>$(ConvertTo-HtmlEsc $f.Detail)</td></tr>")
        }
        $null = $fsb.AppendLine("</table>")
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
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
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

$script:SharedFunctions = @(
    'Get-KitRoot', 'Get-ToolsDir', 'Get-LogStart', 'Get-IocList', 'Test-TrustedPublisher',
    'Save-Rows', 'Out-RawText', 'Invoke-ExeCapture', 'Invoke-NativeTool', 'Get-WmiOrCim', 'Convert-WmiDate',
    'Test-IsPublicIp', 'Test-IsUserWritablePath', 'Get-SignatureInfo', 'Get-SysmonState',
    'Get-UserProfileList', 'Get-UserAssistRows', 'ConvertTo-Rot13', 'Get-FilteredEvents', 'Export-Evtx'
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
        Computer = $Computer; Preset = $Preset
    }
    foreach ($k in $seed.Keys) {
        $lit = "'" + ("$($seed[$k])" -replace "'", "''") + "'"
        [void]$sb.AppendLine("`$$k = $lit")
    }
    [void]$sb.AppendLine("`$script:LogHours = $($LogHours)")
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
    $jobs = [System.Collections.ArrayList]::new()
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
                            if ($bytes[0] -in @(2, 3)) { $state = 'enabled' } elseif ($bytes[0] -in @(6, 7, 13)) { $state = 'disabled' }
                        }
                        Add-Asep 'StartupApproved' $k $prop.Name $state @()
                    }
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
            $ids = @(4624, 4625, 4648, 4672, 4720, 4722, 4724, 4726, 4728, 4732, 4735, 4756, 4688, 1102)
            $ev = Get-FilteredEvents -LogName 'Security' -Ids $ids -Start $start
            Save-Rows -Name 'security_events' -Rows $ev
            $auth = @($ev | Where-Object { $_.Id -in @(4624, 4625) } | ForEach-Object {
                $msg = "$($_.Message)"
                $acct = if ($msg -match 'Account Name:\s+(\S+)') { $Matches[1] } else { '' }
                $ip = if ($msg -match 'Source Network Address:\s+(\S+)') { $Matches[1] } else { '' }
                $lt = if ($msg -match 'Logon Type:\s+(\d+)') { $Matches[1] } else { '' }
                [pscustomobject]@{ Time = $_.TimeCreated; EventId = $_.Id; Account = $acct; SourceIp = $ip; LogonType = $lt }
            })
            Save-Rows -Name 'security_auth_events' -Rows $auth
            $brute = @($auth | Where-Object { $_.EventId -eq 4625 } | Group-Object SourceIp |
                Where-Object { $_.Count -ge 5 } | Sort-Object Count -Descending |
                ForEach-Object { [pscustomobject]@{ SourceIp = $_.Name; FailedLogons = $_.Count } })
            Save-Rows -Name 'security_bruteforce_candidates' -Rows $brute
            $sum = @($auth | Group-Object Account, SourceIp | Sort-Object Count -Descending | Select-Object -First 100 |
                ForEach-Object { [pscustomobject]@{ AccountSource = $_.Name; Count = $_.Count } })
            Save-Rows -Name 'security_auth_summary' -Rows $sum
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
            if ($LogHours -gt 0) { $hayArgs += @('--time-offset', "$($LogHours)h"); $huntNote = "last $($LogHours)h" }
            Write-CaseLog "    hayabusa dfir-timeline Sigma hunt ($huntNote)..." 'Cyan'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs $hayArgs -WorkingDirectory $h.DirectoryName
            if (Test-Path $out) {
                $n = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
                Write-CaseLog "    hayabusa: $n timeline rows (level>=low) in csv\hayabusa_timeline.csv" $(if ($n -gt 0) { 'Yellow' } else { 'Gray' })
            } else { Write-CaseLog "    hayabusa timeline produced no output" 'DarkYellow' }
            Write-CaseLog "    hayabusa logon-summary..." 'Cyan'
            $lsPrefix = Join-Path $CsvDir 'logon_summary'
            $null = Invoke-NativeTool -ExePath $h.FullName -ToolArgs @('logon-summary', '-d', "$evtxDir", '-o', "$lsPrefix", '-q', '-C', '-K') -WorkingDirectory $h.DirectoryName
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
            if (-not (Test-Path -LiteralPath $f)) { Write-CaseLog "    no sysmon_network.csv (no Sysmon / module 3.4 skipped) - beaconing not analyzable" 'DarkGray'; return }
            try { $rows = @(Import-Csv -LiteralPath $f -ErrorAction Stop) } catch { Write-CaseLog "    cannot read sysmon_network.csv" 'DarkYellow'; return }
            if ($rows.Count -lt 15) { Write-CaseLog "    too few Sysmon network events ($($rows.Count)) for beaconing analysis" 'Gray'; Save-Rows -Name 'beacon_candidates' -Rows @(); return }
            $parsed = @()
            foreach ($r in $rows) {
                $t = $null
                try { $t = [datetime]"$($r.Time)" } catch { }
                if ($t) { $parsed += [pscustomobject]@{ T = $t; Image = "$($r.Image)"; Ip = "$($r.DestIp)"; Port = "$($r.DestPort)" } }
            }
            $flagged = @{}
            $fps = Join-Path $CsvDir 'flash_process_scored.csv'
            if (Test-Path -LiteralPath $fps) {
                try { foreach ($fr in @(Import-Csv -LiteralPath $fps)) { if ("$($fr.Verdict)" -match '^(HIGH|MEDIUM)$' -and "$($fr.Path)") { $flagged["$($fr.Path)".ToLower()] = $true } } } catch { }
            }
            $out = @()
            foreach ($g in ($parsed | Group-Object Image, Ip, Port)) {
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
                $out += [pscustomobject]@{
                    Severity = $sev; Rank = $rk; Process = $img; RemoteIp = $ip; Port = "$($ev[0].Port)"
                    Events = $g.Count; SpanMin = [math]::Round($span, 0); MedianIntervalSec = [math]::Round($median, 0)
                    Jitter = $jitter; Regularity = $reg; Flags = ($flags -join ';')
                }
            }
            $out2 = @($out | Sort-Object Rank, Regularity -Descending)
            Save-Rows -Name 'beacon_candidates' -Rows $out2
            $bh = @($out2 | Where-Object { "$($_.Severity)" -eq 'high' }).Count
            $bm = @($out2 | Where-Object { "$($_.Severity)" -eq 'medium' }).Count
            if ($out2.Count -gt 0) {
                Write-CaseLog "    beaconing: $($out2.Count) periodic pattern(s) ($bh high, $bm medium) -> csv\beacon_candidates.csv" $(if ($bh -gt 0) { 'Red' } else { 'Yellow' })
                foreach ($b in ($out2 | Select-Object -First 5)) {
                    Write-CaseLog ("      [{0}] {1} -> {2}:{3} every ~{4}s x{5} (reg {6}, jitter {7}) {8}" -f $b.Severity, (Split-Path $b.Process -Leaf), $b.RemoteIp, $b.Port, $b.MedianIntervalSec, $b.Events, $b.Regularity, $b.Jitter, $b.Flags) $(if ("$($b.Severity)" -eq 'high') { 'Red' } else { 'Yellow' })
                }
            } else {
                Write-CaseLog "    beaconing: no periodic outbound patterns detected in $($parsed.Count) Sysmon network events" 'Gray'
            }
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
            & esentutl.exe /y "$sru" /vss /d "$out" 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-CaseLog "    SRUM copy failed" 'DarkYellow' }
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
                # ---- $MFT: keep only executable-ish files in user paths or created recently (full listing discarded - too big for the case ZIP) ----
                Write-CaseLog "    MFTECmd: parsing live `$MFT..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $mftExe.FullName -ToolArgs @('-f', "$env:SystemDrive\`$MFT", '--csv', $tmp, '--csvf', 'mft_full.csv')
                $mftFull = Join-Path $tmp 'mft_full.csv'
                if (Test-Path -LiteralPath $mftFull) {
                    $exeExt = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jar', '.hta', '.scr', '.msi', '.py', '.wsf', '.lnk')
                    $cutoff = (Get-Date).AddDays(-30)   # ponytail: fixed 30-day recency ($LogHours is not seeded into worker runspaces)
                    $hdr = @((Get-Content -LiteralPath $mftFull -First 1) -split ',' | ForEach-Object { $_.Trim(' "') })
                    $colOf = {
                        param([string]$pattern)
                        @($hdr | Where-Object { $_ -match $pattern } | Select-Object -First 1)[0]
                    }
                    $cName = & $colOf '^FileName$'; $cParent = & $colOf 'ParentPath'; $cExt = & $colOf '^Extension$'
                    $cCreated = & $colOf 'Created'; $cMod = & $colOf 'LastModified'; $cSize = & $colOf 'FileSize'; $cEntry = & $colOf 'EntryNumber'
                    $keep = New-Object System.Collections.Generic.List[object]
                    $total = 0
                    Import-Csv -LiteralPath $mftFull | ForEach-Object {
                        $total++
                        $name = "$($_.$cName)"
                        if (-not $name) { return }
                        $ext = ("$($_.$cExt)").ToLower()
                        if ($exeExt -notcontains $ext) { return }
                        $parent = "$($_.$cParent)"
                        $path = if ($parent) { "$parent\$name" } else { $name }
                        $userPath = Test-IsUserWritablePath $path
                        $created = $null; try { $created = [datetime]"$($_.$cCreated)" } catch { }
                        $recent = ($created -and $created -ge $cutoff)
                        if (-not ($userPath -or $recent)) { return }
                        $flags = @('exec'); if ($userPath) { $flags += 'user-path' }; if ($recent) { $flags += 'recent' }
                        $keep.Add([pscustomobject]@{ Entry = "$($_.$cEntry)"; Created = "$($_.$cCreated)"; LastModified = "$($_.$cMod)"; Size = "$($_.$cSize)"; Name = $name; Path = $path; Flags = ($flags -join ';') })
                    }
                    $out5 = $keep.ToArray()
                    if ($out5.Count -gt 5000) { $out5 = $out5[0..4999] }
                    Save-Rows -Name 'mft_recent' -Rows $out5
                    Write-CaseLog "    MFT: $total entries scanned, $($keep.Count) executable/user-path/recent kept -> csv\mft_recent.csv" 'Gray'
                    Remove-Item -LiteralPath $mftFull -Force -ErrorAction SilentlyContinue
                } else { Write-CaseLog "    MFT parse produced no output (not elevated? non-NTFS volume?) - skipped" 'DarkYellow' }

                # ---- USN journal: per-minute write bursts = ransomware-style mass modification ----
                Write-CaseLog "    MFTECmd: reading live USN journal..." 'Cyan'
                $null = Invoke-NativeTool -ExePath $mftExe.FullName -ToolArgs @('-f', "$env:SystemDrive\`$Extend\`$J", '--csv', $tmp, '--csvf', 'usn_full.csv')
                $usnFull = Join-Path $tmp 'usn_full.csv'
                $bursts = @()
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
                            if ($reason -notmatch 'DataExtend|Truncate|BasicInfoChange') { return }
                            $t = $null; try { $t = [datetime]"$($_.$tCol)" } catch { }
                            if (-not $t) { return }
                            $k = $t.ToString('yyyy-MM-dd HH:mm')
                            if (-not $min.ContainsKey($k)) { $min[$k] = @{ Events = 0; Files = @{} } }
                            $min[$k].Events++
                            if ($nCol) { $f = "$($_.$nCol)"; if ($f -and -not $min[$k].Files.ContainsKey($f)) { $min[$k].Files[$f] = $true } }
                        }
                        foreach ($k in @($min.Keys | Sort-Object)) {
                            if ($min[$k].Events -ge 1000 -and $min[$k].Files.Count -ge 100) {
                                $bursts += [pscustomobject]@{ WindowStart = $k; WriteEvents = $min[$k].Events; DistinctFiles = $min[$k].Files.Count }
                            }
                        }
                    }
                    Remove-Item -LiteralPath $usnFull -Force -ErrorAction SilentlyContinue
                }
                Save-Rows -Name 'usn_write_bursts' -Rows $bursts
                if (@($bursts).Count -gt 0) {
                    Write-CaseLog "    USN: $(@($bursts).Count) mass-modification window(s) >=1000 writes/min - POSSIBLE RANSOMWARE -> csv\usn_write_bursts.csv" 'Red'
                    foreach ($b in @($bursts | Select-Object -First 5)) { Write-CaseLog "      $($b.WindowStart): $($b.WriteEvents) writes over $($b.DistinctFiles) files" 'Red' }
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
                }
            } else {
                Write-CaseLog "    Memory capture FAILED" 'Red'
            }
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
                } else { Write-CaseLog "    AmcacheParser produced no output" 'DarkYellow' }
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
                    foreach ($file in @('History', 'Downloads', 'Preferences', 'Bookmarks')) {
                        $src = Join-Path $b.Root "$pd\$file"
                        if (-not (Test-Path -LiteralPath $src)) { continue }
                        $sub = Join-Path $dst "$($b.Name)_$pd"
                        if (-not (Test-Path -LiteralPath $sub)) { New-Item -ItemType Directory -Path $sub -Force | Out-Null }
                        $outFile = Join-Path $sub $file
                        $ok = $false
                        try { Copy-Item -LiteralPath $src -Destination $outFile -Force -ErrorAction Stop; $ok = $true } catch { }
                        if (-not $ok) { & esentutl.exe /y /vss "$src" /d "$outFile" 2>&1 | Out-Null; $ok = (Test-Path -LiteralPath $outFile) }
                        if ($ok) { $inv += [pscustomobject]@{ Browser = $b.Name; Profile = $pd; File = $file; Bytes = (Get-Item -LiteralPath $outFile).Length } }
                    }
                }
            }
            Save-Rows -Name 'browser_files' -Rows $inv
            $mb = [math]::Round((($inv | Measure-Object Bytes -Sum).Sum) / 1MB, 1)
            Write-CaseLog "    browser: $($inv.Count) file(s) ($mb MB) saved to raw\browser\ (SQLite parsed offline)" 'Gray'
        } }
)

function Get-FilteredEvents {
    param([string]$LogName, [int[]]$Ids, $Start, [int]$MaxMsg = 500)
    try {
        $filter = @{ LogName = $LogName; Id = $Ids }
        if ($Start) { $filter.StartTime = $Start }
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

function Get-PresetSelection {
    param([string]$P)
    $sel = @{}
    foreach ($m in $script:Modules) { $sel[$m.Id] = $false }
    switch ($P) {
        'Flash' { }
        'Quick' { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Quick } }
        'Standard' { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Default } }
        'Full' {
            foreach ($m in $script:Modules) { $sel[$m.Id] = ($m.Id -notin @('3.2', '7.1')) }
        }
        default { foreach ($m in $script:Modules) { $sel[$m.Id] = [bool]$m.Default } }
    }
    if ($IncludeMemory) { $sel['7.1'] = $true }
    return $sel
}

function Show-Menu {
    param([hashtable]$Selection)
    $cats = ($script:Modules | Group-Object Cat | ForEach-Object { $_.Name })
    $range = if ($LogHours -eq 0) { 'All time' } else { "Last $([int]($LogHours/24))d" }
    $count = 0
    $byId = @{}
    $script:Modules | ForEach-Object { $byId[$_.Id] = $count; $count++ }
    while ($true) {
        Clear-Host
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  OPHIRA v$ScriptVersion   |   $Computer   |   Log range: $range" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        $n = 0
        foreach ($cat in $cats) {
            Write-Host ""
            Write-Host ("  {0}" -f $cat) -ForegroundColor White
            foreach ($m in ($script:Modules | Where-Object { $_.Cat -eq $cat })) {
                $mark = if ($Selection[$m.Id]) { '[X]' } else { '[ ]' }
                $color = if ($Selection[$m.Id]) { 'Yellow' } else { 'Gray' }
                $note = if ($m.Id -in @('3.2')) { '  <-- ACTIVE traffic' } elseif ($m.Id -eq '7.1') { '  <-- GB-size' } else { '' }
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
                if ($LogHours -eq 168) { $script:LogHours = 24 }
                elseif ($LogHours -eq 24) { $script:LogHours = 720 }
                elseif ($LogHours -eq 720) { $script:LogHours = 0 }
                else { $script:LogHours = 168 }
                $range = if ($LogHours -eq 0) { 'All time' } else { "Last $([int]($LogHours/24))d" }
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
        elseif ($m.Id -in @('7.1', '4.7', '4.8')) { 'CI' }
        elseif ($m.Id -in @('4.6', '5.4', '5.5', '8.4')) { 'C' }
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

    function Get-LvlRank([string]$l) {
        switch -Regex ("$l") { 'crit' { 5; break } 'high' { 4; break } 'med' { 3; break } 'low' { 2; break } default { 1 } }
    }
    $tacticNames = @{
        'Recon' = 'Reconnaissance'; 'ResDevDev' = 'Resource Development'; 'InitAccess' = 'Initial Access'
        'Exec' = 'Execution'; 'Persis' = 'Persistence'; 'PrivEsc' = 'Privilege Escalation'
        'DefEvade' = 'Defense Evasion'; 'CredAccess' = 'Credential Access'; 'Disc' = 'Discovery'
        'LatMov' = 'Lateral Movement'; 'Collect' = 'Collection'; 'C2' = 'Command and Control'
        'Exfil' = 'Exfiltration'; 'Impact' = 'Impact'; 'ImpairC2' = 'Impair Command and Control'; 'ImpairProc' = 'Impair Process'
    }
    function Get-TacticLabel([string]$abbr) {
        $a = "$abbr".Trim()
        if ($tacticNames.ContainsKey($a)) { return $tacticNames[$a] }
        return $a
    }
    function Split-TagList([string]$s) {
        if (-not "$s") { return @() }
        return @([regex]::Split("$s", '[^A-Za-z0-9.\-]+') | Where-Object { $_ -and $_.Length -gt 1 })
    }

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
    $null = $sb.AppendLine("<div class='nav'><a href='#verdict'>Verdict</a><a href='#coverage'>Coverage</a><a href='#attack'>ATT&CK</a><a href='#ioc'>IOCs</a><a href='#tactics'>Findings by tactic</a><a href='#yara'>YARA</a><a href='#processes'>Processes</a><a href='#sigma'>Sigma</a><a href='#logons'>Logons</a><a href='#persistence'>Persistence</a><a href='#filesystem'>File system</a><a href='#beacons'>Beaconing</a><a href='#network'>Network</a><a href='#snapshot'>Snapshot</a><a href='#recommendations'>Recommendations</a><a href='#evidence'>Evidence index</a></div>")

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
    $yaraScanned = @(Import-CaseCsv 'yara_scanned.csv')
    foreach ($y in ($yaraScanned | Where-Object { "$($_.Hits)" -match '^\d+$' -and [int]$_.Hits -gt 0 -and "$($_.SHA256)" })) { $iocBlock.Add("sha256  $($y.SHA256)") }
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
        $null = $sb.AppendLine("<div class='meta'>Full timeline: csv\hayabusa_timeline.csv &nbsp;|&nbsp; hayabusa's own summary: csv\hayabusa_report.html</div>")
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
        $null = $sb.AppendLine("<div class='meta'>No periodic outbound patterns detected (or no Sysmon network events available - beaconing analysis requires Sysmon event ID 3).</div>")
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
    if (-not $snapAny) { $null = $sb.AppendLine("<div class='meta'>No snapshot data captured (relevant modules skipped).</div>") }

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
    if (-not $Sysmon) {
        $recs.Add('Deploy Sysmon with a community configuration (e.g. SwiftOnSecurity) to gain process/network/image-load telemetry needed for ATT&CK-level detection.')
    }
    if (-not (Test-Path (Join-Path $RawDir 'evtx'))) {
        $recs.Add('Event logs were not exported (module 4.x skipped or access denied) - rerun elevated with the Standard preset for Sigma/ATT&CK coverage.')
    }
    if (-not (Test-IsAdmin)) {
        $recs.Add('This collection ran WITHOUT admin rights - rerun elevated to include registry hives, amcache, Security log and other key sources.')
    }
    if ($LogHours -gt 0 -and $LogHours -le 168) {
        $recs.Add("Analysis window was only the last $([int]($LogHours/24)) day(s) - rerun with a wider window (e.g. -LogHours 720 or 0 = all) if the intrusion may be older.")
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
        'execution_timeline'              = 'Shimcache/amcache program execution history'
        'amcache'                         = 'Amcache full parse (installed/executed programs + SHA1)'
        'ioc_hits_amcache'                = 'Amcache SHA1 x IOC list hits (historical execution)'
        'prefetch_index'                  = 'Prefetch files copied (index)'
        'prefetch_parsed'                 = 'Prefetch parse: run counts + last run times'
        'userassist'                      = 'UserAssist GUI programs executed per user'
        'mft_recent'                      = 'MFT: recently created / user-path executables'
        'usn_write_bursts'                = 'USN journal: mass file-modification windows (ransomware)'
        'lnk_parsed'                      = 'LNK parse (Recent docs - what files were opened)'
        'jumplist_parsed*'                = 'Jump List parse (per-app recent files)'
        'recyclebin'                      = 'RBCmd recycle bin parse (original paths + delete times)'
        'srum_usage'                      = 'SRUM: per-app resource/network usage over weeks'
        'logging_gaps'                    = 'Log clear/stop events + evtx coverage gaps'
        'delta_new'                       = 'Findings NEW since the previous collection'
        'supertimeline'                   = 'All event sources merged chronologically - the master timeline'
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
    $null = $sb.AppendLine("<div class='meta'>Also in the case: <b>supertimeline.csv</b> (master chronology), <b>siem_export.ndjson</b> (Splunk/Elastic-ready records), <b>verdict.json</b>, <b>attack_layer.json</b> (MITRE ATT&CK Navigator layer - load at navigator.mitre.org), <b>case.json</b> (run metadata + module timings), raw evidence under <b>raw\</b> (evtx, registry hives, prefetch, recent/jumplists, browser DBs, firewall log), collection.log</div>")

    $null = $sb.AppendLine("<div class='foot'>Generated $(Get-Date -Format u) by Ophira v$ScriptVersion - all verdicts are correlation heuristics; verify against raw CSV/evtx evidence before acting.</div>")
    $null = $sb.AppendLine("</body></html>")
    $reportPath = Join-Path $CaseDir 'report.html'
    $sb.ToString() | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-CaseLog "    report: $reportPath" 'Cyan'
    return $reportPath
}

function New-SuperTimeline {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @('security_events', 'powershell_events', 'sysmon_events', 'system_events', 'defender_events', 'rdp_localsession', 'rdp_connections')) {
        foreach ($r in (Import-CaseCsv $name)) {
            if ($r.PSObject.Properties['TimeCreated']) {
                $rows.Add([pscustomobject]@{ Timestamp = "$($r.TimeCreated)"; Source = $name; Type = "EID $($r.Id)"; Detail = (("$($r.Message)") -replace '\s+', ' ').Trim() })
            }
        }
    }
    foreach ($r in (Import-CaseCsv 'hayabusa_timeline')) {
        if ($r.PSObject.Properties['Timestamp']) {
            $rule = if ($r.PSObject.Properties['RuleTitle']) { $r.RuleTitle } elseif ($r.PSObject.Properties['Alert']) { $r.Alert } else { $r.RuleFile }
            $rows.Add([pscustomobject]@{ Timestamp = "$($r.Timestamp)"; Source = 'hayabusa'; Type = "$($r.Level): $rule"; Detail = "$($r.Details)" })
        }
    }
    $exec = Import-CaseCsv 'execution_timeline'
    if ($exec.Count -gt 0) {
        $tCol = ($exec[0].PSObject.Properties.Name | Select-Object -First 1)
        foreach ($r in $exec) {
            $line = ($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' '
            $rows.Add([pscustomobject]@{ Timestamp = "$($r.$tCol)"; Source = 'execution'; Type = 'shimcache/amcache'; Detail = $line })
        }
    }
    if ($rows.Count -eq 0) { return }
    $sorted = $rows | Sort-Object { try { [datetime]::Parse($_.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture) } catch { [datetime]::MinValue } }
    $out = Join-Path $CsvDir 'supertimeline.csv'
    $sorted | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
    Write-CaseLog "    supertimeline: $($rows.Count) events -> csv\supertimeline.csv" 'DarkGray'
}

function New-LoggingGaps {
    $rows = @()
    $meanings = @{ 6005 = 'Event logging STARTED'; 6006 = 'Event logging STOPPED (shutdown)'; 104 = 'Event log CLEARED'; 1102 = 'Security audit log CLEARED' }
    foreach ($name in @('system_events', 'security_events')) {
        foreach ($r in (Import-CaseCsv $name)) {
            if ($r.Id -in @(6005, 6006, 104, 1102)) {
                $rows += [pscustomobject]@{ Time = $r.TimeCreated; EventId = $r.Id; Meaning = $meanings[[int]$r.Id]; Source = $name; Message = $r.Message }
            }
        }
    }
    $gapsFile = Join-Path $RawDir 'analysis\evtx_gaps.txt'
    if ((Test-Path $gapsFile) -and (Get-Item $gapsFile).Length -gt 0) {
        $rows += [pscustomobject]@{ Time = ''; EventId = ''; Meaning = 'chronological gaps detected in evtx (see raw\analysis\evtx_gaps.txt)'; Source = 'chainsaw'; Message = '' }
    }
    Save-Rows -Name 'logging_gaps' -Rows $rows
    $bad = @($rows | Where-Object { $_.EventId -in @(104, 1102) })
    if ($bad.Count -gt 0) { Write-CaseLog "    LOGGING GAPS: $($bad.Count) clear/down events - check csv\logging_gaps.csv" 'Red' }
}

function New-SiemExport {
    $lines = [System.Collections.Generic.List[string]]::new()
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
    foreach ($u in (Import-CaseCsv 'usn_write_bursts')) {
        $o = [ordered]@{}; $o['ts'] = "$($u.WindowStart)"; $o['kind'] = 'mass_modification'; $o['host'] = $base.host; $o['write_events'] = [int]"$($u.WriteEvents)"; $o['distinct_files'] = [int]"$($u.DistinctFiles)"; $o['caseid'] = $base.caseid
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
    $usnBursts = Import-CaseCsv 'usn_write_bursts'
    $asep = Import-CaseCsv 'asep_sweep'

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
    $usnBurstN = @($usnBursts).Count
    # ponytail: COM hijacks + StartupApproved excluded from the signal (per-user COM has many legit users, e.g. Teams/OneDrive); they stay report-visible
    $asepHotN = @($asep | Where-Object { $_.Flags -match 'user-path|nondefault' -and "$($_.Category)" -notmatch 'ComHijack|StartupApproved' }).Count

    Add-Signal 'IOC hit - historical execution (amcache SHA1)' 4 @($iocAmc).Count "near-certain true positive evidence"
    Add-Signal 'YARA hit - high/critical rule' 4 $yaraHi (($yara | Where-Object { "$($_.Severity)" -match '^(?i)(high|critical)$' } | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'C2 beaconing - highly regular callbacks' 3 $beaconHi (($beacons | Where-Object { "$($_.Severity)" -match '^(?i)high$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.RemoteIp):$($_.Port) every ~$($_.MedianIntervalSec)s" }) -join '; ')
    Add-Signal 'Ransomware-like mass file modification (USN journal)' 3 $usnBurstN (($usnBursts | Select-Object -First 3 | ForEach-Object { "$($_.WindowStart): $($_.WriteEvents) writes / $($_.DistinctFiles) files" }) -join '; ')
    Add-Signal 'Uncommon persistence mechanism (IFEO/AppInit/Winlogon/netsh/LSA)' 2 $asepHotN (($asep | Where-Object { $_.Flags -match 'user-path|nondefault' -and "$($_.Category)" -notmatch 'ComHijack|StartupApproved' } | Select-Object -First 3 | ForEach-Object { "$($_.Category): $($_.Name) = $($_.Value)" }) -join '; ')
    Add-Signal 'IOC hit - live system' 3 @($iocLive).Count (($iocLive | Select-Object -First 3 | ForEach-Object { $_.Indicator }) -join '; ')
    Add-Signal 'Sigma detection - critical' 3 $hayCrit (($hay | Where-Object { "$($_.Level)" -match 'crit' } | Select-Object -First 3 | ForEach-Object { $_.RuleTitle }) -join '; ')
    Add-Signal 'YARA hit - medium rule' 2 $yaraMed (($yara | Where-Object { "$($_.Severity)" -match '^(?i)medium$' } | Select-Object -First 3 | ForEach-Object { $_.Rule }) -join '; ')
    Add-Signal 'C2 beaconing - periodic callbacks' 2 $beaconMed (($beacons | Where-Object { "$($_.Severity)" -match '^(?i)medium$' } | Select-Object -First 3 | ForEach-Object { "$($_.Process) -> $($_.RemoteIp) every ~$($_.MedianIntervalSec)s" }) -join '; ')
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
    Add-Cov 'Sysmon telemetry (bonus)' ([bool]$Sysmon) 5
    Add-Cov 'RAM capture (bonus)' (Test-Path $MemDir) 3
    $coverageRaw = 0
    foreach ($c in $cov) { if ($c.Collected) { $coverageRaw += $c.Weight } }
    $isAdminRun = Test-IsAdmin
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
    if ($LogHours -gt 0 -and (Test-Path $evtxDir)) { $caveats.Add("Event-log analysis covered only the last $([int]($LogHours/24)) days - older activity not assessed") }
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

function New-Package {
    Write-Host ""
    Write-CaseLog "Packaging case folder..." 'Cyan'
    $os = Get-WmiOrCim -Class Win32_OperatingSystem
    $case = [pscustomobject]@{
        Tool = "Ophira v$ScriptVersion"
        CaseID = $script:CurrentCaseID
        Analyst = $script:CurrentAnalyst
        Computer = $Computer
        StartedUTC = $StartTime.ToUniversalTime().ToString('o')
        FinishedUTC = (Get-Date).ToUniversalTime().ToString('o')
        OS = if ($os) { $os.Caption + ' ' + $os.Version } else { '' }
        Owner = $env:USERNAME
        AdminElevated = (Test-IsAdmin)
        SysmonPresent = (Get-SysmonState)
        LogHours = $LogHours
        OutputFolder = $CaseDir
    }
    if ($script:ModuleTimings) {
        $case | Add-Member -NotePropertyName ModuleTimings -NotePropertyValue $script:ModuleTimings -Force
        $case | Add-Member -NotePropertyName ModuleSecondsTotal -NotePropertyValue ([math]::Round((($script:ModuleTimings | Measure-Object Seconds -Sum).Sum), 1)) -Force
    }
    $case | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8

    try { Invoke-DeltaCompare -Path $DeltaPath } catch { Write-CaseLog "    delta failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-SuperTimeline } catch { Write-CaseLog "    supertimeline failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-LoggingGaps } catch { Write-CaseLog "    logging gaps failed: $($_.Exception.Message)" 'DarkYellow' }

    $script:Verdict = $null
    try {
        $script:Verdict = Get-CompromiseVerdict
        if ($script:Verdict) {
            $script:Verdict | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'verdict.json') -Encoding UTF8
            $case | Add-Member -NotePropertyName Verdict -NotePropertyValue ([pscustomobject]@{
                Level = $script:Verdict.Level
                ConfidencePercent = $script:Verdict.ConfidencePercent
                SignalCount = $script:Verdict.Signals.Count
                CaveatCount = $script:Verdict.Caveats.Count
            }) -Force
            $case | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8
            $vColor = switch ($script:Verdict.LevelRank) { 4 { 'Red' } 3 { 'Red' } 2 { 'Yellow' } 1 { 'Green' } default { 'DarkYellow' } }
            Write-CaseLog "    VERDICT: $($script:Verdict.Level) (confidence $($script:Verdict.ConfidencePercent)%) - $($script:Verdict.Signals.Count) signal(s), $($script:Verdict.Caveats.Count) caveat(s) -> verdict.json" $vColor
        }
    } catch { Write-CaseLog "    verdict engine failed: $($_.Exception.Message)" 'DarkYellow' }

    try { New-SiemExport } catch { Write-CaseLog "    siem export failed: $($_.Exception.Message)" 'DarkYellow' }
    try { New-AttackLayer } catch { Write-CaseLog "    ATT&CK layer failed: $($_.Exception.Message)" 'DarkYellow' }

    try { New-HtmlReport | Out-Null } catch { Write-CaseLog "    report generation failed: $($_.Exception.Message)" 'DarkYellow' }

    $manifest = @()
    $manifest += "Ophira v$ScriptVersion evidence manifest"
    $manifest += "CaseID: $($script:CurrentCaseID)  Analyst: $($script:CurrentAnalyst)"
    $manifest += "Host: $Computer  Collected: $($StartTime.ToString('u'))"
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
        Write-Host "   [6]  Tool links" -ForegroundColor Yellow
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
            '^(?i)6$' { return 'Links' }
            '^(?i)q$' { return $null }
            default { }
        }
    }
}

function Invoke-SetupWizard {
    Write-Host ""
    Write-Host "=== Setup companion tools ===" -ForegroundColor Cyan
    Write-Host "Tools live in tools\ subfolders. Available:" -ForegroundColor Gray
    Write-Host "  winpmem  hayabusa  volatility3  chainsaw  AmcacheParser  RBCmd  MFTECmd  PECmd  LECmd  JLECmd  yara" -ForegroundColor White
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
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    $defTargets = $script:CfgTargets
    if (-not $defTargets -and (Test-Path -LiteralPath $hostsFile)) { $defTargets = 'hosts.txt' }
    $targets = @()
    $targetsIn = ''
    while ($targets.Count -eq 0) {
        $prompt = "  Target PCs (comma-separated, or a .txt file path)$(if ($defTargets) { " [$defTargets]" })"
        $targetsIn = (Read-Host $prompt).Trim()
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
    }

    Write-Host ""
    $cred = $null
    $cIn = (Read-Host "  Credentials: ENTER = your current account ($env:USERDOMAIN\$env:USERNAME), or type a username").Trim()
    if ($cIn) {
        $cred = Get-Credential -UserName $cIn -Message "Password for remote PCs"
        if (-not $cred) { Write-Host "  no credentials entered - using current account" -ForegroundColor Yellow; $cred = $null }
    }

    $defPreset = if ($script:CfgDeployPreset) { $script:CfgDeployPreset } else { 'Standard' }
    $pIn = (Read-Host "  Collection depth: 1=Quick (~1-2 min/PC) or 2=Standard (~3-5 min/PC) [$defPreset]").Trim()
    $preset = $defPreset
    if ($pIn -match '^1' -or $pIn -match '^(?i)q(uick)?$') { $preset = 'Quick' }
    elseif ($pIn -match '^2' -or $pIn -match '^(?i)s(tandard)?$') { $preset = 'Standard' }

    $pushDef = if ($script:CfgPushTools) { 'Y' } else { 'N' }
    $p2In = (Read-Host "  Also push hayabusa for on-host Sigma detection (removed after run)? [y/N] (default $pushDef)").Trim()
    $push = if ($p2In) { $p2In -match '^(?i)y' } else { [bool]$script:CfgPushTools }

    $shareIn = ''
    if ($script:CfgDeployShare) {
        $shareIn = (Read-Host "  Upload results to share (UNC path, 'none' = pull to collections\, ENTER = $($script:CfgDeployShare))").Trim()
        if ($shareIn -ieq 'none') { $shareIn = '' }
    } else {
        $shareIn = (Read-Host "  Upload results to a central share instead of pulling back? (UNC path, ENTER = pull to collections\)").Trim()
    }
    if ($shareIn -and -not (Test-Path $shareIn)) {
        Write-Host "  WARNING: share not reachable right now ($shareIn) - will retry during run" -ForegroundColor Yellow
    }

    $threads = if ($script:CfgThreads -gt 0) { $script:CfgThreads } else { $MaxThreads }

    $advLogHours = -1
    $advIn = (Read-Host "  Advanced options (Full depth, log window, parallelism)? [y/N]").Trim()
    if ($advIn -match '^(?i)y') {
        $dIn = (Read-Host "  Depth: 1=Quick  2=Standard  3=Full - heaviest, includes SRUM etc. [current: $preset]").Trim()
        if ($dIn -match '^3' -or $dIn -match '^(?i)f(ull)?$') { $preset = 'Full' }
        $lhIn = (Read-Host "  Log analysis window in hours (ENTER = 168 = 7 days, 0 = all available)").Trim()
        if ($lhIn -match '^\d+$') { $advLogHours = [int]$lhIn }
        $thIn = (Read-Host "  Hosts to process in parallel (ENTER = current setting)").Trim()
        if ($thIn -match '^\d+$' -and [int]$thIn -gt 0) { $threads = [int]$thIn }
    }

    $shown = ($targets | Select-Object -First 5) -join ', '
    if ($targets.Count -gt 5) { $shown += ", ...($($targets.Count) total)" }
    $credNote = if ($cred) { $cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME (current)" }
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Ready to deploy. Please confirm:" -ForegroundColor White
    Write-Host "    Targets   : $shown"
    Write-Host "    Depth     : $preset"
    if ($advLogHours -ge 0) { Write-Host "    Log window: $(if ($advLogHours -eq 0) { 'all available' } else { "$advLogHours hours" })" }
    Write-Host "    Account   : $credNote"
    Write-Host "    hayabusa  : $(if ($push) { 'push + run + remove' } else { 'not pushed' })"
    Write-Host "    Results   : $(if ($shareIn) { "upload to $shareIn" } else { 'pull to collections\' })"
    if ($CaseID) { Write-Host "    Case ID   : $CaseID" }
    Write-Host "    Parallel  : $threads hosts at once"
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    $go = (Read-Host "  Start? [Y/n]").Trim()
    if ($go -match '^[Nn]') { Write-Host "  Deploy cancelled." -ForegroundColor Yellow; return }

    Invoke-DeployMode -Targets $targets -DeployPreset $preset -Cred $cred -DeployCaseID $CaseID -DeploySharePath $shareIn -Threads $threads -PushBin $push -DeployLogHours $advLogHours

    $rem = (Read-Host "  Remember these answers for next time? [y/N]").Trim()
    if ($rem -match '^(?i)y') {
        $vals = @{ TARGETS = $targetsIn; PRESET = $preset; PUSHTOOLS = $(if ($push) { 'yes' } else { 'no' }) }
        if ($shareIn) { $vals['DEPLOYSHARE'] = $shareIn }
        if (Save-OphiraConfig -Values $vals) { Write-Host "  Saved to ophira.config.txt" -ForegroundColor Green }
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
            Invoke-DeployMode -Targets $ComputerName -DeployPreset $Preset -Cred $Credential -DeployCaseID $CaseID -DeploySharePath $SharePath -Threads $MaxThreads -PushBin ([bool]$PushTools) -DeployLogHours $LogHours
        }
        'UpdateRules' { Invoke-UpdateRulesMode }
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
