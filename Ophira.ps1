<#
Ophira v2.5  -  Windows Incident Response Triage Toolkit
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

$ScriptVersion = "2.5"
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
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
    param([string[]]$Targets, [string]$DeployPreset, $Cred, [string]$DeployCaseID, [string]$DeploySharePath, [int]$Threads = 8, [bool]$PushBin = $false)

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
        param($c, $scriptPath, $toolsDir, $preset, $caseID, $sharePath, $cred, $outFolder, $binZip)
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
            $null = $ps.AddScript($worker.ToString()).AddArgument($c).AddArgument($scriptPath).AddArgument($toolsDir).AddArgument($DeployPreset).AddArgument($DeployCaseID).AddArgument($DeploySharePath).AddArgument($Cred).AddArgument($outFolder).AddArgument($binZip)
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
        $hosts += [pscustomobject]@{
            Host = $host_; Source = $src.Name; CaseID = $meta.CaseID
            Collected = $meta.StartedUTC; Admin = $meta.AdminElevated; Sysmon = $meta.SysmonPresent
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

    $fleetHtml = Join-Path $OutFolder 'fleet_report.html'
    $css = @'
<style>
body{background:#0f1115;color:#d7dce3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 10px;color:#8ab4f8;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
.meta{color:#7d8590;font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #2a2f3a;padding:6px 10px;text-align:left}
th{background:#1d222c;color:#8ab4f8}tr:nth-child(even){background:#151920}
.HIGH{color:#ff8789;font-weight:700}.IOC{color:#ff8789}.path{font-family:Consolas,monospace;font-size:12px;color:#8ab4f8;word-break:break-all}
a{color:#8ab4f8}.foot{margin-top:40px;color:#565e6b;font-size:11px}
</style>
'@
    $fsb = New-Object System.Text.StringBuilder
    $null = $fsb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira Fleet</title>$css</head><body>")
    $null = $fsb.AppendLine("<h1>OPHIRA FLEET REPORT</h1><div class='meta'>$(Get-Date -Format u) - $($hosts.Count) hosts - $($findings.Count) findings - Ophira v$ScriptVersion</div>")
    $null = $fsb.AppendLine("<h2>Host summary</h2><table><tr><th>Host</th><th>High-priority</th><th>Proc anomalies</th><th>Brute force</th><th>Collected</th></tr>")
    foreach ($h in ($hosts | Sort-Object Host)) {
        $hf = @($findings | Where-Object Host -eq $h.Host)
        $hp = @($hf | Where-Object { $_.Type -in @('IOC-HIT', 'AVDetection') }).Count
        $pa = @($hf | Where-Object { $_.Type -eq 'ProcAnomaly' -and $_.Detail -match '^\[HIGH' }).Count
        $bf = @($hf | Where-Object Type -eq 'BruteForce').Count
        $rowClass = if ($hp -gt 0 -or $pa -gt 0) { 'HIGH' } else { '' }
        $null = $fsb.AppendLine("<tr><td class='$rowClass'>$(ConvertTo-HtmlEsc $h.Host)</td><td>$hp</td><td>$pa</td><td>$bf</td><td>$(ConvertTo-HtmlEsc $h.Collected)</td></tr>")
    }
    $null = $fsb.AppendLine("</table>")
    if ($highRisk.Count -gt 0) {
        $null = $fsb.AppendLine("<h2>High-priority findings (IOC / AV)</h2><table><tr><th>Host</th><th>Type</th><th>Detail</th></tr>")
        foreach ($f in ($highRisk | Sort-Object Host | Select-Object -First 100)) {
            $null = $fsb.AppendLine("<tr><td class='IOC'>$(ConvertTo-HtmlEsc $f.Host)</td><td>$(ConvertTo-HtmlEsc $f.Type)</td><td class='path'>$(ConvertTo-HtmlEsc $f.Detail)</td></tr>")
        }
        $null = $fsb.AppendLine("</table>")
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
        elseif ($m.Id -in @('7.1', '4.7')) { 'CI' }
        elseif ($m.Id -in @('4.6', '5.4', '8.4')) { 'C' }
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
    $scored = Import-CaseCsv 'flash_process_scored.csv'
    $iocHits = Import-CaseCsv 'flash_ioc_hits.csv'
    $hayRows = Import-CaseCsv 'hayabusa_timeline.csv'
    $execRows = Import-CaseCsv 'execution_timeline.csv'
    $brute = Import-CaseCsv 'security_bruteforce_candidates.csv'
    $pubConns = Import-CaseCsv 'flash_public_connections.csv'

    $css = @'
<style>
body{background:#0f1115;color:#d7dce3;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:32px 0 10px;color:#8ab4f8;border-bottom:1px solid #2a2f3a;padding-bottom:6px}
.meta{color:#7d8590;font-size:12px}
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
</style>
'@

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Ophira - $Computer</title>$css</head><body>")
    $null = $sb.AppendLine("<h1>OPHIRA TRIAGE REPORT</h1>")
    $null = $sb.AppendLine("<div class='meta'>Host: $Computer &nbsp;|&nbsp; Case: $(ConvertTo-HtmlEsc $script:CurrentCaseID) &nbsp;|&nbsp; Analyst: $(ConvertTo-HtmlEsc $script:CurrentAnalyst) &nbsp;|&nbsp; Collected: $($StartTime.ToString('u')) &nbsp;|&nbsp; Ophira v$ScriptVersion &nbsp;|&nbsp; Sysmon: $(if ($Sysmon) { 'yes' } else { 'no' })</div>")

    $deltaRows = Import-CaseCsv 'delta_new.csv'
    if ($deltaRows.Count -gt 0) {
        $null = $sb.AppendLine("<h2>NEW since previous collection ($(ConvertTo-HtmlEsc $script:DeltaBaseline))</h2><table><tr><th>Type</th><th>Item</th><th>Detail</th></tr>")
        foreach ($d in ($deltaRows | Select-Object -First 40)) {
            $null = $sb.AppendLine("<tr><td><b>$(ConvertTo-HtmlEsc $d.Type)</b></td><td>$(ConvertTo-HtmlEsc $d.Item)</td><td class='path'>$(ConvertTo-HtmlEsc $d.Detail)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }
    $gapRows = Import-CaseCsv 'logging_gaps.csv'
    if ($gapRows.Count -gt 0) {
        $null = $sb.AppendLine("<h2>Logging continuity (check for tampering)</h2><table><tr><th>Time</th><th>Event</th><th>Meaning</th></tr>")
        foreach ($g in ($gapRows | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Time)</td><td>$($g.EventId)</td><td>$(ConvertTo-HtmlEsc $g.Meaning)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

    $high = @($scored | Where-Object Verdict -eq 'HIGH').Count
    $med = @($scored | Where-Object Verdict -eq 'MEDIUM').Count
    $low = @($scored | Where-Object Verdict -eq 'LOW').Count
    $hayCrit = @($hayRows | Where-Object { $_.Level -match 'crit' }).Count
    $hayHigh = @($hayRows | Where-Object { $_.Level -match '^high$' }).Count
    $null = $sb.AppendLine("<div class='chips'>" +
        "<span class='chip HIGH'>HIGH: $high</span><span class='chip MEDIUM'>MEDIUM: $med</span><span class='chip LOW'>LOW: $low</span>" +
        "<span class='chip INFO'>IOC hits: $($iocHits.Count)</span><span class='chip INFO'>Sigma timeline: $($hayRows.Count) rows (crit:$hayCrit high:$hayHigh)</span></div>")

    if ($iocHits.Count -gt 0) {
        $null = $sb.AppendLine("<h2>IOC HITS - investigate first</h2><table><tr><th>Type</th><th>Indicator</th><th>Where</th><th>Context</th><th></th></tr>")
        foreach ($h in $iocHits) {
            $null = $sb.AppendLine("<tr><td><b>$($(ConvertTo-HtmlEsc $h.Type))</b></td><td class='path'>$(ConvertTo-HtmlEsc $h.Indicator)</td><td class='path'>$(ConvertTo-HtmlEsc $h.Where)</td><td>$(ConvertTo-HtmlEsc $h.Context)</td><td>$(New-VtLink $h.Indicator)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

    $amcHits = Import-CaseCsv 'ioc_hits_amcache.csv'
    if ($amcHits.Count -gt 0) {
        $null = $sb.AppendLine("<h2>HISTORICAL EXECUTION IOC HITS (amcache) - near-certain TP evidence</h2><table><tr><th>SHA1</th><th>Application</th><th>Source</th><th></th></tr>")
        foreach ($h in $amcHits) {
            $null = $sb.AppendLine("<tr><td class='path'>$(ConvertTo-HtmlEsc $h.Indicator)</td><td>$(ConvertTo-HtmlEsc $h.Application)</td><td>$(ConvertTo-HtmlEsc $h.SourceFile)</td><td>$(New-VtLink $h.Indicator)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

    $null = $sb.AppendLine("<h2>Process verdicts (correlation scored)</h2>")
    foreach ($p in ($scored | Sort-Object { [int]$_.Score } -Descending | Select-Object -First 30)) {
        $evs = ($p.Evidence -split ';' | Where-Object { $_ }) | ForEach-Object { "<span class='ev'>$(ConvertTo-HtmlEsc $_)</span>" }
        $null = $sb.AppendLine("<div class='card'><span class='badge $($p.Verdict)'>$($p.Verdict) &nbsp;$($p.Score)</span><b>$(ConvertTo-HtmlEsc $p.Name)</b> <span class='meta'>PID $(ConvertTo-HtmlEsc $p.PID)</span> $(New-VtLink $p.Name)<br><span class='path'>$(ConvertTo-HtmlEsc $p.Path)</span><br>$($evs -join ' ')</div>")
    }

    if ($hayRows.Count -gt 0) {
        $alertCol = $null
        foreach ($cand in @('RuleTitle', 'Alert', 'RuleFile')) {
            if ($hayRows[0].PSObject.Properties[$cand]) { $alertCol = $cand; break }
        }
        $null = $sb.AppendLine("<h2>Top Sigma detections (hayabusa)</h2>")
        if ($alertCol) {
            $groups = $hayRows | Group-Object $alertCol | Sort-Object Count -Descending | Select-Object -First 20
            $null = $sb.AppendLine("<table><tr><th>Alert</th><th>Hits</th><th>Max level</th><th>Last seen</th></tr>")
            foreach ($g in $groups) {
                $lvl = (@($g.Group | ForEach-Object { $_.Level }) | Sort-Object -Descending | Select-Object -First 1)
                $lvlClass = switch -Regex ("$lvl") { 'crit' { 'crit'; break } 'high' { 'high'; break } 'med' { 'med'; break } default { 'info' } }
                $last = (@($g.Group | ForEach-Object { $_.Timestamp } | Sort-Object -Descending | Select-Object -First 1) -join '')
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $g.Name)</td><td>$($g.Count)</td><td class='$lvlClass'>$lvl</td><td>$(ConvertTo-HtmlEsc $last)</td></tr>")
            }
            $null = $sb.AppendLine("</table>")
        }
        $null = $sb.AppendLine("<div class='meta'>Full timeline: csv\hayabusa_timeline.csv &nbsp;|&nbsp; hayabusa's own summary: csv\hayabusa_report.html</div>")
    }

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

    if ($brute.Count -gt 0) {
        $null = $sb.AppendLine("<h2>Brute-force candidates</h2><table><tr><th>Source IP</th><th>Failed logons</th><th></th></tr>")
        foreach ($b in $brute) { $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $b.SourceIp)</td><td><b>$($b.FailedLogons)</b></td><td>$(New-VtLink $b.SourceIp)</td></tr>") }
        $null = $sb.AppendLine("</table>")
    }

    if ($pubConns.Count -gt 0) {
        $null = $sb.AppendLine("<h2>Public connections (live)</h2><table><tr><th>Remote</th><th>State</th><th>PID</th><th>Process</th><th></th></tr>")
        foreach ($c in ($pubConns | Select-Object -First 25)) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-HtmlEsc $c.RemoteAddress):$(ConvertTo-HtmlEsc $c.RemotePort)</td><td>$(ConvertTo-HtmlEsc $c.State)</td><td>$(ConvertTo-HtmlEsc $c.PID)</td><td class='path'>$(ConvertTo-HtmlEsc $c.ProcessPath)</td><td>$(New-VtLink $c.RemoteAddress)</td></tr>")
        }
        $null = $sb.AppendLine("</table>")
    }

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
    if ($lines.Count -eq 0) { return }
    $out = Join-Path $CaseDir 'siem_export.ndjson'
    $lines | Set-Content -LiteralPath $out -Encoding UTF8
    Write-CaseLog "    siem export: $($lines.Count) records -> siem_export.ndjson" 'DarkGray'
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
    try { New-SiemExport } catch { Write-CaseLog "    siem export failed: $($_.Exception.Message)" 'DarkYellow' }
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
    Write-Host "  winpmem  hayabusa  volatility3  chainsaw  AmcacheParser  RBCmd  yara" -ForegroundColor White
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

    $shown = ($targets | Select-Object -First 5) -join ', '
    if ($targets.Count -gt 5) { $shown += ", ...($($targets.Count) total)" }
    $credNote = if ($cred) { $cred.UserName } else { "$env:USERDOMAIN\$env:USERNAME (current)" }
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Ready to deploy. Please confirm:" -ForegroundColor White
    Write-Host "    Targets   : $shown"
    Write-Host "    Depth     : $preset"
    Write-Host "    Account   : $credNote"
    Write-Host "    hayabusa  : $(if ($push) { 'push + run + remove' } else { 'not pushed' })"
    Write-Host "    Results   : $(if ($shareIn) { "upload to $shareIn" } else { 'pull to collections\' })"
    if ($CaseID) { Write-Host "    Case ID   : $CaseID" }
    Write-Host "    Parallel  : $threads hosts at once"
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor Cyan
    $go = (Read-Host "  Start? [Y/n]").Trim()
    if ($go -match '^[Nn]') { Write-Host "  Deploy cancelled." -ForegroundColor Yellow; return }

    Invoke-DeployMode -Targets $targets -DeployPreset $preset -Cred $cred -DeployCaseID $CaseID -DeploySharePath $shareIn -Threads $threads -PushBin $push

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
            Invoke-DeployMode -Targets $ComputerName -DeployPreset $Preset -Cred $Credential -DeployCaseID $CaseID -DeploySharePath $SharePath -Threads $MaxThreads -PushBin ([bool]$PushTools)
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
