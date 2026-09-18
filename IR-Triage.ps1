<#
IR-Triage v1.0  -  Windows Incident Response Triage Collector
READ-ONLY by design: never modifies the system, only reads and copies data
into its own output folder. Intended to be handed to a system owner or run
by a responder during early triage / threat hunting.
#>

[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Deploy', 'Analyze', 'Setup', 'Links')]
    [string]$Mode = 'Collect',
    [string]$CaseID = "",
    [string]$Analyst = "",
    [string]$OutputPath = "",
    [ValidateSet('Flash', 'Quick', 'Standard', 'Full', 'Custom')]
    [string]$Preset = 'Standard',
    [switch]$NoMenu,
    [switch]$IncludeMemory,
    [switch]$NoElevate,
    [int]$LogHours = 168,
    [string]$SharePath = "",
    [string[]]$ComputerName,
    [string]$AnalyzePath = '.',
    [string]$HayabusaPath = '',
    [string[]]$SetupTools,
    [System.Management.Automation.PSCredential]$Credential
)

$ScriptVersion = "2.0"
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
    $parts -join ' '
}

function Get-KitRoot {
    if ($PSScriptRoot) { return $PSScriptRoot }
    return (Get-Location).Path
}

function Write-CaseLog {
    param([string]$Message, [string]$Color = 'Gray', [switch]$NoConsole)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    if (-not $NoConsole) { Write-Host $line -ForegroundColor $Color }
    Add-Content -LiteralPath $CaseLog -Value $line -Encoding UTF8
}

function Out-Flash {
    param([string]$Text, [string]$Color = 'White')
    Write-Host $Text -ForegroundColor $Color
    $script:FlashLines.Add(($Text -replace "\x1b\[[0-9;]*m", ''))
}

function Save-Rows {
    param([string]$Name, $Rows)
    $path = Join-Path $CsvDir "$Name.csv"
    try {
        if ($Rows -and @($Rows).Count -gt 0) {
            @($Rows) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
            return "csv\$Name.csv ({0} rows)" -f @($Rows).Count
        } else {
            "# no entries" | Set-Content -LiteralPath $path -Encoding UTF8
            return "csv\$Name.csv (empty)"
        }
    } catch {
        "FAILED: $($_.Exception.Message)" | Set-Content -LiteralPath $path -Encoding UTF8
        return "FAILED"
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

function Get-IocList {
    $tDir = Get-ToolsDir
    if (-not $tDir) { return $null }
    $f = Join-Path $tDir 'iocs.txt'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    $iocs = @{ Hashes = @{}; Ips = @{}; Domains = @{} }
    foreach ($line in (Get-Content -LiteralPath $f)) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        if ($l -match '^[a-fA-F0-9]{32,64}$') { $iocs.Hashes[$l.ToUpper()] = $true }
        elseif ($l -match '^(\d{1,3}\.){3}\d{1,3}$') { $iocs.Ips[$l] = $true }
        else { $iocs.Domains[$l.ToLower()] = $true }
    }
    if ($iocs.Hashes.Count -eq 0 -and $iocs.Ips.Count -eq 0 -and $iocs.Domains.Count -eq 0) { return $null }
    return $iocs
}

function Show-ToolLinks {
    Write-Host ""
    Write-Host "=== IR-Triage companion tools ===" -ForegroundColor Cyan
    $rows = @(
        [pscustomobject]@{ Tool = 'winpmem (RAM capture)'; Url = 'https://github.com/Velocidex/winpmem/releases'; Use = 'module 7.1 memory capture; drop exe in tools\' }
        [pscustomobject]@{ Tool = 'hayabusa (Sigma hunt)'; Url = 'https://github.com/Yamato-Security/hayabusa/releases'; Use = 'module 4.6 on-host Sigma timeline; get win-x64.zip' }
        [pscustomobject]@{ Tool = 'volatility3 (memory analysis)'; Url = 'https://github.com/volatilityfoundation/volatility3/releases'; Use = 'offline: pslist/netscan/malfind; get win-exes zip, keep vol.exe' }
        [pscustomobject]@{ Tool = 'chainsaw (artifact analysis)'; Url = 'https://github.com/WithSecureOpenSource/chainsaw/releases'; Use = 'offline: sigma hunt + shimcache/amcache timeline' }
        [pscustomobject]@{ Tool = 'velociraptor (enterprise)'; Url = 'https://github.com/Velocidex/velociraptor/releases'; Use = 'if you move to always-on agent-based DFIR' }
    )
    $rows | Format-Table Tool, Url, Use -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host "Tip: -Mode Setup downloads winpmem/hayabusa/volatility3/chainsaw into tools\ automatically." -ForegroundColor Yellow
}

function Invoke-SetupMode {
    param([string[]]$Wanted)
    $toolsDir = Join-Path (Get-KitRoot) 'tools'
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    $catalog = @(
        [pscustomobject]@{ Name = 'winpmem';     Repo = 'Velocidex/winpmem';                Pattern = '^go-winpmem_amd64.*signed\.exe$|^winpmem.*x64.*\.exe$'; Zip = $false }
        [pscustomobject]@{ Name = 'hayabusa';    Repo = 'Yamato-Security/hayabusa';         Pattern = '^hayabusa-[\d\.]+-win-x64\.zip$'; Zip = $true }
        [pscustomobject]@{ Name = 'volatility3'; Repo = 'volatilityfoundation/volatility3'; Pattern = '^volatility3-win-exes-.*\.zip$'; Zip = $true }
        [pscustomobject]@{ Name = 'chainsaw';    Repo = 'WithSecureOpenSource/chainsaw';     Pattern = '^chainsaw_all_platforms\+rules\.zip$'; Zip = $true }
    )
    $installed = @()
    foreach ($t in $catalog) {
        if ($Wanted -and $Wanted.Count -gt 0 -and $t.Name -notin $Wanted) { continue }
        Write-Host ""
        Write-Host "=== $($t.Name) ===" -ForegroundColor Cyan
        try {
            $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$($t.Repo)/releases/latest" -Headers @{ 'User-Agent' = 'IR-Triage' } -TimeoutSec 30 -ErrorAction Stop
            $asset = @($rel.assets | Where-Object { $_.name -match $t.Pattern } | Select-Object -First 1)[0]
            if (-not $asset) { Write-Host "  no matching asset found in latest release ($($rel.tag_name)) - download manually: https://github.com/$($t.Repo)/releases" -ForegroundColor Yellow; continue }
            $mb = [math]::Round($asset.size / 1MB, 1)
            Write-Host "  latest: $($asset.name) ($mb MB)"
            $confirm = Read-Host "  download to tools\? [Y/n]"
            if ($confirm -match '^[Nn]') { continue }
            $tmp = Join-Path ([IO.Path]::GetTempPath()) $asset.name
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmp -UseBasicParsing -ErrorAction Stop
            if ($t.Zip) {
                $dest = Join-Path $toolsDir $t.Name
                if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
                Expand-Archive -LiteralPath $tmp -DestinationPath $dest -Force -ErrorAction Stop
                Write-Host "  extracted -> tools\$($t.Name)\" -ForegroundColor Green
            } else {
                Copy-Item -LiteralPath $tmp -Destination (Join-Path $toolsDir $asset.name) -Force -ErrorAction Stop
                Write-Host "  saved -> tools\$($asset.name)" -ForegroundColor Green
            }
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            $installed += $t.Name
        } catch {
            Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  manual download: https://github.com/$($t.Repo)/releases" -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "Setup done: $(if ($installed) { $installed -join ', ' } else { 'nothing installed' })" -ForegroundColor $(if ($installed) { 'Green' } else { 'Yellow' })
    Write-Host "hayabusa/volatility3/chainsaw live in tools\<name>\ subfolders - IR-Triage finds them recursively." -ForegroundColor Gray
}

function Invoke-DeployMode {
    param([string[]]$Targets, [string]$DeployPreset, $Cred, [string]$DeployCaseID, [string]$DeploySharePath)
    $kit = Get-KitRoot
    $scriptPath = Join-Path $kit 'IR-Triage.ps1'
    $tools = Join-Path $kit 'tools'
    $outFolder = Join-Path $kit 'collections'
    if (-not (Test-Path $scriptPath)) { Write-Host "IR-Triage.ps1 not found in $kit" -ForegroundColor Red; return }
    if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder -Force | Out-Null }
    $sessionParams = @{ ComputerName = ''; SessionOption = (New-PSSessionOption -NoMachineProfile) }
    if ($Cred) { $sessionParams.Credential = $Cred }
    $ok = @(); $fail = @()
    $total = $Targets.Count; $i = 0
    foreach ($c in $Targets) {
        $i++
        Write-Host "`n[$i/$total] $c" -ForegroundColor Cyan
        try {
            $sessionParams.ComputerName = $c
            $s = New-PSSession @sessionParams -ErrorAction Stop
            $remoteDir = 'C:\Windows\Temp\IRTriage'
            Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $remoteDir -ErrorAction Stop | Out-Null
            Copy-Item -Path $scriptPath -Destination "$remoteDir\IR-Triage.ps1" -ToSession $s -Force
            if (Test-Path $tools) {
                $rd = "$remoteDir\tools"
                Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $rd | Out-Null
                Get-ChildItem $tools -File -Filter '*.txt' | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$rd\$($_.Name)" -ToSession $s -Force }
                if (Test-Path "$tools\iocs.txt") { Copy-Item -Path "$tools\iocs.txt" -Destination "$rd\iocs.txt" -ToSession $s -Force }
            }
            Write-Host "  kit copied, running collection ($DeployPreset preset)..." -ForegroundColor Gray
            $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteDir\IR-Triage.ps1`" -Mode Collect -NoMenu -NoElevate -Preset $DeployPreset -OutputPath `"$remoteDir\out`" -CaseID `"$DeployCaseID`""
            if ($DeploySharePath) { $cmd += " -SharePath `"$DeploySharePath`"" }
            $res = Invoke-Command -Session $s -ScriptBlock {
                param($c, $t)
                $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $c -Wait -PassThru -WindowStyle Hidden
                $z = Get-ChildItem "$t\out" -Filter '*.zip' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($z) { $z.FullName } else { "NORESULT:exit=$($p.ExitCode)" }
            } -ArgumentList $cmd, $remoteDir
            if ($res -and $res -notmatch '^NORESULT') {
                if ($DeploySharePath) {
                    Write-Host "  result uploaded to share: $res" -ForegroundColor Green
                } else {
                    Copy-Item -Path $res -Destination $outFolder -FromSession $s -Force
                    Write-Host "  pulled: $(Split-Path $res -Leaf) -> $outFolder" -ForegroundColor Green
                }
                $ok += $c
            } else {
                Write-Host "  no result zip produced ($res)" -ForegroundColor Red
                $fail += "$c (no output)"
            }
            Invoke-Command -Session $s -ScriptBlock { Remove-Item 'C:\Windows\Temp\IRTriage' -Recurse -Force -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
            Remove-PSSession $s -Confirm:$false
        } catch {
            Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
            $fail += "$c ($($_.Exception.Message))"
        }
    }
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "  DEPLOYMENT SUMMARY: $($ok.Count)/$total succeeded" -ForegroundColor $(if ($fail.Count) { 'Yellow' } else { 'Green' })
    if ($fail.Count) { $fail | ForEach-Object { Write-Host "  FAILED: $_" -ForegroundColor Red } }
    Write-Host "  Collections in: $(if ($DeploySharePath) { $DeploySharePath } else { $outFolder })"
    Write-Host "  Next: .\IR-Triage.ps1 -Mode Analyze -AnalyzePath <that folder>" -ForegroundColor Cyan
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
    $sources += Get-ChildItem $Path -Filter 'IRCASE_*.zip' -File -ErrorAction SilentlyContinue
    foreach ($d in (Get-ChildItem $Path -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^IRCASE_' })) {
        if ((Test-Path (Join-Path $d.FullName 'case.json')) -and -not ($sources | Where-Object { $_.BaseName -eq $d.Name })) { $sources += $d }
    }
    if (-not $sources) { Write-Host "No IRCASE_* packages found in $Path" -ForegroundColor Red; return }
    $findings = @()
    $hosts = @()
    $evtxDirs = @()
    foreach ($src in $sources) {
        $tmp = $null
        $dir = $src.FullName
        if ($src -is [System.IO.FileInfo]) {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fleet_" + $src.BaseName)
            if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($src.FullName, $tmp)
                $dir = $tmp
            } catch { Write-Host "cannot extract $($src.Name): $($_.Exception.Message)" -ForegroundColor Red; continue }
        }
        $host_ = $src.Name -replace '^IRCASE_', '' -replace '_\d{8}_\d{6}.*$', ''
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
            }
            foreach ($k in $map.Keys) {
                $f = Join-Path $csvDir $k
                if ((Test-Path $f) -and -not ((Get-Content $f -First 1) -match '^#')) {
                    try {
                        $rows = Import-Csv $f
                        foreach ($r in @($rows)) {
                            $detail = ''
                            if ($r.PSObject.Properties['Name']) { $detail += "$($r.Name) " }
                            if ($r.PSObject.Properties['Path']) { $detail += "$($r.Path) " }
                            if ($r.PSObject.Properties['Indicator']) { $detail += "[$($r.Indicator)] $($r.Where)" }
                            if ($r.PSObject.Properties['SourceIp']) { $detail += "$($r.SourceIp) ($($r.FailedLogons) failures)" }
                            if ($r.PSObject.Properties['ThreatName']) { $detail += "$($r.ThreatName) $($r.Resources)" }
                            if ($r.PSObject.Properties['RemoteAddress']) { $detail += "$($r.RemoteAddress):$($r.RemotePort) <- $($r.ProcessPath)" }
                            if ($r.PSObject.Properties['Service']) { $detail += "$($r.Service) $($r.Binary)" }
                            if ($r.PSObject.Properties['Verdict']) { $detail = "[$($r.Verdict) $($r.Score)] " + $detail + " {$($r.Evidence)}" }
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
    foreach ($g in ($findings | Where-Object { $_.Type -in @('ProcAnomaly', 'IOC-HIT', 'TaskFlagged', 'ServiceFlagged') } | Group-Object { ($_.Detail -split ' ')[0] })) {
        $hs = @($g.Group | Select-Object -ExpandProperty Host -Unique)
        if ($hs.Count -gt 1) { $crossHost += [pscustomobject]@{ Indicator = $g.Name; Hosts = ($hs -join ', '); HostCount = $hs.Count } }
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
        $hDir = Split-Path $HayabusaExe -Parent
        Push-Location $hDir
        try { & $HayabusaExe csv-timeline -d "$merged" -o "$hayOut" -q 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
        finally { Pop-Location }
        if (Test-Path $hayOut) {
            $n = @(Get-Content $hayOut | Select-Object -Skip 1).Count
            Write-Host "    hayabusa: $n detections -> $hayOut" -ForegroundColor Yellow
        }
        Remove-Item $merged -Recurse -Force -ErrorAction SilentlyContinue
    }
    $reportCsv = Join-Path $OutFolder 'fleet_report.csv'
    $findings | Sort-Object Host, Type | Export-Csv -LiteralPath $reportCsv -NoTypeInformation -Encoding UTF8
    $summaryTxt = Join-Path $OutFolder 'fleet_summary.txt'
    $lines = @()
    $lines += "IR-Triage fleet analysis - $(Get-Date -Format u)"
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
    $lines | Set-Content -LiteralPath $summaryTxt -Encoding UTF8
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  fleet_report.csv  : $reportCsv" -ForegroundColor Green
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

function ConvertTo-Rot13 {
    param([string]$s)
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
    [pscustomobject]@{ Id = '4.6'; Cat = 'LOGS'; Name = 'Hayabusa Sigma hunt over exported evtx (needs tools\hayabusa)'; Default = $true; Quick = $false;
        Run = {
            $tDir = Get-ToolsDir
            $h = $null
            if ($tDir) { $h = Get-ChildItem -Path $tDir -Recurse -Filter 'hayabusa*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'live-response' } | Select-Object -First 1 }
            if (-not $h) { Write-CaseLog "    hayabusa not in tools\ - skipping (or run: -Mode Setup / -Mode Links)" 'DarkGray'; return }
            $evtxDir = Join-Path $RawDir 'evtx'
            if (-not (Test-Path $evtxDir)) { Write-CaseLog "    no evtx exported - skipping" 'DarkGray'; return }
            $out = Join-Path $CsvDir 'hayabusa_timeline.csv'
            Write-CaseLog "    running hayabusa Sigma timeline (this may take a while)..." 'Cyan'
            Push-Location $h.DirectoryName
            try { & $h.FullName csv-timeline -d "$evtxDir" -o "$out" -q 2>&1 | ForEach-Object { Write-CaseLog "      $_" 'DarkGray' } }
            finally { Pop-Location }
            if (Test-Path $out) {
                $n = @(Get-Content -LiteralPath $out | Select-Object -Skip 1).Count
                Write-CaseLog "    hayabusa: $n detections in csv\hayabusa_timeline.csv" $(if ($n -gt 0) { 'Yellow' } else { 'Gray' })
            } else { Write-CaseLog "    hayabusa produced no output" 'DarkYellow' }
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
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { Write-CaseLog "    reg save $hive failed" 'DarkYellow' }
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
                $vol = Get-ChildItem -Path $tDir -Filter 'vol*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
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
        Write-Host "  IR-TRIAGE v$ScriptVersion   |   $Computer   |   Log range: $range" -ForegroundColor Cyan
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
    $total = @($Selection.Values | Where-Object { $_ }).Count
    $done = 0
    foreach ($m in $script:Modules) {
        if (-not $Selection[$m.Id]) { continue }
        $done++
        Write-Host ""
        Write-CaseLog ("[{0}/{1}] Module {2}: {3}" -f $done, $total, $m.Id, $m.Name) 'Cyan'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            & $m.Run
            $sw.Stop()
            Write-CaseLog ("    done in {0:N1}s" -f $sw.Elapsed.TotalSeconds) 'DarkGreen'
        } catch {
            $sw.Stop()
            Write-CaseLog ("    ERROR: {0}" -f $_.Exception.Message) 'Red'
        }
    }
}

function New-Package {
    Write-Host ""
    Write-CaseLog "Packaging case folder..." 'Cyan'
    $os = Get-WmiOrCim -Class Win32_OperatingSystem
    $case = [pscustomobject]@{
        Tool = "IR-Triage v$ScriptVersion"
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
    $case | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $CaseDir 'case.json') -Encoding UTF8

    $manifest = @()
    $manifest += "IR-Triage v$ScriptVersion evidence manifest"
    $manifest += "CaseID: $($script:CurrentCaseID)  Analyst: $($script:CurrentAnalyst)"
    $manifest += "Host: $Computer  Collected: $($StartTime.ToString('u'))"
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
    if ($SharePath -and $zipped -and (Test-Path $zipPath)) {
        try {
            if (-not (Test-Path $SharePath)) { throw "share path not reachable: $SharePath" }
            Copy-Item -LiteralPath $zipPath -Destination $SharePath -Force -ErrorAction Stop
            $shareResult = "copied to $SharePath"
            Add-Content -LiteralPath (Join-Path $CaseDir 'manifest.txt') -Encoding UTF8 -Value "UPLOADED TO: $SharePath at $(Get-Date -Format u)"
        } catch { $shareResult = "SHARE COPY FAILED: $($_.Exception.Message)" }
    }

    $sizeAll = [math]::Round((Get-ChildItem -LiteralPath $CaseDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
    $zipSize = if ($zipped) { [math]::Round((Get-Item $zipPath).Length / 1MB, 1) } else { 0 }
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  COLLECTION COMPLETE" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  Case folder : $CaseDir  ($sizeAll MB)"
    if ($zipped) { Write-Host "  Package     : $zipPath  ($zipSize MB)" -ForegroundColor White }
    if ($zipHash) { Write-Host "  Zip SHA256  : $zipHash" -ForegroundColor White }
    if ($shareResult) { Write-Host "  Share copy  : $shareResult" -ForegroundColor $(if ($shareResult -match 'FAILED') { 'Red' } else { 'Green' }) }
    Write-Host "  Memory dump : $(if (Test-Path $MemDir) { "$MemDir (NOT in zip - send separately)" } else { 'not captured' })"
    Write-Host ""
    Write-Host "  Send the ZIP file (and memory dump if captured) to the analyst." -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Green
}

if ($Mode -ne 'Collect') {
    switch ($Mode) {
        'Links' { Show-ToolLinks }
        'Setup' { Invoke-SetupMode -Wanted $SetupTools }
        'Analyze' { Invoke-AnalyzeMode -Path $AnalyzePath -HayabusaExe $HayabusaPath }
        'Deploy' {
            if (-not $ComputerName) { Write-Host "-ComputerName required for Deploy mode" -ForegroundColor Red; exit 1 }
            Invoke-DeployMode -Targets $ComputerName -DeployPreset $Preset -Cred $Credential -DeployCaseID $CaseID -DeploySharePath $SharePath
        }
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
$CaseName = "IRCASE_${Computer}_${Stamp}"
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
Write-Host "     ____ _____ ____    _____ _   _ ____  _     ___   _ " -ForegroundColor Cyan
Write-Host "    |  _ \_   _/ __|  |_   _| | | |  _ \| |   / _ \ / \" -ForegroundColor Cyan
Write-Host "    | |_) || || |__     | | | |_| | |_)| |  | | | | ^ |" -ForegroundColor Cyan
Write-Host "    |  _ < | ||  __|    | | |  _  |  _ <| |__| |_| |/ \| " -ForegroundColor Cyan
Write-Host "    |_| \_\|_ |_|       |_| |_| |_|_| \____/ \___/_/ \_\" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  IR-Triage v$ScriptVersion  -  single-script Windows IR toolkit" -ForegroundColor White
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

Write-CaseLog "IR-Triage v$ScriptVersion started on $Computer by $env:USERNAME (admin=$IsAdmin, sysmon=$Sysmon)" 'Gray' -NoConsole

Invoke-FlashTriage

$selection = Get-PresetSelection -P $Preset
if ($NoMenu) {
    Write-Host ""
    Write-CaseLog "NoMenu mode: running preset '$Preset' ($(@($selection.Values | Where-Object { $_ }).Count) modules)" 'Cyan'
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

if (-not $NoMenu) {
    Write-Host ""
    Write-Host "Press any key to close..." -ForegroundColor DarkGray
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { }
}
