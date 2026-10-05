$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.33 - tunnel & remote-access hunt pack: module 8.16 remote_access.csv builder,
# hunt rules R23-R26, verdict wiring, canary battery (tunnel plant + service + SSH keys).
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$stamp = Get-Date -Format 'HHmmss'
$fix = Join-Path ([IO.Path]::GetTempPath()) "ophira_v233_$stamp"
New-Item -ItemType Directory -Path $fix -Force | Out-Null

# ============================================================================
# PART 1 - module 8.16 remote_access builder through the real Run block
# ============================================================================
$m816 = [regex]::Match($src, "(?s)Id = '8\.16';.*?Run = \{(.*?)\r?\n        \} \}\r?\n\)")
if (-not $m816.Success) { throw 'extract failed: module 8.16' }
$RawDir = Join-Path $fix 'raw'
New-Item -ItemType Directory -Path $RawDir -Force | Out-Null

# fixtures: programdata ssh keys + anydesk logs + two profiles
$pd = Join-Path $fix 'ProgramData'
New-Item -ItemType Directory -Path (Join-Path $pd 'ssh') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $pd 'ssh\administrators_authorized_keys') -Value 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIadmin admin@x' -Encoding ASCII
New-Item -ItemType Directory -Path (Join-Path $pd 'AnyDesk') -Force | Out-Null
Set-Content -LiteralPath (Join-Path $pd 'AnyDesk\connection_trace.txt') -Value 'canary trace line' -Encoding ASCII
foreach ($u in @('alice', 'bob')) {
    New-Item -ItemType Directory -Path (Join-Path $fix "Users\$u\.ssh") -Force | Out-Null
}
Set-Content -LiteralPath (Join-Path $fix 'Users\alice\.ssh\authorized_keys') -Value '# only comments' -Encoding ASCII
Set-Content -LiteralPath (Join-Path $fix 'Users\bob\.ssh\authorized_keys') -Value 'ssh-rsa AAAAB3NzaC1yc2EAAAbob bob@x' -Encoding ASCII

$env:ProgramDataPrev = $env:ProgramData
$env:ProgramData = $pd
function Get-WmiOrCim { param([string]$Class, [string]$Filter = '', [string]$Namespace = '')
    @(
        [pscustomobject]@{ Name = 'svchost'; DisplayName = 'Windows Common'; PathName = 'C:\Windows\system32\svchost.exe -k netsvcs'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
        [pscustomobject]@{ Name = 'ngroksvc'; DisplayName = 'ngrok tunnel'; PathName = 'C:\Tools\ngrok.exe service run'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
        [pscustomobject]@{ Name = 'AnyDeskService'; DisplayName = 'AnyDesk Service'; PathName = 'C:\Program Files\AnyDesk.exe --service'; StartMode = 'Auto'; State = 'Stopped'; StartName = 'LocalSystem' }
        [pscustomobject]@{ Name = 'sshd'; DisplayName = 'OpenSSH Server'; PathName = 'C:\Windows\System32\OpenSSH\sshd.exe'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
    )
}
function Get-UserProfileList {
    @(
        [pscustomobject]@{ Sid = 'S-1-5-21-1'; Path = (Join-Path $fix 'Users\alice'); User = 'alice' }
        [pscustomobject]@{ Sid = 'S-1-5-21-2'; Path = (Join-Path $fix 'Users\bob'); User = 'bob' }
    )
}
function Get-ItemProperty { param($Path, $Name, $ErrorAction) [pscustomobject]@{ ServiceDll = 'C:\ProgramData\rdpwrap\rdpwrap.dll' } }
function Save-Rows { param([string]$Name, $Rows) $script:saved816[$Name] = $Rows }
function Out-RawText { param([string]$SubDir, [string]$Name, [string[]]$Text) $script:rawFiles[$Name] = "$SubDir\$Name" }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
$saved816 = @{}
$rawFiles = @{}
$mod816 = [pscustomobject]@{ Id = '8.16'; Name = 'Remote access sweep'; Run = [scriptblock]::Create($m816.Groups[1].Value) }
& $mod816.Run
$env:ProgramData = $env:ProgramDataPrev
Remove-Item Env:\ProgramDataPrev -ErrorAction SilentlyContinue
$ra = @($saved816['remote_access'])
Check "8.16: tunnel service row (running)" (@($ra | Where-Object { $_.Type -eq 'Tunnel service' -and $_.Name -eq 'ngroksvc' -and $_.State -eq 'running' }).Count -eq 1)
Check "8.16: RA tool service row (AnyDesk, stopped)" (@($ra | Where-Object { $_.Type -eq 'RA tool service' -and "$($_.Name)" -match 'AnyDesk' -and $_.State -eq 'Stopped' }).Count -eq 1)
Check "8.16: benign svchost NOT matched" (@($ra | Where-Object { $_.Name -eq 'svchost' }).Count -eq 0)
Check "8.16: sshd presence row" (@($ra | Where-Object { $_.Type -eq 'SSH server' -and $_.Name -eq 'sshd' }).Count -eq 1)
Check "8.16: RDP ServiceDll tamper row (rdpwrap)" (@($ra | Where-Object { $_.Type -eq 'RDP ServiceDll tamper' -and "$($_.Path)" -match 'rdpwrap' }).Count -eq 1)
Check "8.16: administrators_authorized_keys populated (comment-free count = 1)" (@($ra | Where-Object { $_.Type -eq 'SSH authorized_keys' -and $_.Name -eq 'administrators_authorized_keys' -and "$($_.State)" -match 'populated \(1 key' }).Count -eq 1)
Check "8.16: alice comments-only keys NOT populated" (@($ra | Where-Object { $_.Type -eq 'SSH authorized_keys' -and $_.Name -eq 'authorized_keys' -and "$($_.State)" -match 'empty' -and "$($_.Detail)" -match 'alice' }).Count -eq 1)
Check "8.16: bob populated keys + sha256 detail" (@($ra | Where-Object { $_.Type -eq 'SSH authorized_keys' -and "$($_.Detail)" -match 'bob' -and "$($_.Detail)" -match 'sha256 [0-9A-F]{20}' }).Count -eq 1)
Check "8.16: populated key content raw-copied to ra_logs" (@($script:rawFiles.Values | Where-Object { $_ -match '^ra_logs\\authorized_keys_' }).Count -ge 2)
Check "8.16: AnyDesk data dir row + trace copied" (@($ra | Where-Object { $_.Type -eq 'RA tool data dir' -and "$($_.Name)" -match 'AnyDesk' -and "$($_.Detail)" -match 'raw\\ra_logs' }).Count -eq 1 -and (Test-Path (Join-Path $RawDir 'ra_logs\AnyDesk\connection_trace.txt')))
Check "8.16: schema Type/Name/State/Path/Detail" ("$(@($ra)[0].PSObject.Properties.Name -join ',')" -eq 'Type,Name,State,Path,Detail')

# ============================================================================
# PART 2 - R23-R26 through the real New-HuntFindings
# ============================================================================
$mhf = [regex]::Match($src, "(?s)function New-HuntFindings \{.*?\r?\n\}")
if (-not $mhf.Success) { throw 'extract failed: New-HuntFindings' }
$caseCsv = @{
    'processes'           = @([pscustomobject]@{ PID = 4242; PPID = 100; Name = 'ngrok.exe'; Path = 'C:\Tools\ngrok.exe'; Company = ''; Description = ''; CommandLine = 'ngrok.exe tcp 3389'; Created = '2026-10-05 10:00:00'; Flags = '' })
    'services'            = @(
        [pscustomobject]@{ Name = 'chisel'; DisplayName = 'chisel tunnel'; PathName = 'C:\Tools\chisel.exe server'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem'; ProcessId = 99; Flags = '' },
        [pscustomobject]@{ Name = 'AnyDeskService'; DisplayName = 'AnyDesk Service'; PathName = 'C:\Program Files\AnyDesk.exe --service'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem'; ProcessId = 98; Flags = '' }
    )
    'system_new_services' = @([pscustomobject]@{ Time = '2026-10-05 09:00:00'; Service = 'canary_tunneld'; Binary = 'C:\Users\Public\canary_ngrok.exe'; Type = 'NewService' })
    'mft_recent'          = @([pscustomobject]@{ Path = 'C:\Users\Public\ligolo-ng.exe'; Created = '2026-10-05 08:00:00'; CreatedFN = '' })
    'amcache'             = @([pscustomobject]@{ Name = 'frpc.exe'; ApplicationName = ''; SourceSimpleName = ''; Timestamp = '2026-10-05 07:00:00' })
    'remote_access'       = @(
        [pscustomobject]@{ Type = 'RA tool service'; Name = 'AnyDeskService'; State = 'running'; Path = 'C:\Program Files\AnyDesk.exe'; Detail = 'x' },
        [pscustomobject]@{ Type = 'RA tool data dir'; Name = 'TeamViewer'; State = 'present'; Path = 'C:\ProgramData\TeamViewer'; Detail = '3 evidence file(s)' },
        [pscustomobject]@{ Type = 'RDP ServiceDll tamper'; Name = 'TermService'; State = 'tampered'; Path = 'C:\ProgramData\rdpwrap\rdpwrap.dll'; Detail = 'ServiceDll is not termsrv.dll' },
        [pscustomobject]@{ Type = 'SSH authorized_keys'; Name = 'administrators_authorized_keys'; State = 'populated (1 key line(s))'; Path = 'C:\ProgramData\ssh\administrators_authorized_keys'; Detail = 'sha256 ABC' },
        [pscustomobject]@{ Type = 'SSH authorized_keys'; Name = 'authorized_keys'; State = 'empty/comments-only'; Path = 'C:\Users\alice\.ssh\authorized_keys'; Detail = 'profile alice' }
    )
}
function Import-CaseCsv { param([string]$Name) if ($script:caseCsv.ContainsKey($Name)) { return $script:caseCsv[$Name] }; return @() }
$savedHF = @()
function Save-Rows { param([string]$Name, $Rows) if ($Name -eq 'hunt_findings') { $script:savedHF = @($Rows) } }
Invoke-Expression $mhf.Value
New-HuntFindings
$hf = $script:savedHF
$r23a = @($hf | Where-Object { $_.Rule -eq 'Remote-access tunnel binary active' })
Check "R23: high - running process (ngrok.exe)" (@($r23a | Where-Object { "$($_.Entity)" -match 'ngrok\.exe' -and $_.Severity -eq 'high' -and $_.Evidence -match 'running as process' }).Count -eq 1)
Check "R23: high - installed service (chisel)" (@($r23a | Where-Object { "$($_.Entity)" -match 'chisel\.exe' -and $_.Evidence -match "service 'chisel'" }).Count -eq 1)
Check "R23: high - 7045 service install (canary_tunneld)" (@($r23a | Where-Object { "$($_.Entity)" -match 'canary_ngrok\.exe' -and $_.Evidence -match "service 'canary_tunneld'" -and "$($_.Attck)" -eq 'T1543.003' -and $_.Evidence -match 'installed at' }).Count -eq 1)
$r23f = @($hf | Where-Object { $_.Rule -eq 'Remote-access tunnel tool on disk' })
Check "R23: medium - file-only (ligolo-ng + frpc)" ($r23f.Count -eq 2 -and (@($r23f | Where-Object { $_.Entity -match 'ligolo-ng\.exe|frpc\.exe' })).Count -eq 2 -and @($r23f | Where-Object { $_.Severity -ne 'medium' }).Count -eq 0)
$r24 = @($hf | Where-Object { $_.Rule -eq 'Remote-access tool present' })
Check "R24: medium - AnyDesk deduped across services+remote_access" (@($r24 | Where-Object { "$($_.Entity)" -match 'AnyDesk' }).Count -eq 1)
Check "R24: TeamViewer data dir lead included" (@($r24 | Where-Object { "$($_.Entity)" -match 'TeamViewer' }).Count -eq 1)
Check "R25: high - ServiceDll tamper" (@($hf | Where-Object { $_.Rule -eq 'RDP ServiceDll tamper' -and $_.Severity -eq 'high' -and "$($_.Evidence)" -match 'rdpwrap' -and "$($_.Attck)" -eq 'T1112' }).Count -eq 1)
Check "R26: high - populated keys only" (@($hf | Where-Object { $_.Rule -eq 'SSH authorized_keys present' -and $_.Severity -eq 'high' -and "$($_.Entity)" -match 'administrators_authorized_keys' }).Count -eq 1 -and @($hf | Where-Object { "$($_.Entity)" -match 'alice' }).Count -eq 0)
Check "hunt: T1572/T1219/T1098.004 tags" (@($hf | Where-Object { @('T1572', 'T1219', 'T1098.004') -contains "$($_.Attck)" }).Count -ge 4)

# ============================================================================
# PART 3 - verdict wiring + coverage
# ============================================================================
Check "verdict: high-rule regex includes R23/R25/R26" ($src -match 'Remote-access tunnel\|ServiceDll tamper\|authorized_keys')
Check "verdict: signal label mentions tunnel/RDP hijack/SSH keys" ($src -match 'webshell / tunnel / RDP hijack / SSH keys')
Check "coverage: remote access sweep row" ($src -match "Add-Cov 'Remote access sweep \(tunnels/RA tools/SSH keys\)'")

# ============================================================================
# PART 4 - canary battery + scorecard
# ============================================================================
Check "canary: consent mentions fake tunnel tool + service + SSH keys" ($src -match 'fake tunnel tool' -and $src -match 'canary_tunneld service \(registered \+ immediately removed' -and $src -match 'administrators_authorized_keys \(file removed/restored after\)')
Check "canary: ngrok copy kept alive via Start-Process ping" ($src -match [regex]::Escape("Start-Process -FilePath `$canNgrok -ArgumentList '/c', 'ping -n 400 127.0.0.1 > nul' -WindowStyle Hidden -PassThru"))
Check "canary: service registered then deleted (7045 remains)" ($src -match 'sc\.exe create canary_tunneld binPath= "\$canNgrok" start= demand' -and $src -match 'sc\.exe delete canary_tunneld')
Check "canary: labeled key line planted in administrators_authorized_keys" ($src -match [regex]::Escape('Add-Content -LiteralPath $akFile -Value') -and $src -match 'canary@ophira-selftest')
Check "canary: prior key file state restored or file removed" ($src -match [regex]::Escape('if ($akCreated) { Remove-Item -LiteralPath $akFile -Force -ErrorAction Stop }') -and $src -match [regex]::Escape('else { Set-Content -LiteralPath $akFile -Value $akPrev -ErrorAction Stop }'))
Check "canary: ngrok process killed + binary removed in cleanup" ($src -match [regex]::Escape('Stop-Process -Id $ngProc.Id -Force') -and $src -match [regex]::Escape('Remove-Item $canExe, $canNgrok'))
Check "scorecard: R23/RA-telemetry/R26 rows" ((@('R23  remote-access tunnel \(canary_ngrok\)', 'RA   service-install telemetry \(7045 canary_tunneld\)', 'R26  SSH authorized_keys plant') | Where-Object { $src -match $_ }).Count -eq 3)
Check "scorecard: reads remote_access + system_new_services" (($src -match ([regex]::Escape("Join-Path `$csv 'remote_access.csv'"))) -and ($src -match ([regex]::Escape("Join-Path `$csv 'system_new_services.csv'"))))
Check "scorecard: R25 printed n/a (not planted)" ($src -match 'R25  RDP ServiceDll tamper  n/a')

Remove-Item $fix -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
