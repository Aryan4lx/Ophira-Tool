$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.26 - STIX/MISP feed ingest, widened IOC xref (DNS/network/filenames), evidence manifest custody,
# credential-exposure sweep (module 8.15)
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
# PART 1 - feed ingest through the real Get-IocList (iocs.txt + STIX + MISP)
# ============================================================================
$m = [regex]::Match($src, "(?s)function Get-IocList \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Get-IocList extract failed' }
Invoke-Expression $m.Value
$tools1 = Join-Path $env:TEMP "ophira_ioc226_$stamp"
New-Item -ItemType Directory -Path (Join-Path $tools1 'iocs') -Force | Out-Null
function Get-ToolsDir { $tools1 }
Set-Content -LiteralPath (Join-Path $tools1 'iocs.txt') -Value "# manual list`n203.0.113.99" -Encoding ASCII
$stix = @'
{"type":"bundle","id":"bundle--1","objects":[
 {"type":"indicator","spec_version":"2.1","pattern":"[file:hashes.'SHA-256' = 'AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444AAAAAAAABBBBCCCCDDDD' ]","valid_from":"2026-01-01T00:00:00Z"},
 {"type":"indicator","spec_version":"2.1","pattern":"[domain-name:value = 'evil-feed.example.com']","valid_from":"2026-01-01T00:00:00Z"},
 {"type":"indicator","spec_version":"2.1","pattern":"[ipv4-addr:value = '198.51.100.7']","valid_from":"2026-01-01T00:00:00Z"},
 {"type":"indicator","spec_version":"2.1","pattern":"[file:name = 'dropper.exe']","valid_from":"2026-01-01T00:00:00Z"},
 {"type":"note","content":"not an indicator"}
]}
'@
Set-Content -LiteralPath (Join-Path $tools1 'iocs\campaign_stix.json') -Value $stix -Encoding UTF8
$misp = @'
{"response":{"Attribute":[
 {"type":"sha1","value":"1234567890123456789012345678901234567890"},
 {"type":"domain","value":"misp-bad.example.org"},
 {"type":"ip-dst","value":"192.0.2.44"},
 {"type":"filename","value":"mimi.dat"}
]}}
'@
Set-Content -LiteralPath (Join-Path $tools1 'iocs\feed_misp.json') -Value $misp -Encoding UTF8
$iocs = Get-IocList
Check "ingest: iocs.txt still parsed (ip)" ($iocs.Ips.ContainsKey('203.0.113.99'))
Check "ingest: STIX sha256 + domain + ip + filename" (($iocs.Hashes.ContainsKey('AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444AAAAAAAABBBBCCCCDDDD')) -and ($iocs.Domains.ContainsKey('evil-feed.example.com')) -and ($iocs.Ips.ContainsKey('198.51.100.7')) -and ($iocs.Names.ContainsKey('dropper.exe')))
Check "ingest: MISP sha1 + domain + ip-dst + filename (response-wrapped)" (($iocs.Sha1.ContainsKey('1234567890123456789012345678901234567890')) -and ($iocs.Domains.ContainsKey('misp-bad.example.org')) -and ($iocs.Ips.ContainsKey('192.0.2.44')) -and ($iocs.Names.ContainsKey('mimi.dat')))
Check "ingest: feed attribution carried" (($iocs.Feed['evil-feed.example.com'] -eq 'campaign_stix') -and ($iocs.Feed['misp-bad.example.org'] -eq 'feed_misp') -and ($iocs.Feed['203.0.113.99'] -eq 'iocs.txt'))
Remove-Item -LiteralPath $tools1 -Recurse -Force -ErrorAction SilentlyContinue

# ============================================================================
# PART 2 - widened xref through the real New-IocHits
# ============================================================================
$m = [regex]::Match($src, "(?s)function New-IocHits \{.*?\r?\n\}")
if (-not $m.Success) { throw 'New-IocHits extract failed' }
Invoke-Expression $m.Value
$m2 = [regex]::Match($src, "(?s)function Import-CaseCsv \{.*?\r?\n\}")
Invoke-Expression $m2.Value
$case2 = Join-Path $env:TEMP "ophira_x226_$stamp"
$CsvDir = Join-Path $case2 'csv'
New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') }
function Get-IocList { @{ Hashes = @{}; Sha1 = @{}; Ips = @{ '198.51.100.7' = $true }; Domains = @{ 'evil-feed.example.com' = $true }; Names = @{ 'dropper.exe' = $true }; Feed = @{ '198.51.100.7' = 'stix'; 'evil-feed.example.com' = 'stix'; 'dropper.exe' = 'misp' } } }
New-Csv (Join-Path $CsvDir 'sysmon_dns.csv') '"Time","Image","QueryName","QueryResults","ProcessId"' @(
    '"2026-09-28 14:04:00","C:\x\evil.exe","sub.evil-feed.example.com","198.51.100.7","4242"',
    '"2026-09-28 14:04:01","C:\x\app.exe","safe.example.com","1.1.1.1","500"'
)
New-Csv (Join-Path $CsvDir 'sysmon_network.csv') '"Time","Image","DestIp","DestPort","Protocol"' @(
    '"2026-09-28 14:05:00","C:\x\evil.exe","198.51.100.7","443","tcp"',
    '"2026-09-28 14:05:01","C:\x\app.exe","1.1.1.1","443","tcp"'
)
New-Csv (Join-Path $CsvDir 'mft_recent.csv') '"Drive","Entry","Created","CreatedFN","LastModified","Size","Name","Path","Flags"' @(
    '"C:","100001","2026-09-28 14:03:00","","","","dropper.exe","C:\Users\public\dropper.exe","exec;user-path"',
    '"C:","100002","2026-09-28 14:03:00","","","","notepad.exe","C:\Windows\System32\notepad.exe","exec"'
)
New-IocHits
$dns = @($saved['ioc_hits_dns'])
$net = @($saved['ioc_hits_network'])
$mft = @($saved['ioc_hits_mft'])
Check "xref: subdomain of feed domain hit in DNS" ($dns.Count -eq 1 -and $dns[0].Query -eq 'sub.evil-feed.example.com')
Check "xref: DNS hit carries feed + resolved IP" ($dns[0].Feed -eq 'stix' -and "$($dns[0].Resolved)" -match '198\.51\.100\.7')
Check "xref: network hit exact IP only" ($net.Count -eq 1 -and $net[0].RemoteIp -eq '198.51.100.7' -and $net[0].Feed -eq 'stix')
Check "xref: MFT filename exact match only" ($mft.Count -eq 1 -and $mft[0].Indicator -eq 'dropper.exe' -and $mft[0].Feed -eq 'misp')

# ============================================================================
# PART 3 - credential sweep + manifest + structural wiring
# ============================================================================
Check "8.15: module saves credential_sweep" ($src -match "Save-Rows -Name 'credential_sweep'")
Check "8.15: WLAN keys captured to raw\wifi via key=clear" ($src -match 'wlan show profile name="\$p" key=clear' -and $src -match "Out-RawText -SubDir 'wifi'")
Check "8.15: DPAPI Credentials/Protect blobs copied to raw\vault" ($src -match 'AppData\\Local\\Microsoft\\Credentials' -and $src -match 'AppData\\Local\\Microsoft\\Protect')
Check "8.15: LSASS dump hunt is shallow + recorded only" ($src -match "Filter '\*\.dmp'" -and $src -match 'Possible credential dump on disk')
Check "browser: Login Data + Local State added to raw copy" (($src -match "'Bookmarks', 'Login Data'") -and ($src -match 'foreach \(\$rootFile in @\(''Local State''\)\)'))
Check "manifest: chain-of-custody header lines" (($src -match 'evidence manifest \+ chain of custody') -and ($src -match 'Packaged: ') -and ($src -match 'Custody: the case zip is the evidence unit'))
Check "verdict: DNS/network + MFT filename IOC signals (floor 2)" (($src -match "Add-Signal 'IOC hit - known-bad DNS query / historical connection' 2") -and ($src -match 'known-bad filename on disk'))
Check "regen: New-IocHits runs in the shared pipeline" ($src -match 'try \{ New-IocHits \}')
Check "report: credential sweep table + defanged IOC additions" (($src -match 'Credential exposure sweep') -and ($src -match "Import-CaseCsv 'ioc_hits_dns'"))
Check "evidence index: new artifacts documented" (($src -match "'ioc_hits_dns'") -and ($src -match "'credential_sweep'"))
$gi = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) '.gitignore') -Raw
Check "gitignore: tools/iocs/ excluded" ($gi -match 'tools/iocs/')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $case2 -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }
