$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.38 - role-gate wording ([1] IR team / [2] User), NTDS.dit never touched, Setup
# creates the gitignored tools\iocs feed folder with a README.
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ============================================================================
# PART 1 - role gate + owner-facing wording
# ============================================================================
Check "role gate: [1] IR team" ($src -match '\[1\]  IR team')
Check "role gate: [2] User" ($src -match '\[2\]  User')
Check "role gate: old wording gone" ($src -notmatch 'security / incident response team' -and $src -notmatch 'asked me to run this')
Check "owner path: every security-team reference is now IR team" (($src -split "`n" | Where-Object { $_ -match 'security team' }).Count -eq 0)
Check "owner path: IR team wording present (5 sites)" (($src -split "`n" | Where-Object { $_ -match 'IR team' }).Count -ge 5)

# ============================================================================
# PART 2 - NTDS.dit never touched (file or data); registry role check stays
# ============================================================================
Check "ntds: no copy/load/import code for ntds.dit anywhere" ((@('Copy-LockedFile -Source \$ntds', 'raw\\server\\ntds', 'Join-Path \$env:SystemRoot ''NTDS') | Where-Object { $src -match $_ }).Count -eq 0)
Check "ntds: policy comment in module 8.14" ($src -match 'NTDS\.dit is deliberately NEVER touched')
Check "ntds: registry role fingerprint retained" ($src -match "Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'")
Check "ntds: evidence index states the policy" ($src -match 'NTDS\.dit is never collected by policy')

# ============================================================================
# PART 3 - Setup creates tools\iocs + README.txt
# ============================================================================
Check "setup: creates the iocs feed folder when missing" ($src -match '(?s)Invoke-SetupMode -Wanted \$wanted.*?Join-Path \(Get-ToolsDir\) ''iocs''')
Check "setup: README.txt documents accepted feed formats" ($src -match 'STIX 2\.x bundle JSON' -and $src -match 'MISP JSON export' -and $src -match 'iocs\.txt')
Check "setup: folder creation logged" ($src -match 'IOC feed folder ready')

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
