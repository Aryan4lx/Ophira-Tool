$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.44 - FP tuning from the first live case (OPHIRA_DESKTOP-88Q1H74_20261007_082342):
# (1) keylogger YARA rule proximity-gated (Electron bundles carried the strings megabytes apart),
# (2) sigma-high single-rule storm carries no verdict weight (196 events / 1 rule on a dev box),
# (3) R22 birth-attribute checks skip servicing/updater/Store paths and non-PE files,
# (4) Test-IsUserWritablePath anchored (C:\Intel) + WindowsApps never user-writable
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
. (Join-Path $PSScriptRoot '_casehelpers.ps1')

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

# ============================================================================
# PART 1 - static wiring
# ============================================================================
Check "verdict: sigma-high storm gated to >=3 events from >=2 distinct rules" ($src -match [regex]::Escape('if ($hayHigh.Count -ge 3 -and $hayHighRules -ge 2) { 2 } else { 0 }'))
Check "verdict: high signal uses highFloor variable (not hardcoded 2)" ($src -match [regex]::Escape("Add-Signal 'Sigma detection - high' `$highFloor"))
Check "hunt R22: servicing/Store/updater skip list present" ($src -match 'WinSxS\\Temp\\InFlight' -and $src -match 'WindowsApps' -and $src -match 'updated\|Application')
Check "hunt R22: birth-attribute checks gated on PE files only" (($src -match [regex]::Escape('$attrOk = ("$($m.Path)" -notmatch $tfSkipRe)')) -and ($src -match [regex]::Escape('if ($attrOk -and "$($m.CreatedFN)")')))
$pack = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\endpoint\yara\rules\ophira-pack.yar') -Raw
Check "yara pack: keylogger rule proximity-gated (API pair within 8KB)" ($pack -match '(?s)OPHIRA_Suspicious_Keylogger_Strings.*?@a1 - @a2 < 8192.*?@a2 - @a1 < 8192')
Check "yara pack: keylog keyword bounded to the cluster (32KB)" ($pack -match '(?s)OPHIRA_Suspicious_Keylogger_Strings.*?@a3 - @a1 < 32768')

# ============================================================================
# PART 2 - Test-IsUserWritablePath behavioral (anchored roots + WindowsApps guard)
# ============================================================================
$m = [regex]::Match($src, "(?s)function Test-IsUserWritablePath \{.*?\r?\n\}")
if (-not $m.Success) { throw 'Test-IsUserWritablePath extract failed' }
Invoke-Expression $m.Value
Check "path: C:\Intel at drive root = user-writable (legacy temp drop dir)" (Test-IsUserWritablePath 'C:\Intel\tool.exe')
Check "path: C:\AMD at drive root = user-writable" (Test-IsUserWritablePath 'C:\AMD\setup.exe')
Check "path: deep Intel VFS (Store payload) NOT user-writable" (-not (Test-IsUserWritablePath 'C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.32.2604.0_x64__8j3eq9eme6ctt\VFS\ProgramFilesX64\Intel\Intel Graphics Software\IntelGraphicsSoftware.Service.exe'))
Check "path: WindowsApps never user-writable (TrustedInstaller-only)" (-not (Test-IsUserWritablePath 'C:\Program Files\WindowsApps\SomeApp\app.exe'))
Check "path: vendor service under deep \Intel\ folder NOT user-writable" (-not (Test-IsUserWritablePath 'C:\WINDOWS\System32\DriverStore\FileRepository\nvam.inf_amd64\Display.NvContainer\Intel\helper.exe'))
Check "path: user-profile binary still flagged" (Test-IsUserWritablePath 'C:\Users\ary\AppData\Local\evil\evil.exe')
Check "path: ProgramData still flagged" (Test-IsUserWritablePath 'C:\ProgramData\svc\svc.exe')

# ============================================================================
# PART 3 - YARA keylogger rule against the real yr.exe (skipped when tool absent)
# ============================================================================
$yr = Get-ChildItem -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools') -Recurse -Filter 'yr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $yr) {
    Write-Host "  [skip] yr.exe not present - YARA behavioral checks skipped" -ForegroundColor DarkYellow
} else {
    $t = Join-Path $env:TEMP "ophira_v244_$(Get-Date -Format 'HHmmss')"
    New-Item -ItemType Directory -Path $t -Force | Out-Null
    $rng = New-Object System.Random(42)
    $filler = { param($n) $b = New-Object byte[] $n; $rng.NextBytes($b); for ($i = 0; $i -lt $n; $i += 61) { $b[$i] = 0x41 + ($i % 26) }; $b }
    # far.bin: the OpenCode.exe FP shape - all three strings present, megabytes apart
    $ms = New-Object System.IO.MemoryStream
    $b1 = [Text.Encoding]::ASCII.GetBytes("MZ" + ("A" * 500)); $ms.Write($b1, 0, $b1.Length)
    $f = & $filler (1024 * 1024); $ms.Write($f, 0, $f.Length)
    $b2 = [Text.Encoding]::ASCII.GetBytes("GetAsyncKeyState"); $ms.Write($b2, 0, $b2.Length)
    $f = & $filler (1024 * 1024); $ms.Write($f, 0, $f.Length)
    $b3 = [Text.Encoding]::ASCII.GetBytes("SetWindowsHookEx"); $ms.Write($b3, 0, $b3.Length)
    $f = & $filler (1024 * 1024); $ms.Write($f, 0, $f.Length)
    $b4 = [Text.Encoding]::Unicode.GetBytes("keylogger"); $ms.Write($b4, 0, $b4.Length)
    [IO.File]::WriteAllBytes((Join-Path $t 'far.bin'), $ms.ToArray())
    # near.bin: real keylogger shape - import-table cluster + keyword nearby
    $ms2 = New-Object System.IO.MemoryStream
    $b1 = [Text.Encoding]::ASCII.GetBytes("MZ" + ("A" * 500)); $ms2.Write($b1, 0, $b1.Length)
    $b2 = [Text.Encoding]::ASCII.GetBytes("GetAsyncKeyState`0SetWindowsHookEx`0"); $ms2.Write($b2, 0, $b2.Length)
    $f = & $filler 2048; $ms2.Write($f, 0, $f.Length)
    $b3 = [Text.Encoding]::Unicode.GetBytes("keylogger.dll"); $ms2.Write($b3, 0, $b3.Length)
    [IO.File]::WriteAllBytes((Join-Path $t 'near.bin'), $ms2.ToArray())
    $rulesDir = Join-Path $yr.DirectoryName 'rules'
    foreach ($fx in @(@('far.bin', $false), @('near.bin', $true))) {
        $out = & $yr.FullName scan --output-format=ndjson $rulesDir (Join-Path $t $fx[0]) 2>&1
        $hit = @($out | Where-Object { "$_" -match 'OPHIRA_Suspicious_Keylogger_Strings' }).Count -gt 0
        Check "yara behavioral: $($fx[0]) $(if ($fx[1]) { 'MATCHES (clustered keylogger shape)' } else { 'clean (scattered-string bundle shape)' })" ($hit -eq $fx[1])
    }
    Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 } else { exit 0 }
