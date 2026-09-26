# Ophira test runner - syntax gate + all fixture suites (exit 1 on any failure)
$ErrorActionPreference = 'Stop'
$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1'

# ---- syntax gate (PS 5.1 parser) ----
$errs = $null
[void][System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $repoScript -Raw), [ref]$errs)
if ($errs.Count -gt 0) {
    Write-Host "SYNTAX GATE FAILED:" -ForegroundColor Red
    $errs | Select-Object -First 5 | ForEach-Object { Write-Host "  $($_.Message)" }
    exit 1
}
Write-Host "[ok] syntax gate" -ForegroundColor Green

# ---- fixture suites (each test_*.ps1 exits 1 on failure) ----
$failed = @()
foreach ($t in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'test_*.ps1' | Sort-Object Name)) {
    Write-Host ""
    Write-Host "=== $($t.Name) ===" -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $t.FullName
    if ($LASTEXITCODE -ne 0) { $failed += $t.Name }
}

Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host "FAILED SUITES: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "ALL SUITES PASSED" -ForegroundColor Green
exit 0
