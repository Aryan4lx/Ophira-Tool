# Shared fixture helpers - CSV sortment map + path helpers, self-extracted from Ophira.ps1.
# Dot-source from a test file:  . (Join-Path $PSScriptRoot '_casehelpers.ps1')
# (standalone-safe: re-reads the repo script when $src is not already loaded)
if (-not $repoScript) { $repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'Ophira.ps1' }
$hsrc = if ($src) { $src } else { Get-Content -LiteralPath $repoScript -Raw }
$hm = [regex]::Match($hsrc, '(?s)\$script:CsvCatMap = @\{.*?\r?\n\}')
if (-not $hm.Success) { throw '_casehelpers: CsvCatMap extract failed' }
Invoke-Expression $hm.Value
foreach ($hfn in @('Get-CaseCsvPath', 'Test-CaseCsv', 'Get-CaseCsvFullPath', 'Import-CsvFlatMapped')) {
    $hm2 = [regex]::Match($hsrc, "(?s)function $hfn \{.*?\r?\n\}")
    if ($hm2.Success) { Invoke-Expression $hm2.Value }
}
