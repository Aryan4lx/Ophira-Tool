$repoScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Ophira.ps1"
# v2.10 module 5.5 (NTFS forensics) logic test - synthetic MFT/USN CSVs through the real Run block
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath "$repoScript" -Raw
$names = @('Test-IsUserWritablePath')
$defs = ''
foreach ($n in $names) {
    $m = [regex]::Match($src, "(?s)function $n \{.*?\r?\n\}")
    if (-not $m.Success) { throw "extract failed: $n" }
    $defs += $m.Value + "`r`n"
}
Invoke-Expression $defs
$m55 = [regex]::Match($src, "(?s)Id = '5\.5';.*?Run = \{(.*?)\r?\n        \} \}\r?\n    \[pscustomobject\]@\{ Id = '6\.1'")
if (-not $m55.Success) { throw 'module 5.5 extract failed' }
$runCode = $m55.Groups[1].Value

# --- fixture environment ---
$case = Join-Path $env:TEMP ("ophira_mft_test_" + (Get-Date -Format 'HHmmss'))
$csvDir = Join-Path $case 'csv'; $rawDir = Join-Path $case 'raw'; $tmp = Join-Path $env:TEMP 'eztoolfake'
New-Item -ItemType Directory -Path $csvDir, $rawDir, $tmp -Force | Out-Null
Set-Content -LiteralPath (Join-Path $tmp 'MFTECmd.exe') -Value 'fake'
$CsvDir = $csvDir; $RawDir = $rawDir

function Get-ToolsDir { $tmp }
function Write-CaseLog { param([string]$Message, [string]$Color = 'Gray') Write-Host "  log: $Message" -ForegroundColor DarkGray }
$saved = @{}
function Save-Rows { param([string]$Name, $Rows) $script:saved[$Name] = $Rows }

$script:callNo = 0
function Invoke-NativeTool {
    param($ExePath, $ToolArgs)
    $outDir = $ToolArgs[([array]::IndexOf($ToolArgs, '--csv')) + 1]
    if ("$($ToolArgs[1])" -match 'MFT$') {
        # MFTECmd $MFT output fixture (standard CSV columns)
        @'
"EntryNumber","FileName","Extension","FileSize","ParentPath","IsDirectory","Created","LastModified"
"1000","evil.exe",".exe","204800","C:\Users\u\AppData\Roaming","false","2026-08-01 10:00:00.0000000","2026-08-01 10:00:00.0000000"
"1001","svchost.exe",".exe","48000","C:\Windows\System32","false","2026-09-24 10:00:00.0000000","2026-09-24 10:00:00.0000000"
"1002","notes.txt",".txt","50","C:\Users\u\Desktop","false","2026-09-20 10:00:00.0000000","2026-09-20 10:00:00.0000000"
"1003","old_thing.dll",".dll","1000","C:\Program Files\Legit","false","2020-01-01 10:00:00.0000000","2020-01-01 10:00:00.0000000"
"1005","dropped.ps1",".ps1","900","C:\Users\u\AppData\Local\Temp","false","2026-09-25 09:00:00.0000000","2026-09-25 09:00:00.0000000"
'@ | Set-Content -LiteralPath (Join-Path $outDir 'mft_full.csv') -Encoding UTF8
    } else {
        # USN journal fixture: burst minute + quiet minutes + non-write reasons
        $lines = @('"EntryNumber","Offset","TimeStamp","Reason","SourceFile"')
        $burstT = [datetime]'2026-09-25 08:30:00'
        for ($i = 0; $i -lt 1200; $i++) {
            $lines += ('"5{0:d4}","100{0}","{1}","DataExtend, Close","file{2}.docx"' -f $i, $burstT.ToString('yyyy-MM-dd HH:mm:ss.ffffff'), ($i % 150))
        }
        $quietT = [datetime]'2026-09-25 09:00:00'
        for ($i = 0; $i -lt 40; $i++) {
            $lines += ('"6{0:d4}","200{0}","{1}","Close","cfg{0}.ini"' -f $i, $quietT.ToString('yyyy-MM-dd HH:mm:ss.ffffff'))
        }
        $lines += ('"7000","3000","{0}","FileCreate","newone.tmp"' -f $quietT.ToString('yyyy-MM-dd HH:mm:ss.ffffff'))
        $lines -join "`r`n" | Set-Content -LiteralPath (Join-Path $outDir 'usn_full.csv') -Encoding UTF8
    }
}

# run the real module code
$sb = [scriptblock]::Create($runCode)
& $sb

$pass = 0; $fail = 0
function Check([string]$label, [bool]$ok) {
    if ($ok) { $script:pass++; Write-Host "  [ok] $label" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}
$mftKept = @($saved['mft_recent'])
Check "mft_recent kept user-path exe (evil.exe, per drive)" (@($mftKept | Where-Object { $_.Name -eq 'evil.exe' }).Count -ge 1)
Check "mft_recent kept recent system exe (svchost.exe)" (@($mftKept | Where-Object { $_.Name -eq 'svchost.exe' }).Count -ge 1)
Check "mft_recent kept recent dropped.ps1" (@($mftKept | Where-Object { $_.Name -eq 'dropped.ps1' }).Count -ge 1)
Check "mft_recent EXCLUDED .txt" (@($mftKept | Where-Object { $_.Name -eq 'notes.txt' }).Count -eq 0)
Check "mft_recent EXCLUDED old non-user dll" (@($mftKept | Where-Object { $_.Name -eq 'old_thing.dll' }).Count -eq 0)
Check "mft flags: evil.exe has user-path+exec" ("$(@($mftKept | Where-Object { $_.Name -eq 'evil.exe' })[0].Flags)" -match 'user-path' -and "$(@($mftKept | Where-Object { $_.Name -eq 'evil.exe' })[0].Flags)" -match 'exec')
$bursts = @($saved['usn_write_bursts'])
Check "burst windows: 1 per NTFS drive" ($bursts.Count -ge 1 -and $bursts.Count -eq (@($bursts | Select-Object -ExpandProperty Drive -Unique)).Count)
Check "burst window = 2026-09-25 08:30 (all drives)" (@($bursts | Where-Object { "$($_.WindowStart)" -eq '2026-09-25 08:30' }).Count -eq $bursts.Count)
Check "burst events = 1200 (all drives)" (@($bursts | Where-Object { "$($_.WriteEvents)" -eq '1200' }).Count -eq $bursts.Count)
Check "burst distinct files = 150 (all drives)" (@($bursts | Where-Object { "$($_.DistinctFiles)" -eq '150' }).Count -eq $bursts.Count)

Write-Host ""
Write-Host "RESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { exit 1 } else { exit 0 }


