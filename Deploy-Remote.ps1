<#
Deploy-Remote.ps1 - fleet deployment of IR-Triage over WinRM
Reads a list of hosts, copies the kit to each, runs it, pulls the zip back.
Requires: WinRM enabled on targets + admin credentials.
Usage:
  .\Deploy-Remote.ps1 -ComputerName SRV01,SRV02,WS10-IT -Preset Quick
  .\Deploy-Remote.ps1 -ComputerName (Get-Content hosts.txt) -Preset Standard -Credential (Get-Credential)
  .\Deploy-Remote.ps1 -ComputerName SRV01 -Preset Quick -SharePath \\IR-SRV\collections$
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$ComputerName,
    [ValidateSet('Flash', 'Quick', 'Standard', 'Full')]
    [string]$Preset = 'Quick',
    [System.Management.Automation.PSCredential]$Credential,
    [string]$CaseID = '',
    [string]$SharePath = '',
    [string]$KitFolder = $PSScriptRoot,
    [string]$OutFolder = "$PSScriptRoot\collections"
)

$ErrorActionPreference = 'Continue'
$script = Join-Path $KitFolder 'IR-Triage.ps1'
$tools = Join-Path $KitFolder 'tools'
if (-not (Test-Path $script)) { Write-Host "IR-Triage.ps1 not found in $KitFolder" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $OutFolder)) { New-Item -ItemType Directory -Path $OutFolder -Force | Out-Null }

$sessionParams = @{ ComputerName = ''; SessionOption = (New-PSSessionOption -NoMachineProfile) }
if ($Credential) { $sessionParams.Credential = $Credential }

$ok = @(); $fail = @()
$total = $ComputerName.Count; $i = 0
foreach ($c in $ComputerName) {
    $i++
    Write-Host "`n[$i/$total] $c" -ForegroundColor Cyan
    try {
        $sessionParams.ComputerName = $c
        $s = New-PSSession @sessionParams -ErrorAction Stop
        $remoteDir = 'C:\Windows\Temp\IRTriage'
        Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $remoteDir -ErrorAction Stop | Out-Null
        Copy-Item -Path $script -Destination "$remoteDir\IR-Triage.ps1" -ToSession $s -Force
        if (Test-Path $tools) {
            $rd = "$remoteDir\tools"
            Invoke-Command -Session $s -ScriptBlock { $null = New-Item -ItemType Directory -Path $args[0] -Force } -ArgumentList $rd | Out-Null
            Get-ChildItem $tools -File | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$rd\$($_.Name)" -ToSession $s -Force }
        }
        Write-Host "  kit copied, running collection ($Preset preset)..." -ForegroundColor Gray
        $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$remoteDir\IR-Triage.ps1`" -NoMenu -NoElevate -Preset $Preset -OutputPath `"$remoteDir\out`" -CaseID `"$CaseID`""
        if ($SharePath) { $cmd += " -SharePath `"$SharePath`"" }
        $res = Invoke-Command -Session $s -ScriptBlock {
            param($c, $t)
            $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $c -Wait -PassThru -WindowStyle Hidden
            $z = Get-ChildItem "$t\out" -Filter '*.zip' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($z) { $z.FullName } else { "NORESULT:exit=$($p.ExitCode)" }
        } -ArgumentList $cmd, $remoteDir
        if ($res -and $res -notmatch '^NORESULT') {
            if ($SharePath) {
                Write-Host "  result uploaded to share: $res" -ForegroundColor Green
            } else {
                Copy-Item -Path $res -Destination $OutFolder -FromSession $s -Force
                Write-Host "  pulled: $(Split-Path $res -Leaf) -> $OutFolder" -ForegroundColor Green
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
Write-Host "  Collections in: $(if ($SharePath) { $SharePath } else { $OutFolder })"
Write-Host "  Next: run Analyze-Fleet.ps1 against the folder with the zips" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
