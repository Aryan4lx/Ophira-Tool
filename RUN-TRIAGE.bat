@echo off
title IR Triage Collection
echo ============================================================
echo   IR TRIAGE - Incident Response Collection
echo   You will get an administrator prompt (UAC). Click YES.
echo   Wait until the window says COLLECTION COMPLETE.
echo ============================================================
echo.
powershell.exe -NoProfile -Command "try { Unblock-File -LiteralPath '%~dp0IR-Triage.ps1' -ErrorAction SilentlyContinue } catch {}"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0IR-Triage.ps1" %*
echo.
pause
