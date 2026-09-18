@echo off
title Ophira Evidence Collection
echo ============================================================
echo   OPHIRA - Security Evidence Collection
echo.
echo   What to expect:
echo     1. Windows will ask for permission (click YES)
echo     2. Collection runs 3-5 minutes - DO NOT close this window
echo     3. At the end it shows you the file to send back
echo.
echo   Nothing on this computer is changed or deleted.
echo ============================================================
echo.
powershell.exe -NoProfile -Command "try { Unblock-File -LiteralPath '%~dp0Ophira.ps1' -ErrorAction SilentlyContinue } catch {}"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Ophira.ps1" -SimpleUI -Preset Standard %*
echo.
if NOT "%1"=="" echo (custom options were passed - see output above)
pause
