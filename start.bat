@echo off
cd /d "%~dp0"
pwsh -ExecutionPolicy Bypass -NoProfile -File "%~dp0start.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Co loi xay ra khi khoi dong.
    pause
)

