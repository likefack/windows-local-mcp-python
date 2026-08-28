@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Primary settings-management entry point. The interactive UI lives in PowerShell.
set "SCRIPT_ROOT=%~dp0"
set "SETUP_SCRIPT=%SCRIPT_ROOT%setup-localmcp.ps1"

if not exist "%SETUP_SCRIPT%" (
    >&2 echo setup-localmcp.ps1 was not found. Extract the full package again.
    pause
    exit /b 1
)

where powershell.exe >nul 2>&1
if errorlevel 1 (
    >&2 echo Windows PowerShell is not available.
    pause
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SETUP_SCRIPT%"
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" pause
exit /b %EXIT_CODE%
