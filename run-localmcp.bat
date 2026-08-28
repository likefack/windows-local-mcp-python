@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Normal startup entry point. The config selector is read by PowerShell.
set "SCRIPT_ROOT=%~dp0"
set "RUN_SCRIPT=%SCRIPT_ROOT%run-localmcp.ps1"

if not exist "%RUN_SCRIPT%" (
    >&2 echo run-localmcp.ps1 was not found. Extract the full package again.
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RUN_SCRIPT%" %*
exit /b %ERRORLEVEL%
