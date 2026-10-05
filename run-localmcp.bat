@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Normal startup entry point. The config selector is read by PowerShell.
set "SCRIPT_ROOT=%~dp0"
set "RUN_SCRIPT=%SCRIPT_ROOT%run-localmcp.ps1"

if not exist "%RUN_SCRIPT%" (
    >&2 echo run-localmcp.ps1 was not found. Extract the full package again.
    set "EXIT_CODE=1"
    goto :startup_failed
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%RUN_SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" goto :startup_finished

:startup_failed
>&2 echo.
>&2 echo Windows Local MCP startup failed. Review the diagnostic message above.

:startup_finished
rem Keep the result visible when Explorer opened this batch and startup returned.
rem Automation can set WLMCP_NO_PAUSE=1 without changing any startup checks.
if /I not "%WLMCP_NO_PAUSE%"=="1" pause
exit /b %EXIT_CODE%
