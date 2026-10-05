@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Run as the normal user. PowerShell requests UAC only for the installation step.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0update-localmcp.ps1" %*
set "EXIT_CODE=%ERRORLEVEL%"
if /I not "%WLMCP_NO_PAUSE%"=="1" pause
exit /b %EXIT_CODE%
