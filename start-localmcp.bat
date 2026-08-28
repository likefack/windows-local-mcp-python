@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Deprecated compatibility wrapper. Use configure-localmcp.bat for settings.
call "%~dp0configure-localmcp.bat" %*
exit /b %ERRORLEVEL%
