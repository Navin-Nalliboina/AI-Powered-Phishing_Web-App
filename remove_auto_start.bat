@echo off
title CyberShield AI - Remove Windows Auto-Start
color 0E
echo ===================================================================
echo     REMOVE CYBERSHIELD AI FROM WINDOWS STARTUP                     
echo ===================================================================
echo.

set STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
set SHORTCUT_PATH=%STARTUP_DIR%\CyberShield_AI.lnk

if exist "%SHORTCUT_PATH%" (
    del "%SHORTCUT_PATH%"
    echo [SUCCESS] CyberShield AI was removed from Windows Startup.
) else (
    echo [*] CyberShield AI was not registered in Windows Startup.
)

echo.
pause
