@echo off
title CyberShield AI - Setup Windows Auto-Start
color 0A
echo ===================================================================
echo     CONFIGURE CYBERSHIELD AI TO RUN AUTOMATICALLY ON WINDOWS BOOT  
echo ===================================================================
echo.

set SCRIPT_DIR=%~dp0
set VBS_TARGET=%SCRIPT_DIR%start_background.vbs
set STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
set SHORTCUT_PATH=%STARTUP_DIR%\CyberShield_AI.lnk

echo [*] Creating Windows Startup shortcut...

powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = '%VBS_TARGET%'; $s.WorkingDirectory = '%SCRIPT_DIR%'; $s.IconLocation = '%SCRIPT_DIR%logo.ico,0'; $s.Description = 'CyberShield AI Background Service'; $s.Save()"

if exist "%SHORTCUT_PATH%" (
    echo.
    echo [SUCCESS] CyberShield AI has been added to Windows Startup!
    echo Every time you turn on your PC, the AI threat detector will start
    echo automatically in the background on http://127.0.0.1:8000
    echo.
    echo To disable this anytime, simply run "remove_auto_start.bat".
) else (
    echo [!] Failed to create startup shortcut.
)

echo.
pause
