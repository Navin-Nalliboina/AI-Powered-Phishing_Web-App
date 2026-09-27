
@echo off
title AI-Powered Phishing & Threat Detection Web App
cd /d "%~dp0"

:: 1. Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python was not found in your system PATH!
    echo Please install Python 3.10 or higher from https://python.org
    pause
    exit /b 1
)

:: 2. Launch Tkinter GUI Window
start "" pythonw launcher.py

exit /b 0
