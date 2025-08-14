@echo off
setlocal enabledelayedexpansion

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please run as administrator.
    echo Right-click on this file and select "Run as administrator".
    pause
    exit /b
)

:: Set the current directory to the script location
cd /d "%~dp0"

:: Activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

:menu
cls
echo Windows Intrusion Detection System (IDS)
echo ===================================
echo.
echo Select components to start:
echo 1. IDS Manager (Web Interface on http://localhost:5000)
echo 2. HIDS Agent
echo 3. NIDS Sensor
echo 4. All Components
echo 5. Exit
echo.

set /p choice=Enter your choice (1-5): 

if "%choice%"=="1" goto manager
if "%choice%"=="2" goto hids
if "%choice%"=="3" goto nids
if "%choice%"=="4" goto all
if "%choice%"=="5" goto end

echo Invalid choice. Please try again.
pause
goto menu

:manager
echo Starting IDS Manager...
start cmd /k "title IDS Manager && if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) && python main.py --component manager"
goto end

:hids
echo Starting HIDS Agent...
start cmd /k "title HIDS Agent && if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) && python main.py --component hids"
goto end

:nids
echo Starting NIDS Sensor...
start cmd /k "title NIDS Sensor && if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) && python main.py --component nids"
goto end

:all
echo Starting all IDS components...
start cmd /k "title IDS Manager && if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) && python main.py --component manager"
timeout /t 2 >nul
start cmd /k "title HIDS Agent && if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) && python main.py --component hids"
timeout /t 2 >nul
start cmd /k "title NIDS Sensor && if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat) && python main.py --component nids"
goto end

:end
echo.
echo Script completed.
if "%choice%"=="5" exit /b