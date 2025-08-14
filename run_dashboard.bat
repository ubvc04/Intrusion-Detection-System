@echo off
setlocal

:: Check for admin rights and elevate if needed
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B
:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo Windows IDS Dashboard Launcher
echo ============================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Python is not installed or not in PATH.
    echo Please install Python 3.8 or higher.
    goto :end
)

:: Check if virtual environment exists, create if not
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo Error: Failed to create virtual environment.
        goto :end
    )
)

:: Activate virtual environment and install dependencies
echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to install dependencies.
    goto :end
)

:: Start the IDS components in separate windows
echo Starting IDS components...

:: Start Manager with WebSocket dashboard
start "IDS Manager" cmd /c "venv\Scripts\activate.bat && python main.py --component manager --debug"

:: Wait for manager to initialize
echo Waiting for manager to initialize...
timeout /t 5 /nobreak >nul

:: Start HIDS
start "IDS HIDS" cmd /c "venv\Scripts\activate.bat && python main.py --component hids --debug"

:: Check for Npcap/WinPcap installation
echo Checking for packet capture drivers...
powershell -Command "& {
  $npcapInstalled = Test-Path 'C:\Windows\System32\Npcap'
  $winpcapInstalled = Test-Path 'C:\Windows\System32\wpcap.dll'
  
  if (!$npcapInstalled -and !$winpcapInstalled) {
    Write-Host 'WARNING: Neither Npcap nor WinPcap detected. NIDS component will not function properly.' -ForegroundColor Yellow
    Write-Host 'Please download and install Npcap from https://npcap.com/#download' -ForegroundColor Yellow
    Write-Host 'Make sure to select "WinPcap API-compatible Mode" during installation.' -ForegroundColor Yellow
    Write-Host 'After installation, restart this script.' -ForegroundColor Yellow
  } elseif ($npcapInstalled) {
    Write-Host 'Npcap detected. NIDS component should work properly.' -ForegroundColor Green
  } elseif ($winpcapInstalled) {
    Write-Host 'WinPcap detected. NIDS component should work properly.' -ForegroundColor Green
  }
}"

:: Start NIDS
start "IDS NIDS" cmd /c "venv\Scripts\activate.bat && python main.py --component nids --debug"

:: Open dashboard in browser
echo Opening dashboard in browser...
timeout /t 2 /nobreak >nul
start http://localhost:5000

echo.
echo IDS Dashboard is now running.
echo - Real-time Dashboard: http://localhost:5000
echo - HIDS and NIDS agents are running in separate windows.
echo.
echo To test the real-time functionality, you can run:
echo python test_dashboard.py
echo.
echo Press Ctrl+C in each window to stop the components.

:end
endlocal