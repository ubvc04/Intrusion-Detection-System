# Windows IDS Runner Script

# Function to check if running as administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if running as administrator
if (-not (Test-Admin)) {
    Write-Host "This script requires administrator privileges. Restarting with elevated permissions..."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Activate virtual environment if it exists
if (Test-Path "$PSScriptRoot\venv\Scripts\Activate.ps1") {
    . "$PSScriptRoot\venv\Scripts\Activate.ps1"
}

# Function to start a component in a new window
function Start-Component {
    param (
        [string]$Component
    )
    
    $pythonPath = "python"
    $scriptPath = "$PSScriptRoot\main.py"
    
    Start-Process PowerShell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; if (Test-Path .\venv\Scripts\Activate.ps1) { .\venv\Scripts\Activate.ps1 }; $pythonPath $scriptPath --component $Component"
}

# Display menu
Write-Host "Windows Intrusion Detection System (IDS)" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Select components to start:" -ForegroundColor Yellow
Write-Host "1. IDS Manager (Web Interface on http://localhost:5000)" -ForegroundColor Green
Write-Host "2. HIDS Agent" -ForegroundColor Green
Write-Host "3. NIDS Sensor" -ForegroundColor Green
Write-Host "4. All Components" -ForegroundColor Green
Write-Host "5. Exit" -ForegroundColor Red
Write-Host ""

$choice = Read-Host "Enter your choice (1-5)"

switch ($choice) {
    "1" {
        Write-Host "Starting IDS Manager..." -ForegroundColor Cyan
        Start-Component "manager"
    }
    "2" {
        Write-Host "Starting HIDS Agent..." -ForegroundColor Cyan
        Start-Component "hids"
    }
    "3" {
        Write-Host "Starting NIDS Sensor..." -ForegroundColor Cyan
        Start-Component "nids"
    }
    "4" {
        Write-Host "Starting all IDS components..." -ForegroundColor Cyan
        Start-Component "manager"
        Start-Sleep -Seconds 2
        Start-Component "hids"
        Start-Sleep -Seconds 2
        Start-Component "nids"
    }
    "5" {
        Write-Host "Exiting..." -ForegroundColor Red
        exit
    }
    default {
        Write-Host "Invalid choice. Exiting..." -ForegroundColor Red
        exit
    }
}