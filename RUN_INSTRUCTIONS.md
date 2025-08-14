# Running the Windows Intrusion Detection System (IDS)

## Prerequisites

- Windows 10 or 11
- Python 3.8 or higher
- Administrator privileges (required for HIDS and NIDS components)
- Virtual environment with required dependencies installed

## Components

The Windows IDS consists of three main components:

1. **IDS Manager**: Web interface and central management system (runs on http://localhost:5000)
2. **HIDS Agent**: Host-based Intrusion Detection System (monitors file system, registry, and event logs)
3. **NIDS Sensor**: Network-based Intrusion Detection System (monitors network traffic)

## Running the System

### Option 1: Using the Provided Scripts (Recommended)

#### PowerShell Script

1. Right-click on `run_ids.ps1` and select "Run with PowerShell as Administrator"
2. Select which components you want to run from the menu

#### Batch File

1. Right-click on `run_ids.bat` and select "Run as administrator"
2. Select which components you want to run from the menu

### Option 2: Manual Execution

To run the components manually, open a Command Prompt or PowerShell window with administrator privileges and execute the following commands:

```
# Activate the virtual environment (if using)
.\venv\Scripts\activate

# Run the IDS Manager
python main.py --component manager

# Run the HIDS Agent (in a separate admin window)
python main.py --component hids

# Run the NIDS Sensor (in a separate admin window)
python main.py --component nids
```

## Accessing the Web Interface

Once the IDS Manager is running, you can access the web interface at:

**http://localhost:5000**

## Important Notes

- Both the HIDS Agent and NIDS Sensor **require administrator privileges** to function properly
- The HIDS Agent monitors system events, file changes, and registry modifications
- The NIDS Sensor captures and analyzes network packets
- All components log information to the `logs` directory
- Configuration settings can be modified in `config/config.ini`