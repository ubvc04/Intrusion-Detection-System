# Setup Guide for Windows IDS

This guide provides step-by-step instructions for setting up the Windows Intrusion Detection System on Windows 10/11.

## Prerequisites

### 1. Install Python 3.11

1. Download Python 3.11 from the [official Python website](https://www.python.org/downloads/release/python-3110/)
2. Run the installer
3. **Important:** Check the box that says "Add Python 3.11 to PATH"
4. Select "Install Now" for a standard installation
5. Verify installation by opening Command Prompt and typing:
   ```
   python --version
   ```
   You should see `Python 3.11.x`

### 2. Install Npcap

Npcap is required for the NIDS component to capture network packets.

1. Download Npcap from the [official Npcap website](https://npcap.com/#download)
2. Run the installer with default settings
3. Ensure "WinPcap API-compatible Mode" is selected during installation
4. Complete the installation

## Setting Up the IDS

### 1. Clone or Download the Repository

```
git clone https://github.com/yourusername/windows-ids.git
# or download and extract the ZIP file
cd windows-ids
```

### 2. Create and Activate Virtual Environment

```powershell
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
.\venv\Scripts\activate

# Your prompt should change to indicate the virtual environment is active
(venv) PS C:\path\to\windows-ids>
```

### 3. Install Dependencies

```powershell
# Make sure pip is up to date
python -m pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

## Configuration

### 1. Edit Configuration File

Open `config/config.ini` and adjust settings according to your environment:

```ini
[HIDS]
# Paths to monitor for file integrity
monitored_paths = C:\Windows\System32\drivers,C:\Windows\System32\config

# Event log settings
event_logs = Security,System,Application

[NIDS]
# Network interface to monitor
# Leave blank to auto-select the primary interface
interface = 

# Packet capture settings
promiscuous_mode = True
snap_length = 65535
timeout = 1000

[Manager]
# Database settings
db_path = data/ids.db

# Web interface settings
host = 127.0.0.1
port = 8080

[Logging]
level = INFO
log_file = logs/ids.log
```

### 2. Review Detection Rules

Review and customize detection rules in:
- `config/hids_rules.json` - Host-based detection rules
- `config/nids_rules.json` - Network-based detection rules

## Running the IDS

### 1. Start the IDS Manager

```powershell
# Ensure you're in the project root directory with virtual environment activated
python main.py --component manager
```

### 2. Start the HIDS Agent

Open a new Command Prompt or PowerShell window:

```powershell
# Navigate to the project directory
cd path\to\windows-ids

# Activate the virtual environment
.\venv\Scripts\activate

# Start the HIDS agent
python main.py --component hids
```

### 3. Start the NIDS Sensor

Open another Command Prompt or PowerShell window:

```powershell
# Navigate to the project directory
cd path\to\windows-ids

# Activate the virtual environment
.\venv\Scripts\activate

# Start the NIDS sensor
python main.py --component nids
```

### 4. Access the Web Interface

Open your web browser and navigate to:
```
http://127.0.0.1:8080
```

## Troubleshooting

### NIDS Sensor Issues

- **Error: No interfaces found**: Ensure Npcap is properly installed
- **Permission errors**: Run the Command Prompt or PowerShell as Administrator

### HIDS Agent Issues

- **Access denied to Event Logs**: Run the Command Prompt or PowerShell as Administrator
- **WMI errors**: Ensure WMI service is running (`Get-Service Winmgmt`)

### General Issues

- **Module not found errors**: Verify all dependencies are installed (`pip list`)
- **Port already in use**: Change the port in `config.ini` if port 8080 is already in use

## Next Steps

After successful setup, refer to the [TESTING.md](TESTING.md) guide to verify your installation is working correctly.