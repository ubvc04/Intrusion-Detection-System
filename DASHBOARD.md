# Windows IDS Web Dashboard

This document provides instructions for running the Windows IDS with the real-time web dashboard.

## Overview

The Windows IDS Web Dashboard provides a real-time view of security events detected by the Host-based Intrusion Detection System (HIDS) and Network-based Intrusion Detection System (NIDS) components. The dashboard uses WebSockets to display events in real-time without requiring page refreshes.

## Features

- Real-time security event monitoring
- Event filtering by severity and source
- Event statistics and visualizations
- Detailed event information
- Dark mode interface for reduced eye strain
- Responsive design for different screen sizes

## Requirements

- Windows 10 or later
- Python 3.11 or later
- Administrator privileges (required for HIDS and NIDS functionality)

## Installation

1. Clone or download the Windows IDS repository
2. Navigate to the project directory
3. Create a virtual environment (optional but recommended):
   ```
   python -m venv venv
   venv\Scripts\activate
   ```
4. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Running the Dashboard

### Option 1: Using the Batch Script (Recommended)

The easiest way to start the Windows IDS with the web dashboard is to use the provided batch script:

1. Right-click on `run_dashboard.bat` and select "Run as administrator"
2. The script will:
   - Activate or create a virtual environment
   - Install dependencies if needed
   - Start the IDS Manager with web dashboard
   - Start the HIDS agent
   - Start the NIDS sensor
   - Open the dashboard in your default web browser

### Option 2: Manual Execution

If you prefer to start the components manually:

1. Open a command prompt with administrator privileges
2. Activate the virtual environment (if using one):
   ```
   venv\Scripts\activate
   ```
3. Start the IDS Manager with web dashboard:
   ```
   python main.py --component manager
   ```
4. Open another command prompt with administrator privileges
5. Activate the virtual environment
6. Start the HIDS agent:
   ```
   python main.py --component hids
   ```
7. Open a third command prompt with administrator privileges
8. Activate the virtual environment
9. Start the NIDS sensor:
   ```
   python main.py --component nids
   ```
10. Open a web browser and navigate to `http://localhost:5000`

## Configuration

The IDS components can be configured by editing the `config/config.ini` file. Some important settings for the web dashboard include:

- `web_host`: The IP address to bind the web server to (default: 127.0.0.1)
- `web_port`: The port to run the web server on (default: 5000)

After changing the configuration, restart the IDS components for the changes to take effect.

## Testing Real-time Functionality

A test script is provided to simulate events for testing the real-time WebSocket functionality:

```
python test_dashboard.py
```

This script will generate random IDS events of various types and severities and send them to the manager. You can modify the script to adjust the event generation rate and types.

## Troubleshooting

### Dashboard Not Loading

- Ensure the IDS Manager is running
- Check that the web server is running on the configured host and port
- Verify that your browser supports WebSockets

### No Events Appearing

- Ensure the HIDS and NIDS components are running
- Check the logs for any error messages
- Verify that the components are properly configured
- Try running the test_dashboard.py script to generate sample events

### Permission Issues

- Ensure you're running all components with administrator privileges
- Check the Windows Event Log for any permission-related errors

### WebSocket Connection Issues

- Verify that Flask-SocketIO is properly installed
- Check browser console for any connection errors
- Ensure your network allows WebSocket connections

## Logs

Logs for each component are stored in the `logs` directory:

- `logs/ids.log`: Main IDS log
- `logs/hids.log`: HIDS agent log
- `logs/nids.log`: NIDS sensor log
- `logs/manager.log`: IDS Manager log

These logs can be useful for troubleshooting issues with the IDS components.

## Stopping the IDS

To stop the IDS components:

1. Press `Ctrl+C` in each command prompt window
2. Close the web browser

Alternatively, you can close all command prompt windows to terminate all components.