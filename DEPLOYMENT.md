# Deployment Guide for Windows IDS

This guide provides instructions for deploying the Windows Intrusion Detection System in a production environment.

## Prerequisites

- Successful completion of setup and testing (refer to [SETUP.md](SETUP.md) and [TESTING.md](TESTING.md))
- Windows 10/11 with administrative privileges
- Python 3.11 installed
- Npcap installed

## Production Deployment Considerations

### 1. Service Installation

For a production environment, the IDS components should run as Windows services to ensure they start automatically and run in the background.

#### Using NSSM (Non-Sucking Service Manager)

1. Download NSSM from [nssm.cc](https://nssm.cc/download)
2. Extract the appropriate version (32-bit or 64-bit) to a location on your system
3. Install each component as a service:

```powershell
# Install IDS Manager as a service
.\nssm.exe install "IDS Manager" "C:\path\to\python.exe" "C:\path\to\ids\main.py --component manager"
.\nssm.exe set "IDS Manager" AppDirectory "C:\path\to\ids"
.\nssm.exe set "IDS Manager" DisplayName "IDS Manager Service"
.\nssm.exe set "IDS Manager" Description "Windows IDS Manager Component"
.\nssm.exe set "IDS Manager" Start SERVICE_AUTO_START
.\nssm.exe set "IDS Manager" ObjectName "LocalSystem"

# Install HIDS Agent as a service
.\nssm.exe install "IDS HIDS Agent" "C:\path\to\python.exe" "C:\path\to\ids\main.py --component hids"
.\nssm.exe set "IDS HIDS Agent" AppDirectory "C:\path\to\ids"
.\nssm.exe set "IDS HIDS Agent" DisplayName "IDS HIDS Agent Service"
.\nssm.exe set "IDS HIDS Agent" Description "Windows IDS Host-based Detection Component"
.\nssm.exe set "IDS HIDS Agent" Start SERVICE_AUTO_START
.\nssm.exe set "IDS HIDS Agent" ObjectName "LocalSystem"

# Install NIDS Sensor as a service
.\nssm.exe install "IDS NIDS Sensor" "C:\path\to\python.exe" "C:\path\to\ids\main.py --component nids"
.\nssm.exe set "IDS NIDS Sensor" AppDirectory "C:\path\to\ids"
.\nssm.exe set "IDS NIDS Sensor" DisplayName "IDS NIDS Sensor Service"
.\nssm.exe set "IDS NIDS Sensor" Description "Windows IDS Network-based Detection Component"
.\nssm.exe set "IDS NIDS Sensor" Start SERVICE_AUTO_START
.\nssm.exe set "IDS NIDS Sensor" ObjectName "LocalSystem"
```

4. Start the services:

```powershell
Start-Service "IDS Manager"
Start-Service "IDS HIDS Agent"
Start-Service "IDS NIDS Sensor"
```

### 2. Production Configuration

Modify the configuration for production use:

1. Edit `config/config.ini`:

```ini
[Manager]
# Change from localhost to specific IP if needed
host = 0.0.0.0  # Listen on all interfaces (or specify a particular IP)
port = 8080

# Enable HTTPS for production
enable_https = True
cert_file = config/cert.pem
key_file = config/key.pem

# Authentication settings
enable_auth = True
users_file = config/users.json

[Logging]
# Increase log level for production
level = WARNING
log_file = logs/ids.log
log_max_size = 10485760  # 10MB
log_backup_count = 10
```

2. Generate SSL certificate for HTTPS:

```powershell
# Navigate to the project directory
cd C:\path\to\ids

# Create a self-signed certificate (for internal use)
openssl req -x509 -newkey rsa:4096 -keyout config/key.pem -out config/cert.pem -days 365 -nodes
```

3. Create users for authentication:

Create a file at `config/users.json`:

```json
{
  "admin": {
    "password_hash": "HASH_VALUE_HERE",
    "role": "admin"
  },
  "analyst": {
    "password_hash": "HASH_VALUE_HERE",
    "role": "analyst"
  }
}
```

Use the following Python script to generate password hashes:

```python
import hashlib
import os
import base64
import getpass

def generate_password_hash(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt + key).decode('utf-8')

password = getpass.getpass("Enter password: ")
print(generate_password_hash(password))
```

### 3. Firewall Configuration

Configure Windows Firewall to allow necessary traffic:

```powershell
# Allow web interface access
New-NetFirewallRule -DisplayName "IDS Web Interface" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

# If using a distributed setup, allow communication between components
New-NetFirewallRule -DisplayName "IDS Internal Communication" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
```

### 4. Log Rotation

Ensure logs don't consume excessive disk space:

1. The IDS uses Python's built-in `RotatingFileHandler` for log rotation
2. Configure log rotation settings in `config.ini`
3. For additional management, consider using Windows Task Scheduler to archive old logs

### 5. Database Maintenance

Set up regular database maintenance:

```powershell
# Create a PowerShell script for database maintenance (save as maintenance.ps1)
$env:PYTHONPATH = "C:\path\to\ids"
C:\path\to\python.exe -c "from manager.database import DatabaseHandler; DatabaseHandler().perform_maintenance()"

# Schedule it to run weekly using Task Scheduler
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\path\to\maintenance.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "IDS Database Maintenance" -Action $action -Trigger $trigger -Principal $principal
```

## Distributed Deployment

For larger environments, you can deploy components on separate machines:

### Manager Server

1. Install and configure the IDS Manager on a dedicated server
2. Update `config.ini` to listen on a specific IP address
3. Configure the database for remote access if needed

### HIDS Agents

1. Install the HIDS agent on each Windows host to be monitored
2. Configure each agent to connect to the central Manager server
3. Update `config.ini` with the Manager server's address

### NIDS Sensors

1. Install NIDS sensors at strategic network points
2. Configure each sensor to connect to the central Manager server
3. Update `config.ini` with the Manager server's address and appropriate network interface

## Monitoring and Maintenance

### Health Monitoring

1. Set up monitoring for the IDS services
2. Configure email alerts for service failures
3. Regularly check log files for errors

### Rule Updates

1. Regularly update detection rules
2. Create a process for testing and deploying new rules
3. Consider automating rule updates

### Performance Tuning

1. Monitor system resource usage
2. Adjust configuration parameters as needed
3. Consider database optimization for large deployments

## Backup and Recovery

### Regular Backups

1. Back up the SQLite database regularly
2. Back up configuration files
3. Store backups securely

### Recovery Procedure

1. Stop IDS services
2. Restore database and configuration files
3. Start IDS services
4. Verify system functionality

## Security Considerations

### Securing the Web Interface

1. Use HTTPS with a valid certificate
2. Implement strong authentication
3. Consider IP-based access restrictions

### Protecting IDS Components

1. Keep the system updated with security patches
2. Use principle of least privilege for service accounts
3. Regularly audit access to the IDS

## Conclusion

Following this deployment guide will help you establish a robust and secure Windows Intrusion Detection System in your production environment. Regular maintenance and updates are essential to ensure the system remains effective against evolving threats.