# Testing Guide for Windows IDS

This guide provides instructions for testing the Windows Intrusion Detection System to verify it's working correctly.

## Prerequisites

- Ensure the IDS is properly set up and running (refer to [SETUP.md](SETUP.md))
- All components (HIDS agent, NIDS sensor, and IDS manager) should be active
- Web interface should be accessible at http://127.0.0.1:8080

## Test Scenarios

### 1. NIDS Testing: Port Scan Detection

#### Using Nmap

1. Install Nmap from [nmap.org](https://nmap.org/download.html) on a separate machine on the same network
2. Run a basic port scan against the machine running the IDS:

```
nmap -sS -p 1-1000 [target-ip]
```

#### Expected Results

- The NIDS sensor should detect the port scan activity
- Alerts should appear in the web interface under the "Alerts" section
- The alert should identify the source IP and classify it as a port scan attack

### 2. HIDS Testing: Failed Login Attempts

#### Simulating Failed RDP Logins

1. On another machine, attempt to connect to the target machine via RDP
2. Use an incorrect username and/or password multiple times
3. Alternatively, use the following PowerShell command to simulate failed logins locally:

```powershell
# Run as Administrator
$username = "nonexistentuser"
$password = ConvertTo-SecureString "incorrectpassword" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

# Attempt to start a process with invalid credentials (will fail)
for ($i=1; $i -le 5; $i++) {
    try {
        Start-Process "cmd.exe" -Credential $cred -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Login attempt $i failed (expected)"
    }
    Start-Sleep -Seconds 1
}
```

#### Expected Results

- The HIDS agent should detect the failed login attempts (Event ID 4625)
- Alerts should appear in the web interface
- The alert should show details about the failed login attempts

### 3. HIDS Testing: File Integrity Monitoring

#### Modifying Protected Files

1. Identify a file in one of the monitored paths (check `config.ini` for monitored_paths)
2. Create a backup of the file before modifying it
3. Modify the file using an administrator command prompt:

```powershell
# Example - create a test file in a monitored directory
# (adjust path based on your configuration)
Copy-Item "C:\Windows\System32\drivers\etc\hosts" "C:\Windows\System32\drivers\etc\hosts.bak"
Add-Content "C:\Windows\System32\drivers\etc\hosts" "`n# Test modification for IDS"
```

4. Restore the original file after testing:

```powershell
Copy-Item "C:\Windows\System32\drivers\etc\hosts.bak" "C:\Windows\System32\drivers\etc\hosts" -Force
Remove-Item "C:\Windows\System32\drivers\etc\hosts.bak"
```

#### Expected Results

- The HIDS agent should detect the file modification
- An alert should appear in the web interface
- The alert should include details about which file was modified

### 4. HIDS Testing: Registry Modification

#### Simulating Persistence Technique

1. Create a backup of the registry key before modifying:

```powershell
# Export the Run key before modification
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "$env:TEMP\run_key_backup.reg"
```

2. Add a test entry to the Run key:

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestIDS" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

3. Restore the original registry key after testing:

```powershell
# Remove the test entry
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestIDS" /f

# Or restore from backup if needed
# reg import "$env:TEMP\run_key_backup.reg"
```

#### Expected Results

- The HIDS agent should detect the registry modification
- An alert should appear in the web interface
- The alert should identify it as a potential persistence technique

### 5. NIDS Testing: Suspicious Connection

#### Simulating Connection to Known Malicious IP

1. Add a test IP address to the malicious IP list in your configuration
2. Attempt to connect to that IP using PowerShell:

```powershell
# Replace with an IP address you've added to your malicious IP list
$testIP = "93.184.216.34"  # example.com - replace with your test IP

try {
    $connection = New-Object System.Net.Sockets.TcpClient
    $connection.Connect($testIP, 80)
    $connection.Close()
    Write-Host "Connected to test IP"
} catch {
    Write-Host "Failed to connect to test IP: $_"
}
```

#### Expected Results

- The NIDS sensor should detect the connection to the suspicious IP
- An alert should appear in the web interface
- The alert should identify the destination as a known malicious IP

## Correlation Testing

### Combined Attack Scenario

To test the correlation engine, perform multiple related actions:

1. Run a port scan from a machine
2. From the same machine, attempt multiple failed logins
3. Check if the IDS correlates these events and generates a higher severity alert

#### Expected Results

- Individual alerts for each action
- A correlated alert that links the activities together
- Higher severity level for the correlated alert

## Verifying Alerts

For all tests:

1. Check the web interface at http://127.0.0.1:8080
2. Navigate to the Alerts section
3. Verify that appropriate alerts are generated
4. Check the logs directory for detailed logs

## Troubleshooting Tests

- If alerts aren't appearing, check the log files for errors
- Verify that all IDS components are running
- Ensure you're running the tests with sufficient privileges (Administrator)
- Check that the actions you're performing match the configured detection rules

## Next Steps

After successful testing, refer to the [DEPLOYMENT.md](DEPLOYMENT.md) guide for information on deploying the IDS in a production environment.