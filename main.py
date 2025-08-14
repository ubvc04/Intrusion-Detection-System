#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows Intrusion Detection System (IDS) - Main Entry Point

This script serves as the main entry point for the Windows IDS, allowing users to start
the HIDS agent, NIDS sensor, or IDS manager components.

Usage:
    python main.py --component [hids|nids|manager]
"""

import os
import sys
import argparse
import logging
import configparser
import ctypes
import subprocess
import time
from pathlib import Path

# Ensure the project root is in the Python path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Import utility modules
from utils.logger import setup_logger

def setup_directories():
    """
    Create necessary directories if they don't exist.
    """
    directories = [
        'logs',
        'data',
        'config'
    ]
    
    for directory in directories:
        dir_path = project_root / directory
        if not dir_path.exists():
            dir_path.mkdir(parents=True)
            print(f"Created directory: {dir_path}")

def load_config():
    """
    Load the configuration file or create a default one if it doesn't exist.
    """
    config_path = project_root / 'config' / 'config.ini'
    
    if not config_path.exists():
        # Create a default configuration file
        config = configparser.ConfigParser()
        
        # General settings
        config['General'] = {
            'debug': 'false',
            'log_level': 'INFO'
        }
        
        # HIDS settings
        config['HIDS'] = {
            'enabled': 'true',
            'scan_interval': '300',  # seconds
            'file_monitoring': 'true',
            'registry_monitoring': 'true',
            'process_monitoring': 'true'
        }
        
        # NIDS settings
        config['NIDS'] = {
            'enabled': 'true',
            'interface': 'default',
            'promiscuous_mode': 'true',
            'packet_buffer': '1024',
            'dns_monitoring': 'true',
            'http_monitoring': 'true',
            'smtp_monitoring': 'true'
        }
        
        # Manager settings
        config['Manager'] = {
            'web_interface': 'true',
            'web_port': '8080',
            'web_host': '127.0.0.1',
            'alert_email': 'false',
            'email_recipient': ''
        }
        
        # Write the configuration file
        with open(config_path, 'w') as f:
            config.write(f)
        
        print(f"Created default configuration file at {config_path}")
    
    # Load the configuration
    config = configparser.ConfigParser()
    config.read(config_path)
    
    return config

def create_default_rules():
    """
    Create default rules files if they don't exist.
    """
    # HIDS rules
    hids_rules_path = project_root / 'config' / 'hids_rules.conf'
    if not hids_rules_path.exists():
        with open(hids_rules_path, 'w') as f:
            f.write("# HIDS Rules Configuration\n")
            f.write("# Format: rule_type|path|condition|severity|description\n\n")
            
            # Example file integrity rules
            f.write("# File integrity monitoring rules\n")
            f.write("file|C:\\Windows\\System32\\drivers\\etc\\hosts|modified|high|Hosts file modified\n")
            f.write("file|C:\\Windows\\System32\\config|modified|critical|Windows registry files modified\n")
            
            # Example registry monitoring rules
            f.write("\n# Registry monitoring rules\n")
            f.write("registry|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|modified|high|Startup registry key modified\n")
            f.write("registry|HKLM\\System\\CurrentControlSet\\Services|added|medium|New service installed\n")
            
            # Example process monitoring rules
            f.write("\n# Process monitoring rules\n")
            f.write("process|cmd.exe|started|low|Command prompt executed\n")
            f.write("process|powershell.exe|started|medium|PowerShell executed\n")
        
        print(f"Created default HIDS rules at {hids_rules_path}")
    
    # NIDS rules
    nids_rules_path = project_root / 'config' / 'nids_rules.conf'
    if not nids_rules_path.exists():
        with open(nids_rules_path, 'w') as f:
            f.write("# NIDS Rules Configuration\n")
            f.write("# Format: protocol|source|destination|port|pattern|severity|description\n\n")
            
            # Example DNS rules
            f.write("# DNS monitoring rules\n")
            f.write("dns|any|any|53|.*\\.evil\\.com$|high|Known malicious domain\n")
            f.write("dns|any|any|53|.*\\.suspicious\\.net$|medium|Suspicious domain access\n")
            
            # Example HTTP rules
            f.write("\n# HTTP monitoring rules\n")
            f.write("http|any|any|80|.*\\/admin\\.php|high|Admin page access attempt\n")
            f.write("http|any|any|80|.*\\?id=.*'|high|SQL injection attempt\n")
            
            # Example SMTP rules
            f.write("\n# SMTP monitoring rules\n")
            f.write("smtp|any|any|25|.*\\.exe|medium|Executable file in email\n")
            f.write("smtp|any|any|25|.*\\.zip|low|Compressed file in email\n")
        
        print(f"Created default NIDS rules at {nids_rules_path}")
    
    # Suspicious domains list
    suspicious_domains_path = project_root / 'config' / 'suspicious_domains.txt'
    if not suspicious_domains_path.exists():
        with open(suspicious_domains_path, 'w') as f:
            f.write("# One domain per line\n")
            f.write("# Example:\n")
            f.write("# malicious-domain.com\n")
        print(f"Created empty suspicious domains file at {suspicious_domains_path}")

def is_admin():
    """
    Check if the script is running with administrator privileges.
    
    Returns:
        bool: True if running as admin, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# Check for admin privileges at the module level
if not is_admin():
    print("This application requires administrator privileges. Elevating...")

    # Path to the python.exe inside your virtual environment
    python_exe = sys.executable
    script = os.path.abspath(sys.argv[0])
    
    # Create the argument list with proper escaping
    args_list = [f'"{script}"']
    for arg in sys.argv[1:]:
        args_list.append(f'"{arg}"')
    
    # Join all arguments with commas for PowerShell's ArgumentList parameter
    args_string = ", ".join(args_list)
    
    # Build the complete PowerShell command
    powershell_cmd = f'Start-Process "{python_exe}" -ArgumentList {args_string} -Verb RunAs'
    
    # Execute the PowerShell command
    subprocess.run(["powershell", "-Command", powershell_cmd])
    sys.exit()

def main():
    """
    Main entry point for the Windows IDS.
    """
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Windows Intrusion Detection System')
    parser.add_argument('--component', choices=['hids', 'nids', 'manager'], required=True,
                        help='Component to start (hids, nids, or manager)')
    parser.add_argument('--config', default=None, help='Path to configuration file')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Setup directories and configuration
    setup_directories()
    config = load_config()
    create_default_rules()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logger = setup_logger(log_level, name='ids')
    
    logger.info(f"Starting Windows IDS - {args.component.upper()} component")
    
    # Start the requested component
    if args.component == 'hids':
        from components.hids.agent import start_hids_agent
        start_hids_agent(config, logger)
    elif args.component == 'nids':
        from components.nids.sensor import start_nids_sensor
        start_nids_sensor(config, logger)
    elif args.component == 'manager':
        from components.manager.server import start_manager
        start_manager(config, logger)

if __name__ == "__main__":
    main()