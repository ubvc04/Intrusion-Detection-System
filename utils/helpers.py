#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Helper Utility Module

This module provides common utility functions used across different components
of the Windows Intrusion Detection System.
"""

import os
import sys
import time
import socket
import hashlib
import ipaddress
import uuid
from datetime import datetime
from pathlib import Path

def get_timestamp():
    """
    Get the current timestamp in ISO 8601 format.
    
    Returns:
        str: Current timestamp in ISO 8601 format
    """
    return datetime.now().isoformat()

def calculate_file_hash(file_path, algorithm='sha256'):
    """
    Calculate the hash of a file using the specified algorithm.
    
    Args:
        file_path (str): Path to the file
        algorithm (str): Hash algorithm to use (default: sha256)
        
    Returns:
        str: Hexadecimal digest of the file hash
        
    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be read
    """
    try:
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            # Read the file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
                
        return hash_obj.hexdigest()
    except (FileNotFoundError, PermissionError) as e:
        raise e
    except Exception as e:
        raise RuntimeError(f"Error calculating hash for {file_path}: {str(e)}")

def is_valid_ip(ip_str):
    """
    Check if a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip_str (str): String to check
        
    Returns:
        bool: True if the string is a valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_hostname():
    """
    Get the hostname of the current machine.
    
    Returns:
        str: Hostname of the current machine
    """
    return socket.gethostname()

def get_local_ip():
    """
    Get the primary local IP address of the current machine.
    
    Returns:
        str: Primary local IP address
    """
    try:
        # Create a socket and connect to an external server to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Fallback to localhost if unable to determine
        return "127.0.0.1"

def generate_event_id():
    """
    Generate a unique event ID.
    
    Returns:
        str: Unique event ID
    """
    # Generate a UUID
    event_uuid = uuid.uuid4()
    
    # Get current timestamp
    timestamp = int(time.time())
    
    # Get hostname
    hostname = get_hostname()
    
    # Create a unique string
    unique_string = f"{event_uuid}-{timestamp}-{hostname}"
    
    # Hash the string to create a shorter ID
    event_id = hashlib.md5(unique_string.encode()).hexdigest()[:12]
    
    return event_id

def get_severity_color(severity):
    """
    Get the color for a severity level.
    
    Args:
        severity (str): Severity level (critical, warning, info)
    
    Returns:
        str: Color code
    """
    if severity == 'critical':
        return '#ef4444'  # Red
    elif severity == 'warning':
        return '#f59e0b'  # Yellow
    elif severity == 'info':
        return '#3b82f6'  # Blue
    else:
        return '#6b7280'  # Gray

def get_event_icon(event_type):
    """
    Get the icon for an event type.
    
    Args:
        event_type (str): Event type
    
    Returns:
        str: Icon class
    """
    if event_type == 'file_integrity':
        return 'fa-file-alt'
    elif event_type == 'registry':
        return 'fa-cogs'
    elif event_type == 'process':
        return 'fa-microchip'
    elif event_type == 'network':
        return 'fa-network-wired'
    elif event_type == 'dns':
        return 'fa-globe'
    elif event_type == 'http':
        return 'fa-cloud'
    elif event_type == 'smtp':
        return 'fa-envelope'
    else:
        return 'fa-exclamation-circle'

def format_timestamp(timestamp):
    """
    Format a timestamp for display.
    
    Args:
        timestamp (str): ISO format timestamp
    
    Returns:
        str: Formatted timestamp
    """
    try:
        # Parse ISO format timestamp
        dt = datetime.fromisoformat(timestamp)
        
        # Format for display
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    except Exception:
        return timestamp

def truncate_string(string, max_length=100):
    """
    Truncate a string to a maximum length.
    
    Args:
        string (str): String to truncate
        max_length (int): Maximum length
    
    Returns:
        str: Truncated string
    """
    if not string:
        return ''
    
    if len(string) <= max_length:
        return string
    
    return string[:max_length] + '...'

def format_event_data(event_type, source, details, severity="info"):
    """
    Format event data in a standardized structure.
    
    Args:
        event_type (str): Type of event (e.g., 'file_change', 'network_connection')
        source (str): Source of the event (e.g., 'hids', 'nids')
        details (dict): Detailed information about the event
        severity (str): Severity level (default: "info")
        
    Returns:
        dict: Formatted event data
    """
    return {
        "timestamp": get_timestamp(),
        "type": event_type,
        "source": source,
        "hostname": get_hostname(),
        "ip_address": get_local_ip(),
        "severity": severity,
        "details": details
    }

def load_list_from_file(file_path):
    """
    Load a list of items from a text file, ignoring comments and empty lines.
    
    Args:
        file_path (str): Path to the text file
        
    Returns:
        list: List of non-empty, non-comment lines from the file
        
    Raises:
        FileNotFoundError: If the file does not exist
    """
    items = []
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                # Remove whitespace and ignore comments and empty lines
                line = line.strip()
                if line and not line.startswith('#'):
                    items.append(line)
        return items
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Error loading list from {file_path}: {str(e)}")

def is_admin():
    """
    Check if the script is running with administrator privileges.
    
    Returns:
        bool: True if running with administrator privileges, False otherwise
    """
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # For non-Windows systems, check if UID is 0 (root)
            return os.geteuid() == 0
    except Exception:
        return False

def ensure_admin():
    """
    Ensure the script is running with administrator privileges.
    Exits if not running as administrator.
    """
    if not is_admin():
        print("This program requires administrator privileges.")
        print("Please run as administrator.")
        sys.exit(1)