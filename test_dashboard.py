#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for the WebSocket-enabled dashboard

This script simulates events being sent to the dashboard to test the real-time functionality.
"""

import os
import sys
import time
import json
import random
import requests
from datetime import datetime
from utils.helpers import generate_event_id

# Configuration
MANAGER_URL = "http://localhost:5000"
NUM_EVENTS = 10
DELAY = 2  # seconds between events

# Event types and severities
EVENT_TYPES = [
    "file_integrity",
    "registry",
    "process",
    "network",
    "dns",
    "http",
    "smtp"
]

SEVERITIES = [
    "info",
    "warning",
    "critical"
]

SOURCES = [
    "HIDS-Agent",
    "NIDS-Sensor",
    "Correlation-Engine"
]

# Generate random event details based on type
def generate_event_details(event_type):
    if event_type == "file_integrity":
        actions = ["created", "modified", "deleted", "permission_changed"]
        return {
            "path": f"C:\\Windows\\System32\\{random.choice(['drivers', 'config', 'logs'])}\\{random.choice(['file1.dll', 'file2.sys', 'file3.exe', 'config.ini'])}",
            "action": random.choice(actions),
            "hash_before": f"{random.randint(1000000, 9999999)}abcdef",
            "hash_after": f"{random.randint(1000000, 9999999)}abcdef"
        }
    
    elif event_type == "registry":
        actions = ["created", "modified", "deleted"]
        keys = [
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"
        ]
        return {
            "key": random.choice(keys),
            "action": random.choice(actions),
            "value": f"Value-{random.randint(1, 100)}"
        }
    
    elif event_type == "process":
        actions = ["started", "terminated", "accessed_memory", "created_thread"]
        processes = ["svchost.exe", "explorer.exe", "cmd.exe", "powershell.exe", "rundll32.exe"]
        return {
            "name": random.choice(processes),
            "pid": random.randint(1000, 9999),
            "action": random.choice(actions),
            "user": random.choice(["SYSTEM", "Administrator", "User"])
        }
    
    elif event_type == "network":
        protocols = ["TCP", "UDP"]
        return {
            "protocol": random.choice(protocols),
            "source_ip": f"192.168.1.{random.randint(2, 254)}",
            "source_port": random.randint(1024, 65535),
            "destination_ip": f"203.0.113.{random.randint(1, 254)}",
            "destination_port": random.choice([80, 443, 22, 25, 53, 3389])
        }
    
    elif event_type == "dns":
        domains = ["example.com", "google.com", "microsoft.com", "suspicious-domain.com", "malware-site.net"]
        query_types = ["A", "AAAA", "MX", "TXT", "CNAME"]
        return {
            "domain": random.choice(domains),
            "query_type": random.choice(query_types),
            "resolved_ip": f"203.0.113.{random.randint(1, 254)}"
        }
    
    elif event_type == "http":
        methods = ["GET", "POST", "PUT", "DELETE"]
        urls = [
            "http://example.com/login",
            "https://api.service.com/data",
            "http://suspicious-site.com/download",
            "https://legitimate-service.com/api/v1/users"
        ]
        return {
            "method": random.choice(methods),
            "url": random.choice(urls),
            "status_code": random.choice([200, 301, 400, 403, 404, 500]),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
    
    elif event_type == "smtp":
        senders = ["user@example.com", "admin@company.com", "suspicious@unknown.net"]
        recipients = ["user@company.com", "admin@example.com", "victim@target.com"]
        return {
            "sender": random.choice(senders),
            "recipient": random.choice(recipients),
            "subject": random.choice(["Important Update", "Your Account", "Security Alert", "Action Required"]),
            "has_attachment": random.choice([True, False])
        }
    
    else:
        return {"message": "Unknown event type"}

# Generate a random event
def generate_random_event():
    event_type = random.choice(EVENT_TYPES)
    severity = random.choice(SEVERITIES)
    source = random.choice(SOURCES)
    
    # Higher chance of critical events for certain types
    if event_type in ["registry", "process"] and random.random() < 0.4:
        severity = "critical"
    
    # Generate event details
    details = generate_event_details(event_type)
    
    # Create event
    event = {
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "type": event_type,
        "severity": severity,
        "details": details
    }
    
    return event

# Send an event to the manager API
def send_event(event):
    try:
        response = requests.post(
            f"{MANAGER_URL}/api/events",
            json=event,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 201:
            print(f"Event sent successfully: {event['type']} ({event['severity']})")
            return True
        else:
            print(f"Failed to send event: {response.status_code} - {response.text}")
            return False
    
    except requests.RequestException as e:
        print(f"Error sending event: {e}")
        return False

# Main function
def main():
    print(f"\nStarting dashboard test - sending {NUM_EVENTS} events to {MANAGER_URL}\n")
    
    # Check if the manager API is available
    try:
        response = requests.get(f"{MANAGER_URL}/api/events")
        if response.status_code != 200:
            print(f"Manager API not available: {response.status_code} - {response.text}")
            return
    except requests.RequestException as e:
        print(f"Manager API not available: {e}")
        print("Make sure the manager component is running.")
        return
    
    # Send events
    for i in range(NUM_EVENTS):
        event = generate_random_event()
        if send_event(event):
            print(f"Event {i+1}/{NUM_EVENTS} sent successfully")
        else:
            print(f"Failed to send event {i+1}/{NUM_EVENTS}")
        
        # Wait before sending the next event
        if i < NUM_EVENTS - 1:
            print(f"Waiting {DELAY} seconds...")
            time.sleep(DELAY)
    
    print("\nTest completed. Check the dashboard to see the events.")

if __name__ == "__main__":
    main()