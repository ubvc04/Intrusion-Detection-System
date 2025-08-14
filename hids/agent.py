#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HIDS Agent Module

This module implements the Host-based Intrusion Detection System (HIDS) agent
for Windows systems. It monitors Windows Event Logs, file integrity, and registry changes.
"""

import os
import sys
import time
import json
import socket
import threading
import requests
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Import utility modules
from utils.logger import get_component_logger
from utils.helpers import ensure_admin, format_event_data

# Import HIDS components
from hids.event_monitor import EventLogMonitor
from hids.file_monitor import FileIntegrityMonitor
from hids.registry_monitor import RegistryMonitor

class HIDSAgent:
    """
    Host-based Intrusion Detection System Agent for Windows.
    
    This class coordinates the different monitoring components of the HIDS agent
    and handles communication with the IDS Manager.
    """
    
    def __init__(self, config):
        """
        Initialize the HIDS Agent.
        
        Args:
            config: Configuration object containing HIDS settings
        """
        # Ensure running with administrator privileges
        ensure_admin()
        
        # Initialize logger
        self.logger = get_component_logger('hids', config)
        self.logger.info("Initializing HIDS Agent")
        
        # Store configuration
        self.config = config
        
        # Parse HIDS-specific configuration
        self.monitored_paths = [p.strip() for p in config['HIDS']['monitored_paths'].split(',')]
        self.event_logs = [l.strip() for l in config['HIDS']['event_logs'].split(',')]
        self.scan_interval = int(config['HIDS']['scan_interval'])
        self.hash_algorithm = config['HIDS']['hash_algorithm']
        
        # Manager connection settings
        self.manager_host = config['Manager']['host']
        self.manager_port = config['Manager']['port']
        self.manager_url = f"http://{self.manager_host}:{self.manager_port}/api/events"
        
        # Load detection rules
        self.rules_file = project_root / 'config' / 'hids_rules.json'
        self.rules = self._load_rules()
        
        # Initialize monitoring components
        self.event_monitor = EventLogMonitor(self.event_logs, self.rules, self.logger)
        self.file_monitor = FileIntegrityMonitor(self.monitored_paths, 
                                               self.hash_algorithm,
                                               self.scan_interval,
                                               self.logger)
        self.registry_monitor = RegistryMonitor(self.rules, self.logger)
        
        # Initialize state
        self.running = False
        self.hostname = socket.gethostname()
        
        # Initialize threads
        self.threads = []
    
    def _load_rules(self):
        """
        Load HIDS detection rules from the rules file.
        
        Returns:
            list: List of detection rules
        """
        try:
            with open(self.rules_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading rules from {self.rules_file}: {e}")
            self.logger.warning("Using default rules")
            return []
    
    def _send_event(self, event):
        """
        Send an event to the IDS Manager.
        
        Args:
            event (dict): Event data to send
            
        Returns:
            bool: True if the event was sent successfully, False otherwise
        """
        try:
            response = requests.post(self.manager_url, json=event, timeout=5)
            if response.status_code == 200:
                self.logger.debug(f"Event sent successfully: {event['type']}")
                return True
            else:
                self.logger.warning(f"Failed to send event: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error sending event to manager: {e}")
            return False
    
    def _event_callback(self, event_type, details, severity="info"):
        """
        Callback function for handling events from monitoring components.
        
        Args:
            event_type (str): Type of event
            details (dict): Event details
            severity (str): Event severity
        """
        # Format the event data
        event = format_event_data(event_type, "hids", details, severity)
        
        # Log the event
        self.logger.info(f"HIDS event detected: {event_type} - {severity}")
        self.logger.debug(f"Event details: {details}")
        
        # Send the event to the IDS Manager
        self._send_event(event)
    
    def start(self):
        """
        Start the HIDS Agent and all monitoring components.
        """
        if self.running:
            self.logger.warning("HIDS Agent is already running")
            return
        
        self.logger.info("Starting HIDS Agent")
        self.running = True
        
        try:
            # Start event log monitoring
            self.logger.info("Starting Event Log Monitor")
            event_thread = threading.Thread(
                target=self.event_monitor.start_monitoring,
                args=(self._event_callback,),
                daemon=True
            )
            event_thread.start()
            self.threads.append(event_thread)
            
            # Start file integrity monitoring
            self.logger.info("Starting File Integrity Monitor")
            file_thread = threading.Thread(
                target=self.file_monitor.start_monitoring,
                args=(self._event_callback,),
                daemon=True
            )
            file_thread.start()
            self.threads.append(file_thread)
            
            # Start registry monitoring
            self.logger.info("Starting Registry Monitor")
            registry_thread = threading.Thread(
                target=self.registry_monitor.start_monitoring,
                args=(self._event_callback,),
                daemon=True
            )
            registry_thread.start()
            self.threads.append(registry_thread)
            
            # Keep the main thread alive
            self.logger.info(f"HIDS Agent started on {self.hostname}")
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.stop()
        except Exception as e:
            self.logger.error(f"Error in HIDS Agent: {e}")
            self.stop()
    
    def stop(self):
        """
        Stop the HIDS Agent and all monitoring components.
        """
        if not self.running:
            return
        
        self.logger.info("Stopping HIDS Agent")
        self.running = False
        
        # Stop monitoring components
        self.event_monitor.stop_monitoring()
        self.file_monitor.stop_monitoring()
        self.registry_monitor.stop_monitoring()
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.logger.info("HIDS Agent stopped")

# For testing purposes
if __name__ == "__main__":
    import configparser
    
    # Load configuration
    config = configparser.ConfigParser()
    config_path = project_root / 'config' / 'config.ini'
    
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    config.read(config_path)
    
    # Create and start HIDS agent
    agent = HIDSAgent(config)
    agent.start()