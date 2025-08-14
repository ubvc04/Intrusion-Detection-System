#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HIDS Agent Module

This module implements the Host-based Intrusion Detection System (HIDS) agent,
which monitors the local system for suspicious activities and sends events to the IDS Manager.
"""

import os
import sys
import time
import json
import threading
import logging
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Import HIDS components
from hids.file_monitor import FileIntegrityMonitor as FileMonitor
from hids.registry_monitor import RegistryMonitor
from hids.process_monitor import ProcessMonitor
from utils.helpers import generate_event_id

class HIDSAgent:
    """
    Host-based Intrusion Detection System (HIDS) Agent
    
    This class implements the HIDS agent, which monitors the local system for suspicious activities
    and sends events to the IDS Manager.
    """
    
    def __init__(self, config, log):
        """
        Initialize the HIDS agent.
        
        Args:
            config: Configuration object
            log: Logger instance
        """
        self.config = config
        self.logger = log
        self.running = False
        self.monitors = []
        self.event_callback = None
        
        # Load HIDS rules
        self.rules_file = project_root / 'config' / 'hids_rules.conf'
        self.logger.info(f"Loading HIDS rules from {self.rules_file}")
        
        # Initialize monitors
        self._initialize_monitors()
    
    def _initialize_monitors(self):
        """
        Initialize the HIDS monitors based on configuration.
        """
        try:
            # Check if file monitoring is enabled
            if self.config['HIDS'].getboolean('enable_file_monitoring', True):
                self.logger.info("Initializing file monitor")
                file_monitor = FileMonitor(self.config, self.logger)
                self.monitors.append(file_monitor)
            
            # Check if registry monitoring is enabled
            if self.config['HIDS'].getboolean('enable_registry_monitoring', True):
                self.logger.info("Initializing registry monitor")
                registry_monitor = RegistryMonitor(self.config, self.logger)
                self.monitors.append(registry_monitor)
            
            # Check if process monitoring is enabled
            if self.config['HIDS'].getboolean('enable_process_monitoring', True):
                self.logger.info("Initializing process monitor")
                process_monitor = ProcessMonitor(self.config, self.logger)
                self.monitors.append(process_monitor)
            
            self.logger.info(f"Initialized {len(self.monitors)} monitors")
        
        except Exception as e:
            self.logger.error(f"Error initializing monitors: {e}")
            raise
    
    def set_event_callback(self, callback):
        """
        Set the event callback function.
        
        Args:
            callback: Function to call when an event is detected
        """
        self.event_callback = callback
    
    def _event_callback(self, event_type, severity, message, details=None, data=None):
        """
        Internal event callback function.
        
        Args:
            event_type: Type of event (file_integrity, registry, process)
            severity: Severity of event (critical, warning, info)
            message: Event message
            details: Additional details
            data: Event data
        """
        # Create event object
        event = {
            'id': generate_event_id(),
            'timestamp': datetime.now().isoformat(),
            'source': 'hids',
            'type': event_type,
            'severity': severity,
            'message': message,
            'details': details,
            'data': data
        }
        
        # Log the event
        log_message = f"HIDS event: {severity.upper()} - {message}"
        if details:
            log_message += f" - {details}"
        
        if severity == 'critical':
            self.logger.critical(log_message)
        elif severity == 'warning':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Call the external callback if set
        if self.event_callback:
            self.event_callback(event)
    
    def start(self):
        """
        Start the HIDS agent.
        """
        if self.running:
            self.logger.warning("HIDS agent is already running")
            return
        
        self.logger.info("Starting HIDS agent")
        self.running = True
        
        # Start monitors
        for monitor in self.monitors:
            monitor.set_event_callback(self._event_callback)
            monitor_thread = threading.Thread(target=monitor.start, daemon=True)
            monitor_thread.start()
        
        self.logger.info("HIDS agent started")
    
    def stop(self):
        """
        Stop the HIDS agent.
        """
        if not self.running:
            self.logger.warning("HIDS agent is not running")
            return
        
        self.logger.info("Stopping HIDS agent")
        self.running = False
        
        # Stop monitors
        for monitor in self.monitors:
            monitor.stop()
        
        self.logger.info("HIDS agent stopped")

def start_hids_agent(config, log):
    """
    Start the HIDS agent and connect to the IDS Manager.
    
    Args:
        config: Configuration object
        log: Logger instance
    """
    log.info("Starting HIDS agent")
    
    try:
        # Import requests here to avoid circular imports
        import requests
        
        # Create HIDS agent
        agent = HIDSAgent(config, log)
        
        # Define event callback function
        def send_event_to_manager(event):
            try:
                # Get manager API URL from config
                manager_host = config['Manager'].get('host', '127.0.0.1')
                manager_port = config['Manager'].get('api_port', '5000')
                manager_url = f"http://{manager_host}:{manager_port}/api/events"
                
                # Send event to manager
                response = requests.post(manager_url, json=event)
                
                if response.status_code != 200:
                    log.error(f"Failed to send event to manager: {response.status_code} - {response.text}")
            except Exception as e:
                log.error(f"Error sending event to manager: {e}")
        
        # Set event callback
        agent.set_event_callback(send_event_to_manager)
        
        # Start agent
        agent.start()
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Keyboard interrupt received")
            agent.stop()
        
    except Exception as e:
        log.error(f"Error starting HIDS agent: {e}")
        raise

# For testing purposes
if __name__ == "__main__":
    import logging
    import configparser
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("HIDS-Agent")
    
    # Load configuration
    config = configparser.ConfigParser()
    config_path = project_root / 'config' / 'config.ini'
    
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    config.read(config_path)
    
    # Start the HIDS agent
    start_hids_agent(config, logger)