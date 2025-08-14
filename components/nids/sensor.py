#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NIDS Sensor Module

This module implements the Network-based Intrusion Detection System (NIDS) sensor,
which monitors network traffic for suspicious activities and sends events to the IDS Manager.
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

# Import NIDS components
from nids.packet_capture import PacketCapture
from nids.dns_analyzer import DNSAnalyzer
from nids.http_analyzer import HTTPAnalyzer
from nids.smtp_analyzer import SMTPAnalyzer
from utils.helpers import generate_event_id

class NIDSSensor:
    """
    Network-based Intrusion Detection System (NIDS) Sensor
    
    This class implements the NIDS sensor, which monitors network traffic for suspicious activities
    and sends events to the IDS Manager.
    """
    
    def __init__(self, config, log):
        """
        Initialize the NIDS sensor.
        
        Args:
            config: Configuration object
            log: Logger instance
        """
        self.config = config
        self.logger = log
        self.running = False
        self.analyzers = []
        self.event_callback = None
        
        # Load NIDS rules
        self.rules_file = project_root / 'config' / 'nids_rules.conf'
        self.logger.info(f"Loading NIDS rules from {self.rules_file}")
        
        # Initialize packet capture
        self.packet_capture = None
        self._initialize_packet_capture()
        
        # Initialize analyzers
        self._initialize_analyzers()
    
    def _initialize_packet_capture(self):
        """
        Initialize the packet capture module.
        """
        try:
            # Get interface from config
            interface = self.config['NIDS'].get('interface', None)
            
            # Create packet capture instance
            self.logger.info(f"Initializing packet capture on interface {interface}")
            self.packet_capture = PacketCapture(interface, self.config, self.logger)
        
        except Exception as e:
            self.logger.error(f"Error initializing packet capture: {e}")
            raise
    
    def _initialize_analyzers(self):
        """
        Initialize the NIDS analyzers based on configuration.
        """
        try:
            # Check if DNS analysis is enabled
            if self.config['NIDS'].getboolean('enable_dns_analysis', True):
                self.logger.info("Initializing DNS analyzer")
                dns_analyzer = DNSAnalyzer(self.config, self.logger)
                self.analyzers.append(dns_analyzer)
            
            # Check if HTTP analysis is enabled
            if self.config['NIDS'].getboolean('enable_http_analysis', True):
                self.logger.info("Initializing HTTP analyzer")
                http_analyzer = HTTPAnalyzer(self.config, self.logger)
                self.analyzers.append(http_analyzer)
            
            # Check if SMTP analysis is enabled
            if self.config['NIDS'].getboolean('enable_smtp_analysis', True):
                self.logger.info("Initializing SMTP analyzer")
                smtp_analyzer = SMTPAnalyzer(self.config, self.logger)
                self.analyzers.append(smtp_analyzer)
            
            self.logger.info(f"Initialized {len(self.analyzers)} analyzers")
        
        except Exception as e:
            self.logger.error(f"Error initializing analyzers: {e}")
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
            event_type: Type of event (dns, http, smtp, network)
            severity: Severity of event (critical, warning, info)
            message: Event message
            details: Additional details
            data: Event data
        """
        # Create event object
        event = {
            'id': generate_event_id(),
            'timestamp': datetime.now().isoformat(),
            'source': 'nids',
            'type': event_type,
            'severity': severity,
            'message': message,
            'details': details,
            'data': data
        }
        
        # Log the event
        log_message = f"NIDS event: {severity.upper()} - {message}"
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
    
    def _packet_callback(self, packet):
        """
        Callback function for packet capture.
        
        Args:
            packet: Captured packet
        """
        # Process packet with analyzers
        for analyzer in self.analyzers:
            analyzer.analyze_packet(packet, self._event_callback)
    
    def start(self):
        """
        Start the NIDS sensor.
        """
        if self.running:
            self.logger.warning("NIDS sensor is already running")
            return
        
        self.logger.info("Starting NIDS sensor")
        self.running = True
        
        # Start analyzers
        for analyzer in self.analyzers:
            analyzer.start()
        
        # Set packet callback
        self.packet_capture.set_callback(self._packet_callback)
        
        # Start packet capture in a separate thread
        capture_thread = threading.Thread(target=self.packet_capture.start, daemon=True)
        capture_thread.start()
        
        self.logger.info("NIDS sensor started")
    
    def stop(self):
        """
        Stop the NIDS sensor.
        """
        if not self.running:
            self.logger.warning("NIDS sensor is not running")
            return
        
        self.logger.info("Stopping NIDS sensor")
        self.running = False
        
        # Stop packet capture
        if self.packet_capture:
            self.packet_capture.stop()
        
        # Stop analyzers
        for analyzer in self.analyzers:
            analyzer.stop()
        
        self.logger.info("NIDS sensor stopped")

def start_nids_sensor(config, log):
    """
    Start the NIDS sensor and connect to the IDS Manager.
    
    Args:
        config: Configuration object
        log: Logger instance
    """
    log.info("Starting NIDS sensor")
    
    try:
        # Import requests here to avoid circular imports
        import requests
        
        # Create NIDS sensor
        sensor = NIDSSensor(config, log)
        
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
        sensor.set_event_callback(send_event_to_manager)
        
        # Start sensor
        sensor.start()
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Keyboard interrupt received")
            sensor.stop()
        
    except Exception as e:
        log.error(f"Error starting NIDS sensor: {e}")
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
    logger = logging.getLogger("NIDS-Sensor")
    
    # Load configuration
    config = configparser.ConfigParser()
    config_path = project_root / 'config' / 'config.ini'
    
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    config.read(config_path)
    
    # Start the NIDS sensor
    start_nids_sensor(config, logger)