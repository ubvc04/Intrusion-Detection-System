#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NIDS Sensor Module

This module implements the Network-based Intrusion Detection System (NIDS) sensor
for Windows systems. It captures and analyzes network packets to detect suspicious
network activity.
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
from utils.helpers import ensure_admin, format_event_data, load_list_from_file

# Import NIDS components
from nids.packet_capture import PacketCapture
from nids.traffic_analyzer import TrafficAnalyzer
from nids.signature_detector import SignatureDetector

class NIDSSensor:
    """
    Network-based Intrusion Detection System Sensor for Windows.
    
    This class coordinates the different components of the NIDS sensor
    and handles communication with the IDS Manager.
    """
    
    def __init__(self, config):
        """
        Initialize the NIDS Sensor.
        
        Args:
            config: Configuration object containing NIDS settings
        """
        # Ensure running with administrator privileges
        ensure_admin()
        
        # Initialize logger
        self.logger = get_component_logger('nids', config)
        self.logger.info("Initializing NIDS Sensor")
        
        # Store configuration
        self.config = config
        
        # Parse NIDS-specific configuration
        self.interface = config['NIDS']['interface']
        self.promiscuous_mode = config['NIDS'].getboolean('promiscuous_mode')
        self.snap_length = int(config['NIDS']['snap_length'])
        self.timeout = int(config['NIDS']['timeout'])
        self.bpf_filter = config['NIDS']['bpf_filter']
        
        # Manager connection settings
        self.manager_host = config['Manager']['host']
        self.manager_port = config['Manager']['port']
        self.manager_url = f"http://{self.manager_host}:{self.manager_port}/api/events"
        
        # Load detection rules
        self.rules_file = project_root / 'config' / 'nids_rules.json'
        self.rules = self._load_rules()
        
        # Load malicious IPs and suspicious domains
        self.malicious_ips = self._load_malicious_ips()
        self.suspicious_domains = self._load_suspicious_domains()
        
        # Initialize components
        self.packet_capture = PacketCapture(
            interface=self.interface,
            promiscuous_mode=self.promiscuous_mode,
            snap_length=self.snap_length,
            timeout=self.timeout,
            bpf_filter=self.bpf_filter,
            logger=self.logger
        )
        
        self.traffic_analyzer = TrafficAnalyzer(
            rules=self.rules,
            malicious_ips=self.malicious_ips,
            suspicious_domains=self.suspicious_domains,
            logger=self.logger
        )
        
        self.signature_detector = SignatureDetector(
            rules=self.rules,
            logger=self.logger
        )
        
        # Initialize state
        self.running = False
        self.hostname = socket.gethostname()
        
        # Initialize threads
        self.threads = []
    
    def _load_rules(self):
        """
        Load NIDS detection rules from the rules file.
        
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
    
    def _load_malicious_ips(self):
        """
        Load list of known malicious IP addresses.
        
        Returns:
            list: List of malicious IP addresses
        """
        ip_list_file = None
        
        # Find the IP list file path from rules
        for rule in self.rules:
            if rule.get('detection_type') == 'malicious_ip' and 'ip_list_file' in rule:
                ip_list_file = project_root / rule['ip_list_file']
                break
        
        # Use default path if not specified in rules
        if not ip_list_file:
            ip_list_file = project_root / 'config' / 'malicious_ips.txt'
        
        try:
            return load_list_from_file(ip_list_file)
        except Exception as e:
            self.logger.error(f"Error loading malicious IPs from {ip_list_file}: {e}")
            return []
    
    def _load_suspicious_domains(self):
        """
        Load list of suspicious domains.
        
        Returns:
            list: List of suspicious domains
        """
        domain_list_file = None
        
        # Find the domain list file path from rules
        for rule in self.rules:
            if rule.get('detection_type') == 'dns_request' and 'domain_list_file' in rule:
                domain_list_file = project_root / rule['domain_list_file']
                break
        
        # Use default path if not specified in rules
        if not domain_list_file:
            domain_list_file = project_root / 'config' / 'suspicious_domains.txt'
        
        try:
            return load_list_from_file(domain_list_file)
        except Exception as e:
            self.logger.error(f"Error loading suspicious domains from {domain_list_file}: {e}")
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
        Callback function for handling events from components.
        
        Args:
            event_type (str): Type of event
            details (dict): Event details
            severity (str): Event severity
        """
        # Format the event data
        event = format_event_data(event_type, "nids", details, severity)
        
        # Log the event
        self.logger.info(f"NIDS event detected: {event_type} - {severity}")
        self.logger.debug(f"Event details: {details}")
        
        # Send the event to the IDS Manager
        self._send_event(event)
    
    def _packet_callback(self, packet):
        """
        Callback function for handling captured packets.
        
        Args:
            packet: Captured packet object
        """
        # Analyze the packet for suspicious traffic
        self.traffic_analyzer.analyze_packet(packet, self._event_callback)
        
        # Check packet against signatures
        self.signature_detector.check_packet(packet, self._event_callback)
    
    def start(self):
        """
        Start the NIDS Sensor and all components.
        """
        if self.running:
            self.logger.warning("NIDS Sensor is already running")
            return
        
        self.logger.info("Starting NIDS Sensor")
        self.running = True
        
        try:
            # Start packet capture in a separate thread
            self.logger.info("Starting Packet Capture")
            capture_thread = threading.Thread(
                target=self.packet_capture.start_capture,
                args=(self._packet_callback,),
                daemon=True
            )
            capture_thread.start()
            self.threads.append(capture_thread)
            
            # Keep the main thread alive
            self.logger.info(f"NIDS Sensor started on {self.hostname}")
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.stop()
        except Exception as e:
            self.logger.error(f"Error in NIDS Sensor: {e}")
            self.stop()
    
    def stop(self):
        """
        Stop the NIDS Sensor and all components.
        """
        if not self.running:
            return
        
        self.logger.info("Stopping NIDS Sensor")
        self.running = False
        
        # Stop packet capture
        self.packet_capture.stop_capture()
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        self.logger.info("NIDS Sensor stopped")

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
    
    # Create and start NIDS sensor
    sensor = NIDSSensor(config)
    sensor.start()