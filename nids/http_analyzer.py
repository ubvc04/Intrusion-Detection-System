#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP Analyzer Module

This module implements HTTP traffic analysis for the Network-based Intrusion Detection System (NIDS).
It detects suspicious HTTP requests, potential web attacks, and malicious patterns in HTTP traffic.
"""

import re
import json
import logging
import time
from datetime import datetime
from utils.helpers import generate_event_id

class HTTPAnalyzer:
    """
    HTTP Traffic Analyzer
    
    Analyzes HTTP traffic to detect suspicious requests, potential web attacks,
    and malicious patterns in HTTP traffic.
    """
    
    def __init__(self, config, callback=None):
        """
        Initialize the HTTP analyzer.
        
        Args:
            config: Configuration object containing HTTP analysis settings
            callback: Callback function for sending events
        """
        self.config = config
        self.callback = callback
        self.logger = logging.getLogger('ids.nids.http')
        self.suspicious_patterns = []
        self.running = False
        self.load_suspicious_patterns()
        
    def load_suspicious_patterns(self):
        """
        Load suspicious HTTP patterns from NIDS rules.
        """
        try:
            with open(self.config.get('NIDS', 'rules_file'), 'r') as f:
                rules = json.loads(f.read())
                
            http_rules = [rule for rule in rules if rule.get('protocol') == 'http']
            
            for rule in http_rules:
                pattern = rule.get('pattern')
                if pattern:
                    try:
                        self.suspicious_patterns.append({
                            'regex': re.compile(pattern, re.IGNORECASE),
                            'name': rule.get('name', 'Unknown HTTP Attack'),
                            'severity': rule.get('severity', 'medium'),
                            'description': rule.get('description', 'Suspicious HTTP traffic detected')
                        })
                    except re.error as e:
                        self.logger.error(f"Invalid regex pattern in HTTP rule: {pattern}. Error: {str(e)}")
                        
            self.logger.info(f"Loaded {len(self.suspicious_patterns)} HTTP detection patterns")
        except Exception as e:
            self.logger.error(f"Failed to load HTTP rules: {str(e)}")
            
    def analyze_packet(self, packet):
        """
        Analyze HTTP packet for suspicious patterns.
        
        Args:
            packet: Scapy packet object
        
        Returns:
            True if packet was analyzed, False otherwise
        """
        # Check if packet has HTTP layer
        if not packet.haslayer('TCP') or not (packet.haslayer('HTTP') or packet.haslayer('Raw')):
            return False
            
        # Extract HTTP data
        http_data = ""
        if packet.haslayer('HTTP'):
            http_data = str(packet.getlayer('HTTP'))
        elif packet.haslayer('Raw'):
            raw_data = packet.getlayer('Raw').load
            try:
                http_data = raw_data.decode('utf-8', errors='ignore')
            except:
                return False
                
        # Skip if no HTTP data
        if not http_data:
            return False
            
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern['regex'].search(http_data):
                self._generate_alert(packet, pattern, http_data)
                return True
                
        return True
        
    def _generate_alert(self, packet, pattern, http_data):
        """
        Generate an alert for suspicious HTTP traffic.
        
        Args:
            packet: Scapy packet object
            pattern: Matched pattern information
            http_data: HTTP data from the packet
        """
        if not self.callback:
            return
            
        # Extract source and destination
        src_ip = packet.getlayer('IP').src if packet.haslayer('IP') else 'Unknown'
        dst_ip = packet.getlayer('IP').dst if packet.haslayer('IP') else 'Unknown'
        src_port = packet.getlayer('TCP').sport if packet.haslayer('TCP') else 0
        dst_port = packet.getlayer('TCP').dport if packet.haslayer('TCP') else 0
        
        # Create event
        event = {
            'id': generate_event_id(),
            'timestamp': datetime.now().isoformat(),
            'source': 'nids',
            'type': 'http_attack',
            'severity': pattern['severity'],
            'host': src_ip,
            'details': {
                'name': pattern['name'],
                'description': pattern['description'],
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': 'HTTP',
                'sample': http_data[:200] + ('...' if len(http_data) > 200 else '')
            }
        }
        
        # Send event
        self.callback(event)
        self.logger.warning(f"HTTP attack detected: {pattern['name']} from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        
    def start(self):
        """
        Start the HTTP analyzer.
        
        This method is called by the NIDS sensor to start the analyzer.
        The HTTP analyzer doesn't need a separate thread as it processes
        packets on-demand when they are passed to analyze_packet.
        """
        self.running = True
        self.logger.info("HTTP analyzer started")
        
    def stop(self):
        """
        Stop the HTTP analyzer.
        """
        self.running = False
        self.logger.info("HTTP analyzer stopped")