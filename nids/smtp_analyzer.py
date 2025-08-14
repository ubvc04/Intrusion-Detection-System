#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SMTP Analyzer Module

This module implements SMTP traffic analysis for the Network-based Intrusion Detection System (NIDS).
It detects suspicious email traffic, potential email-based attacks, and malicious patterns in SMTP communications.
"""

import re
import json
import logging
from datetime import datetime
from utils.helpers import generate_event_id

class SMTPAnalyzer:
    """
    SMTP Traffic Analyzer
    
    Analyzes SMTP traffic to detect suspicious email communications, potential email-based attacks,
    and malicious patterns in SMTP traffic.
    """
    
    def __init__(self, config, callback=None):
        """
        Initialize the SMTP analyzer.
        
        Args:
            config: Configuration object containing SMTP analysis settings
            callback: Callback function for sending events
        """
        self.config = config
        self.callback = callback
        self.logger = logging.getLogger('ids.nids.smtp')
        self.suspicious_patterns = []
        self.running = False
        self.load_suspicious_patterns()
        
    def load_suspicious_patterns(self):
        """
        Load suspicious SMTP patterns from NIDS rules.
        """
        try:
            with open(self.config.get('NIDS', 'rules_file'), 'r') as f:
                rules = json.loads(f.read())
                
            smtp_rules = [rule for rule in rules if rule.get('protocol') == 'smtp']
            
            for rule in smtp_rules:
                pattern = rule.get('pattern')
                if pattern:
                    try:
                        self.suspicious_patterns.append({
                            'regex': re.compile(pattern, re.IGNORECASE),
                            'name': rule.get('name', 'Unknown SMTP Attack'),
                            'severity': rule.get('severity', 'medium'),
                            'description': rule.get('description', 'Suspicious SMTP traffic detected')
                        })
                    except re.error as e:
                        self.logger.error(f"Invalid regex pattern in SMTP rule: {pattern}. Error: {str(e)}")
                        
            self.logger.info(f"Loaded {len(self.suspicious_patterns)} SMTP detection patterns")
        except Exception as e:
            self.logger.error(f"Failed to load SMTP rules: {str(e)}")
            
    def analyze_packet(self, packet):
        """
        Analyze SMTP packet for suspicious patterns.
        
        Args:
            packet: Scapy packet object
        
        Returns:
            True if packet was analyzed, False otherwise
        """
        # Check if packet has TCP layer and is likely SMTP (port 25, 465, or 587)
        if not packet.haslayer('TCP'):
            return False
            
        tcp_layer = packet.getlayer('TCP')
        smtp_ports = [25, 465, 587]
        if not (tcp_layer.sport in smtp_ports or tcp_layer.dport in smtp_ports):
            return False
            
        # Extract SMTP data
        smtp_data = ""
        if packet.haslayer('Raw'):
            raw_data = packet.getlayer('Raw').load
            try:
                smtp_data = raw_data.decode('utf-8', errors='ignore')
            except:
                return False
                
        # Skip if no SMTP data
        if not smtp_data:
            return False
            
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern['regex'].search(smtp_data):
                self._generate_alert(packet, pattern, smtp_data)
                return True
                
        return True
        
    def _generate_alert(self, packet, pattern, smtp_data):
        """
        Generate an alert for suspicious SMTP traffic.
        
        Args:
            packet: Scapy packet object
            pattern: Matched pattern information
            smtp_data: SMTP data from the packet
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
            'type': 'smtp_attack',
            'severity': pattern['severity'],
            'host': src_ip,
            'details': {
                'name': pattern['name'],
                'description': pattern['description'],
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': 'SMTP',
                'sample': smtp_data[:200] + ('...' if len(smtp_data) > 200 else '')
            }
        }
        
        # Send event
        self.callback(event)
        self.logger.warning(f"SMTP attack detected: {pattern['name']} from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        
    def start(self):
        """
        Start the SMTP analyzer.
        
        This method is called by the NIDS sensor to start the analyzer.
        The SMTP analyzer doesn't need a separate thread as it processes
        packets on-demand when they are passed to analyze_packet.
        """
        self.running = True
        self.logger.info("SMTP analyzer started")
        
    def stop(self):
        """
        Stop the SMTP analyzer.
        """
        self.running = False
        self.logger.info("SMTP analyzer stopped")