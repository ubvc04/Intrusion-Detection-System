#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Traffic Analyzer Module

This module analyzes DNS traffic for the NIDS sensor, detecting suspicious
domain lookups and potential DNS-based attacks.
"""

import os
import sys
import re
import time
import threading
from pathlib import Path

# Import Scapy with error handling
try:
    from scapy.all import DNS, DNSQR, DNSRR
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please ensure Npcap is installed and Scapy is properly installed in your virtual environment.")
    sys.exit(1)

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Import utility modules
from utils.helpers import generate_event_id

class DNSAnalyzer:
    """
    Analyzes DNS traffic for suspicious activity.
    
    This class monitors DNS queries and responses, checking domain names against
    known malicious domains and detecting suspicious patterns.
    """
    
    def __init__(self, config, logger=None):
        """
        Initialize the DNS Analyzer.
        
        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.running = False
        self.callback = None
        
        # Load suspicious domains list
        self.suspicious_domains = []
        self.load_suspicious_domains()
        
        # Compile regex patterns for suspicious domains
        self.domain_patterns = []
        self.compile_domain_patterns()
        
        self.logger.info("DNS Analyzer initialized")
    
    def load_suspicious_domains(self):
        """
        Load suspicious domains from configuration file.
        """
        domains_file = project_root / 'config' / 'suspicious_domains.txt'
        
        if not domains_file.exists():
            self.logger.warning(f"Suspicious domains file not found: {domains_file}")
            return
        
        try:
            with open(domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.suspicious_domains.append(line)
            
            self.logger.info(f"Loaded {len(self.suspicious_domains)} suspicious domains")
        except Exception as e:
            self.logger.error(f"Error loading suspicious domains: {e}")
    
    def compile_domain_patterns(self):
        """
        Compile regex patterns for domain matching from rules.
        """
        rules_file = project_root / 'config' / 'nids_rules.conf'
        
        if not rules_file.exists():
            self.logger.warning(f"NIDS rules file not found: {rules_file}")
            return
        
        try:
            with open(rules_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('|')
                        if len(parts) >= 7 and parts[0] == 'dns':
                            pattern = parts[4]
                            try:
                                regex = re.compile(pattern)
                                self.domain_patterns.append({
                                    'regex': regex,
                                    'severity': parts[5],
                                    'description': parts[6]
                                })
                            except re.error as e:
                                self.logger.error(f"Invalid regex pattern '{pattern}': {e}")
            
            self.logger.info(f"Compiled {len(self.domain_patterns)} domain patterns")
        except Exception as e:
            self.logger.error(f"Error compiling domain patterns: {e}")
    
    def set_callback(self, callback):
        """
        Set the callback function for detected events.
        
        Args:
            callback: Function to call with event data
        """
        self.callback = callback
    
    def analyze_packet(self, packet):
        """
        Analyze a DNS packet for suspicious activity.
        
        Args:
            packet: Scapy packet object
        """
        if not packet.haslayer(DNS):
            return
        
        # Extract DNS query information
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8').lower()
            qname = qname.rstrip('.')
            
            # Check against suspicious domains list
            for domain in self.suspicious_domains:
                if domain in qname or qname.endswith('.' + domain):
                    self._generate_event(qname, 'high', f"DNS query to suspicious domain: {qname}")
                    break
            
            # Check against regex patterns
            for pattern in self.domain_patterns:
                if pattern['regex'].search(qname):
                    self._generate_event(qname, pattern['severity'], pattern['description'])
                    break
    
    def _generate_event(self, domain, severity, description):
        """
        Generate an event for a suspicious DNS query.
        
        Args:
            domain (str): The domain name
            severity (str): Event severity (low, medium, high, critical)
            description (str): Event description
        """
        event = {
            'event_id': generate_event_id(),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'component': 'nids',
            'event_type': 'dns_suspicious_query',
            'severity': severity,
            'source': 'dns_analyzer',
            'description': description,
            'details': {
                'domain': domain
            }
        }
        
        self.logger.warning(f"Suspicious DNS query detected: {domain}")
        
        if self.callback:
            self.callback(event)
            
    def start(self):
        """
        Start the DNS analyzer.
        
        This method is called by the NIDS sensor to start the analyzer.
        The DNS analyzer doesn't need a separate thread as it processes
        packets on-demand when they are passed to analyze_packet.
        """
        self.running = True
        self.logger.info("DNS analyzer started")
        
    def stop(self):
        """
        Stop the DNS analyzer.
        """
        self.running = False
        self.logger.info("DNS analyzer stopped")