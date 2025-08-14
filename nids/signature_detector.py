#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Signature Detector Module

This module implements signature-based detection for the NIDS sensor,
matching packet contents against known attack patterns.
"""

import re
from datetime import datetime

# Import Scapy with error handling
try:
    from scapy.all import IP, TCP, UDP, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please ensure Scapy is properly installed in your virtual environment.")
    import sys
    sys.exit(1)

class SignatureDetector:
    """
    Detects known attack signatures in network packets.
    """
    
    def __init__(self, rules=None, logger=None):
        """
        Initialize the signature detector.
        
        Args:
            rules (list): List of signature detection rules
            logger: Logger instance
        """
        self.logger = logger
        self.rules = []
        
        # Process and compile signature rules
        if rules:
            self._compile_rules(rules)
    
    def _compile_rules(self, rules):
        """
        Process and compile signature detection rules.
        
        Args:
            rules (list): List of detection rules
        """
        for rule in rules:
            if rule.get('detection_type') == 'signature':
                try:
                    # Compile regex pattern if present
                    if 'pattern' in rule:
                        rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE | re.DOTALL)
                    
                    # Add the rule to the list
                    self.rules.append(rule)
                    
                    if self.logger:
                        self.logger.debug(f"Compiled signature rule: {rule['name']}")
                
                except re.error as e:
                    if self.logger:
                        self.logger.error(f"Error compiling regex pattern for rule '{rule.get('name', 'unknown')}': {e}")
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error processing rule '{rule.get('name', 'unknown')}': {e}")
    
    def _extract_payload(self, packet):
        """
        Extract the payload from a packet for signature matching.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            tuple: (payload_bytes, payload_text, protocol, src_port, dst_port)
        """
        payload_bytes = None
        payload_text = ""
        protocol = None
        src_port = None
        dst_port = None
        
        # Extract protocol and port information
        if TCP in packet:
            protocol = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # Extract payload from HTTP layer if present
        if HTTP in packet or HTTPRequest in packet or HTTPResponse in packet:
            if HTTPRequest in packet:
                # Extract HTTP request information
                http_layer = packet[HTTPRequest]
                method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else ""
                path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else ""
                payload_text = f"{method} {path}\r\n"
                
                # Add headers
                for header_name, header_value in http_layer.fields.items():
                    if isinstance(header_name, str) and header_name.startswith('\\'):
                        header_name = header_name[1:]
                        if isinstance(header_value, bytes):
                            header_value = header_value.decode('utf-8', errors='ignore')
                        payload_text += f"{header_name}: {header_value}\r\n"
            
            elif HTTPResponse in packet:
                # Extract HTTP response information
                http_layer = packet[HTTPResponse]
                status_code = http_layer.Status_Code if hasattr(http_layer, 'Status_Code') else ""
                reason = http_layer.Reason_Phrase.decode() if hasattr(http_layer, 'Reason_Phrase') else ""
                payload_text = f"HTTP/1.1 {status_code} {reason}\r\n"
                
                # Add headers
                for header_name, header_value in http_layer.fields.items():
                    if isinstance(header_name, str) and header_name.startswith('\\'):
                        header_name = header_name[1:]
                        if isinstance(header_value, bytes):
                            header_value = header_value.decode('utf-8', errors='ignore')
                        payload_text += f"{header_name}: {header_value}\r\n"
        
        # Extract raw payload if present
        if Raw in packet:
            payload_bytes = bytes(packet[Raw])
            try:
                # Try to decode as UTF-8, ignoring errors
                decoded = payload_bytes.decode('utf-8', errors='ignore')
                payload_text += decoded
            except Exception:
                # If decoding fails, just use the bytes
                pass
        
        return payload_bytes, payload_text, protocol, src_port, dst_port
    
    def check_packet(self, packet, callback):
        """
        Check a packet against signature detection rules.
        
        Args:
            packet: Scapy packet object
            callback: Callback function for alerts
        """
        if not self.rules:
            return
        
        # Skip packets without IP layer
        if IP not in packet:
            return
        
        # Extract source and destination IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Extract payload and protocol information
        payload_bytes, payload_text, protocol, src_port, dst_port = self._extract_payload(packet)
        
        # Skip if no payload to check
        if not payload_bytes and not payload_text:
            return
        
        # Check each rule
        for rule in self.rules:
            match_found = False
            match_details = {}
            
            # Skip if protocol doesn't match
            if 'protocol' in rule and protocol and rule['protocol'].lower() != protocol.lower():
                continue
            
            # Skip if port filter doesn't match
            if 'port' in rule:
                rule_port = int(rule['port'])
                if rule.get('port_direction', 'dst') == 'dst' and dst_port != rule_port:
                    continue
                elif rule.get('port_direction') == 'src' and src_port != rule_port:
                    continue
                elif rule.get('port_direction') == 'both' and src_port != rule_port and dst_port != rule_port:
                    continue
            
            # Check pattern match
            if 'compiled_pattern' in rule and payload_text:
                match = rule['compiled_pattern'].search(payload_text)
                if match:
                    match_found = True
                    match_details['pattern_match'] = match.group(0)[:100]  # Limit to 100 chars
                    match_details['match_position'] = match.start()
            
            # Check content match (exact byte sequence)
            elif 'content' in rule and payload_bytes:
                content_bytes = rule['content'].encode('utf-8', errors='ignore')
                if content_bytes in payload_bytes:
                    match_found = True
                    match_details['content_match'] = rule['content'][:100]  # Limit to 100 chars
                    match_details['match_position'] = payload_bytes.find(content_bytes)
            
            # If a match is found, trigger an alert
            if match_found:
                if self.logger:
                    self.logger.warning(f"Signature match: {rule['name']} from {src_ip} to {dst_ip}")
                
                # Prepare event details
                details = {
                    "rule_name": rule['name'],
                    "rule_id": rule.get('id', 'unknown'),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": protocol,
                    "source_port": src_port,
                    "destination_port": dst_port,
                    "timestamp": datetime.now().isoformat(),
                    **match_details
                }
                
                # Add description if available
                if 'description' in rule:
                    details['description'] = rule['description']
                
                # Call the callback with event details
                severity = rule.get('severity', 'medium')
                callback("signature_match", details, severity)

# For testing purposes
if __name__ == "__main__":
    import logging
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("SignatureDetector")
    
    # Create a simple callback function
    def alert_callback(event_type, details, severity):
        print(f"ALERT [{severity.upper()}]: {event_type}")
        print(f"Details: {details}")
        print("-" * 50)
    
    # Create test rules
    test_rules = [
        {
            "name": "SQL Injection Attempt",
            "id": "SIG-001",
            "detection_type": "signature",
            "pattern": "(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*(?:FROM|INTO|WHERE).*(?:'|\"|\\\\)",
            "protocol": "tcp",
            "port": 80,
            "severity": "high",
            "description": "Possible SQL injection attempt detected"
        },
        {
            "name": "Command Injection Attempt",
            "id": "SIG-002",
            "detection_type": "signature",
            "pattern": "(?:;|\\||`|\\$\\(|\\$\\{).*(?:cat|ls|pwd|whoami|echo|bash|cmd)",
            "protocol": "tcp",
            "severity": "high",
            "description": "Possible command injection attempt detected"
        }
    ]
    
    # Create a signature detector instance
    detector = SignatureDetector(rules=test_rules, logger=logger)
    
    print("This is a test module and requires actual packet capture to function properly.")
    print(f"Loaded {len(detector.rules)} signature rules")