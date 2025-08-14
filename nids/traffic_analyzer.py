#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Traffic Analyzer Module

This module analyzes network traffic to detect suspicious activities
such as port scans, high connection rates, and connections to known
malicious IPs or domains.
"""

import time
import socket
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# Import Scapy with error handling
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR
    from scapy.layers.http import HTTP
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please ensure Scapy is properly installed in your virtual environment.")
    import sys
    sys.exit(1)

class TrafficAnalyzer:
    """
    Analyzes network traffic to detect suspicious activities.
    """
    
    def __init__(self, rules=None, malicious_ips=None, suspicious_domains=None, logger=None):
        """
        Initialize the traffic analyzer.
        
        Args:
            rules (list): List of detection rules
            malicious_ips (list): List of known malicious IP addresses
            suspicious_domains (list): List of suspicious domains
            logger: Logger instance
        """
        self.rules = rules or []
        self.malicious_ips = set(malicious_ips or [])
        self.suspicious_domains = set(suspicious_domains or [])
        self.logger = logger
        
        # Initialize connection tracking
        self.connections = defaultdict(list)  # {src_ip: [(dst_ip, dst_port, timestamp), ...]}
        self.port_scan_threshold = self._get_rule_param('port_scan', 'threshold', 10)
        self.port_scan_interval = self._get_rule_param('port_scan', 'interval', 60)  # seconds
        
        # Initialize rate limiting
        self.connection_rates = defaultdict(list)  # {src_ip: [timestamp, ...]}
        self.rate_limit_threshold = self._get_rule_param('connection_rate', 'threshold', 100)
        self.rate_limit_interval = self._get_rule_param('connection_rate', 'interval', 60)  # seconds
        
        # Initialize DNS request tracking
        self.dns_requests = defaultdict(list)  # {domain: [timestamp, ...]}
        self.dns_request_threshold = self._get_rule_param('dns_request', 'threshold', 50)
        self.dns_request_interval = self._get_rule_param('dns_request', 'interval', 60)  # seconds
        
        # Initialize last cleanup time
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
    
    def _get_rule_param(self, rule_type, param_name, default_value):
        """
        Get a parameter value from the rules configuration.
        
        Args:
            rule_type (str): Type of rule
            param_name (str): Name of the parameter
            default_value: Default value if not found in rules
            
        Returns:
            Parameter value from rules or default value
        """
        for rule in self.rules:
            if rule.get('detection_type') == rule_type and param_name in rule:
                return rule[param_name]
        return default_value
    
    def _cleanup_old_data(self):
        """
        Clean up old connection and rate data.
        """
        current_time = time.time()
        
        # Only cleanup periodically
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        if self.logger:
            self.logger.debug("Cleaning up old traffic data")
        
        # Clean up old connections
        cutoff_time = current_time - max(self.port_scan_interval, self.rate_limit_interval)
        
        # Clean connections
        for src_ip in list(self.connections.keys()):
            self.connections[src_ip] = [
                conn for conn in self.connections[src_ip]
                if conn[2] > cutoff_time
            ]
            if not self.connections[src_ip]:
                del self.connections[src_ip]
        
        # Clean connection rates
        for src_ip in list(self.connection_rates.keys()):
            self.connection_rates[src_ip] = [
                timestamp for timestamp in self.connection_rates[src_ip]
                if timestamp > cutoff_time
            ]
            if not self.connection_rates[src_ip]:
                del self.connection_rates[src_ip]
        
        # Clean DNS requests
        for domain in list(self.dns_requests.keys()):
            self.dns_requests[domain] = [
                timestamp for timestamp in self.dns_requests[domain]
                if timestamp > cutoff_time
            ]
            if not self.dns_requests[domain]:
                del self.dns_requests[domain]
        
        self.last_cleanup = current_time
    
    def _is_private_ip(self, ip_str):
        """
        Check if an IP address is private.
        
        Args:
            ip_str (str): IP address string
            
        Returns:
            bool: True if the IP is private, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False
    
    def _check_port_scan(self, src_ip, dst_ip, dst_port, timestamp, callback):
        """
        Check if a source IP is performing a port scan.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            dst_port (int): Destination port
            timestamp (float): Packet timestamp
            callback: Callback function for alerts
        """
        # Add the connection to tracking
        self.connections[src_ip].append((dst_ip, dst_port, timestamp))
        
        # Get recent connections within the interval
        recent_time = timestamp - self.port_scan_interval
        recent_connections = [
            conn for conn in self.connections[src_ip]
            if conn[2] >= recent_time
        ]
        
        # Count unique ports for the same destination IP
        dst_ports = Counter([(conn[0], conn[1]) for conn in recent_connections])
        
        # Check if any destination has too many unique ports accessed
        for (target_ip, _), count in dst_ports.items():
            if count >= self.port_scan_threshold:
                # Port scan detected
                if self.logger:
                    self.logger.warning(f"Port scan detected from {src_ip} to {target_ip} ({count} ports)")
                
                # Call the callback with event details
                details = {
                    "source_ip": src_ip,
                    "destination_ip": target_ip,
                    "port_count": count,
                    "interval": self.port_scan_interval,
                    "threshold": self.port_scan_threshold,
                    "timestamp": datetime.fromtimestamp(timestamp).isoformat()
                }
                callback("port_scan", details, "high")
    
    def _check_connection_rate(self, src_ip, timestamp, callback):
        """
        Check if a source IP has a high connection rate.
        
        Args:
            src_ip (str): Source IP address
            timestamp (float): Packet timestamp
            callback: Callback function for alerts
        """
        # Add the connection timestamp
        self.connection_rates[src_ip].append(timestamp)
        
        # Get recent connections within the interval
        recent_time = timestamp - self.rate_limit_interval
        recent_connections = [
            ts for ts in self.connection_rates[src_ip]
            if ts >= recent_time
        ]
        
        # Check if the rate exceeds the threshold
        if len(recent_connections) > self.rate_limit_threshold:
            # High connection rate detected
            if self.logger:
                self.logger.warning(f"High connection rate detected from {src_ip} ({len(recent_connections)} connections)")
            
            # Call the callback with event details
            details = {
                "source_ip": src_ip,
                "connection_count": len(recent_connections),
                "interval": self.rate_limit_interval,
                "threshold": self.rate_limit_threshold,
                "timestamp": datetime.fromtimestamp(timestamp).isoformat()
            }
            callback("high_connection_rate", details, "medium")
    
    def _check_malicious_ip(self, src_ip, dst_ip, dst_port, callback):
        """
        Check if a packet involves a known malicious IP.
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            dst_port (int): Destination port
            callback: Callback function for alerts
        """
        # Check if either source or destination IP is in the malicious list
        is_src_malicious = src_ip in self.malicious_ips
        is_dst_malicious = dst_ip in self.malicious_ips
        
        if is_src_malicious or is_dst_malicious:
            # Malicious IP detected
            malicious_ip = src_ip if is_src_malicious else dst_ip
            other_ip = dst_ip if is_src_malicious else src_ip
            direction = "inbound" if is_src_malicious else "outbound"
            
            if self.logger:
                self.logger.warning(f"Connection with malicious IP detected: {malicious_ip} ({direction})")
            
            # Call the callback with event details
            details = {
                "malicious_ip": malicious_ip,
                "other_ip": other_ip,
                "direction": direction,
                "port": dst_port,
                "timestamp": datetime.now().isoformat()
            }
            callback("malicious_ip_connection", details, "high")
    
    def _check_dns_request(self, domain, timestamp, callback):
        """
        Check if a DNS request is for a suspicious domain or if there are too many requests.
        
        Args:
            domain (str): Requested domain
            timestamp (float): Packet timestamp
            callback: Callback function for alerts
        """
        # Check if the domain is in the suspicious list
        if domain in self.suspicious_domains:
            if self.logger:
                self.logger.warning(f"DNS request for suspicious domain: {domain}")
            
            # Call the callback with event details
            details = {
                "domain": domain,
                "reason": "suspicious_domain",
                "timestamp": datetime.fromtimestamp(timestamp).isoformat()
            }
            callback("suspicious_dns_request", details, "high")
            return
        
        # Add the DNS request timestamp
        self.dns_requests[domain].append(timestamp)
        
        # Get recent requests within the interval
        recent_time = timestamp - self.dns_request_interval
        recent_requests = [
            ts for ts in self.dns_requests[domain]
            if ts >= recent_time
        ]
        
        # Check if the rate exceeds the threshold
        if len(recent_requests) > self.dns_request_threshold:
            # High DNS request rate detected
            if self.logger:
                self.logger.warning(f"High DNS request rate for domain: {domain} ({len(recent_requests)} requests)")
            
            # Call the callback with event details
            details = {
                "domain": domain,
                "request_count": len(recent_requests),
                "interval": self.dns_request_interval,
                "threshold": self.dns_request_threshold,
                "reason": "high_request_rate",
                "timestamp": datetime.fromtimestamp(timestamp).isoformat()
            }
            callback("suspicious_dns_request", details, "medium")
    
    def analyze_packet(self, packet, callback):
        """
        Analyze a network packet for suspicious activities.
        
        Args:
            packet: Scapy packet object
            callback: Callback function for alerts
        """
        # Periodically clean up old data
        self._cleanup_old_data()
        
        # Get current timestamp
        timestamp = time.time()
        
        # Check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Skip analysis for private-to-private communications if configured
            skip_private = self._get_rule_param('general', 'skip_private_traffic', True)
            if skip_private and self._is_private_ip(src_ip) and self._is_private_ip(dst_ip):
                return
            
            # Check for TCP traffic
            if TCP in packet:
                dst_port = packet[TCP].dport
                
                # Check for port scanning
                self._check_port_scan(src_ip, dst_ip, dst_port, timestamp, callback)
                
                # Check connection rate
                self._check_connection_rate(src_ip, timestamp, callback)
                
                # Check for malicious IPs
                self._check_malicious_ip(src_ip, dst_ip, dst_port, callback)
            
            # Check for UDP traffic
            elif UDP in packet:
                dst_port = packet[UDP].dport
                
                # Check for malicious IPs in UDP traffic
                self._check_malicious_ip(src_ip, dst_ip, dst_port, callback)
                
                # Check for DNS requests
                if dst_port == 53 and DNS in packet and packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                    self._check_dns_request(qname, timestamp, callback)

# For testing purposes
if __name__ == "__main__":
    import logging
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("TrafficAnalyzer")
    
    # Create a simple callback function
    def alert_callback(event_type, details, severity):
        print(f"ALERT [{severity.upper()}]: {event_type}")
        print(f"Details: {details}")
        print("-" * 50)
    
    # Create a traffic analyzer instance
    analyzer = TrafficAnalyzer(
        malicious_ips=["1.2.3.4", "5.6.7.8"],
        suspicious_domains=["malicious.com", "suspicious.net"],
        logger=logger
    )
    
    # Test with a simulated packet (this won't work as-is, just for illustration)
    print("This is a test module and requires actual packet capture to function properly.")