#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Event Correlation Module

This module implements event correlation for the IDS Manager,
detecting patterns across multiple events to identify complex attacks.
"""

import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict

class EventCorrelator:
    """
    Correlates events to detect complex attack patterns.
    """
    
    def __init__(self, db_manager, logger=None):
        """
        Initialize the event correlator.
        
        Args:
            db_manager: Database manager instance
            logger: Logger instance
        """
        self.db_manager = db_manager
        self.logger = logger
        
        # Initialize state
        self.running = False
        self.correlation_thread = None
        self.correlation_interval = 60  # seconds
        
        # Initialize correlation rules
        self.rules = [
            # Brute force login attempts
            {
                "name": "Brute Force Login Attempts",
                "description": "Multiple failed login attempts from the same source",
                "conditions": [
                    {"type": "failed_login", "count": 5, "timeframe": 300}  # 5 failed logins in 5 minutes
                ],
                "severity": "high"
            },
            # Port scan followed by connection
            {
                "name": "Port Scan Followed by Connection",
                "description": "Port scan followed by connection to a specific port",
                "conditions": [
                    {"type": "port_scan", "count": 1, "timeframe": 600},
                    {"type": "connection", "count": 1, "timeframe": 600, "after": "port_scan"}
                ],
                "severity": "high"
            },
            # Multiple high severity events from same source
            {
                "name": "Multiple High Severity Events",
                "description": "Multiple high severity events from the same source",
                "conditions": [
                    {"severity": "high", "count": 3, "timeframe": 300}  # 3 high severity events in 5 minutes
                ],
                "severity": "critical"
            },
            # File modification followed by suspicious process
            {
                "name": "File Modification Followed by Suspicious Process",
                "description": "File modification followed by suspicious process execution",
                "conditions": [
                    {"type": "file_change", "count": 1, "timeframe": 600},
                    {"type": "process_creation", "count": 1, "timeframe": 600, "after": "file_change"}
                ],
                "severity": "high"
            },
            # Registry modification followed by network connection
            {
                "name": "Registry Modification Followed by Network Connection",
                "description": "Registry modification followed by suspicious network connection",
                "conditions": [
                    {"type": "registry_change", "count": 1, "timeframe": 600},
                    {"type": "connection", "count": 1, "timeframe": 600, "after": "registry_change"}
                ],
                "severity": "high"
            },
            # NIDS and HIDS events correlation
            {
                "name": "NIDS and HIDS Correlation",
                "description": "Network intrusion detection followed by host-based suspicious activity",
                "conditions": [
                    {"source": "nids", "count": 1, "timeframe": 600},
                    {"source": "hids", "count": 1, "timeframe": 600, "after": "nids"}
                ],
                "severity": "high"
            }
        ]
    
    def start(self):
        """
        Start the event correlation engine.
        """
        if self.running:
            if self.logger:
                self.logger.warning("Event correlator is already running")
            return
        
        self.running = True
        
        if self.logger:
            self.logger.info("Starting event correlation engine")
        
        # Start correlation thread
        self.correlation_thread = threading.Thread(target=self._correlation_loop, daemon=True)
        self.correlation_thread.start()
    
    def stop(self):
        """
        Stop the event correlation engine.
        """
        if not self.running:
            return
        
        self.running = False
        
        if self.logger:
            self.logger.info("Stopping event correlation engine")
        
        # Wait for correlation thread to finish
        if self.correlation_thread and self.correlation_thread.is_alive():
            self.correlation_thread.join(timeout=5)
            if self.correlation_thread.is_alive():
                if self.logger:
                    self.logger.warning("Correlation thread did not terminate gracefully")
    
    def _correlation_loop(self):
        """
        Main correlation loop that runs periodically.
        """
        while self.running:
            try:
                # Run correlation
                self._correlate_events()
                
                # Sleep for the correlation interval
                for _ in range(self.correlation_interval):
                    if not self.running:
                        break
                    time.sleep(1)
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in correlation loop: {e}")
                time.sleep(10)  # Sleep for a short time before retrying
    
    def _correlate_events(self):
        """
        Correlate events based on rules.
        """
        if self.logger:
            self.logger.debug("Running event correlation")
        
        # Get recent events
        now = datetime.now()
        start_time = (now - timedelta(minutes=10)).isoformat()  # Look at events from the last 10 minutes
        
        events = self.db_manager.get_events({
            'start_time': start_time,
            'acknowledged': False,
            'correlated_with': None  # Only get events that haven't been correlated yet
        }, limit=1000)
        
        if not events:
            return
        
        # Group events by source IP or hostname
        grouped_events = defaultdict(list)
        
        for event in events:
            # Extract source identifier (IP or hostname)
            source_id = None
            
            if 'details' in event and isinstance(event['details'], dict):
                # Try to get source IP from details
                if 'source_ip' in event['details']:
                    source_id = event['details']['source_ip']
                elif 'ip_address' in event['details']:
                    source_id = event['details']['ip_address']
                elif 'hostname' in event['details']:
                    source_id = event['details']['hostname']
            
            # If no source ID found, use a default group
            if not source_id:
                source_id = "unknown"
            
            grouped_events[source_id].append(event)
        
        # Check each group against correlation rules
        for source_id, source_events in grouped_events.items():
            self._check_correlation_rules(source_id, source_events)
    
    def _check_correlation_rules(self, source_id, events):
        """
        Check a group of events against correlation rules.
        
        Args:
            source_id (str): Source identifier (IP or hostname)
            events (list): List of events from the source
        """
        for rule in self.rules:
            try:
                # Check if events match the rule conditions
                matched_events = self._match_rule_conditions(rule, events)
                
                if matched_events:
                    # Create a correlated event
                    self._create_correlated_event(rule, source_id, matched_events)
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error checking correlation rule '{rule['name']}': {e}")
    
    def _match_rule_conditions(self, rule, events):
        """
        Check if events match the conditions of a correlation rule.
        
        Args:
            rule (dict): Correlation rule
            events (list): List of events to check
            
        Returns:
            list: List of matched events, or empty list if no match
        """
        conditions = rule['conditions']
        matched_events = []
        
        # Simple case: single condition
        if len(conditions) == 1:
            condition = conditions[0]
            matching = self._find_matching_events(condition, events)
            
            if len(matching) >= condition['count']:
                matched_events.extend(matching[:condition['count']])
                return matched_events
        
        # Complex case: multiple conditions with sequence
        elif len(conditions) > 1:
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: e['timestamp'])
            
            # Track matched events for each condition
            condition_matches = {}
            
            # Check first condition
            first_condition = conditions[0]
            first_matches = self._find_matching_events(first_condition, sorted_events)
            
            if len(first_matches) < first_condition['count']:
                return []  # First condition not met
            
            condition_matches[0] = first_matches[:first_condition['count']]
            
            # Check subsequent conditions
            for i in range(1, len(conditions)):
                condition = conditions[i]
                
                # If this condition should come after a previous one
                if 'after' in condition:
                    # Find the index of the referenced condition
                    ref_index = None
                    for j, cond in enumerate(conditions):
                        if cond.get('type') == condition['after']:
                            ref_index = j
                            break
                    
                    if ref_index is not None and ref_index in condition_matches:
                        # Get the latest timestamp from the referenced condition's matches
                        ref_events = condition_matches[ref_index]
                        latest_ref_time = max(e['timestamp'] for e in ref_events)
                        
                        # Only consider events after the latest reference event
                        filtered_events = [e for e in sorted_events if e['timestamp'] > latest_ref_time]
                        matches = self._find_matching_events(condition, filtered_events)
                    else:
                        matches = []
                else:
                    matches = self._find_matching_events(condition, sorted_events)
                
                if len(matches) < condition['count']:
                    return []  # Condition not met
                
                condition_matches[i] = matches[:condition['count']]
            
            # If all conditions are met, combine all matched events
            for matches in condition_matches.values():
                matched_events.extend(matches)
            
            return matched_events
        
        return []
    
    def _find_matching_events(self, condition, events):
        """
        Find events matching a condition.
        
        Args:
            condition (dict): Condition to match
            events (list): List of events to check
            
        Returns:
            list: List of matching events
        """
        matching = []
        
        # Calculate timeframe
        now = datetime.now()
        timeframe = condition.get('timeframe', 300)  # Default: 5 minutes
        cutoff_time = (now - timedelta(seconds=timeframe)).isoformat()
        
        for event in events:
            # Skip events outside the timeframe
            if event['timestamp'] < cutoff_time:
                continue
            
            # Check event properties against condition
            matches = True
            
            if 'type' in condition and event['type'] != condition['type']:
                matches = False
            
            if 'source' in condition and event['source'] != condition['source']:
                matches = False
            
            if 'severity' in condition and event['severity'] != condition['severity']:
                matches = False
            
            # Add custom property checks as needed
            
            if matches:
                matching.append(event)
        
        return matching
    
    def _create_correlated_event(self, rule, source_id, matched_events):
        """
        Create a correlated event from matched events.
        
        Args:
            rule (dict): Correlation rule that was matched
            source_id (str): Source identifier (IP or hostname)
            matched_events (list): List of events that matched the rule
        """
        if self.logger:
            self.logger.info(f"Correlation rule '{rule['name']}' matched for {source_id} with {len(matched_events)} events")
        
        # Extract event IDs
        event_ids = [event['id'] for event in matched_events]
        
        # Create a new correlated event
        correlated_event = {
            'timestamp': datetime.now().isoformat(),
            'source': 'correlation',
            'type': 'correlated_event',
            'severity': rule['severity'],
            'details': {
                'rule_name': rule['name'],
                'rule_description': rule['description'],
                'source_id': source_id,
                'matched_event_count': len(matched_events),
                'matched_event_ids': event_ids,
                'matched_event_types': [event['type'] for event in matched_events]
            }
        }
        
        # Store the correlated event
        correlated_event_id = self.db_manager.store_event(correlated_event)
        
        if correlated_event_id != -1:
            # Mark the matched events as correlated with this event
            self.db_manager.correlate_events(event_ids, correlated_event_id)
    
    def process_event(self, event_id):
        """
        Process a single event for correlation.
        
        This method is called when a new event is received.
        
        Args:
            event_id (int): ID of the event to process
        """
        try:
            # Get the event
            event = self.db_manager.get_event_by_id(event_id)
            
            if not event:
                return
            
            # Get recent events from the same source
            source_id = None
            
            if 'details' in event and isinstance(event['details'], dict):
                # Try to get source IP from details
                if 'source_ip' in event['details']:
                    source_id = event['details']['source_ip']
                elif 'ip_address' in event['details']:
                    source_id = event['details']['ip_address']
                elif 'hostname' in event['details']:
                    source_id = event['details']['hostname']
            
            if not source_id:
                return
            
            # Get recent events from the same source
            now = datetime.now()
            start_time = (now - timedelta(minutes=10)).isoformat()
            
            filters = {
                'start_time': start_time,
                'acknowledged': False,
                'correlated_with': None
            }
            
            events = self.db_manager.get_events(filters, limit=100)
            
            # Filter events from the same source
            source_events = []
            
            for e in events:
                e_source_id = None
                
                if 'details' in e and isinstance(e['details'], dict):
                    if 'source_ip' in e['details']:
                        e_source_id = e['details']['source_ip']
                    elif 'ip_address' in e['details']:
                        e_source_id = e['details']['ip_address']
                    elif 'hostname' in e['details']:
                        e_source_id = e['details']['hostname']
                
                if e_source_id == source_id:
                    source_events.append(e)
            
            # Add the current event
            source_events.append(event)
            
            # Check correlation rules
            self._check_correlation_rules(source_id, source_events)
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error processing event {event_id} for correlation: {e}")

# For testing purposes
if __name__ == "__main__":
    import logging
    import sys
    from pathlib import Path
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("EventCorrelator")
    
    # Set project root
    project_root = Path(__file__).resolve().parent.parent
    
    # Import database manager
    sys.path.insert(0, str(project_root))
    from manager.database import DatabaseManager
    
    # Create database manager
    db_path = project_root / 'data' / 'ids.db'
    db_manager = DatabaseManager(str(db_path), logger)
    db_manager.initialize_database()
    
    # Create event correlator
    correlator = EventCorrelator(db_manager, logger)
    
    # Start correlator
    correlator.start()
    
    try:
        # Run for a while
        print("Event correlator running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("Stopping event correlator")
    
    finally:
        # Stop correlator
        correlator.stop()