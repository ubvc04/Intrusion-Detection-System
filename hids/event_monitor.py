#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Event Log Monitor Module

This module implements Windows Event Log monitoring for the HIDS agent.
It uses the pywin32 library to access Windows Event Logs and detect security events.
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Import Windows-specific modules
try:
    import win32evtlog
    import win32con
    import win32evtlogutil
    import winerror
except ImportError as e:
    raise ImportError(f"Required Windows modules not available: {e}. Please install pywin32.")

class EventLogMonitor:
    """
    Windows Event Log Monitor for HIDS.
    
    This class monitors Windows Event Logs for security events such as failed logons,
    process creation, and privilege escalations.
    """
    
    def __init__(self, event_logs, rules, logger):
        """
        Initialize the Event Log Monitor.
        
        Args:
            event_logs (list): List of event logs to monitor (e.g., ['Security', 'System'])
            rules (list): List of detection rules
            logger: Logger instance
        """
        self.event_logs = event_logs
        self.rules = rules
        self.logger = logger
        
        # Initialize state
        self.running = False
        self.handles = {}
        self.last_read_time = {}
        self.lock = threading.Lock()
        
        # Event tracking for threshold-based rules
        self.event_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Map event IDs to rule IDs for quick lookup
        self.event_id_map = self._build_event_id_map()
        
        self.logger.info(f"Event Log Monitor initialized for logs: {', '.join(event_logs)}")
    
    def _build_event_id_map(self):
        """
        Build a mapping of event IDs to rule IDs for quick lookup.
        
        Returns:
            dict: Mapping of event IDs to lists of rule indices
        """
        event_id_map = defaultdict(list)
        
        for i, rule in enumerate(self.rules):
            if 'event_id' in rule:
                event_id_map[rule['event_id']].append(i)
        
        return event_id_map
    
    def _open_event_logs(self):
        """
        Open handles to the specified event logs.
        
        Returns:
            bool: True if all logs were opened successfully, False otherwise
        """
        success = True
        
        for log_name in self.event_logs:
            try:
                # Open the event log
                handle = win32evtlog.OpenEventLog(None, log_name)
                
                # Store the handle and the last read time
                self.handles[log_name] = handle
                self.last_read_time[log_name] = datetime.now()
                
                self.logger.debug(f"Opened event log: {log_name}")
            except Exception as e:
                self.logger.error(f"Failed to open event log {log_name}: {e}")
                success = False
        
        return success
    
    def _close_event_logs(self):
        """
        Close handles to all open event logs.
        """
        for log_name, handle in self.handles.items():
            try:
                win32evtlog.CloseEventLog(handle)
                self.logger.debug(f"Closed event log: {log_name}")
            except Exception as e:
                self.logger.error(f"Error closing event log {log_name}: {e}")
    
    def _process_event(self, event, log_name):
        """
        Process a Windows Event Log event and check against detection rules.
        
        Args:
            event: Windows Event Log event object
            log_name (str): Name of the event log
            
        Returns:
            tuple: (matched_rule, event_data) if a rule matched, (None, None) otherwise
        """
        try:
            # Extract event data
            event_id = event.EventID
            event_time = event.TimeGenerated
            event_source = event.SourceName
            event_data = self._extract_event_data(event)
            
            # Add to event history for threshold-based rules
            event_key = f"{log_name}_{event_id}"
            with self.lock:
                self.event_history[event_key].append((event_time, event_data))
            
            # Check if this event ID is in our rule map
            if event_id in self.event_id_map:
                # Check each rule that matches this event ID
                for rule_idx in self.event_id_map[event_id]:
                    rule = self.rules[rule_idx]
                    
                    # Skip if log name doesn't match
                    if 'log_name' in rule and rule['log_name'] != log_name:
                        continue
                    
                    # Check for threshold-based rules
                    if 'threshold' in rule and 'time_window' in rule:
                        if self._check_threshold_rule(rule, event_key):
                            return rule, event_data
                    
                    # Check for process creation rules
                    elif event_id == 4688 and 'process_names' in rule:
                        if self._check_process_rule(rule, event_data):
                            return rule, event_data
                    
                    # Default case: event ID match is sufficient
                    else:
                        return rule, event_data
            
            return None, None
        
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
            return None, None
    
    def _extract_event_data(self, event):
        """
        Extract relevant data from a Windows Event Log event.
        
        Args:
            event: Windows Event Log event object
            
        Returns:
            dict: Extracted event data
        """
        data = {
            'event_id': event.EventID,
            'time_generated': event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
            'source_name': event.SourceName,
            'event_type': event.EventType,
            'event_category': event.EventCategory,
            'record_number': event.RecordNumber,
        }
        
        # Extract event-specific data
        try:
            # Convert the event data to a string
            event_data_str = win32evtlogutil.SafeFormatMessage(event, event.StringInserts)
            data['description'] = event_data_str
            
            # Extract specific fields based on event ID
            if event.EventID == 4625:  # Failed logon
                data.update(self._parse_failed_logon(event_data_str))
            elif event.EventID == 4688:  # Process creation
                data.update(self._parse_process_creation(event_data_str))
            elif event.EventID == 4672:  # Special privileges assigned
                data.update(self._parse_privilege_assignment(event_data_str))
        
        except Exception as e:
            self.logger.error(f"Error extracting event data: {e}")
        
        return data
    
    def _parse_failed_logon(self, event_data_str):
        """
        Parse failed logon event data (Event ID 4625).
        
        Args:
            event_data_str (str): Event data string
            
        Returns:
            dict: Parsed event data
        """
        data = {}
        
        try:
            # Extract username
            if "Account Name:" in event_data_str:
                lines = event_data_str.split('\n')
                for i, line in enumerate(lines):
                    if "Account Name:" in line and i < len(lines) - 1:
                        data['username'] = lines[i+1].strip()
                        break
            
            # Extract source IP
            if "Source Network Address:" in event_data_str:
                start = event_data_str.find("Source Network Address:") + len("Source Network Address:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                data['source_ip'] = event_data_str[start:end].strip()
            
            # Extract failure reason
            if "Failure Reason:" in event_data_str:
                start = event_data_str.find("Failure Reason:") + len("Failure Reason:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                data['failure_reason'] = event_data_str[start:end].strip()
        
        except Exception as e:
            self.logger.error(f"Error parsing failed logon event: {e}")
        
        return data
    
    def _parse_process_creation(self, event_data_str):
        """
        Parse process creation event data (Event ID 4688).
        
        Args:
            event_data_str (str): Event data string
            
        Returns:
            dict: Parsed event data
        """
        data = {}
        
        try:
            # Extract process name
            if "New Process Name:" in event_data_str:
                start = event_data_str.find("New Process Name:") + len("New Process Name:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                process_path = event_data_str[start:end].strip()
                data['process_path'] = process_path
                data['process_name'] = process_path.split('\\')[-1]
            
            # Extract command line (if available)
            if "Process Command Line:" in event_data_str:
                start = event_data_str.find("Process Command Line:") + len("Process Command Line:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                data['command_line'] = event_data_str[start:end].strip()
            
            # Extract creator user
            if "Account Name:" in event_data_str:
                start = event_data_str.find("Account Name:") + len("Account Name:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                data['user'] = event_data_str[start:end].strip()
        
        except Exception as e:
            self.logger.error(f"Error parsing process creation event: {e}")
        
        return data
    
    def _parse_privilege_assignment(self, event_data_str):
        """
        Parse special privilege assignment event data (Event ID 4672).
        
        Args:
            event_data_str (str): Event data string
            
        Returns:
            dict: Parsed event data
        """
        data = {}
        
        try:
            # Extract account name
            if "Account Name:" in event_data_str:
                start = event_data_str.find("Account Name:") + len("Account Name:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                data['username'] = event_data_str[start:end].strip()
            
            # Extract privileges
            if "Privileges:" in event_data_str:
                start = event_data_str.find("Privileges:") + len("Privileges:")
                end = event_data_str.find("\n", start)
                if end == -1:  # If no newline found
                    end = len(event_data_str)
                data['privileges'] = event_data_str[start:end].strip()
        
        except Exception as e:
            self.logger.error(f"Error parsing privilege assignment event: {e}")
        
        return data
    
    def _check_threshold_rule(self, rule, event_key):
        """
        Check if a threshold-based rule has been triggered.
        
        Args:
            rule (dict): Detection rule
            event_key (str): Event key for history lookup
            
        Returns:
            bool: True if the rule was triggered, False otherwise
        """
        threshold = rule['threshold']
        time_window = rule['time_window']  # in seconds
        
        with self.lock:
            # Get events in the time window
            now = datetime.now()
            cutoff_time = now - timedelta(seconds=time_window)
            
            # Count events in the time window
            count = sum(1 for event_time, _ in self.event_history[event_key] 
                      if event_time >= cutoff_time)
            
            return count >= threshold
    
    def _check_process_rule(self, rule, event_data):
        """
        Check if a process creation rule has been triggered.
        
        Args:
            rule (dict): Detection rule
            event_data (dict): Event data
            
        Returns:
            bool: True if the rule was triggered, False otherwise
        """
        # Check if process name is in the list of suspicious processes
        if 'process_name' in event_data and 'process_names' in rule:
            process_name = event_data['process_name'].lower()
            if any(p.lower() == process_name for p in rule['process_names']):
                # If command line contains any suspicious strings
                if 'command_line' in event_data and 'command_line_contains' in rule:
                    command_line = event_data['command_line'].lower()
                    return any(s.lower() in command_line for s in rule['command_line_contains'])
                return True
        
        return False
    
    def start_monitoring(self, callback):
        """
        Start monitoring Windows Event Logs.
        
        Args:
            callback: Callback function to call when an event is detected
        """
        if self.running:
            self.logger.warning("Event Log Monitor is already running")
            return
        
        self.running = True
        self.logger.info("Starting Event Log Monitor")
        
        # Open event logs
        if not self._open_event_logs():
            self.logger.error("Failed to open one or more event logs")
            self.running = False
            return
        
        try:
            # Main monitoring loop
            while self.running:
                for log_name, handle in self.handles.items():
                    try:
                        # Read new events
                        events = win32evtlog.ReadEventLog(
                            handle,
                            win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                            0
                        )
                        
                        # Process each event
                        for event in events:
                            # Check if the event matches any rules
                            matched_rule, event_data = self._process_event(event, log_name)
                            
                            if matched_rule:
                                # Call the callback with the event data
                                self.logger.debug(f"Rule matched: {matched_rule['id']} - {matched_rule['name']}")
                                
                                # Add rule information to event data
                                event_data['rule_id'] = matched_rule['id']
                                event_data['rule_name'] = matched_rule['name']
                                event_data['rule_description'] = matched_rule['description']
                                
                                # Call the callback
                                callback(
                                    "event_log",
                                    event_data,
                                    matched_rule.get('severity', 'medium')
                                )
                    
                    except win32evtlog.error as e:
                        if e.winerror == winerror.ERROR_HANDLE_EOF:
                            # No more events, wait and try again
                            pass
                        else:
                            self.logger.error(f"Error reading event log {log_name}: {e}")
                    
                    except Exception as e:
                        self.logger.error(f"Unexpected error monitoring event log {log_name}: {e}")
                
                # Sleep before checking for new events
                time.sleep(1)
        
        finally:
            # Clean up
            self._close_event_logs()
            self.running = False
            self.logger.info("Event Log Monitor stopped")
    
    def stop_monitoring(self):
        """
        Stop monitoring Windows Event Logs.
        """
        self.logger.info("Stopping Event Log Monitor")
        self.running = False