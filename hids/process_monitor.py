#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Process Monitor Module

This module implements process monitoring for the Host-based Intrusion Detection System (HIDS).
It detects suspicious process activities, unauthorized process executions, and potential malicious processes.
"""

import os
import time
import json
import psutil
import logging
import threading
from datetime import datetime
from utils.helpers import generate_event_id

class ProcessMonitor:
    """
    Process Activity Monitor
    
    Monitors system processes for suspicious activities, unauthorized executions,
    and potential malicious processes.
    """
    
    def __init__(self, config, callback=None):
        """
        Initialize the process monitor.
        
        Args:
            config: Configuration object containing process monitoring settings
            callback: Callback function for sending events
        """
        self.config = config
        self.callback = callback
        self.logger = logging.getLogger('ids.hids.process')
        self.running = False
        self.monitor_thread = None
        self.scan_interval = int(config.get('HIDS', 'process_scan_interval', fallback=30))
        self.suspicious_processes = []
        self.baseline_processes = {}
        self.load_suspicious_processes()
        
    def load_suspicious_processes(self):
        """
        Load suspicious process patterns from HIDS rules.
        """
        try:
            with open(self.config.get('HIDS', 'rules_file'), 'r') as f:
                rules = json.loads(f.read())
                
            process_rules = [rule for rule in rules if rule.get('type') == 'process']
            
            for rule in process_rules:
                process_name = rule.get('process_name')
                if process_name:
                    self.suspicious_processes.append({
                        'name': process_name,
                        'rule_name': rule.get('name', 'Suspicious Process'),
                        'severity': rule.get('severity', 'medium'),
                        'description': rule.get('description', 'Suspicious process detected')
                    })
                    
            self.logger.info(f"Loaded {len(self.suspicious_processes)} suspicious process patterns")
        except Exception as e:
            self.logger.error(f"Failed to load process rules: {str(e)}")
            
    def start(self):
        """
        Start the process monitor.
        """
        if self.running:
            return
            
        self.running = True
        self.build_process_baseline()
        self.monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Process monitor started")
        
    def stop(self):
        """
        Stop the process monitor.
        """
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Process monitor stopped")
        
    def build_process_baseline(self):
        """
        Build a baseline of running processes.
        """
        self.baseline_processes = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    proc_info = proc.info
                    self.baseline_processes[proc.pid] = {
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'cmdline': proc_info['cmdline'],
                        'username': proc_info['username']
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
            self.logger.info(f"Built process baseline with {len(self.baseline_processes)} processes")
        except Exception as e:
            self.logger.error(f"Failed to build process baseline: {str(e)}")
            
    def _monitor_processes(self):
        """
        Monitor processes for suspicious activities.
        """
        while self.running:
            try:
                current_processes = {}
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                    try:
                        proc_info = proc.info
                        current_processes[proc.pid] = {
                            'name': proc_info['name'],
                            'exe': proc_info['exe'],
                            'cmdline': proc_info['cmdline'],
                            'username': proc_info['username'],
                            'create_time': proc_info['create_time']
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
                        
                # Check for new processes
                for pid, proc_info in current_processes.items():
                    if pid not in self.baseline_processes:
                        # New process detected
                        self._check_suspicious_process(pid, proc_info)
                        
                # Update baseline
                self.baseline_processes = current_processes
                
                # Sleep for the scan interval
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error monitoring processes: {str(e)}")
                time.sleep(self.scan_interval)
                
    def _check_suspicious_process(self, pid, proc_info):
        """
        Check if a process is suspicious.
        
        Args:
            pid: Process ID
            proc_info: Process information
        """
        process_name = proc_info['name'].lower() if proc_info['name'] else ''
        process_exe = proc_info['exe'] if proc_info['exe'] else ''
        process_cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
        
        for suspicious in self.suspicious_processes:
            suspicious_name = suspicious['name'].lower()
            if (suspicious_name in process_name or 
                suspicious_name in process_exe.lower() or 
                suspicious_name in process_cmdline.lower()):
                self._generate_alert(pid, proc_info, suspicious)
                return
                
    def _generate_alert(self, pid, proc_info, suspicious):
        """
        Generate an alert for a suspicious process.
        
        Args:
            pid: Process ID
            proc_info: Process information
            suspicious: Suspicious process information
        """
        if not self.callback:
            return
            
        # Create event
        event = {
            'id': generate_event_id(),
            'timestamp': datetime.now().isoformat(),
            'source': 'hids',
            'type': 'suspicious_process',
            'severity': suspicious['severity'],
            'host': os.environ.get('COMPUTERNAME', 'unknown'),
            'details': {
                'name': suspicious['rule_name'],
                'description': suspicious['description'],
                'pid': pid,
                'process_name': proc_info['name'],
                'process_path': proc_info['exe'],
                'command_line': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                'username': proc_info['username'],
                'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else ''
            }
        }
        
        # Send event
        self.callback(event)
        self.logger.warning(f"Suspicious process detected: {proc_info['name']} (PID: {pid}) - {suspicious['rule_name']}")