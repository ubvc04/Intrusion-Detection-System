#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Registry Monitor Module

This module implements Windows Registry monitoring for the HIDS agent.
It detects changes to registry keys that are commonly used for persistence
and other malicious activities.
"""

import time
import threading
from datetime import datetime

# Import Windows-specific modules
try:
    import winreg
    import win32api
    import win32con
    import win32event
    import win32security
except ImportError as e:
    raise ImportError(f"Required Windows modules not available: {e}. Please install pywin32.")

class RegistryMonitor:
    """
    Windows Registry Monitor for HIDS.
    
    This class monitors specified registry keys for changes that might indicate
    persistence mechanisms or other suspicious activities.
    """
    
    def __init__(self, rules, logger):
        """
        Initialize the Registry Monitor.
        
        Args:
            rules (list): List of detection rules
            logger: Logger instance
        """
        self.rules = rules
        self.logger = logger
        
        # Initialize state
        self.running = False
        self.baseline = {}
        self.lock = threading.Lock()
        
        # Extract registry keys to monitor from rules
        self.monitored_keys = self._extract_registry_keys()
        
        self.logger.info(f"Registry Monitor initialized with {len(self.monitored_keys)} keys")
        self.logger.debug(f"Monitored registry keys: {', '.join(self.monitored_keys)}")
    
    def _extract_registry_keys(self):
        """
        Extract registry keys to monitor from the rules.
        
        Returns:
            list: List of registry keys to monitor
        """
        keys = []
        
        for rule in self.rules:
            if 'registry_keys' in rule:
                keys.extend(rule['registry_keys'])
        
        # Add default keys if none specified in rules
        if not keys:
            keys = [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
            ]
        
        return list(set(keys))  # Remove duplicates
    
    def _parse_registry_key(self, key_path):
        """
        Parse a registry key path into its components.
        
        Args:
            key_path (str): Registry key path (e.g., "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            
        Returns:
            tuple: (root_key, sub_key) where root_key is a winreg constant
        """
        parts = key_path.split('\\', 1)
        root_name = parts[0].upper()
        sub_key = parts[1] if len(parts) > 1 else ""
        
        root_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
            "HKCC": winreg.HKEY_CURRENT_CONFIG
        }
        
        if root_name not in root_map:
            raise ValueError(f"Invalid registry root key: {root_name}")
        
        return root_map[root_name], sub_key
    
    def _read_registry_key(self, key_path):
        """
        Read all values from a registry key.
        
        Args:
            key_path (str): Registry key path
            
        Returns:
            dict: Mapping of value names to their data
        """
        values = {}
        
        try:
            root_key, sub_key = self._parse_registry_key(key_path)
            
            with winreg.OpenKey(root_key, sub_key, 0, winreg.KEY_READ) as key:
                # Get the number of values in the key
                num_values = winreg.QueryInfoKey(key)[1]
                
                # Read each value
                for i in range(num_values):
                    name, data, type_id = winreg.EnumValue(key, i)
                    
                    # Convert data to string for consistent comparison
                    if type_id == winreg.REG_SZ or type_id == winreg.REG_EXPAND_SZ:
                        str_data = data
                    elif type_id == winreg.REG_MULTI_SZ:
                        str_data = ", ".join(data)
                    elif type_id == winreg.REG_DWORD or type_id == winreg.REG_QWORD:
                        str_data = str(data)
                    elif type_id == winreg.REG_BINARY:
                        str_data = data.hex()
                    else:
                        str_data = str(data)
                    
                    values[name] = {
                        'data': str_data,
                        'type': type_id
                    }
        
        except FileNotFoundError:
            # Key doesn't exist, return empty dict
            pass
        except PermissionError as e:
            self.logger.warning(f"Permission denied accessing registry key {key_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error reading registry key {key_path}: {e}")
        
        return values
    
    def _build_baseline(self):
        """
        Build a baseline of registry values for all monitored keys.
        
        Returns:
            dict: Mapping of registry keys to their values
        """
        baseline = {}
        
        for key_path in self.monitored_keys:
            try:
                values = self._read_registry_key(key_path)
                baseline[key_path] = values
            except Exception as e:
                self.logger.error(f"Error building baseline for registry key {key_path}: {e}")
        
        self.logger.info(f"Built registry baseline with {len(baseline)} keys")
        return baseline
    
    def _compare_with_baseline(self, current):
        """
        Compare current registry values with the baseline to detect changes.
        
        Args:
            current (dict): Current registry values
            
        Returns:
            dict: Dictionary of changes categorized by type (modified, added, deleted)
        """
        changes = {
            'modified': [],
            'added': [],
            'deleted': []
        }
        
        # Check each key in the baseline
        for key_path, baseline_values in self.baseline.items():
            if key_path in current:
                current_values = current[key_path]
                
                # Check for modified and deleted values
                for value_name, baseline_value in baseline_values.items():
                    if value_name in current_values:
                        # Value exists in both, check if modified
                        if current_values[value_name]['data'] != baseline_value['data']:
                            changes['modified'].append({
                                'key_path': key_path,
                                'value_name': value_name,
                                'old_data': baseline_value['data'],
                                'new_data': current_values[value_name]['data'],
                                'type': current_values[value_name]['type']
                            })
                    else:
                        # Value exists in baseline but not in current, it's deleted
                        changes['deleted'].append({
                            'key_path': key_path,
                            'value_name': value_name,
                            'data': baseline_value['data'],
                            'type': baseline_value['type']
                        })
                
                # Check for added values
                for value_name, current_value in current_values.items():
                    if value_name not in baseline_values:
                        # Value exists in current but not in baseline, it's new
                        changes['added'].append({
                            'key_path': key_path,
                            'value_name': value_name,
                            'data': current_value['data'],
                            'type': current_value['type']
                        })
            else:
                # Key exists in baseline but not in current, it's deleted
                # This is unlikely to happen unless the key was deleted
                self.logger.warning(f"Registry key {key_path} no longer exists")
        
        # Check for new keys in current that weren't in baseline
        for key_path, current_values in current.items():
            if key_path not in self.baseline:
                # Key exists in current but not in baseline, it's new
                for value_name, current_value in current_values.items():
                    changes['added'].append({
                        'key_path': key_path,
                        'value_name': value_name,
                        'data': current_value['data'],
                        'type': current_value['type']
                    })
        
        return changes
    
    def _find_matching_rule(self, change):
        """
        Find a rule that matches the registry change.
        
        Args:
            change (dict): Registry change information
            
        Returns:
            dict: Matching rule or None if no match
        """
        key_path = change['key_path']
        
        for rule in self.rules:
            if 'registry_keys' in rule and key_path in rule['registry_keys']:
                return rule
        
        return None
    
    def start_monitoring(self, callback):
        """
        Start monitoring registry keys for changes.
        
        Args:
            callback: Callback function to call when changes are detected
        """
        if self.running:
            self.logger.warning("Registry Monitor is already running")
            return
        
        self.running = True
        self.logger.info("Starting Registry Monitor")
        
        try:
            # Build initial baseline
            with self.lock:
                self.baseline = self._build_baseline()
            
            # Main monitoring loop
            while self.running:
                # Sleep for a short interval
                time.sleep(5)
                
                if not self.running:
                    break
                
                # Build current snapshot
                current = self._build_baseline()
                
                # Compare with baseline
                with self.lock:
                    changes = self._compare_with_baseline(current)
                
                # Process changes
                total_changes = sum(len(changes[change_type]) for change_type in changes)
                
                if total_changes > 0:
                    self.logger.info(f"Detected {total_changes} registry changes")
                    
                    # Process each change
                    for change_type, items in changes.items():
                        for item in items:
                            # Find matching rule
                            rule = self._find_matching_rule(item)
                            severity = "medium"
                            
                            if rule:
                                severity = rule.get('severity', 'medium')
                                item['rule_id'] = rule['id']
                                item['rule_name'] = rule['name']
                                item['rule_description'] = rule['description']
                            
                            # Log the change
                            self.logger.debug(f"{change_type.capitalize()} registry value: {item['key_path']}\\{item['value_name']}")
                            
                            # Call the callback
                            callback(
                                "registry",
                                {
                                    'change_type': change_type,
                                    'key_path': item['key_path'],
                                    'value_name': item['value_name'],
                                    'details': item
                                },
                                severity
                            )
                
                # Update baseline with current snapshot
                with self.lock:
                    self.baseline = current
        
        except Exception as e:
            self.logger.error(f"Error in Registry Monitor: {e}")
        
        finally:
            self.running = False
            self.logger.info("Registry Monitor stopped")
    
    def stop_monitoring(self):
        """
        Stop monitoring registry keys for changes.
        """
        self.logger.info("Stopping Registry Monitor")
        self.running = False