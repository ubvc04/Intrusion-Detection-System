#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File Integrity Monitor Module

This module implements file integrity monitoring for the HIDS agent.
It tracks changes to critical system files and directories by calculating
and comparing file hashes.
"""

import os
import time
import threading
from pathlib import Path
from datetime import datetime

# Import utility modules
sys_path = str(Path(__file__).resolve().parent.parent)
import sys
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)

from utils.helpers import calculate_file_hash

class FileIntegrityMonitor:
    """
    File Integrity Monitor for HIDS.
    
    This class monitors specified files and directories for changes by calculating
    and comparing file hashes at regular intervals.
    """
    
    def __init__(self, monitored_paths, hash_algorithm='sha256', scan_interval=300, logger=None):
        """
        Initialize the File Integrity Monitor.
        
        Args:
            monitored_paths (list): List of file and directory paths to monitor
            hash_algorithm (str): Hash algorithm to use (default: sha256)
            scan_interval (int): Interval between scans in seconds (default: 300)
            logger: Logger instance
        """
        self.monitored_paths = monitored_paths
        self.hash_algorithm = hash_algorithm
        self.scan_interval = scan_interval
        self.logger = logger
        
        # Initialize state
        self.running = False
        self.baseline = {}
        self.lock = threading.Lock()
        
        self.logger.info(f"File Integrity Monitor initialized with {len(monitored_paths)} paths")
        self.logger.debug(f"Monitored paths: {', '.join(monitored_paths)}")
    
    def _scan_directory(self, directory):
        """
        Recursively scan a directory and calculate hashes for all files.
        
        Args:
            directory (str): Directory path to scan
            
        Returns:
            dict: Mapping of file paths to hash values
        """
        file_hashes = {}
        
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_hash = calculate_file_hash(file_path, self.hash_algorithm)
                        file_hashes[file_path] = {
                            'hash': file_hash,
                            'size': os.path.getsize(file_path),
                            'last_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                        }
                    except (FileNotFoundError, PermissionError) as e:
                        # Skip files that can't be accessed
                        self.logger.debug(f"Skipping file {file_path}: {e}")
                    except Exception as e:
                        self.logger.error(f"Error calculating hash for {file_path}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
        
        return file_hashes
    
    def _build_baseline(self):
        """
        Build a baseline of file hashes for all monitored paths.
        
        Returns:
            dict: Mapping of file paths to hash values
        """
        baseline = {}
        
        for path in self.monitored_paths:
            try:
                if os.path.isdir(path):
                    # Scan directory recursively
                    dir_hashes = self._scan_directory(path)
                    baseline.update(dir_hashes)
                elif os.path.isfile(path):
                    # Calculate hash for a single file
                    file_hash = calculate_file_hash(path, self.hash_algorithm)
                    baseline[path] = {
                        'hash': file_hash,
                        'size': os.path.getsize(path),
                        'last_modified': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                    }
                else:
                    self.logger.warning(f"Monitored path does not exist: {path}")
            
            except Exception as e:
                self.logger.error(f"Error building baseline for {path}: {e}")
        
        self.logger.info(f"Built baseline with {len(baseline)} files")
        return baseline
    
    def _compare_with_baseline(self, current):
        """
        Compare current file hashes with the baseline to detect changes.
        
        Args:
            current (dict): Current file hashes
            
        Returns:
            dict: Dictionary of changes categorized by type (modified, added, deleted)
        """
        changes = {
            'modified': [],
            'added': [],
            'deleted': []
        }
        
        # Check for modified and added files
        for file_path, file_info in current.items():
            if file_path in self.baseline:
                # File exists in baseline, check if modified
                if file_info['hash'] != self.baseline[file_path]['hash']:
                    changes['modified'].append({
                        'path': file_path,
                        'old_hash': self.baseline[file_path]['hash'],
                        'new_hash': file_info['hash'],
                        'old_size': self.baseline[file_path]['size'],
                        'new_size': file_info['size'],
                        'old_last_modified': self.baseline[file_path]['last_modified'],
                        'new_last_modified': file_info['last_modified']
                    })
            else:
                # File doesn't exist in baseline, it's new
                changes['added'].append({
                    'path': file_path,
                    'hash': file_info['hash'],
                    'size': file_info['size'],
                    'last_modified': file_info['last_modified']
                })
        
        # Check for deleted files
        for file_path in self.baseline:
            if file_path not in current:
                changes['deleted'].append({
                    'path': file_path,
                    'hash': self.baseline[file_path]['hash'],
                    'size': self.baseline[file_path]['size'],
                    'last_modified': self.baseline[file_path]['last_modified']
                })
        
        return changes
    
    def start_monitoring(self, callback):
        """
        Start monitoring files for changes.
        
        Args:
            callback: Callback function to call when changes are detected
        """
        if self.running:
            self.logger.warning("File Integrity Monitor is already running")
            return
        
        self.running = True
        self.logger.info("Starting File Integrity Monitor")
        
        try:
            # Build initial baseline
            with self.lock:
                self.baseline = self._build_baseline()
            
            # Main monitoring loop
            while self.running:
                # Sleep for the scan interval
                time.sleep(self.scan_interval)
                
                if not self.running:
                    break
                
                self.logger.debug("Scanning for file changes")
                
                # Build current snapshot
                current = self._build_baseline()
                
                # Compare with baseline
                with self.lock:
                    changes = self._compare_with_baseline(current)
                
                # Process changes
                total_changes = sum(len(changes[change_type]) for change_type in changes)
                
                if total_changes > 0:
                    self.logger.info(f"Detected {total_changes} file changes")
                    
                    # Log details of changes
                    for change_type, items in changes.items():
                        for item in items:
                            self.logger.debug(f"{change_type.capitalize()} file: {item['path']}")
                            
                            # Call the callback for each change
                            callback(
                                "file_integrity",
                                {
                                    'change_type': change_type,
                                    'file_path': item['path'],
                                    'details': item
                                },
                                "high" if change_type in ['modified', 'deleted'] else "medium"
                            )
                
                # Update baseline with current snapshot
                with self.lock:
                    self.baseline = current
        
        except Exception as e:
            self.logger.error(f"Error in File Integrity Monitor: {e}")
        
        finally:
            self.running = False
            self.logger.info("File Integrity Monitor stopped")
    
    def stop_monitoring(self):
        """
        Stop monitoring files for changes.
        """
        self.logger.info("Stopping File Integrity Monitor")
        self.running = False