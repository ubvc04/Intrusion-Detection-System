#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDS Manager Module

This module implements the central manager for the Intrusion Detection System,
which receives events from HIDS and NIDS components, stores them in a database,
and provides an API for the web interface.
"""

import os
import sys
import json
import time
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Import utility modules
from utils.logger import get_component_logger
from utils.helpers import get_timestamp

# Import manager components
from manager.api import start_api_server
from manager.correlation import EventCorrelator
from manager.database import DatabaseManager

class IDSManager:
    """
    Central manager for the Intrusion Detection System.
    
    This class coordinates the different components of the IDS manager,
    including the database, API server, and event correlation engine.
    """
    
    def __init__(self, config):
        """
        Initialize the IDS Manager.
        
        Args:
            config: Configuration object containing manager settings
        """
        # Initialize logger
        self.logger = get_component_logger('manager', config)
        self.logger.info("Initializing IDS Manager")
        
        # Store configuration
        self.config = config
        
        # Parse manager-specific configuration
        self.host = config['Manager']['host']
        self.port = int(config['Manager']['port'])
        self.db_path = project_root / config['Manager']['database_path']
        self.correlation_enabled = config['Manager'].getboolean('correlation_enabled', fallback=True)
        self.retention_days = int(config['Manager'].get('retention_days', fallback=30))
        
        # Ensure database directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database manager
        self.db_manager = DatabaseManager(str(self.db_path), self.logger)
        
        # Initialize event correlator if enabled
        self.correlator = None
        if self.correlation_enabled:
            self.correlator = EventCorrelator(self.db_manager, self.logger)
        
        # Initialize state
        self.running = False
        self.threads = []
        
        # Initialize event callback
        self._event_callback = self._default_event_callback
    
    def _maintenance_task(self):
        """
        Perform periodic maintenance tasks like database cleanup.
        """
        while self.running:
            try:
                # Perform database cleanup
                cutoff_date = datetime.now() - timedelta(days=self.retention_days)
                cutoff_timestamp = cutoff_date.isoformat()
                
                self.logger.info(f"Performing database cleanup, removing events older than {cutoff_date.strftime('%Y-%m-%d')}")
                deleted_count = self.db_manager.delete_old_events(cutoff_timestamp)
                self.logger.info(f"Deleted {deleted_count} old events from database")
                
                # Sleep for 24 hours before next cleanup
                for _ in range(24 * 60 * 60):
                    if not self.running:
                        break
                    time.sleep(1)
            
            except Exception as e:
                self.logger.error(f"Error in maintenance task: {e}")
                # Sleep for 1 hour before retry on error
                for _ in range(60 * 60):
                    if not self.running:
                        break
                    time.sleep(1)
    
    def start(self):
        """
        Start the IDS Manager and all components.
        """
        if self.running:
            self.logger.warning("IDS Manager is already running")
            return
        
        self.logger.info("Starting IDS Manager")
        self.running = True
        
        try:
            # Initialize database
            self.db_manager.initialize_database()
            
            # Start API server in a separate thread
            self.logger.info(f"Starting API server on {self.host}:{self.port}")
            api_thread = threading.Thread(
                target=start_api_server,
                args=(self.host, self.port, self.db_manager, self.correlator, self.logger),
                daemon=True
            )
            api_thread.start()
            self.threads.append(api_thread)
            
            # Start maintenance task in a separate thread
            self.logger.info("Starting maintenance task")
            maintenance_thread = threading.Thread(
                target=self._maintenance_task,
                daemon=True
            )
            maintenance_thread.start()
            self.threads.append(maintenance_thread)
            
            # Start event correlator if enabled
            if self.correlation_enabled and self.correlator:
                self.logger.info("Starting event correlation engine")
                correlation_thread = threading.Thread(
                    target=self.correlator.start,
                    daemon=True
                )
                correlation_thread.start()
                self.threads.append(correlation_thread)
            
            # Keep the main thread alive
            self.logger.info(f"IDS Manager started on {self.host}:{self.port}")
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.stop()
        except Exception as e:
            self.logger.error(f"Error in IDS Manager: {e}")
            self.stop()
    
    def stop(self):
        """
        Stop the IDS Manager and all components.
        """
        if not self.running:
            return
        
        self.logger.info("Stopping IDS Manager")
        self.running = False
        
        # Stop event correlator if enabled
        if self.correlation_enabled and self.correlator:
            self.correlator.stop()
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Close database connection
        self.db_manager.close()
        
        self.logger.info("IDS Manager stopped")
        
    def _default_event_callback(self, event):
        """
        Default event callback function that logs events.
        
        Args:
            event (dict): Event data
        """
        self.logger.info(f"Received event: {event.get('event_type')} - {event.get('description')}")
        
        # Store event in database
        try:
            self.db_manager.add_event(event)
        except Exception as e:
            self.logger.error(f"Error storing event in database: {e}")
        
        # Process event with correlator if enabled
        if self.correlation_enabled and self.correlator:
            self.correlator.process_event(event)

# For testing purposes
if __name__ == "__main__":
    import configparser
    
    # Load configuration
    config = configparser.ConfigParser()
    config_path = project_root / 'config' / 'config.ini'
    
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    config.read(config_path)
    
    # Create and start IDS manager
    manager = IDSManager(config)
    manager.start()