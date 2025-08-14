#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Manager Module

This module handles database operations for the IDS Manager,
including storing events, retrieving events, and managing the database schema.
"""

import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path

class DatabaseManager:
    """
    Manages database operations for the IDS Manager.
    """
    
    def __init__(self, db_path, logger=None):
        """
        Initialize the database manager.
        
        Args:
            db_path (str): Path to the SQLite database file
            logger: Logger instance
        """
        self.db_path = db_path
        self.logger = logger
        self.conn = None
        self.cursor = None
    
    def _connect(self):
        """
        Connect to the SQLite database.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Ensure directory exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir)
            
            # Connect to database
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON")
            
            # Configure connection
            self.conn.row_factory = sqlite3.Row
            
            # Don't create a persistent cursor here to avoid recursive cursor issues
            # Each method should create its own cursor when needed
            self.cursor = None
            
            if self.logger:
                self.logger.debug(f"Connected to database: {self.db_path}")
            
            return True
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Database connection error: {e}")
            return False
    
    def initialize_database(self):
        """
        Initialize the database schema if it doesn't exist.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        if not self._connect():
            return False
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Create events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT NOT NULL,
                    acknowledged INTEGER DEFAULT 0,
                    correlated_with INTEGER DEFAULT NULL,
                    FOREIGN KEY (correlated_with) REFERENCES events(id) ON DELETE SET NULL
                )
            """)
            
            # Create index on timestamp for faster queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
            """)
            
            # Create index on source for faster filtering
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)
            """)
            
            # Create index on type for faster filtering
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)
            """)
            
            # Create index on severity for faster filtering
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)
            """)
            
            # Create index on acknowledged for faster filtering
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_acknowledged ON events(acknowledged)
            """)
            
            # Create hosts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL UNIQUE,
                    ip_address TEXT,
                    last_seen TEXT NOT NULL,
                    os_info TEXT,
                    status TEXT DEFAULT 'active'
                )
            """)
            
            # Create rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    description TEXT,
                    source TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Create correlation_rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS correlation_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    conditions TEXT NOT NULL,
                    timeframe INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                self.logger.info("Database initialized successfully")
            
            return True
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Database initialization error: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return False
    
    def store_event(self, event):
        """
        Store an event in the database.
        
        Args:
            event (dict): Event data to store
            
        Returns:
            int: ID of the stored event, or -1 if failed
        """
        if not self.conn:
            if not self._connect():
                return -1
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Extract event data
            timestamp = event.get('timestamp', datetime.now().isoformat())
            source = event.get('source', 'unknown')
            event_type = event.get('type', 'unknown')
            severity = event.get('severity', 'info')
            details = json.dumps(event.get('details', {}))
            
            # Insert event into database
            cursor.execute("""
                INSERT INTO events (timestamp, source, type, severity, details)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, source, event_type, severity, details))
            
            # Get the ID of the inserted event
            event_id = cursor.lastrowid
            
            # Update host information if available
            if 'hostname' in event:
                hostname = event['hostname']
                ip_address = event.get('ip_address', '')
                os_info = event.get('os_info', '')
                
                # Check if host exists
                cursor.execute("""
                    SELECT id FROM hosts WHERE hostname = ?
                """, (hostname,))
                
                host_exists = cursor.fetchone()
                
                if host_exists:
                    # Update existing host
                    cursor.execute("""
                        UPDATE hosts
                        SET ip_address = CASE WHEN ? != '' THEN ? ELSE ip_address END,
                            last_seen = ?,
                            os_info = CASE WHEN ? != '' THEN ? ELSE os_info END,
                            status = 'active'
                        WHERE hostname = ?
                    """, (ip_address, ip_address, timestamp, os_info, os_info, hostname))
                else:
                    # Insert new host
                    cursor.execute("""
                        INSERT INTO hosts (hostname, ip_address, last_seen, os_info)
                        VALUES (?, ?, ?, ?)
                    """, (hostname, ip_address, timestamp, os_info))
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                self.logger.debug(f"Stored event: {event_type} (ID: {event_id})")
            
            return event_id
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error storing event: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return -1
    
    def get_events(self, filters=None, limit=100, offset=0, order_by="timestamp", order="DESC"):
        """
        Get events from the database with optional filtering.
        
        Args:
            filters (dict): Filters to apply (source, type, severity, start_time, end_time, acknowledged)
            limit (int): Maximum number of events to return
            offset (int): Offset for pagination
            order_by (str): Field to order by
            order (str): Order direction (ASC or DESC)
            
        Returns:
            list: List of events matching the filters
        """
        if not self.conn:
            if not self._connect():
                return []
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Build query
            query = "SELECT * FROM events"
            params = []
            
            # Apply filters
            if filters:
                conditions = []
                
                if 'source' in filters and filters['source']:
                    conditions.append("source = ?")
                    params.append(filters['source'])
                
                if 'type' in filters and filters['type']:
                    conditions.append("type = ?")
                    params.append(filters['type'])
                
                if 'severity' in filters and filters['severity']:
                    conditions.append("severity = ?")
                    params.append(filters['severity'])
                
                if 'start_time' in filters and filters['start_time']:
                    conditions.append("timestamp >= ?")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters and filters['end_time']:
                    conditions.append("timestamp <= ?")
                    params.append(filters['end_time'])
                
                if 'acknowledged' in filters:
                    conditions.append("acknowledged = ?")
                    params.append(1 if filters['acknowledged'] else 0)
                
                if 'search' in filters and filters['search']:
                    conditions.append("(details LIKE ? OR type LIKE ? OR source LIKE ?)")
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term, search_term])
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
            
            # Add order by clause
            valid_order_fields = ["timestamp", "source", "type", "severity", "id"]
            if order_by not in valid_order_fields:
                order_by = "timestamp"
            
            valid_order_directions = ["ASC", "DESC"]
            if order.upper() not in valid_order_directions:
                order = "DESC"
            
            query += f" ORDER BY {order_by} {order}"
            
            # Add limit and offset
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            # Execute query
            cursor.execute(query, params)
            
            # Fetch results
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            events = []
            for row in rows:
                event = dict(row)
                
                # Parse JSON details
                try:
                    event['details'] = json.loads(event['details'])
                except json.JSONDecodeError:
                    event['details'] = {}
                
                events.append(event)
            
            return events
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting events: {e}")
            return []
    
    def get_event_count(self, filters=None):
        """
        Get the count of events matching the filters.
        
        Args:
            filters (dict): Filters to apply
            
        Returns:
            int: Count of matching events
        """
        if not self.conn:
            if not self._connect():
                return 0
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Build query
            query = "SELECT COUNT(*) FROM events"
            params = []
            
            # Apply filters
            if filters:
                conditions = []
                
                if 'source' in filters and filters['source']:
                    conditions.append("source = ?")
                    params.append(filters['source'])
                
                if 'type' in filters and filters['type']:
                    conditions.append("type = ?")
                    params.append(filters['type'])
                
                if 'severity' in filters and filters['severity']:
                    conditions.append("severity = ?")
                    params.append(filters['severity'])
                
                if 'start_time' in filters and filters['start_time']:
                    conditions.append("timestamp >= ?")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters and filters['end_time']:
                    conditions.append("timestamp <= ?")
                    params.append(filters['end_time'])
                
                if 'acknowledged' in filters:
                    conditions.append("acknowledged = ?")
                    params.append(1 if filters['acknowledged'] else 0)
                
                if 'search' in filters and filters['search']:
                    conditions.append("(details LIKE ? OR type LIKE ? OR source LIKE ?)")
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term, search_term])
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
            
            # Execute query
            cursor.execute(query, params)
            
            # Fetch result
            count = cursor.fetchone()[0]
            
            return count
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting event count: {e}")
            return 0
    
    def get_event_by_id(self, event_id):
        """
        Get an event by its ID.
        
        Args:
            event_id (int): ID of the event
            
        Returns:
            dict: Event data, or None if not found
        """
        if not self.conn:
            if not self._connect():
                return None
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Execute query
            cursor.execute("""
                SELECT * FROM events WHERE id = ?
            """, (event_id,))
            
            # Fetch result
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Convert row to dictionary
            event = dict(row)
            
            # Parse JSON details
            try:
                event['details'] = json.loads(event['details'])
            except json.JSONDecodeError:
                event['details'] = {}
            
            return event
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting event by ID: {e}")
            return None
    
    def acknowledge_event(self, event_id, acknowledged=True):
        """
        Mark an event as acknowledged or unacknowledged.
        
        Args:
            event_id (int): ID of the event
            acknowledged (bool): Whether to acknowledge or unacknowledge
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.conn:
            if not self._connect():
                return False
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Update event
            cursor.execute("""
                UPDATE events
                SET acknowledged = ?
                WHERE id = ?
            """, (1 if acknowledged else 0, event_id))
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                action = "acknowledged" if acknowledged else "unacknowledged"
                self.logger.debug(f"Event {event_id} {action}")
            
            return True
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error acknowledging event: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return False
    
    def correlate_events(self, event_ids, primary_event_id):
        """
        Mark events as correlated with a primary event.
        
        Args:
            event_ids (list): IDs of events to correlate
            primary_event_id (int): ID of the primary event
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.conn:
            if not self._connect():
                return False
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Update events
            for event_id in event_ids:
                if event_id != primary_event_id:
                    cursor.execute("""
                        UPDATE events
                        SET correlated_with = ?
                        WHERE id = ?
                    """, (primary_event_id, event_id))
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                self.logger.debug(f"Correlated events {event_ids} with primary event {primary_event_id}")
            
            return True
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error correlating events: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return False
    
    def get_hosts(self):
        """
        Get all hosts from the database.
        
        Returns:
            list: List of hosts
        """
        if not self.conn:
            if not self._connect():
                return []
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Execute query
            cursor.execute("""
                SELECT * FROM hosts ORDER BY hostname
            """)
            
            # Fetch results
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            hosts = [dict(row) for row in rows]
            
            return hosts
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting hosts: {e}")
            return []
    
    def get_event_stats(self, timeframe="day"):
        """
        Get event statistics for the specified timeframe.
        
        Args:
            timeframe (str): Timeframe for statistics (hour, day, week, month)
            
        Returns:
            dict: Event statistics
        """
        if not self.conn:
            if not self._connect():
                return {}
        
        try:
            stats = {}
            
            # Get current timestamp
            now = datetime.now()
            
            # Calculate start time based on timeframe
            if timeframe == "hour":
                start_time = now.replace(minute=0, second=0, microsecond=0).isoformat()
                group_by = "strftime('%Y-%m-%d %H:%M', timestamp)"
                interval = "5 minutes"
            elif timeframe == "day":
                start_time = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                group_by = "strftime('%Y-%m-%d %H', timestamp)"
                interval = "1 hour"
            elif timeframe == "week":
                # Calculate start of week (Monday)
                start_of_week = now - timedelta(days=now.weekday())
                start_time = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                group_by = "strftime('%Y-%m-%d', timestamp)"
                interval = "1 day"
            elif timeframe == "month":
                start_time = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
                group_by = "strftime('%Y-%m-%d', timestamp)"
                interval = "1 day"
            else:
                # Default to day
                start_time = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                group_by = "strftime('%Y-%m-%d %H', timestamp)"
                interval = "1 hour"
            
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Get event counts by severity
            cursor.execute(f"""
                SELECT severity, COUNT(*) as count
                FROM events
                WHERE timestamp >= ?
                GROUP BY severity
            """, (start_time,))
            
            severity_counts = {}
            for row in cursor.fetchall():
                severity_counts[row['severity']] = row['count']
            
            stats['severity_counts'] = severity_counts
            
            # Get event counts by source
            cursor.execute(f"""
                SELECT source, COUNT(*) as count
                FROM events
                WHERE timestamp >= ?
                GROUP BY source
            """, (start_time,))
            
            source_counts = {}
            for row in cursor.fetchall():
                source_counts[row['source']] = row['count']
            
            stats['source_counts'] = source_counts
            
            # Get event counts by type
            cursor.execute(f"""
                SELECT type, COUNT(*) as count
                FROM events
                WHERE timestamp >= ?
                GROUP BY type
                ORDER BY count DESC
                LIMIT 10
            """, (start_time,))
            
            type_counts = {}
            for row in cursor.fetchall():
                type_counts[row['type']] = row['count']
            
            stats['type_counts'] = type_counts
            
            # Get event counts over time
            cursor.execute(f"""
                SELECT {group_by} as time_period, COUNT(*) as count
                FROM events
                WHERE timestamp >= ?
                GROUP BY time_period
                ORDER BY time_period
            """, (start_time,))
            
            time_counts = {}
            for row in cursor.fetchall():
                time_counts[row['time_period']] = row['count']
            
            stats['time_counts'] = time_counts
            stats['timeframe'] = timeframe
            stats['interval'] = interval
            
            return stats
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting event stats: {e}")
            return {}
    
    def delete_old_events(self, cutoff_timestamp):
        """
        Delete events older than the cutoff timestamp.
        
        Args:
            cutoff_timestamp (str): Cutoff timestamp in ISO format
            
        Returns:
            int: Number of deleted events
        """
        if not self.conn:
            if not self._connect():
                return 0
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Get count of events to delete
            cursor.execute("""
                SELECT COUNT(*) FROM events WHERE timestamp < ?
            """, (cutoff_timestamp,))
            
            count = cursor.fetchone()[0]
            
            # Delete events
            cursor.execute("""
                DELETE FROM events WHERE timestamp < ?
            """, (cutoff_timestamp,))
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                self.logger.debug(f"Deleted {count} old events")
            
            return count
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error deleting old events: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return 0
    
    def close(self):
        """
        Close the database connection.
        """
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None
            
            if self.logger:
                self.logger.debug("Database connection closed")

# For testing purposes
if __name__ == "__main__":
    import logging
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("DatabaseManager")
    
    # Create a test database
    db_path = "test_database.db"
    db_manager = DatabaseManager(db_path, logger)
    
    # Initialize database
    db_manager.initialize_database()
    
    # Store a test event
    test_event = {
        "timestamp": datetime.now().isoformat(),
        "source": "test",
        "type": "test_event",
        "severity": "info",
        "details": {"message": "This is a test event"},
        "hostname": "test-host",
        "ip_address": "127.0.0.1"
    }
    
    event_id = db_manager.store_event(test_event)
    print(f"Stored test event with ID: {event_id}")
    
    # Get events
    events = db_manager.get_events()
    print(f"Retrieved {len(events)} events")
    
    # Close connection
    db_manager.close()