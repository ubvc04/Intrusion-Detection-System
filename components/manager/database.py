#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Manager Module for WebSocket-enabled Dashboard

This module handles database operations for the IDS Manager,
including storing events, retrieving events, and managing the database schema.
"""

import os
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

class DatabaseManager:
    """
    Manages database operations for the IDS Manager with WebSocket support.
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
        self.event_callback = None
    
    def set_event_callback(self, callback):
        """
        Set a callback function to be called when new events are added.
        This is used for WebSocket notifications.
        
        Args:
            callback: Function to call with event data when new events are added
        """
        self.event_callback = callback
    
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
            self.cursor = self.conn.cursor()
            
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
            event (dict): Event data
            
        Returns:
            int: ID of the stored event, or -1 if error
        """
        if not self.conn:
            if not self._connect():
                return -1
        
        try:
            # Extract event data
            timestamp = event.get('timestamp', datetime.now().isoformat())
            source = event.get('source', 'unknown')
            event_type = event.get('type', 'unknown')
            severity = event.get('severity', 'info')
            details = json.dumps(event.get('details', {}))
            
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Insert event into database
            cursor.execute("""
                INSERT INTO events (timestamp, source, type, severity, details)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, source, event_type, severity, details))
            
            # Get the ID of the inserted event
            event_id = cursor.lastrowid
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                self.logger.debug(f"Stored event with ID {event_id}")
            
            # Call the event callback if set
            if self.event_callback:
                # Add the ID to the event data
                event['id'] = event_id
                self.event_callback(event)
            
            return event_id
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error storing event: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return -1
    
    def get_events(self, limit=100, offset=0, sort_by='timestamp', sort_order='desc', 
                  filters=None, search=None):
        """
        Get events from the database with pagination, sorting, and filtering.
        
        Args:
            limit (int): Maximum number of events to return
            offset (int): Offset for pagination
            sort_by (str): Field to sort by
            sort_order (str): Sort order ('asc' or 'desc')
            filters (dict): Filters to apply
            search (str): Search term to filter by
            
        Returns:
            tuple: (list of events, total count)
        """
        if not self.conn:
            if not self._connect():
                return [], 0
        
        try:
            # Build query
            query = "SELECT * FROM events"
            count_query = "SELECT COUNT(*) FROM events"
            params = []
            where_clauses = []
            
            # Apply filters
            if filters:
                for key, value in filters.items():
                    if key in ['source', 'type', 'severity']:
                        where_clauses.append(f"{key} = ?")
                        params.append(value)
                    elif key == 'acknowledged':
                        where_clauses.append(f"acknowledged = ?")
                        params.append(1 if value else 0)
                    elif key == 'start_date':
                        where_clauses.append(f"timestamp >= ?")
                        params.append(value)
                    elif key == 'end_date':
                        where_clauses.append(f"timestamp <= ?")
                        params.append(value)
            
            # Apply search
            if search:
                where_clauses.append("(source LIKE ? OR type LIKE ? OR details LIKE ?)")
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term])
            
            # Add WHERE clause if needed
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
                count_query += " WHERE " + " AND ".join(where_clauses)
            
            # Add ORDER BY clause
            if sort_by in ['id', 'timestamp', 'source', 'type', 'severity', 'acknowledged']:
                sort_order = 'DESC' if sort_order.lower() == 'desc' else 'ASC'
                query += f" ORDER BY {sort_by} {sort_order}"
            
            # Add LIMIT and OFFSET clauses
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Execute count query
            cursor.execute(count_query, params[:-2] if params else [])
            total_count = cursor.fetchone()[0]
            
            # Execute main query
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            events = []
            for row in rows:
                event = dict(row)
                # Parse details JSON
                try:
                    event['details'] = json.loads(event['details'])
                except json.JSONDecodeError:
                    event['details'] = {}
                events.append(event)
            
            return events, total_count
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting events: {e}")
            
            return [], 0
    
    def get_event(self, event_id):
        """
        Get a specific event by ID.
        
        Args:
            event_id (int): ID of the event to get
            
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
            cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            # Convert row to dictionary
            event = dict(row)
            
            # Parse details JSON
            try:
                event['details'] = json.loads(event['details'])
            except json.JSONDecodeError:
                event['details'] = {}
            
            return event
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting event {event_id}: {e}")
            
            return None
    
    def acknowledge_event(self, event_id):
        """
        Mark an event as acknowledged.
        
        Args:
            event_id (int): ID of the event to acknowledge
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.conn:
            if not self._connect():
                return False
        
        try:
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Execute update
            cursor.execute("""
                UPDATE events
                SET acknowledged = 1
                WHERE id = ?
            """, (event_id,))
            
            # Commit changes
            self.conn.commit()
            
            # Check if any rows were affected
            if cursor.rowcount == 0:
                if self.logger:
                    self.logger.warning(f"No event found with ID {event_id}")
                return False
            
            if self.logger:
                self.logger.debug(f"Acknowledged event with ID {event_id}")
            
            # Call the event callback if set
            if self.event_callback:
                event = self.get_event(event_id)
                if event:
                    self.event_callback({'type': 'acknowledge', 'event': event})
            
            return True
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error acknowledging event {event_id}: {e}")
            
            # Rollback changes
            if self.conn:
                self.conn.rollback()
            
            return False
    
    def get_statistics(self):
        """
        Get statistics about events in the database.
        
        Returns:
            dict: Statistics data
        """
        if not self.conn:
            if not self._connect():
                return {}
        
        try:
            stats = {}
            
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Get total event count
            cursor.execute("SELECT COUNT(*) FROM events")
            stats['total_events'] = cursor.fetchone()[0]
            
            # Get count by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM events
                GROUP BY severity
                ORDER BY count DESC
            """)
            stats['by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Get count by type
            cursor.execute("""
                SELECT type, COUNT(*) as count
                FROM events
                GROUP BY type
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['by_type'] = {row['type']: row['count'] for row in cursor.fetchall()}
            
            # Get count by source
            cursor.execute("""
                SELECT source, COUNT(*) as count
                FROM events
                GROUP BY source
                ORDER BY count DESC
                LIMIT 10
            """)
            stats['by_source'] = {row['source']: row['count'] for row in cursor.fetchall()}
            
            # Get events over time (last 24 hours by hour)
            now = datetime.now()
            stats['over_time'] = []
            
            for i in range(24, 0, -1):
                start_time = (now - timedelta(hours=i)).isoformat()
                end_time = (now - timedelta(hours=i-1)).isoformat()
                
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM events
                    WHERE timestamp >= ? AND timestamp < ?
                """, (start_time, end_time))
                
                count = cursor.fetchone()[0]
                hour_label = (now - timedelta(hours=i)).strftime('%H:00')
                
                stats['over_time'].append({
                    'hour': hour_label,
                    'count': count
                })
            
            # Get unacknowledged count
            cursor.execute("SELECT COUNT(*) FROM events WHERE acknowledged = 0")
            stats['unacknowledged'] = cursor.fetchone()[0]
            
            return stats
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting statistics: {e}")
            
            return {}
    
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
            where_clauses = []
            
            # Apply filters
            if filters:
                for key, value in filters.items():
                    if key in ['source', 'type', 'severity']:
                        where_clauses.append(f"{key} = ?")
                        params.append(value)
                    elif key == 'acknowledged':
                        where_clauses.append(f"acknowledged = ?")
                        params.append(1 if value else 0)
                    elif key == 'start_date':
                        where_clauses.append(f"timestamp >= ?")
                        params.append(value)
                    elif key == 'end_date':
                        where_clauses.append(f"timestamp <= ?")
                        params.append(value)
                    elif key == 'search':
                        where_clauses.append("(source LIKE ? OR type LIKE ? OR details LIKE ?)")
                        search_term = f"%{value}%"
                        params.extend([search_term, search_term, search_term])
            
            # Add WHERE clause if needed
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
            
            # Execute query
            cursor.execute(query, params)
            
            # Fetch result
            count = cursor.fetchone()[0]
            
            return count
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error getting event count: {e}")
            
            return 0
    
    def cleanup_old_events(self, days_to_keep):
        """
        Delete events older than the specified number of days.
        
        Args:
            days_to_keep (int): Number of days to keep events for
            
        Returns:
            int: Number of events deleted
        """
        if not self.conn:
            if not self._connect():
                return 0
        
        try:
            # Calculate cutoff date
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            # Create a cursor for this operation
            cursor = self.conn.cursor()
            
            # Execute delete
            cursor.execute("""
                DELETE FROM events
                WHERE timestamp < ?
            """, (cutoff_date,))
            
            # Get number of rows deleted
            deleted_count = cursor.rowcount
            
            # Commit changes
            self.conn.commit()
            
            if self.logger:
                self.logger.info(f"Deleted {deleted_count} events older than {days_to_keep} days")
            
            return deleted_count
        
        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"Error cleaning up old events: {e}")
            
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
                self.logger.debug("Closed database connection")