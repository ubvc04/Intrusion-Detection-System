#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Event Broadcasting Module for WebSocket-enabled Dashboard

This module handles real-time event broadcasting to connected WebSocket clients.
"""

import json
import threading
import time
from datetime import datetime
from queue import Queue, Empty

class EventBroadcaster:
    """
    Manages real-time event broadcasting to WebSocket clients.
    """
    
    def __init__(self, socketio, logger=None):
        """
        Initialize the event broadcaster.
        
        Args:
            socketio: Flask-SocketIO instance
            logger: Logger instance
        """
        self.socketio = socketio
        self.logger = logger
        self.clients = set()
        self.event_queue = Queue()
        self.running = False
        self.broadcast_thread = None
        self.lock = threading.Lock()
    
    def start(self):
        """
        Start the event broadcaster thread.
        """
        if self.running:
            return
        
        self.running = True
        self.broadcast_thread = threading.Thread(target=self._broadcast_worker, daemon=True)
        self.broadcast_thread.start()
        
        if self.logger:
            self.logger.info("Event broadcaster started")
    
    def stop(self):
        """
        Stop the event broadcaster thread.
        """
        self.running = False
        
        if self.broadcast_thread:
            self.broadcast_thread.join(timeout=2.0)
            self.broadcast_thread = None
        
        if self.logger:
            self.logger.info("Event broadcaster stopped")
    
    def add_client(self, client_id):
        """
        Add a client to the broadcaster.
        
        Args:
            client_id: ID of the client to add
        """
        with self.lock:
            self.clients.add(client_id)
        
        if self.logger:
            self.logger.debug(f"Client {client_id} connected, total clients: {len(self.clients)}")
    
    def remove_client(self, client_id):
        """
        Remove a client from the broadcaster.
        
        Args:
            client_id: ID of the client to remove
        """
        with self.lock:
            if client_id in self.clients:
                self.clients.remove(client_id)
        
        if self.logger:
            self.logger.debug(f"Client {client_id} disconnected, total clients: {len(self.clients)}")
    
    def broadcast_event(self, event):
        """
        Queue an event for broadcasting to all connected clients.
        
        Args:
            event: Event data to broadcast
        """
        self.event_queue.put(event)
    
    def _broadcast_worker(self):
        """
        Worker thread that processes the event queue and broadcasts events.
        """
        while self.running:
            try:
                # Get an event from the queue with a timeout
                event = self.event_queue.get(timeout=1.0)
                
                # Broadcast the event to all connected clients
                with self.lock:
                    if self.clients:
                        try:
                            # Format the event for broadcasting
                            event_data = self._format_event(event)
                            
                            # Emit the event to all clients
                            self.socketio.emit('event', event_data, namespace='/events')
                            
                            if self.logger:
                                self.logger.debug(f"Broadcasted event to {len(self.clients)} clients")
                        
                        except Exception as e:
                            if self.logger:
                                self.logger.error(f"Error broadcasting event: {e}")
                
                # Mark the task as done
                self.event_queue.task_done()
            
            except Empty:
                # No events in the queue, sleep briefly
                time.sleep(0.1)
            
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in broadcast worker: {e}")
                time.sleep(1.0)  # Sleep longer on error
    
    def _format_event(self, event):
        """
        Format an event for broadcasting.
        
        Args:
            event: Event data to format
            
        Returns:
            dict: Formatted event data
        """
        # If this is an acknowledgment event, return it as is
        if isinstance(event, dict) and event.get('type') == 'acknowledge':
            return event
        
        # Otherwise, format it as a new event
        return {
            'type': 'new_event',
            'event': event,
            'timestamp': datetime.now().isoformat()
        }