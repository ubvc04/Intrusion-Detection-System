#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDS Manager Server Module

This module implements the web server for the IDS Manager,
providing a real-time dashboard for security events using WebSockets.
"""

import os
import sys
import json
import threading
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Import Flask and Flask-SocketIO
try:
    from flask import Flask, render_template, request, jsonify, send_from_directory
    from flask_socketio import SocketIO
    from flask_cors import CORS
except ImportError as e:
    print(f"Error importing Flask or Flask-SocketIO: {e}")
    print("Please ensure Flask, Flask-SocketIO and dependencies are properly installed.")
    print("Run: pip install flask flask-socketio flask-cors")
    sys.exit(1)

# Import manager components
from manager.manager import IDSManager

# Create Flask app and SocketIO instance
app = Flask(__name__, 
            static_folder=str(project_root / 'components' / 'manager' / 'static'),
            template_folder=str(project_root / 'components' / 'manager' / 'templates'))
app.config['SECRET_KEY'] = 'ids-secret-key!'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
ids_manager = None
logger = None

# Event queue for real-time updates
event_queue = []

@app.route('/')
def index():
    """
    Render the dashboard index page.
    """
    return render_template('index.html')

@app.route('/api/events', methods=['GET'])
def get_events():
    """
    Get events with optional filtering.
    
    Query parameters:
        source (str): Filter by source
        type (str): Filter by type
        severity (str): Filter by severity
        start_time (str): Filter by start time (ISO format)
        end_time (str): Filter by end time (ISO format)
        acknowledged (bool): Filter by acknowledged status
        search (str): Search term
        limit (int): Maximum number of events to return
        offset (int): Offset for pagination
        order_by (str): Field to order by
        order (str): Order direction (ASC or DESC)
    
    Returns:
        JSON response with events and metadata
    """
    try:
        # Parse query parameters
        filters = {}
        
        if 'source' in request.args:
            filters['source'] = request.args.get('source')
        
        if 'type' in request.args:
            filters['type'] = request.args.get('type')
        
        if 'severity' in request.args:
            filters['severity'] = request.args.get('severity')
        
        if 'start_time' in request.args:
            filters['start_time'] = request.args.get('start_time')
        
        if 'end_time' in request.args:
            filters['end_time'] = request.args.get('end_time')
        
        if 'acknowledged' in request.args:
            filters['acknowledged'] = request.args.get('acknowledged').lower() == 'true'
        
        if 'search' in request.args:
            filters['search'] = request.args.get('search')
        
        # Parse pagination parameters
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Parse ordering parameters
        order_by = request.args.get('order_by', 'timestamp')
        order = request.args.get('order', 'DESC')
        
        # Get events from database
        events = ids_manager.db_manager.get_events(filters, limit, offset, order_by, order)
        
        # Get total count for pagination
        total_count = ids_manager.db_manager.get_event_count(filters)
        
        # Return JSON response
        return jsonify({
            'status': 'success',
            'data': {
                'events': events,
                'total': total_count,
                'limit': limit,
                'offset': offset
            }
        })
    
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/events/<event_id>', methods=['GET'])
def get_event(event_id):
    """
    Get a specific event by ID.
    
    Args:
        event_id (str): Event ID
    
    Returns:
        JSON response with event data
    """
    try:
        # Get event from database
        event = ids_manager.db_manager.get_event(event_id)
        
        if not event:
            return jsonify({
                'status': 'error',
                'message': f"Event with ID {event_id} not found"
            }), 404
        
        # Return JSON response
        return jsonify({
            'status': 'success',
            'data': {
                'event': event
            }
        })
    
    except Exception as e:
        logger.error(f"Error getting event {event_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/events/<event_id>/acknowledge', methods=['POST'])
def acknowledge_event(event_id):
    """
    Acknowledge an event.
    
    Args:
        event_id (str): Event ID
    
    Returns:
        JSON response with status
    """
    try:
        # Acknowledge event in database
        success = ids_manager.db_manager.acknowledge_event(event_id)
        
        if not success:
            return jsonify({
                'status': 'error',
                'message': f"Event with ID {event_id} not found"
            }), 404
        
        # Return JSON response
        return jsonify({
            'status': 'success',
            'message': f"Event {event_id} acknowledged"
        })
    
    except Exception as e:
        logger.error(f"Error acknowledging event {event_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get system statistics.
    
    Returns:
        JSON response with statistics
    """
    try:
        # Get statistics from database
        stats = ids_manager.db_manager.get_statistics()
        
        # Return JSON response
        return jsonify({
            'status': 'success',
            'data': {
                'stats': stats
            }
        })
    
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """
    Get all monitored hosts.
    
    Returns:
        JSON response with hosts data
    """
    try:
        # Get hosts from database
        hosts = ids_manager.db_manager.get_hosts()
        
        # Return JSON response
        return jsonify({
            'status': 'success',
            'data': {
                'hosts': hosts
            }
        })
    
    except Exception as e:
        logger.error(f"Error getting hosts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """
    Handle WebSocket connection.
    """
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    """
    Handle WebSocket disconnection.
    """
    logger.info(f"Client disconnected: {request.sid}")

def event_broadcaster():
    """
    Background thread that broadcasts events to connected clients.
    """
    global event_queue
    
    while ids_manager and ids_manager.running:
        # Check if there are events in the queue
        if event_queue:
            # Get the next event
            event = event_queue.pop(0)
            
            # Broadcast the event to all connected clients
            socketio.emit('new_event', event)
            
            # Log the broadcast
            logger.debug(f"Broadcasted event: {event['id']}")
        
        # Sleep to avoid high CPU usage
        socketio.sleep(0.1)

def add_event_to_queue(event):
    """
    Add an event to the broadcast queue.
    
    Args:
        event (dict): Event data
    """
    global event_queue
    event_queue.append(event)

def start_manager(config, log):
    """
    Start the IDS Manager with web interface.
    
    Args:
        config: Configuration object
        log: Logger instance
    """
    global ids_manager, logger
    
    # Set logger
    logger = log
    logger.info("Starting IDS Manager with web interface")
    
    try:
        # Create IDS Manager instance
        ids_manager = IDSManager(config)
        
        # Override the event callback to add WebSocket broadcasting
        original_event_callback = ids_manager._event_callback
        
        def websocket_event_callback(event):
            # Call the original callback
            original_event_callback(event)
            
            # Add the event to the broadcast queue
            add_event_to_queue(event)
        
        # Replace the event callback
        ids_manager._event_callback = websocket_event_callback
        
        # Start the IDS Manager in a separate thread
        manager_thread = threading.Thread(target=ids_manager.start, daemon=True)
        manager_thread.start()
        
        # Start the event broadcaster in a separate thread
        broadcaster_thread = threading.Thread(target=event_broadcaster, daemon=True)
        broadcaster_thread.start()
        
        # Get host and port from config
        host = config['Manager'].get('web_host', '0.0.0.0')
        port = int(config['Manager'].get('web_port', 5000))
        
        # Log the actual host and port being used
        logger.info(f"Using configuration: web_host={host}, web_port={port}")
        
        # Start the web server
        logger.info(f"Starting web server on {host}:{port}")
        socketio.run(app, host=host, port=port, debug=False, use_reloader=False)
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        if ids_manager:
            ids_manager.stop()
    except Exception as e:
        logger.error(f"Error starting IDS Manager: {e}")
        if ids_manager:
            ids_manager.stop()
        raise

# For testing purposes
if __name__ == "__main__":
    import logging
    import configparser
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("IDS-Manager")
    
    # Load configuration
    config = configparser.ConfigParser()
    config_path = project_root / 'config' / 'config.ini'
    
    if not config_path.exists():
        print(f"Configuration file not found: {config_path}")
        sys.exit(1)
    
    config.read(config_path)
    
    # Start the manager
    start_manager(config, logger)