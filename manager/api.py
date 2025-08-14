#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Module

This module implements the REST API for the IDS Manager,
providing endpoints for the web interface to interact with the system.
"""

import os
import json
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path

# Import Flask with error handling
try:
    from flask import Flask, request, jsonify, send_from_directory, Response
    from flask_cors import CORS
    from werkzeug.middleware.proxy_fix import ProxyFix
except ImportError as e:
    print(f"Error importing Flask: {e}")
    print("Please ensure Flask and its dependencies are properly installed in your virtual environment.")
    import sys
    sys.exit(1)

# Create Flask app
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
CORS(app)

# Global variables
db_manager = None
event_correlator = None
logger = None
project_root = None

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
        events = db_manager.get_events(filters, limit, offset, order_by, order)
        
        # Get total count for pagination
        total_count = db_manager.get_event_count(filters)
        
        # Return JSON response
        return jsonify({
            'events': events,
            'metadata': {
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
                'filters': filters
            }
        })
    
    except Exception as e:
        logger.error(f"Error in get_events: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events', methods=['POST'])
def create_event():
    """
    Create a new event.
    
    Request body:
        JSON object with event data
    
    Returns:
        JSON response with created event ID
    """
    try:
        # Get event data from request
        event_data = request.json
        
        if not event_data:
            return jsonify({'error': 'No event data provided'}), 400
        
        # Ensure required fields are present
        required_fields = ['type', 'source']
        for field in required_fields:
            if field not in event_data:
                return jsonify({'error': f"Missing required field: {field}"}), 400
        
        # Add timestamp if not present
        if 'timestamp' not in event_data:
            event_data['timestamp'] = datetime.now().isoformat()
        
        # Add severity if not present
        if 'severity' not in event_data:
            event_data['severity'] = 'info'
        
        # Store event in database
        event_id = db_manager.store_event(event_data)
        
        if event_id == -1:
            return jsonify({'error': 'Failed to store event'}), 500
        
        # Trigger event correlation if enabled
        if event_correlator:
            threading.Thread(target=event_correlator.process_event, args=(event_id,), daemon=True).start()
        
        # Return success response
        return jsonify({'id': event_id}), 201
    
    except Exception as e:
        logger.error(f"Error in create_event: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    """
    Get an event by ID.
    
    Args:
        event_id (int): ID of the event
    
    Returns:
        JSON response with event data
    """
    try:
        # Get event from database
        event = db_manager.get_event_by_id(event_id)
        
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        # Return event data
        return jsonify(event)
    
    except Exception as e:
        logger.error(f"Error in get_event: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/<int:event_id>/acknowledge', methods=['POST'])
def acknowledge_event(event_id):
    """
    Acknowledge an event.
    
    Args:
        event_id (int): ID of the event
    
    Returns:
        JSON response with success status
    """
    try:
        # Get acknowledge status from request
        data = request.json or {}
        acknowledged = data.get('acknowledged', True)
        
        # Update event in database
        success = db_manager.acknowledge_event(event_id, acknowledged)
        
        if not success:
            return jsonify({'error': 'Failed to acknowledge event'}), 500
        
        # Return success response
        action = "acknowledged" if acknowledged else "unacknowledged"
        return jsonify({'message': f"Event {event_id} {action}"})
    
    except Exception as e:
        logger.error(f"Error in acknowledge_event: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """
    Get all hosts.
    
    Returns:
        JSON response with hosts data
    """
    try:
        # Get hosts from database
        hosts = db_manager.get_hosts()
        
        # Return hosts data
        return jsonify({'hosts': hosts})
    
    except Exception as e:
        logger.error(f"Error in get_hosts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Get event statistics.
    
    Query parameters:
        timeframe (str): Timeframe for statistics (hour, day, week, month)
    
    Returns:
        JSON response with statistics data
    """
    try:
        # Parse query parameters
        timeframe = request.args.get('timeframe', 'day')
        
        # Get statistics from database
        stats = db_manager.get_event_stats(timeframe)
        
        # Return statistics data
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error in get_stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
def serve_static(path):
    """
    Serve static files for the web interface.
    
    Args:
        path (str): Path to the requested file
    
    Returns:
        Static file response
    """
    try:
        # Determine static files directory
        static_dir = project_root / 'manager' / 'static'
        
        # Check if file exists
        if not (static_dir / path).exists() and not path.startswith('api/'):
            # Return index.html for client-side routing
            path = 'index.html'
        
        # Serve the file
        return send_from_directory(static_dir, path)
    
    except Exception as e:
        logger.error(f"Error serving static file {path}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """
    Serve the main index.html file for the web interface.
    """
    try:
        return send_from_directory(project_root / 'manager' / 'static', 'index.html')
    except Exception as e:
        logger.error(f"Error serving index.html: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    
    Returns:
        JSON response with health status
    """
    try:
        # Check database connection
        db_status = "ok" if db_manager and db_manager.conn else "error"
        
        # Return health status
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'components': {
                'database': db_status,
                'correlator': 'ok' if event_correlator else 'disabled'
            }
        })
    
    except Exception as e:
        logger.error(f"Error in health_check: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

def start_api_server(host, port, database_manager, correlator, log):
    """
    Start the API server.
    
    Args:
        host (str): Host to bind to
        port (int): Port to bind to
        database_manager: Database manager instance
        correlator: Event correlator instance
        log: Logger instance
    """
    global db_manager, event_correlator, logger, project_root
    
    # Set global variables
    db_manager = database_manager
    event_correlator = correlator
    logger = log
    project_root = Path(__file__).resolve().parent.parent
    
    try:
        # Start Flask app
        logger.info(f"Starting API server on {host}:{port}")
        app.run(host=host, port=port, threaded=True)
    
    except Exception as e:
        logger.error(f"Error starting API server: {e}")
        raise

# For testing purposes
if __name__ == "__main__":
    import logging
    from pathlib import Path
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("API")
    
    # Set project root
    project_root = Path(__file__).resolve().parent.parent
    
    # Import database manager
    sys.path.insert(0, str(project_root))
    from manager.database import DatabaseManager
    
    # Create database manager
    db_path = project_root / 'data' / 'ids.db'
    db_manager = DatabaseManager(str(db_path), logger)
    db_manager.initialize_database()
    
    # Start API server
    start_api_server('127.0.0.1', 5000, db_manager, None, logger)