#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDS Manager API Module

This module implements the REST API for the IDS Manager,
providing endpoints for retrieving and managing security events.
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, Blueprint

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Create API blueprint
api_bp = Blueprint('api', __name__)

# Global variables
db_manager = None
logger = None

@api_bp.route('/events', methods=['GET'])
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

@api_bp.route('/events', methods=['POST'])
def add_event():
    """
    Add a new event.
    
    Request body:
        JSON object with event data
    
    Returns:
        JSON response with status
    """
    try:
        # Get event data from request
        event_data = request.json
        
        # Validate event data
        required_fields = ['id', 'timestamp', 'source', 'type', 'severity', 'message']
        for field in required_fields:
            if field not in event_data:
                return jsonify({
                    'status': 'error',
                    'message': f"Missing required field: {field}"
                }), 400
        
        # Add event to database
        db_manager.add_event(event_data)
        
        # Return success response
        return jsonify({
            'status': 'success',
            'message': 'Event added successfully',
            'data': {
                'event_id': event_data['id']
            }
        })
    
    except Exception as e:
        logger.error(f"Error adding event: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/events/<event_id>', methods=['GET'])
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
        event = db_manager.get_event(event_id)
        
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

@api_bp.route('/events/<event_id>/acknowledge', methods=['POST'])
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
        success = db_manager.acknowledge_event(event_id)
        
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

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """
    Get system statistics.
    
    Returns:
        JSON response with statistics
    """
    try:
        # Get statistics from database
        stats = db_manager.get_statistics()
        
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

def start_api_server(host, port, database_manager, log):
    """
    Start the API server.
    
    Args:
        host (str): Host to bind to
        port (int): Port to listen on
        database_manager: Database manager instance
        log: Logger instance
    
    Returns:
        Flask app instance
    """
    global db_manager, logger
    
    # Set global variables
    db_manager = database_manager
    logger = log
    
    # Create Flask app
    app = Flask(__name__)
    
    # Register API blueprint
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Start the server
    logger.info(f"Starting API server on {host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
    
    return app