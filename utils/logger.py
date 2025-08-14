#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logger Utility Module

This module provides a centralized logging configuration for all components of the
Windows Intrusion Detection System.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

def setup_logger(level=logging.INFO, log_file=None, name='ids'):
    """
    Configure and return a logger with the specified settings.
    
    Args:
        level: The logging level (default: INFO)
        log_file: Path to the log file (default: None, logs to console only)
        name: Logger name (default: 'ids')
        
    Returns:
        A configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates when reconfiguring
    for handler in logger.handlers[:]:  
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Create file handler if log_file is specified
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Create rotating file handler (10MB max size, 5 backups)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_component_logger(component_name, config):
    """
    Get a logger configured for a specific component.
    
    Args:
        component_name: Name of the component (e.g., 'hids', 'nids', 'manager')
        config: Configuration object containing logging settings
        
    Returns:
        A configured logger instance for the component
    """
    log_level = getattr(logging, config['Logging']['level'])
    log_file = config['Logging']['log_file']
    
    # Create component-specific log file path
    log_path = Path(log_file)
    component_log_file = log_path.parent / f"{log_path.stem}_{component_name}{log_path.suffix}"
    
    return setup_logger(log_level, str(component_log_file), f"ids.{component_name}")