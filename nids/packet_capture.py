#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Packet Capture Module

This module handles network packet capture for the NIDS sensor using Scapy,
which works with Npcap on Windows systems.
"""

import os
import sys
import time
import threading
from pathlib import Path

# Import Scapy with error handling
try:
    from scapy.all import sniff, conf
    from scapy.error import Scapy_Exception
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please ensure Npcap is installed and Scapy is properly installed in your virtual environment.")
    sys.exit(1)

class PacketCapture:
    """
    Handles network packet capture using Scapy with Npcap on Windows.
    """
    
    def __init__(self, interface=None, promiscuous_mode=True, snap_length=65536, 
                 timeout=1000, bpf_filter="", logger=None):
        """
        Initialize the packet capture component.
        
        Args:
            interface (str): Network interface to capture packets from
            promiscuous_mode (bool): Whether to enable promiscuous mode
            snap_length (int): Maximum number of bytes to capture per packet
            timeout (int): Read timeout in milliseconds
            bpf_filter (str): Berkeley Packet Filter string
            logger: Logger instance
        """
        self.interface = interface
        self.promiscuous_mode = promiscuous_mode
        self.snap_length = snap_length
        self.timeout = timeout
        self.bpf_filter = bpf_filter
        self.logger = logger
        
        # Initialize state
        self.running = False
        self.sniffer_thread = None
        self.stop_event = threading.Event()
        self.packet_callback = None
        
    def set_callback(self, callback):
        """
        Set the callback function for packet processing.
        
        Args:
            callback: Function to call for each captured packet
        """
        self.packet_callback = callback
        
        # Validate and set interface
        self._validate_interface()
    
    def _validate_interface(self):
        """
        Validate the specified interface or select the default one.
        """
        try:
            # Get list of available interfaces
            available_interfaces = conf.ifaces
            
            # If no interface specified, use the default one
            if not self.interface:
                self.interface = conf.iface
                if self.logger:
                    self.logger.info(f"Using default interface: {self.interface.name}")
            else:
                # Find the interface by name
                interface_found = False
                for iface_name, iface_data in available_interfaces.items():
                    if self.interface.lower() in iface_name.lower() or \
                       (hasattr(iface_data, 'name') and self.interface.lower() in iface_data.name.lower()):
                        self.interface = iface_name
                        interface_found = True
                        if self.logger:
                            self.logger.info(f"Using interface: {self.interface}")
                        break
                
                if not interface_found:
                    if self.logger:
                        self.logger.warning(f"Interface '{self.interface}' not found, using default: {conf.iface.name}")
                    self.interface = conf.iface
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error validating interface: {e}")
                self.logger.info(f"Using default interface: {conf.iface.name}")
            self.interface = conf.iface
    
    def _packet_sniffer(self):
        """
        Internal method to sniff packets and pass them to the callback.
        """
        if self.logger:
            self.logger.debug(f"Starting packet sniffer on interface {self.interface}")
        
        try:
            # Start sniffing packets
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                filter=self.bpf_filter,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except Scapy_Exception as e:
            if self.logger:
                self.logger.error(f"Scapy error during packet capture: {e}")
        except OSError as e:
            if self.logger:
                self.logger.error(f"OS error during packet capture: {e}")
                self.logger.error("This may be due to insufficient permissions or Npcap not being installed properly.")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Unexpected error during packet capture: {e}")
        finally:
            if self.logger:
                self.logger.debug("Packet sniffer stopped")
    
    def set_callback(self, packet_callback):
        """
        Set the callback function for captured packets.
        
        Args:
            packet_callback: Function to call for each captured packet
        """
        self.packet_callback = packet_callback
        if self.logger:
            self.logger.debug("Packet callback set")
    
    def start_capture(self, packet_callback=None):
        """
        Start capturing packets and pass them to the callback function.
        
        Args:
            packet_callback: Function to call for each captured packet (optional if set_callback was used)
        
        Returns:
            bool: True if capture started successfully, False otherwise
        """
        if self.running:
            if self.logger:
                self.logger.warning("Packet capture is already running")
            return False
        
        # Use provided callback or the one set earlier
        if packet_callback:
            self.packet_callback = packet_callback
        
        if not self.packet_callback:
            if self.logger:
                self.logger.error("No packet callback function set")
            return False
        
        # Reset stop event
        self.stop_event.clear()
        self.running = True
        
        return True
        
        if self.logger:
            self.logger.info(f"Starting packet capture on interface {self.interface}")
            if self.bpf_filter:
                self.logger.info(f"Using BPF filter: {self.bpf_filter}")
            self.logger.info(f"Promiscuous mode: {self.promiscuous_mode}")
        
        try:
            # Set promiscuous mode if requested
            if self.promiscuous_mode:
                # Note: Scapy with Npcap on Windows should handle promiscuous mode automatically
                # when sniffing, but we log it for clarity
                if self.logger:
                    self.logger.debug("Enabling promiscuous mode")
            
            # Start the sniffer in a separate thread
            self.sniffer_thread = threading.Thread(
                target=self._packet_sniffer,
                daemon=True
            )
            self.sniffer_thread.start()
            
            if self.logger:
                self.logger.info("Packet capture started successfully")
        
        except Exception as e:
            self.running = False
            if self.logger:
                self.logger.error(f"Failed to start packet capture: {e}")
            raise
    
    def start(self):
        """
        Start the packet capture using the previously set callback.
        This is a convenience method for the NIDS sensor.
        """
        self.start_capture()
    
    def stop_capture(self):
        """
        Stop the packet capture.
        """
        if not self.running:
            return
        
        if self.logger:
            self.logger.info("Stopping packet capture")
        
        # Signal the sniffer to stop
        self.stop_event.set()
        
        # Wait for the sniffer thread to finish
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=5)
            if self.sniffer_thread.is_alive():
                if self.logger:
                    self.logger.warning("Sniffer thread did not terminate gracefully")
        
        self.running = False
        if self.logger:
            self.logger.info("Packet capture stopped")
            
    def stop(self):
        """
        Stop the packet capture.
        This is a convenience method for the NIDS sensor.
        """
        self.stop_capture()

# For testing purposes
if __name__ == "__main__":
    import logging
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("PacketCapture")
    
    # Create packet capture instance
    capture = PacketCapture(logger=logger)
    
    # Define a simple packet callback
    def simple_callback(packet):
        print(f"Captured packet: {packet.summary()}")
    
    try:
        # Start capture
        capture.start_capture(simple_callback)
        
        # Run for 30 seconds
        print("Capturing packets for 30 seconds...")
        time.sleep(30)
        
    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        # Stop capture
        capture.stop_capture()
        print("Packet capture stopped")