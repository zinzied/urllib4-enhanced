#!/usr/bin/env python3
"""
Example demonstrating HTTP/3 connection migration in urllib4-enhanced.

This script shows how to use the connection migration feature in HTTP/3,
which allows a connection to seamlessly transition between network interfaces
without disrupting the application.
"""

import logging
import time
from typing import Dict, List, Optional

import urllib4
from urllib4.http3 import HTTP3Connection, HTTP3Settings, QUICSettings
from urllib4.http3.migration import MigrationTrigger

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("http3_migration_example")


def discover_network_interfaces():
    """Discover network interfaces."""
    try:
        import netifaces
        
        logger.info("Discovering network interfaces...")
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            logger.info(f"Interface: {interface}")
            
            # Get addresses for this interface
            addresses = netifaces.ifaddresses(interface)
            
            # Process IPv4 addresses
            if netifaces.AF_INET in addresses:
                for addr_info in addresses[netifaces.AF_INET]:
                    ip = addr_info["addr"]
                    netmask = addr_info.get("netmask", "unknown")
                    logger.info(f"  IPv4: {ip} (netmask: {netmask})")
                    
            # Process IPv6 addresses
            if netifaces.AF_INET6 in addresses:
                for addr_info in addresses[netifaces.AF_INET6]:
                    ip = addr_info["addr"]
                    logger.info(f"  IPv6: {ip}")
                    
        return True
    except ImportError:
        logger.error("netifaces package not installed. Install with: pip install netifaces")
        return False


def connection_migration_example():
    """Example demonstrating HTTP/3 connection migration."""
    logger.info("HTTP/3 Connection Migration Example")
    logger.info("==================================")
    
    # Check if netifaces is available
    if not discover_network_interfaces():
        return
        
    # Create QUIC settings with multipath and active migration enabled
    quic_settings = QUICSettings(
        enable_multipath=True,
        max_paths=4,
        enable_active_migration=True,
    )
    
    http3_settings = HTTP3Settings(
        quic=quic_settings,
    )
    
    try:
        # Create HTTP/3 connection
        logger.info("\nCreating HTTP/3 connection to cloudflare-quic.com with migration enabled...")
        conn = HTTP3Connection(
            "cloudflare-quic.com",
            settings=http3_settings,
        )
        
        # Connect to the server
        logger.info("Connecting...")
        conn.connect()
        logger.info("Connected!")
        
        # Check if migration manager is initialized
        if conn._migration_manager is None:
            logger.warning("Migration manager not initialized. The server might not support connection migration.")
            return
            
        # Get active paths
        active_paths = conn._multipath_manager.get_active_paths()
        logger.info(f"Active paths: {len(active_paths)}")
        
        for i, path in enumerate(active_paths):
            logger.info(f"  Path {i+1}: {path.local_addr} -> {path.remote_addr}")
            
        # Make a request
        logger.info("\nSending request...")
        start_time = time.time()
        response = conn.request("GET", "/")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"Status: {response.status}")
        logger.info(f"Headers: {dict(response.headers)}")
        logger.info(f"Body length: {len(response.data)} bytes")
        
        # Simulate a network change
        logger.info("\nSimulating network change...")
        
        # Handle the network change
        if conn.handle_network_change():
            logger.info("Connection migrated successfully!")
        else:
            logger.info("Connection migration not performed.")
            
        # Get active paths after migration
        active_paths = conn._multipath_manager.get_active_paths()
        logger.info(f"Active paths after migration: {len(active_paths)}")
        
        for i, path in enumerate(active_paths):
            logger.info(f"  Path {i+1}: {path.local_addr} -> {path.remote_addr}")
            
        # Make another request after migration
        logger.info("\nSending another request after migration...")
        start_time = time.time()
        response = conn.request("GET", "/cdn-cgi/trace")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"Status: {response.status}")
        logger.info(f"Body:\n{response.data.decode()}")
        
        # Manually trigger migration
        logger.info("\nManually triggering migration...")
        try:
            if conn.migrate_connection():
                logger.info("Manual migration successful!")
            else:
                logger.info("Manual migration failed.")
        except Exception as e:
            logger.error(f"Migration error: {e}")
            
        # Check migration history
        if hasattr(conn._migration_manager, "get_migration_history"):
            history = conn._migration_manager.get_migration_history()
            logger.info(f"\nMigration history: {len(history)} events")
            
            for i, event in enumerate(history):
                logger.info(f"  Migration {i+1}:")
                logger.info(f"    Trigger: {event.trigger.name}")
                logger.info(f"    Success: {event.success}")
                logger.info(f"    Duration: {event.duration:.3f} seconds")
                if event.old_path:
                    logger.info(f"    Old path: {event.old_path.local_addr} -> {event.old_path.remote_addr}")
                if event.new_path:
                    logger.info(f"    New path: {event.new_path.local_addr} -> {event.new_path.remote_addr}")
                    
        # Close the connection
        logger.info("\nClosing connection...")
        conn.close()
        logger.info("Connection closed")
        
    except ImportError as e:
        logger.error(f"HTTP/3 support not available: {e}")
        logger.error("Install aioquic with: pip install aioquic")
    except Exception as e:
        logger.error(f"Error: {e}")


def main():
    """Run the HTTP/3 connection migration example."""
    connection_migration_example()


if __name__ == "__main__":
    main()
