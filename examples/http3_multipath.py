#!/usr/bin/env python3
"""
Example demonstrating Multipath QUIC support in urllib4-enhanced.

This script shows how to use the Multipath QUIC support in urllib4-enhanced,
which allows using multiple network paths simultaneously for improved
performance and reliability.
"""

import logging
import time
from typing import Dict, List, Optional

import urllib4
from urllib4.http3 import HTTP3Connection, HTTP3Settings, QUICSettings

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("http3_multipath_example")


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


def multipath_quic_example():
    """Example using Multipath QUIC."""
    logger.info("Multipath QUIC Example")
    logger.info("=====================")
    
    # Check if netifaces is available
    if not discover_network_interfaces():
        return
        
    # Create QUIC settings with multipath enabled
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
        logger.info("\nCreating HTTP/3 connection to cloudflare-quic.com with multipath enabled...")
        conn = HTTP3Connection(
            "cloudflare-quic.com",
            settings=http3_settings,
        )
        
        # Connect to the server
        logger.info("Connecting...")
        conn.connect()
        logger.info("Connected!")
        
        # Check if multipath manager is initialized
        if conn._multipath_manager is None:
            logger.warning("Multipath manager not initialized. The server might not support Multipath QUIC.")
        else:
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
        
        # Make another request to demonstrate path usage
        logger.info("\nSending another request...")
        start_time = time.time()
        response = conn.request("GET", "/cdn-cgi/trace")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"Status: {response.status}")
        logger.info(f"Body:\n{response.data.decode()}")
        
        # Check path metrics
        if conn._multipath_manager is not None:
            logger.info("\nPath metrics:")
            for path_id, path in conn._multipath_manager.paths.items():
                metrics = path.metrics
                logger.info(f"  Path {path_id} ({path.local_addr} -> {path.remote_addr}):")
                logger.info(f"    Status: {path.status}")
                logger.info(f"    RTT: {metrics.smoothed_rtt} ms")
                logger.info(f"    Loss rate: {metrics.loss_rate:.4f}")
                logger.info(f"    Packets sent: {metrics.packets_sent}")
                logger.info(f"    Packets received: {metrics.packets_received}")
                
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
    """Run the Multipath QUIC example."""
    multipath_quic_example()


if __name__ == "__main__":
    main()
