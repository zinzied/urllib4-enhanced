#!/usr/bin/env python3
"""
Example demonstrating HTTP/3 support in urllib4-enhanced.

This script shows how to use the HTTP/3 support in urllib4-enhanced,
including making requests to HTTP/3-enabled servers.
"""

import logging
import time
from typing import Dict, List, Optional

import urllib4
from urllib4.http3 import HTTP3Connection, HTTP3Settings, QUICSettings, inject_into_urllib4

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("http3_example")


def direct_http3_request():
    """Example using HTTP3Connection directly."""
    logger.info("HTTP/3 Direct Connection Example")
    logger.info("===============================")
    
    # Create HTTP/3 settings
    quic_settings = QUICSettings(
        max_datagram_size=1350,
        initial_max_data=10 * 1024 * 1024,  # 10 MB
        initial_max_stream_data_bidi_local=1 * 1024 * 1024,  # 1 MB
        initial_max_stream_data_bidi_remote=1 * 1024 * 1024,  # 1 MB
        initial_max_streams_bidi=100,
        idle_timeout=30 * 1000,  # 30 seconds
        enable_0rtt=True,
    )
    
    http3_settings = HTTP3Settings(
        quic=quic_settings,
        max_field_section_size=16 * 1024,  # 16 KB
        enable_push=True,
    )
    
    try:
        # Create HTTP/3 connection
        logger.info("Creating HTTP/3 connection to cloudflare-quic.com...")
        conn = HTTP3Connection(
            "cloudflare-quic.com",
            settings=http3_settings,
        )
        
        # Connect to the server
        logger.info("Connecting...")
        conn.connect()
        logger.info("Connected!")
        
        # Make a request
        logger.info("Sending request...")
        start_time = time.time()
        response = conn.request("GET", "/")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"Status: {response.status}")
        logger.info(f"Headers: {dict(response.headers)}")
        logger.info(f"Body length: {len(response.data)} bytes")
        logger.info(f"First 100 bytes: {response.data[:100]}")
        
        # Make another request to demonstrate connection reuse
        logger.info("\nSending another request...")
        start_time = time.time()
        response = conn.request("GET", "/cdn-cgi/trace")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"Status: {response.status}")
        logger.info(f"Body:\n{response.data.decode()}")
        
        # Close the connection
        logger.info("Closing connection...")
        conn.close()
        logger.info("Connection closed")
        
    except ImportError as e:
        logger.error(f"HTTP/3 support not available: {e}")
        logger.error("Install aioquic with: pip install aioquic")
    except Exception as e:
        logger.error(f"Error: {e}")


def injected_http3_request():
    """Example using HTTP/3 through the injected urllib4 API."""
    logger.info("\nHTTP/3 Injected API Example")
    logger.info("==========================")
    
    try:
        # Inject HTTP/3 support into urllib4
        logger.info("Injecting HTTP/3 support...")
        inject_into_urllib4()
        
        # Create a pool manager
        http = urllib4.PoolManager()
        
        # Make a request to a server that supports HTTP/3
        logger.info("Making request to cloudflare-quic.com...")
        start_time = time.time()
        response = http.request("GET", "https://cloudflare-quic.com/")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"HTTP version: {response.version}")
        logger.info(f"Status: {response.status}")
        logger.info(f"Headers: {dict(response.headers)}")
        logger.info(f"Body length: {len(response.data)} bytes")
        
        # Make another request to demonstrate connection reuse
        logger.info("\nMaking another request...")
        start_time = time.time()
        response = http.request("GET", "https://cloudflare-quic.com/cdn-cgi/trace")
        elapsed = time.time() - start_time
        
        # Print response info
        logger.info(f"Response received in {elapsed:.3f} seconds")
        logger.info(f"HTTP version: {response.version}")
        logger.info(f"Status: {response.status}")
        logger.info(f"Body:\n{response.data.decode()}")
        
        # Extract HTTP/3 support from urllib4
        logger.info("Extracting HTTP/3 support...")
        from urllib4.http3 import extract_from_urllib4
        extract_from_urllib4()
        logger.info("HTTP/3 support extracted")
        
    except ImportError as e:
        logger.error(f"HTTP/3 support not available: {e}")
        logger.error("Install aioquic with: pip install aioquic")
    except Exception as e:
        logger.error(f"Error: {e}")


def zero_rtt_example():
    """Example demonstrating 0-RTT connection establishment."""
    logger.info("\nHTTP/3 0-RTT Example")
    logger.info("===================")
    
    try:
        # Create HTTP/3 settings with 0-RTT enabled
        quic_settings = QUICSettings(
            enable_0rtt=True,
        )
        
        http3_settings = HTTP3Settings(
            quic=quic_settings,
        )
        
        # First connection to get a session ticket
        logger.info("Creating first HTTP/3 connection to cloudflare-quic.com...")
        conn1 = HTTP3Connection(
            "cloudflare-quic.com",
            settings=http3_settings,
        )
        
        # Connect and make a request
        logger.info("Connecting and making first request...")
        start_time = time.time()
        conn1.connect()
        response = conn1.request("GET", "/")
        elapsed = time.time() - start_time
        
        logger.info(f"First request completed in {elapsed:.3f} seconds")
        logger.info(f"Status: {response.status}")
        
        # Get the session ticket
        session_ticket = conn1.session_ticket
        logger.info(f"Session ticket received: {session_ticket is not None}")
        
        # Close the first connection
        conn1.close()
        
        # Second connection using the session ticket
        if session_ticket:
            logger.info("\nCreating second HTTP/3 connection with session ticket...")
            conn2 = HTTP3Connection(
                "cloudflare-quic.com",
                settings=http3_settings,
                session_ticket=session_ticket,
            )
            
            # Connect and make a request
            logger.info("Connecting and making second request with 0-RTT...")
            start_time = time.time()
            conn2.connect()
            response = conn2.request("GET", "/")
            elapsed = time.time() - start_time
            
            logger.info(f"Second request completed in {elapsed:.3f} seconds")
            logger.info(f"Status: {response.status}")
            
            # Close the second connection
            conn2.close()
        else:
            logger.warning("No session ticket received, cannot demonstrate 0-RTT")
            
    except ImportError as e:
        logger.error(f"HTTP/3 support not available: {e}")
        logger.error("Install aioquic with: pip install aioquic")
    except Exception as e:
        logger.error(f"Error: {e}")


def main():
    """Run the HTTP/3 examples."""
    direct_http3_request()
    injected_http3_request()
    zero_rtt_example()


if __name__ == "__main__":
    main()
