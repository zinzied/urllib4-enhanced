#!/usr/bin/env python3
"""
Example demonstrating enhanced WebSocket features in urllib4-enhanced.

This script shows how to use the enhanced WebSocket features in urllib4-enhanced,
including compression, subprotocols, and health monitoring.
"""

import json
import logging
import time
from typing import Dict, List, Optional

from urllib4.websocket import WebSocketConnection
from urllib4.websocket.backpressure import BackpressureSettings, BackpressureStrategy

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("websocket_example")


def echo_example():
    """Example using a simple echo WebSocket server."""
    logger.info("WebSocket Echo Example")
    logger.info("======================")
    
    # Create a WebSocket connection with compression enabled
    ws = WebSocketConnection(
        "wss://echo.websocket.org",
        enable_compression=True,
        compression_level=9,
        enable_health_monitoring=True,
        ping_interval=30.0,
        ping_timeout=5.0,
    )
    
    try:
        # Connect to the server
        logger.info("Connecting to echo.websocket.org...")
        ws.connect()
        logger.info("Connected!")
        
        # Send a text message
        text_message = "Hello, WebSocket!"
        logger.info(f"Sending text message: {text_message}")
        ws.send(text_message)
        
        # Receive the echo
        response = ws.receive(timeout=5.0)
        logger.info(f"Received text message: {response.text}")
        
        # Send a binary message
        binary_message = b"\x01\x02\x03\x04\x05"
        logger.info(f"Sending binary message: {binary_message.hex()}")
        ws.send(binary_message)
        
        # Receive the echo
        response = ws.receive(timeout=5.0)
        logger.info(f"Received binary message: {response.data.hex()}")
        
        # Send a ping
        logger.info("Sending ping...")
        ws.ping(b"ping data")
        
        # Wait a bit to allow for the pong to be processed
        time.sleep(1)
        
    finally:
        # Close the connection
        logger.info("Closing connection...")
        ws.close()
        logger.info("Connection closed")


def json_example():
    """Example using the JSON subprotocol."""
    logger.info("\nWebSocket JSON Subprotocol Example")
    logger.info("=================================")
    
    # Create a WebSocket connection with the JSON subprotocol
    ws = WebSocketConnection(
        "wss://echo.websocket.org",
        protocols=["json"],
        enable_compression=True,
    )
    
    try:
        # Connect to the server
        logger.info("Connecting to echo.websocket.org...")
        ws.connect()
        logger.info("Connected!")
        
        # Check if the JSON subprotocol was selected
        if ws._selected_protocol == "json":
            logger.info("JSON subprotocol selected")
            
            # Send a JSON object
            json_data = {
                "message": "Hello, JSON!",
                "numbers": [1, 2, 3, 4, 5],
                "nested": {
                    "key": "value",
                    "boolean": True,
                    "null": None,
                },
            }
            
            logger.info(f"Sending JSON data: {json_data}")
            ws.send(json_data)
            
            # Receive the echo
            response = ws.receive(timeout=5.0)
            
            if isinstance(response, dict):
                logger.info(f"Received decoded JSON: {response}")
            else:
                # If the server doesn't support the JSON subprotocol,
                # we'll get a raw message
                logger.info(f"Received raw message: {response.text}")
                
                # Try to decode it manually
                try:
                    decoded = json.loads(response.text)
                    logger.info(f"Manually decoded JSON: {decoded}")
                except Exception as e:
                    logger.error(f"Failed to decode JSON: {e}")
        else:
            logger.info(f"Server selected protocol: {ws._selected_protocol}")
            
            # Send a JSON string manually
            json_str = json.dumps({
                "message": "Hello, JSON!",
                "numbers": [1, 2, 3, 4, 5],
            })
            
            logger.info(f"Sending JSON string: {json_str}")
            ws.send(json_str)
            
            # Receive the echo
            response = ws.receive(timeout=5.0)
            logger.info(f"Received text message: {response.text}")
            
            # Try to decode it manually
            try:
                decoded = json.loads(response.text)
                logger.info(f"Manually decoded JSON: {decoded}")
            except Exception as e:
                logger.error(f"Failed to decode JSON: {e}")
                
    finally:
        # Close the connection
        logger.info("Closing connection...")
        ws.close()
        logger.info("Connection closed")


def backpressure_example():
    """Example demonstrating backpressure handling."""
    logger.info("\nWebSocket Backpressure Example")
    logger.info("=============================")
    
    # Create backpressure settings
    backpressure_settings = BackpressureSettings(
        max_queue_size=10,
        max_message_size=1024 * 1024,  # 1 MB
        strategy=BackpressureStrategy.BLOCK,
        max_block_time=5.0,
        rate_limit_enabled=True,
        rate_limit_messages=10,  # 10 messages per second
        rate_limit_bytes=1024 * 10,  # 10 KB per second
    )
    
    # Create a WebSocket connection with backpressure handling
    ws = WebSocketConnection(
        "wss://echo.websocket.org",
        backpressure_settings=backpressure_settings,
    )
    
    try:
        # Connect to the server
        logger.info("Connecting to echo.websocket.org...")
        ws.connect()
        logger.info("Connected!")
        
        # Send messages rapidly to trigger rate limiting
        logger.info("Sending messages rapidly to demonstrate rate limiting...")
        for i in range(20):
            message = f"Message {i}: " + "X" * 1000  # 1 KB message
            logger.info(f"Sending message {i}...")
            ws.send(message)
            
            # Try to receive the echo immediately
            try:
                response = ws.receive(timeout=0.1)
                logger.info(f"Received echo for message {i}")
            except Exception as e:
                logger.info(f"No immediate response: {e}")
                
        # Wait for all messages to be processed
        logger.info("Waiting for all messages to be processed...")
        time.sleep(5)
        
        # Try to receive any remaining echoes
        logger.info("Receiving remaining echoes...")
        try:
            while True:
                response = ws.receive(timeout=0.5)
                logger.info(f"Received message: {response.text[:20]}...")
        except Exception as e:
            logger.info(f"No more messages: {e}")
            
    finally:
        # Close the connection
        logger.info("Closing connection...")
        ws.close()
        logger.info("Connection closed")


def main():
    """Run the WebSocket examples."""
    echo_example()
    json_example()
    backpressure_example()


if __name__ == "__main__":
    main()
