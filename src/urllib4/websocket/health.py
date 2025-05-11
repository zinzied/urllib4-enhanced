"""
WebSocket connection health monitoring for urllib4.

This module provides utilities for monitoring the health of WebSocket
connections and handling backpressure.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from .protocol import WebSocketFrame, WebSocketFrameType

log = logging.getLogger(__name__)


class ConnectionState(Enum):
    """WebSocket connection state."""
    
    CONNECTING = auto()
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()


@dataclass
class ConnectionStats:
    """
    Statistics for a WebSocket connection.
    
    This class tracks various metrics about a WebSocket connection,
    such as message counts, bytes transferred, and latency.
    """
    
    # Message counts
    messages_sent: int = 0
    messages_received: int = 0
    
    # Frame counts
    frames_sent: int = 0
    frames_received: int = 0
    
    # Byte counts
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # Ping/pong metrics
    pings_sent: int = 0
    pongs_received: int = 0
    ping_timeouts: int = 0
    
    # Latency metrics (in milliseconds)
    min_latency: Optional[float] = None
    max_latency: Optional[float] = None
    avg_latency: Optional[float] = None
    
    # Error counts
    protocol_errors: int = 0
    
    # Timestamps
    connection_time: Optional[float] = None
    last_message_sent_time: Optional[float] = None
    last_message_received_time: Optional[float] = None
    
    def update_latency(self, latency: float) -> None:
        """
        Update latency metrics.
        
        :param latency: The measured latency in milliseconds
        """
        if self.min_latency is None or latency < self.min_latency:
            self.min_latency = latency
            
        if self.max_latency is None or latency > self.max_latency:
            self.max_latency = latency
            
        if self.avg_latency is None:
            self.avg_latency = latency
        else:
            # Exponential moving average with alpha=0.1
            self.avg_latency = 0.9 * self.avg_latency + 0.1 * latency
    
    def message_sent(self, size: int) -> None:
        """
        Record a sent message.
        
        :param size: The size of the message in bytes
        """
        self.messages_sent += 1
        self.bytes_sent += size
        self.last_message_sent_time = time.time()
    
    def message_received(self, size: int) -> None:
        """
        Record a received message.
        
        :param size: The size of the message in bytes
        """
        self.messages_received += 1
        self.bytes_received += size
        self.last_message_received_time = time.time()
    
    def frame_sent(self, size: int) -> None:
        """
        Record a sent frame.
        
        :param size: The size of the frame in bytes
        """
        self.frames_sent += 1
        self.bytes_sent += size
    
    def frame_received(self, size: int) -> None:
        """
        Record a received frame.
        
        :param size: The size of the frame in bytes
        """
        self.frames_received += 1
        self.bytes_received += size
    
    def ping_sent(self) -> None:
        """Record a sent ping."""
        self.pings_sent += 1
    
    def pong_received(self) -> None:
        """Record a received pong."""
        self.pongs_received += 1
    
    def ping_timeout(self) -> None:
        """Record a ping timeout."""
        self.ping_timeouts += 1
    
    def protocol_error(self) -> None:
        """Record a protocol error."""
        self.protocol_errors += 1
    
    def connected(self) -> None:
        """Record connection establishment."""
        self.connection_time = time.time()
    
    def get_idle_time(self) -> Optional[float]:
        """
        Get the time since the last message was sent or received.
        
        :return: The idle time in seconds, or None if no messages have been exchanged
        """
        if self.last_message_sent_time is None and self.last_message_received_time is None:
            return None
            
        last_time = max(
            self.last_message_sent_time or 0,
            self.last_message_received_time or 0
        )
        
        return time.time() - last_time
    
    def get_uptime(self) -> Optional[float]:
        """
        Get the connection uptime.
        
        :return: The uptime in seconds, or None if not connected
        """
        if self.connection_time is None:
            return None
            
        return time.time() - self.connection_time


class HealthMonitor:
    """
    Monitors the health of a WebSocket connection.
    
    This class periodically sends ping frames to check if the connection
    is still alive and tracks various metrics about the connection.
    """
    
    def __init__(
        self,
        ping_interval: float = 30.0,
        ping_timeout: float = 10.0,
        max_ping_timeouts: int = 2,
    ) -> None:
        """
        Initialize a new HealthMonitor.
        
        :param ping_interval: The interval between pings in seconds
        :param ping_timeout: The timeout for pong responses in seconds
        :param max_ping_timeouts: The maximum number of consecutive ping timeouts
        """
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.max_ping_timeouts = max_ping_timeouts
        
        self.stats = ConnectionStats()
        self.state = ConnectionState.CONNECTING
        
        self._ping_timer: Optional[threading.Timer] = None
        self._ping_data: Dict[bytes, float] = {}
        self._consecutive_timeouts = 0
        self._lock = threading.RLock()
        
        self._on_timeout_callback: Optional[Callable[[], None]] = None
    
    def start(self) -> None:
        """Start monitoring the connection."""
        with self._lock:
            self.stats.connected()
            self.state = ConnectionState.OPEN
            self._schedule_ping()
    
    def stop(self) -> None:
        """Stop monitoring the connection."""
        with self._lock:
            if self._ping_timer:
                self._ping_timer.cancel()
                self._ping_timer = None
                
            self.state = ConnectionState.CLOSED
    
    def set_timeout_callback(self, callback: Callable[[], None]) -> None:
        """
        Set a callback to be called when the connection times out.
        
        :param callback: The callback function
        """
        self._on_timeout_callback = callback
    
    def _schedule_ping(self) -> None:
        """Schedule the next ping."""
        if self.state != ConnectionState.OPEN:
            return
            
        self._ping_timer = threading.Timer(self.ping_interval, self._send_ping)
        self._ping_timer.daemon = True
        self._ping_timer.start()
    
    def _send_ping(self) -> None:
        """Send a ping frame."""
        if self.state != ConnectionState.OPEN:
            return
            
        # Generate random ping data
        import os
        ping_data = os.urandom(4)
        
        # Record the ping
        with self._lock:
            self._ping_data[ping_data] = time.time()
            self.stats.ping_sent()
            
        # Create a ping frame
        frame = WebSocketFrame.create_ping(ping_data)
        
        # Send the frame (this will be handled by the connection)
        if self._on_ping_callback:
            self._on_ping_callback(frame)
            
        # Schedule a timeout check
        threading.Timer(self.ping_timeout, self._check_pong_timeout, args=[ping_data]).start()
        
        # Schedule the next ping
        self._schedule_ping()
    
    def _check_pong_timeout(self, ping_data: bytes) -> None:
        """
        Check if a pong response has been received.
        
        :param ping_data: The ping data to check
        """
        with self._lock:
            if ping_data in self._ping_data:
                # No pong received
                del self._ping_data[ping_data]
                self.stats.ping_timeout()
                self._consecutive_timeouts += 1
                
                if self._consecutive_timeouts >= self.max_ping_timeouts:
                    log.warning(
                        "WebSocket connection timed out after %d consecutive ping timeouts",
                        self._consecutive_timeouts
                    )
                    
                    if self._on_timeout_callback:
                        self._on_timeout_callback()
    
    def handle_pong(self, pong_data: bytes) -> None:
        """
        Handle a pong frame.
        
        :param pong_data: The pong data
        """
        with self._lock:
            if pong_data in self._ping_data:
                # Calculate latency
                latency = (time.time() - self._ping_data[pong_data]) * 1000  # ms
                
                # Update stats
                self.stats.pong_received()
                self.stats.update_latency(latency)
                
                # Reset timeout counter
                self._consecutive_timeouts = 0
                
                # Remove from pending pings
                del self._ping_data[pong_data]
    
    def frame_sent(self, frame: WebSocketFrame, encoded_size: int) -> None:
        """
        Record a sent frame.
        
        :param frame: The frame that was sent
        :param encoded_size: The size of the encoded frame in bytes
        """
        self.stats.frame_sent(encoded_size)
        
        if frame.opcode in (WebSocketFrameType.TEXT, WebSocketFrameType.BINARY) and frame.fin:
            self.stats.message_sent(len(frame.payload))
    
    def frame_received(self, frame: WebSocketFrame, encoded_size: int) -> None:
        """
        Record a received frame.
        
        :param frame: The frame that was received
        :param encoded_size: The size of the encoded frame in bytes
        """
        self.stats.frame_received(encoded_size)
        
        if frame.opcode in (WebSocketFrameType.TEXT, WebSocketFrameType.BINARY) and frame.fin:
            self.stats.message_received(len(frame.payload))
            
        if frame.opcode == WebSocketFrameType.PONG:
            self.handle_pong(frame.payload)
    
    def protocol_error(self) -> None:
        """Record a protocol error."""
        self.stats.protocol_error()
    
    _on_ping_callback: Optional[Callable[[WebSocketFrame], None]] = None
    
    def set_ping_callback(self, callback: Callable[[WebSocketFrame], None]) -> None:
        """
        Set a callback to be called when a ping needs to be sent.
        
        :param callback: The callback function
        """
        self._on_ping_callback = callback
