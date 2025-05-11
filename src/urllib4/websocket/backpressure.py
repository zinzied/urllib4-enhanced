"""
WebSocket backpressure handling for urllib4.

This module provides utilities for handling backpressure in WebSocket
connections, ensuring that messages are sent at a rate that the receiver
can handle.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from .protocol import WebSocketFrame, WebSocketFrameType

log = logging.getLogger(__name__)


class BackpressureStrategy(Enum):
    """Strategies for handling backpressure."""
    
    # Drop messages when the queue is full
    DROP = auto()
    
    # Block until there's space in the queue
    BLOCK = auto()
    
    # Apply backpressure to the sender
    APPLY = auto()


@dataclass
class BackpressureSettings:
    """Settings for backpressure handling."""
    
    # Maximum queue size
    max_queue_size: int = 1000
    
    # Maximum message size in bytes
    max_message_size: int = 1024 * 1024  # 1 MB
    
    # Strategy for handling backpressure
    strategy: BackpressureStrategy = BackpressureStrategy.BLOCK
    
    # Maximum time to block when using BLOCK strategy (in seconds)
    max_block_time: float = 10.0
    
    # Rate limiting settings
    rate_limit_enabled: bool = False
    rate_limit_messages: int = 100  # messages per second
    rate_limit_bytes: int = 1024 * 1024  # bytes per second


class BackpressureHandler:
    """
    Handles backpressure for WebSocket connections.
    
    This class ensures that messages are sent at a rate that the receiver
    can handle, using various strategies such as queuing, dropping, or
    applying backpressure to the sender.
    """
    
    def __init__(self, settings: Optional[BackpressureSettings] = None) -> None:
        """
        Initialize a new BackpressureHandler.
        
        :param settings: The backpressure settings
        """
        self.settings = settings or BackpressureSettings()
        
        # Message queue
        self.queue: queue.Queue[WebSocketFrame] = queue.Queue(self.settings.max_queue_size)
        
        # Rate limiting state
        self._message_count = 0
        self._byte_count = 0
        self._last_reset = time.time()
        
        # Worker thread
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
        
        # Callbacks
        self._on_send_callback: Optional[Callable[[WebSocketFrame], None]] = None
        self._on_drop_callback: Optional[Callable[[WebSocketFrame], None]] = None
        self._on_backpressure_callback: Optional[Callable[[], None]] = None
    
    def start(self) -> None:
        """Start the backpressure handler."""
        with self._lock:
            if self._running:
                return
                
            self._running = True
            self._worker_thread = threading.Thread(target=self._worker, daemon=True)
            self._worker_thread.start()
    
    def stop(self) -> None:
        """Stop the backpressure handler."""
        with self._lock:
            self._running = False
            
            if self._worker_thread:
                self._worker_thread.join(timeout=1.0)
                self._worker_thread = None
    
    def queue_frame(self, frame: WebSocketFrame) -> bool:
        """
        Queue a frame for sending.
        
        :param frame: The frame to queue
        :return: True if the frame was queued, False if it was dropped
        """
        # Check message size
        if len(frame.payload) > self.settings.max_message_size:
            log.warning(
                "Message size (%d bytes) exceeds maximum (%d bytes)",
                len(frame.payload),
                self.settings.max_message_size
            )
            
            if self._on_drop_callback:
                self._on_drop_callback(frame)
                
            return False
            
        # Handle backpressure based on strategy
        if self.settings.strategy == BackpressureStrategy.DROP:
            try:
                self.queue.put_nowait(frame)
                return True
            except queue.Full:
                log.warning("Message queue full, dropping message")
                
                if self._on_drop_callback:
                    self._on_drop_callback(frame)
                    
                return False
                
        elif self.settings.strategy == BackpressureStrategy.BLOCK:
            try:
                self.queue.put(frame, timeout=self.settings.max_block_time)
                return True
            except queue.Full:
                log.warning("Message queue full and block timeout exceeded, dropping message")
                
                if self._on_drop_callback:
                    self._on_drop_callback(frame)
                    
                return False
                
        elif self.settings.strategy == BackpressureStrategy.APPLY:
            if self.queue.full():
                log.warning("Message queue full, applying backpressure")
                
                if self._on_backpressure_callback:
                    self._on_backpressure_callback()
                    
                # Wait for space in the queue
                self.queue.put(frame)
                return True
            else:
                self.queue.put(frame)
                return True
                
        return False
    
    def _worker(self) -> None:
        """Worker thread that sends queued frames."""
        while self._running:
            try:
                # Get a frame from the queue
                frame = self.queue.get(timeout=0.1)
                
                # Apply rate limiting if enabled
                if self.settings.rate_limit_enabled:
                    self._apply_rate_limiting(frame)
                
                # Send the frame
                if self._on_send_callback:
                    self._on_send_callback(frame)
                    
                # Mark the task as done
                self.queue.task_done()
            except queue.Empty:
                # No frames to send
                pass
            except Exception as e:
                log.error("Error in backpressure worker: %s", e, exc_info=True)
    
    def _apply_rate_limiting(self, frame: WebSocketFrame) -> None:
        """
        Apply rate limiting to a frame.
        
        :param frame: The frame to rate limit
        """
        now = time.time()
        elapsed = now - self._last_reset
        
        # Reset counters if a second has passed
        if elapsed >= 1.0:
            self._message_count = 0
            self._byte_count = 0
            self._last_reset = now
            
        # Check if we've exceeded the rate limits
        if (
            self._message_count >= self.settings.rate_limit_messages or
            self._byte_count >= self.settings.rate_limit_bytes
        ):
            # Sleep for the remainder of the second
            sleep_time = 1.0 - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
                
                # Reset counters
                self._message_count = 0
                self._byte_count = 0
                self._last_reset = time.time()
                
        # Update counters
        self._message_count += 1
        self._byte_count += len(frame.payload)
    
    def set_send_callback(self, callback: Callable[[WebSocketFrame], None]) -> None:
        """
        Set a callback to be called when a frame is ready to be sent.
        
        :param callback: The callback function
        """
        self._on_send_callback = callback
    
    def set_drop_callback(self, callback: Callable[[WebSocketFrame], None]) -> None:
        """
        Set a callback to be called when a frame is dropped.
        
        :param callback: The callback function
        """
        self._on_drop_callback = callback
    
    def set_backpressure_callback(self, callback: Callable[[], None]) -> None:
        """
        Set a callback to be called when backpressure is applied.
        
        :param callback: The callback function
        """
        self._on_backpressure_callback = callback
