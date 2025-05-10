"""
HTTP/2 Flow Control implementation for urllib4.

This module provides optimized flow control mechanisms for HTTP/2 connections,
improving performance by managing window sizes adaptively.
"""

from __future__ import annotations

import logging
import threading
import time
import typing
from enum import Enum, auto

if typing.TYPE_CHECKING:
    import h2.connection  # type: ignore[import-untyped]

log = logging.getLogger(__name__)


class FlowControlStrategy(Enum):
    """Strategies for HTTP/2 flow control window management."""
    
    # Fixed window size, never changes
    FIXED = auto()
    
    # Increases window size based on throughput
    ADAPTIVE = auto()
    
    # Aggressive window size increases for high bandwidth
    AGGRESSIVE = auto()


class WindowManager:
    """
    Manages HTTP/2 flow control windows adaptively.
    
    This class monitors data flow and adjusts window sizes to optimize
    throughput based on network conditions.
    """
    
    # Default initial window size (64KB)
    DEFAULT_INITIAL_WINDOW_SIZE = 65535
    
    # Maximum window size (16MB)
    MAX_WINDOW_SIZE = 16 * 1024 * 1024
    
    def __init__(
        self,
        strategy: FlowControlStrategy = FlowControlStrategy.ADAPTIVE,
        initial_window_size: int = DEFAULT_INITIAL_WINDOW_SIZE,
    ) -> None:
        """
        Initialize a new WindowManager.
        
        :param strategy: The flow control strategy to use
        :param initial_window_size: Initial window size in bytes
        """
        self.strategy = strategy
        self.current_window_size = initial_window_size
        self.target_window_size = initial_window_size
        
        # Metrics for adaptive strategies
        self._bytes_received = 0
        self._last_adjustment_time = time.monotonic()
        self._throughput_samples: list[float] = []
        self._lock = threading.Lock()
    
    def record_data_received(self, bytes_count: int) -> None:
        """
        Record data received for throughput calculation.
        
        :param bytes_count: Number of bytes received
        """
        if self.strategy == FlowControlStrategy.FIXED:
            return
            
        with self._lock:
            self._bytes_received += bytes_count
            
            # Check if we should recalculate window size
            current_time = time.monotonic()
            elapsed = current_time - self._last_adjustment_time
            
            # Adjust every second
            if elapsed >= 1.0:
                throughput = self._bytes_received / elapsed  # bytes/second
                self._throughput_samples.append(throughput)
                
                # Keep only the last 5 samples
                if len(self._throughput_samples) > 5:
                    self._throughput_samples.pop(0)
                
                self._adjust_window_size()
                
                # Reset metrics
                self._bytes_received = 0
                self._last_adjustment_time = current_time
    
    def _adjust_window_size(self) -> None:
        """Adjust the target window size based on throughput metrics."""
        if not self._throughput_samples:
            return
            
        # Calculate average throughput
        avg_throughput = sum(self._throughput_samples) / len(self._throughput_samples)
        
        if self.strategy == FlowControlStrategy.ADAPTIVE:
            # Adaptive strategy: window size should be ~2x the throughput
            # This gives us about 2 seconds worth of data in the window
            new_size = int(avg_throughput * 2)
            
            # Constrain growth/shrinkage rate
            if new_size > self.target_window_size:
                # Growing: at most double
                self.target_window_size = min(
                    new_size, 
                    self.target_window_size * 2
                )
            else:
                # Shrinking: at most halve
                self.target_window_size = max(
                    new_size, 
                    self.target_window_size // 2
                )
                
        elif self.strategy == FlowControlStrategy.AGGRESSIVE:
            # Aggressive strategy: window size should be ~4x the throughput
            new_size = int(avg_throughput * 4)
            self.target_window_size = new_size
        
        # Ensure we don't exceed maximum window size
        self.target_window_size = min(self.target_window_size, self.MAX_WINDOW_SIZE)
        
        # Ensure we don't go below the initial window size
        self.target_window_size = max(
            self.target_window_size, 
            self.DEFAULT_INITIAL_WINDOW_SIZE
        )
        
        log.debug(
            "Adjusted target window size to %d bytes (avg throughput: %d bytes/sec)",
            self.target_window_size,
            int(avg_throughput)
        )
    
    def get_window_update_size(self) -> int:
        """
        Calculate how much to increase the window by.
        
        :return: The number of bytes to increase the window by
        """
        with self._lock:
            if self.current_window_size >= self.target_window_size:
                return 0
                
            update_size = self.target_window_size - self.current_window_size
            self.current_window_size = self.target_window_size
            return update_size
    
    def apply_to_connection(self, conn: "h2.connection.H2Connection") -> None:
        """
        Apply window settings to an H2Connection.
        
        :param conn: The H2Connection to apply settings to
        """
        # Update the connection-level window if needed
        update_size = self.get_window_update_size()
        if update_size > 0:
            conn.increment_flow_control_window(update_size)
            log.debug("Increased connection flow control window by %d bytes", update_size)


class StreamWindowManager(WindowManager):
    """
    Manages HTTP/2 flow control windows for individual streams.
    
    This extends WindowManager to track and optimize windows for
    multiple concurrent streams.
    """
    
    def __init__(
        self,
        strategy: FlowControlStrategy = FlowControlStrategy.ADAPTIVE,
        initial_window_size: int = WindowManager.DEFAULT_INITIAL_WINDOW_SIZE,
    ) -> None:
        """
        Initialize a new StreamWindowManager.
        
        :param strategy: The flow control strategy to use
        :param initial_window_size: Initial window size in bytes
        """
        super().__init__(strategy, initial_window_size)
        self._stream_windows: dict[int, int] = {}
        
    def record_stream_data_received(self, stream_id: int, bytes_count: int) -> None:
        """
        Record data received on a specific stream.
        
        :param stream_id: The stream ID
        :param bytes_count: Number of bytes received
        """
        # Record for overall connection metrics
        self.record_data_received(bytes_count)
        
        # Initialize stream window if not present
        with self._lock:
            if stream_id not in self._stream_windows:
                self._stream_windows[stream_id] = self.current_window_size
    
    def get_stream_window_update_size(self, stream_id: int) -> int:
        """
        Calculate how much to increase a stream window by.
        
        :param stream_id: The stream ID
        :return: The number of bytes to increase the window by
        """
        with self._lock:
            if stream_id not in self._stream_windows:
                self._stream_windows[stream_id] = self.current_window_size
                return 0
                
            current = self._stream_windows[stream_id]
            if current >= self.target_window_size:
                return 0
                
            update_size = self.target_window_size - current
            self._stream_windows[stream_id] = self.target_window_size
            return update_size
    
    def apply_to_stream(
        self, conn: "h2.connection.H2Connection", stream_id: int
    ) -> None:
        """
        Apply window settings to a specific stream.
        
        :param conn: The H2Connection to apply settings to
        :param stream_id: The stream ID to update
        """
        update_size = self.get_stream_window_update_size(stream_id)
        if update_size > 0:
            conn.increment_flow_control_window(update_size, stream_id=stream_id)
            log.debug(
                "Increased stream %d flow control window by %d bytes", 
                stream_id, 
                update_size
            )
