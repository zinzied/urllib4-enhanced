"""
HTTP/2 Settings management for urllib4.

This module provides optimized HTTP/2 settings configuration for different
network conditions and usage patterns.
"""

from __future__ import annotations

import enum
import logging
import typing
from dataclasses import dataclass
from enum import Enum, auto

if typing.TYPE_CHECKING:
    import h2.connection  # type: ignore[import-untyped]
    import h2.settings  # type: ignore[import-untyped]

log = logging.getLogger(__name__)


class ConnectionProfile(Enum):
    """Predefined connection profiles for different network conditions."""
    
    # Default balanced settings
    BALANCED = auto()
    
    # Optimized for high-bandwidth, low-latency connections
    HIGH_PERFORMANCE = auto()
    
    # Optimized for mobile or high-latency connections
    MOBILE = auto()
    
    # Optimized for low memory usage
    LOW_MEMORY = auto()
    
    # Optimized for many concurrent streams
    HIGH_CONCURRENCY = auto()


@dataclass
class HTTP2Settings:
    """
    HTTP/2 settings configuration.
    
    This class represents the various settings that can be configured
    for an HTTP/2 connection.
    """
    
    # Maximum number of concurrent streams
    max_concurrent_streams: int = 100
    
    # Initial window size
    initial_window_size: int = 65535
    
    # Maximum frame size
    max_frame_size: int = 16384
    
    # Header table size for HPACK
    header_table_size: int = 4096
    
    # Whether to enable push
    enable_push: bool = True
    
    # Maximum header list size
    max_header_list_size: typing.Optional[int] = None
    
    def to_h2_settings(self) -> dict[int, int]:
        """
        Convert to h2 settings dictionary.
        
        :return: Dictionary of settings IDs to values
        """
        import h2.settings
        
        settings = {
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams,
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: self.initial_window_size,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: self.max_frame_size,
            h2.settings.SettingCodes.HEADER_TABLE_SIZE: self.header_table_size,
            h2.settings.SettingCodes.ENABLE_PUSH: int(self.enable_push),
        }
        
        if self.max_header_list_size is not None:
            settings[h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE] = self.max_header_list_size
            
        return settings
    
    def apply_to_connection(self, conn: "h2.connection.H2Connection") -> None:
        """
        Apply these settings to an H2Connection.
        
        :param conn: The H2Connection to apply settings to
        """
        conn.update_settings(self.to_h2_settings())
        log.debug("Applied HTTP/2 settings: %r", self.to_h2_settings())


class SettingsManager:
    """
    Manages HTTP/2 settings for different connection profiles.
    
    This class provides predefined settings for different network conditions
    and usage patterns.
    """
    
    @staticmethod
    def get_settings(profile: ConnectionProfile = ConnectionProfile.BALANCED) -> HTTP2Settings:
        """
        Get HTTP/2 settings for a specific connection profile.
        
        :param profile: The connection profile to use
        :return: HTTP2Settings configured for the profile
        """
        if profile == ConnectionProfile.BALANCED:
            return HTTP2Settings(
                max_concurrent_streams=100,
                initial_window_size=65535,
                max_frame_size=16384,
                header_table_size=4096,
                enable_push=True,
            )
            
        elif profile == ConnectionProfile.HIGH_PERFORMANCE:
            return HTTP2Settings(
                max_concurrent_streams=256,
                initial_window_size=10 * 1024 * 1024,  # 10MB
                max_frame_size=16384,
                header_table_size=16384,
                enable_push=True,
            )
            
        elif profile == ConnectionProfile.MOBILE:
            return HTTP2Settings(
                max_concurrent_streams=32,
                initial_window_size=65535,
                max_frame_size=16384,
                header_table_size=4096,
                enable_push=False,  # Disable push to save bandwidth
            )
            
        elif profile == ConnectionProfile.LOW_MEMORY:
            return HTTP2Settings(
                max_concurrent_streams=32,
                initial_window_size=65535,
                max_frame_size=16384,
                header_table_size=1024,  # Smaller header table
                enable_push=False,
                max_header_list_size=8192,  # Limit header size
            )
            
        elif profile == ConnectionProfile.HIGH_CONCURRENCY:
            return HTTP2Settings(
                max_concurrent_streams=1000,
                initial_window_size=1 * 1024 * 1024,  # 1MB
                max_frame_size=16384,
                header_table_size=8192,
                enable_push=True,
            )
            
        else:
            # Default to balanced if unknown profile
            return HTTP2Settings()


class DynamicSettingsManager:
    """
    Dynamically adjusts HTTP/2 settings based on connection performance.
    
    This class monitors connection metrics and adjusts settings to
    optimize performance.
    """
    
    def __init__(
        self, 
        initial_profile: ConnectionProfile = ConnectionProfile.BALANCED
    ) -> None:
        """
        Initialize a new DynamicSettingsManager.
        
        :param initial_profile: The initial connection profile to use
        """
        self.current_profile = initial_profile
        self.current_settings = SettingsManager.get_settings(initial_profile)
        
        # Metrics for adaptive adjustments
        self._rtt_samples: list[float] = []
        self._throughput_samples: list[float] = []
        self._error_count = 0
        
    def record_rtt(self, rtt_seconds: float) -> None:
        """
        Record a round-trip time measurement.
        
        :param rtt_seconds: The measured RTT in seconds
        """
        self._rtt_samples.append(rtt_seconds)
        if len(self._rtt_samples) > 10:
            self._rtt_samples.pop(0)
        self._maybe_adjust_settings()
        
    def record_throughput(self, bytes_per_second: float) -> None:
        """
        Record a throughput measurement.
        
        :param bytes_per_second: The measured throughput in bytes/second
        """
        self._throughput_samples.append(bytes_per_second)
        if len(self._throughput_samples) > 10:
            self._throughput_samples.pop(0)
        self._maybe_adjust_settings()
        
    def record_error(self) -> None:
        """Record a connection or stream error."""
        self._error_count += 1
        self._maybe_adjust_settings()
        
    def _maybe_adjust_settings(self) -> None:
        """
        Potentially adjust settings based on collected metrics.
        
        This method analyzes the collected performance metrics and
        may switch to a different connection profile if appropriate.
        """
        # Need enough samples to make a decision
        if len(self._rtt_samples) < 5 or len(self._throughput_samples) < 5:
            return
            
        avg_rtt = sum(self._rtt_samples) / len(self._rtt_samples)
        avg_throughput = sum(self._throughput_samples) / len(self._throughput_samples)
        
        # High latency detection
        high_latency = avg_rtt > 0.5  # 500ms
        
        # High bandwidth detection
        high_bandwidth = avg_throughput > 1 * 1024 * 1024  # 1MB/s
        
        # Error rate detection
        high_error_rate = self._error_count > 5
        
        # Decision logic
        new_profile = self.current_profile
        
        if high_latency and not high_bandwidth:
            new_profile = ConnectionProfile.MOBILE
        elif high_bandwidth and not high_latency:
            new_profile = ConnectionProfile.HIGH_PERFORMANCE
        elif high_error_rate:
            # If seeing many errors, go conservative
            new_profile = ConnectionProfile.LOW_MEMORY
        else:
            # Default to balanced
            new_profile = ConnectionProfile.BALANCED
            
        # Apply new profile if changed
        if new_profile != self.current_profile:
            self.current_profile = new_profile
            self.current_settings = SettingsManager.get_settings(new_profile)
            log.info("Switched to HTTP/2 profile: %s", new_profile.name)
            
        # Reset error count after adjustment
        self._error_count = 0
