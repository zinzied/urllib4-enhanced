"""
HTTP/3 and QUIC settings for urllib4.

This module provides settings classes for HTTP/3 and QUIC connections.
"""

from __future__ import annotations

import enum
import logging
import typing
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union

log = logging.getLogger(__name__)


class QUICVersion(Enum):
    """QUIC protocol versions."""
    
    DRAFT_29 = auto()
    DRAFT_32 = auto()
    VERSION_1 = auto()
    VERSION_2 = auto()


@dataclass
class QUICSettings:
    """
    QUIC connection settings.
    
    This class encapsulates settings for QUIC connections.
    """
    
    # QUIC versions to support, in order of preference
    versions: List[QUICVersion] = field(
        default_factory=lambda: [
            QUICVersion.VERSION_1,
            QUICVersion.VERSION_2,
            QUICVersion.DRAFT_29,
        ]
    )
    
    # Maximum packet size
    max_datagram_size: int = 1350
    
    # Connection flow control
    initial_max_data: int = 10 * 1024 * 1024  # 10 MB
    
    # Stream flow control
    initial_max_stream_data_bidi_local: int = 1 * 1024 * 1024  # 1 MB
    initial_max_stream_data_bidi_remote: int = 1 * 1024 * 1024  # 1 MB
    initial_max_stream_data_uni: int = 1 * 1024 * 1024  # 1 MB
    
    # Stream concurrency
    initial_max_streams_bidi: int = 100
    initial_max_streams_uni: int = 100
    
    # Idle timeout in milliseconds
    idle_timeout: int = 30 * 1000  # 30 seconds
    
    # Disable migration
    disable_migration: bool = False
    
    # Enable active connection migration
    enable_active_migration: bool = False
    
    # Congestion control algorithm
    congestion_control_algorithm: str = "cubic"
    
    # Multipath QUIC
    enable_multipath: bool = False
    max_paths: int = 4
    
    # 0-RTT
    enable_0rtt: bool = True
    
    # Datagram support
    enable_datagrams: bool = False
    
    # TLS settings
    alpn_protocols: List[str] = field(default_factory=lambda: ["h3"])
    
    def to_dict(self) -> Dict[str, Union[int, bool, List[str]]]:
        """
        Convert settings to a dictionary for aioquic.
        
        :return: Dictionary of settings
        """
        return {
            "max_datagram_size": self.max_datagram_size,
            "initial_max_data": self.initial_max_data,
            "initial_max_stream_data_bidi_local": self.initial_max_stream_data_bidi_local,
            "initial_max_stream_data_bidi_remote": self.initial_max_stream_data_bidi_remote,
            "initial_max_stream_data_uni": self.initial_max_stream_data_uni,
            "initial_max_streams_bidi": self.initial_max_streams_bidi,
            "initial_max_streams_uni": self.initial_max_streams_uni,
            "idle_timeout": self.idle_timeout,
            "alpn_protocols": self.alpn_protocols,
            "disable_active_migration": not self.enable_active_migration,
        }


@dataclass
class HTTP3Settings:
    """
    HTTP/3 connection settings.
    
    This class encapsulates settings for HTTP/3 connections.
    """
    
    # QUIC settings
    quic: QUICSettings = field(default_factory=QUICSettings)
    
    # HTTP/3 settings
    max_field_section_size: int = 16 * 1024  # 16 KB
    qpack_max_table_capacity: int = 4096
    qpack_blocked_streams: int = 100
    
    # Enable server push
    enable_push: bool = True
    
    # Connection pooling
    max_connections_per_host: int = 10
    
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0  # seconds
    
    # Timeout settings
    connect_timeout: float = 10.0  # seconds
    read_timeout: float = 30.0  # seconds
    
    # WebTransport settings
    enable_webtransport: bool = False
    
    def to_dict(self) -> Dict[str, Union[int, bool]]:
        """
        Convert settings to a dictionary for aioquic.
        
        :return: Dictionary of settings
        """
        return {
            "max_field_section_size": self.max_field_section_size,
            "qpack_max_table_capacity": self.qpack_max_table_capacity,
            "qpack_blocked_streams": self.qpack_blocked_streams,
            "enable_webtransport": self.enable_webtransport,
        }
