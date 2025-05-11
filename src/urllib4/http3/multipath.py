"""
Multipath QUIC support for urllib4.

This module provides support for Multipath QUIC, which allows using multiple
network paths simultaneously for improved performance and reliability.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union

log = logging.getLogger(__name__)

# Import aioquic conditionally to avoid hard dependency
try:
    import aioquic
    import aioquic.quic.connection
    import aioquic.quic.events
    
    AIOQUIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    AIOQUIC_AVAILABLE = False


class PathStatus(Enum):
    """Status of a network path."""
    
    UNKNOWN = auto()
    VALIDATING = auto()
    ACTIVE = auto()
    STANDBY = auto()
    FAILED = auto()


@dataclass
class PathMetrics:
    """
    Metrics for a network path.
    
    This class tracks various metrics about a network path,
    such as RTT, loss rate, and bandwidth.
    """
    
    # RTT metrics (in milliseconds)
    min_rtt: Optional[float] = None
    max_rtt: Optional[float] = None
    smoothed_rtt: Optional[float] = None
    rtt_variance: Optional[float] = None
    
    # Loss metrics
    loss_rate: float = 0.0
    
    # Bandwidth metrics (in bytes per second)
    bandwidth: Optional[float] = None
    
    # Congestion metrics
    congestion_window: Optional[int] = None
    bytes_in_flight: int = 0
    
    # Packet counts
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    
    # Timestamps
    last_packet_sent_time: Optional[float] = None
    last_packet_received_time: Optional[float] = None
    
    def update_rtt(self, rtt: float) -> None:
        """
        Update RTT metrics.
        
        :param rtt: The measured RTT in milliseconds
        """
        if self.min_rtt is None or rtt < self.min_rtt:
            self.min_rtt = rtt
            
        if self.max_rtt is None or rtt > self.max_rtt:
            self.max_rtt = rtt
            
        if self.smoothed_rtt is None:
            self.smoothed_rtt = rtt
            self.rtt_variance = rtt / 2
        else:
            # Update smoothed RTT and RTT variance using the algorithm from RFC 6298
            self.rtt_variance = 0.75 * self.rtt_variance + 0.25 * abs(self.smoothed_rtt - rtt)
            self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * rtt
            
    def update_loss_rate(self, lost: int, total: int) -> None:
        """
        Update loss rate.
        
        :param lost: The number of lost packets
        :param total: The total number of packets
        """
        if total > 0:
            # Exponential moving average with alpha=0.1
            new_loss_rate = lost / total
            self.loss_rate = 0.9 * self.loss_rate + 0.1 * new_loss_rate
            
    def update_bandwidth(self, bytes_received: int, elapsed: float) -> None:
        """
        Update bandwidth estimate.
        
        :param bytes_received: The number of bytes received
        :param elapsed: The elapsed time in seconds
        """
        if elapsed > 0:
            # Calculate bandwidth in bytes per second
            bw = bytes_received / elapsed
            
            if self.bandwidth is None:
                self.bandwidth = bw
            else:
                # Exponential moving average with alpha=0.1
                self.bandwidth = 0.9 * self.bandwidth + 0.1 * bw
                
    def packet_sent(self, size: int) -> None:
        """
        Record a sent packet.
        
        :param size: The size of the packet in bytes
        """
        self.packets_sent += 1
        self.bytes_in_flight += size
        self.last_packet_sent_time = time.time()
        
    def packet_received(self, size: int) -> None:
        """
        Record a received packet.
        
        :param size: The size of the packet in bytes
        """
        self.packets_received += 1
        self.last_packet_received_time = time.time()
        
    def packet_lost(self, size: int) -> None:
        """
        Record a lost packet.
        
        :param size: The size of the packet in bytes
        """
        self.packets_lost += 1
        self.bytes_in_flight -= size
        
    def packet_acknowledged(self, size: int) -> None:
        """
        Record an acknowledged packet.
        
        :param size: The size of the packet in bytes
        """
        self.bytes_in_flight -= size


class NetworkPath:
    """
    Represents a network path for Multipath QUIC.
    
    This class encapsulates a network path, including its local and remote
    addresses, socket, and metrics.
    """
    
    def __init__(
        self,
        path_id: int,
        local_addr: Tuple[str, int],
        remote_addr: Tuple[str, int],
        socket: Optional[socket.socket] = None,
    ) -> None:
        """
        Initialize a new NetworkPath.
        
        :param path_id: The path ID
        :param local_addr: The local address (IP, port)
        :param remote_addr: The remote address (IP, port)
        :param socket: The socket for this path
        """
        self.path_id = path_id
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.socket = socket
        
        self.status = PathStatus.UNKNOWN
        self.metrics = PathMetrics()
        self.last_activity = time.time()
        
    def is_active(self) -> bool:
        """
        Check if the path is active.
        
        :return: True if the path is active
        """
        return self.status == PathStatus.ACTIVE
        
    def is_usable(self) -> bool:
        """
        Check if the path is usable.
        
        :return: True if the path is usable
        """
        return self.status in (PathStatus.ACTIVE, PathStatus.STANDBY)
        
    def send(self, data: bytes) -> int:
        """
        Send data on this path.
        
        :param data: The data to send
        :return: The number of bytes sent
        :raises OSError: If the socket is not available or an error occurs
        """
        if self.socket is None:
            raise OSError("Socket not available")
            
        bytes_sent = self.socket.sendto(data, self.remote_addr)
        self.metrics.packet_sent(len(data))
        self.last_activity = time.time()
        
        return bytes_sent
        
    def receive(self, buffer_size: int = 2048) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data on this path.
        
        :param buffer_size: The buffer size
        :return: The received data and the sender address
        :raises OSError: If the socket is not available or an error occurs
        """
        if self.socket is None:
            raise OSError("Socket not available")
            
        data, addr = self.socket.recvfrom(buffer_size)
        self.metrics.packet_received(len(data))
        self.last_activity = time.time()
        
        return data, addr
        
    def close(self) -> None:
        """Close the path."""
        if self.socket is not None:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
            
        self.status = PathStatus.FAILED


class MultipathManager:
    """
    Manages multiple network paths for Multipath QUIC.
    
    This class discovers and manages multiple network paths for a QUIC
    connection, allowing for improved performance and reliability.
    """
    
    def __init__(
        self,
        quic_connection: "aioquic.quic.connection.QuicConnection",
        max_paths: int = 4,
    ) -> None:
        """
        Initialize a new MultipathManager.
        
        :param quic_connection: The QUIC connection
        :param max_paths: The maximum number of paths to use
        """
        if not AIOQUIC_AVAILABLE:
            raise ImportError(
                "Multipath QUIC support requires the aioquic package. "
                "Install with: pip install aioquic"
            )
            
        self.quic_connection = quic_connection
        self.max_paths = max_paths
        
        self.paths: Dict[int, NetworkPath] = {}
        self.primary_path_id: Optional[int] = None
        
        self._lock = threading.RLock()
        self._next_path_id = 0
        
    def add_path(
        self,
        local_addr: Tuple[str, int],
        remote_addr: Tuple[str, int],
        socket: Optional[socket.socket] = None,
    ) -> int:
        """
        Add a new path.
        
        :param local_addr: The local address (IP, port)
        :param remote_addr: The remote address (IP, port)
        :param socket: The socket for this path
        :return: The path ID
        """
        with self._lock:
            # Check if we've reached the maximum number of paths
            if len(self.paths) >= self.max_paths:
                raise ValueError(f"Maximum number of paths ({self.max_paths}) reached")
                
            # Create a new path ID
            path_id = self._next_path_id
            self._next_path_id += 1
            
            # Create a new socket if not provided
            if socket is None:
                socket = self._create_socket(local_addr)
                
            # Create the path
            path = NetworkPath(path_id, local_addr, remote_addr, socket)
            self.paths[path_id] = path
            
            # Set as primary path if this is the first path
            if self.primary_path_id is None:
                self.primary_path_id = path_id
                path.status = PathStatus.ACTIVE
            else:
                path.status = PathStatus.STANDBY
                
            log.debug(f"Added path {path_id}: {local_addr} -> {remote_addr}")
            
            return path_id
            
    def remove_path(self, path_id: int) -> None:
        """
        Remove a path.
        
        :param path_id: The path ID
        """
        with self._lock:
            if path_id in self.paths:
                path = self.paths[path_id]
                path.close()
                del self.paths[path_id]
                
                # If this was the primary path, select a new one
                if self.primary_path_id == path_id:
                    self._select_primary_path()
                    
                log.debug(f"Removed path {path_id}")
                
    def _create_socket(self, local_addr: Tuple[str, int]) -> socket.socket:
        """
        Create a socket for a path.
        
        :param local_addr: The local address (IP, port)
        :return: The created socket
        """
        # Determine socket family based on the address
        if ":" in local_addr[0]:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
            
        # Create the socket
        sock = socket.socket(family, socket.SOCK_DGRAM)
        
        # Bind to the local address
        sock.bind(local_addr)
        
        return sock
        
    def _select_primary_path(self) -> None:
        """Select a new primary path."""
        if not self.paths:
            self.primary_path_id = None
            return
            
        # Find the best path based on metrics
        best_path_id = None
        best_score = float("-inf")
        
        for path_id, path in self.paths.items():
            if path.is_usable():
                # Calculate a score based on RTT, loss rate, and bandwidth
                score = 0.0
                
                if path.metrics.smoothed_rtt is not None:
                    # Lower RTT is better
                    score -= path.metrics.smoothed_rtt
                    
                # Lower loss rate is better
                score -= path.metrics.loss_rate * 1000
                
                if path.metrics.bandwidth is not None:
                    # Higher bandwidth is better
                    score += path.metrics.bandwidth / 1000
                    
                if score > best_score:
                    best_score = score
                    best_path_id = path_id
                    
        if best_path_id is not None:
            self.primary_path_id = best_path_id
            self.paths[best_path_id].status = PathStatus.ACTIVE
            log.debug(f"Selected path {best_path_id} as primary")
        else:
            self.primary_path_id = None
            
    def get_primary_path(self) -> Optional[NetworkPath]:
        """
        Get the primary path.
        
        :return: The primary path, or None if no primary path is available
        """
        if self.primary_path_id is None:
            return None
            
        return self.paths.get(self.primary_path_id)
        
    def get_active_paths(self) -> List[NetworkPath]:
        """
        Get all active paths.
        
        :return: List of active paths
        """
        return [path for path in self.paths.values() if path.is_active()]
        
    def distribute_data(self, data: bytes) -> Dict[int, bytes]:
        """
        Distribute data across multiple paths.
        
        :param data: The data to distribute
        :return: Dictionary mapping path IDs to data chunks
        """
        active_paths = self.get_active_paths()
        if not active_paths:
            # No active paths, use primary path if available
            primary_path = self.get_primary_path()
            if primary_path is not None:
                return {primary_path.path_id: data}
            return {}
            
        # For now, just send all data on the primary path
        # In a real implementation, we would distribute the data
        # across multiple paths based on their metrics
        primary_path = self.get_primary_path()
        if primary_path is not None:
            return {primary_path.path_id: data}
            
        # Fallback: use the first active path
        return {active_paths[0].path_id: data}
        
    def update_path_metrics(
        self,
        path_id: int,
        rtt: Optional[float] = None,
        lost: Optional[int] = None,
        total: Optional[int] = None,
        bytes_received: Optional[int] = None,
        elapsed: Optional[float] = None,
    ) -> None:
        """
        Update metrics for a path.
        
        :param path_id: The path ID
        :param rtt: The measured RTT in milliseconds
        :param lost: The number of lost packets
        :param total: The total number of packets
        :param bytes_received: The number of bytes received
        :param elapsed: The elapsed time in seconds
        """
        with self._lock:
            if path_id in self.paths:
                path = self.paths[path_id]
                
                if rtt is not None:
                    path.metrics.update_rtt(rtt)
                    
                if lost is not None and total is not None:
                    path.metrics.update_loss_rate(lost, total)
                    
                if bytes_received is not None and elapsed is not None:
                    path.metrics.update_bandwidth(bytes_received, elapsed)
                    
    def close_all_paths(self) -> None:
        """Close all paths."""
        with self._lock:
            for path in self.paths.values():
                path.close()
                
            self.paths.clear()
            self.primary_path_id = None
