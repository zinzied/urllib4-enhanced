"""
HTTP/3 connection migration support for urllib4.

This module provides support for HTTP/3 connection migration, which allows
a connection to seamlessly transition between network interfaces or addresses
without disrupting the application.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union, Callable

from .multipath import MultipathManager, NetworkPath, PathStatus

log = logging.getLogger(__name__)

# Import aioquic conditionally to avoid hard dependency
try:
    import aioquic
    import aioquic.quic.connection
    import aioquic.quic.events
    
    AIOQUIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    AIOQUIC_AVAILABLE = False


class MigrationTrigger(Enum):
    """Triggers for connection migration."""
    
    NETWORK_CHANGE = auto()  # Network interface change detected
    PATH_DEGRADATION = auto()  # Current path performance degraded
    MANUAL = auto()  # Manually triggered by the application
    PEER_MIGRATION = auto()  # Peer-initiated migration


class MigrationEvent:
    """
    Event representing a connection migration.
    
    This class encapsulates information about a connection migration event.
    """
    
    def __init__(
        self,
        trigger: MigrationTrigger,
        old_path: Optional[NetworkPath] = None,
        new_path: Optional[NetworkPath] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """
        Initialize a new MigrationEvent.
        
        :param trigger: The trigger for the migration
        :param old_path: The old network path
        :param new_path: The new network path
        :param timestamp: The timestamp of the migration
        """
        self.trigger = trigger
        self.old_path = old_path
        self.new_path = new_path
        self.timestamp = timestamp or time.time()
        self.success = False
        self.error: Optional[Exception] = None
        self.duration: Optional[float] = None
        
    def complete(self, success: bool, error: Optional[Exception] = None) -> None:
        """
        Mark the migration as complete.
        
        :param success: Whether the migration was successful
        :param error: The error that occurred, if any
        """
        self.success = success
        self.error = error
        self.duration = time.time() - self.timestamp


@dataclass
class MigrationPolicy:
    """
    Policy for connection migration.
    
    This class defines when and how connection migration should be performed.
    """
    
    # Whether to enable automatic migration
    enable_auto_migration: bool = True
    
    # Minimum time between migrations (in seconds)
    min_migration_interval: float = 5.0
    
    # RTT threshold for path degradation (in milliseconds)
    rtt_degradation_threshold: float = 200.0
    
    # Loss rate threshold for path degradation
    loss_degradation_threshold: float = 0.05  # 5%
    
    # Whether to prefer the previous path after a network change
    prefer_previous_path: bool = True
    
    # Maximum number of migration attempts
    max_migration_attempts: int = 3
    
    # Timeout for migration attempts (in seconds)
    migration_timeout: float = 10.0


class MigrationManager:
    """
    Manages connection migration for HTTP/3.
    
    This class handles the migration of HTTP/3 connections between
    different network paths.
    """
    
    def __init__(
        self,
        quic_connection: "aioquic.quic.connection.QuicConnection",
        multipath_manager: MultipathManager,
        policy: Optional[MigrationPolicy] = None,
    ) -> None:
        """
        Initialize a new MigrationManager.
        
        :param quic_connection: The QUIC connection
        :param multipath_manager: The multipath manager
        :param policy: The migration policy
        """
        if not AIOQUIC_AVAILABLE:
            raise ImportError(
                "HTTP/3 connection migration requires the aioquic package. "
                "Install with: pip install aioquic"
            )
            
        self.quic_connection = quic_connection
        self.multipath_manager = multipath_manager
        self.policy = policy or MigrationPolicy()
        
        self._lock = threading.RLock()
        self._migration_history: List[MigrationEvent] = []
        self._last_migration_time: Optional[float] = None
        self._migration_in_progress = False
        self._preferred_path_id: Optional[int] = None
        
        # Callbacks
        self._pre_migration_callback: Optional[Callable[[MigrationEvent], None]] = None
        self._post_migration_callback: Optional[Callable[[MigrationEvent], None]] = None
        
    def set_pre_migration_callback(
        self, callback: Callable[[MigrationEvent], None]
    ) -> None:
        """
        Set the callback to be called before migration.
        
        :param callback: The callback function
        """
        self._pre_migration_callback = callback
        
    def set_post_migration_callback(
        self, callback: Callable[[MigrationEvent], None]
    ) -> None:
        """
        Set the callback to be called after migration.
        
        :param callback: The callback function
        """
        self._post_migration_callback = callback
        
    def can_migrate(self) -> bool:
        """
        Check if migration is possible.
        
        :return: True if migration is possible
        """
        with self._lock:
            # Check if migration is already in progress
            if self._migration_in_progress:
                return False
                
            # Check if we've migrated recently
            if (
                self._last_migration_time is not None
                and time.time() - self._last_migration_time < self.policy.min_migration_interval
            ):
                return False
                
            # Check if we have alternative paths
            active_paths = self.multipath_manager.get_active_paths()
            if len(active_paths) <= 1:
                return False
                
            # Check if the QUIC connection supports migration
            if getattr(self.quic_connection, "disable_active_migration", False):
                return False
                
            return True
            
    def migrate(
        self, trigger: MigrationTrigger, target_path_id: Optional[int] = None
    ) -> bool:
        """
        Migrate the connection to a new path.
        
        :param trigger: The trigger for the migration
        :param target_path_id: The ID of the path to migrate to, or None to select automatically
        :return: True if migration was successful
        """
        with self._lock:
            # Check if migration is possible
            if not self.can_migrate():
                return False
                
            # Mark migration as in progress
            self._migration_in_progress = True
            
            try:
                # Get the current path
                current_path = self.multipath_manager.get_primary_path()
                if current_path is None:
                    log.warning("No current path for migration")
                    return False
                    
                # Select the target path
                target_path = None
                if target_path_id is not None:
                    # Use the specified path
                    target_path = self.multipath_manager.paths.get(target_path_id)
                    if target_path is None or not target_path.is_usable():
                        log.warning(f"Target path {target_path_id} not found or not usable")
                        return False
                else:
                    # Select the best alternative path
                    alternative_paths = [
                        p for p in self.multipath_manager.get_active_paths()
                        if p.path_id != current_path.path_id
                    ]
                    
                    if not alternative_paths:
                        log.warning("No alternative paths available for migration")
                        return False
                        
                    # If we have a preferred path and it's usable, use it
                    if (
                        self.policy.prefer_previous_path
                        and self._preferred_path_id is not None
                        and self._preferred_path_id in self.multipath_manager.paths
                    ):
                        preferred_path = self.multipath_manager.paths[self._preferred_path_id]
                        if preferred_path.is_usable():
                            target_path = preferred_path
                            
                    # Otherwise, use the path with the best metrics
                    if target_path is None:
                        # Sort by RTT (lower is better)
                        alternative_paths.sort(
                            key=lambda p: p.metrics.smoothed_rtt or float("inf")
                        )
                        target_path = alternative_paths[0]
                        
                # Create a migration event
                event = MigrationEvent(
                    trigger=trigger,
                    old_path=current_path,
                    new_path=target_path,
                )
                
                # Call pre-migration callback
                if self._pre_migration_callback:
                    try:
                        self._pre_migration_callback(event)
                    except Exception as e:
                        log.error(f"Error in pre-migration callback: {e}")
                        
                # Perform the migration
                log.info(
                    f"Migrating from path {current_path.path_id} to {target_path.path_id} "
                    f"(trigger: {trigger.name})"
                )
                
                # Remember the old path as preferred for future migrations
                self._preferred_path_id = current_path.path_id
                
                # Set the new primary path
                self.multipath_manager.primary_path_id = target_path.path_id
                
                # Update the QUIC connection's address
                self.quic_connection.change_connection_id()
                
                # Record the migration
                self._last_migration_time = time.time()
                event.complete(success=True)
                self._migration_history.append(event)
                
                # Call post-migration callback
                if self._post_migration_callback:
                    try:
                        self._post_migration_callback(event)
                    except Exception as e:
                        log.error(f"Error in post-migration callback: {e}")
                        
                return True
            except Exception as e:
                log.error(f"Error during migration: {e}")
                return False
            finally:
                # Mark migration as complete
                self._migration_in_progress = False
                
    def check_path_degradation(self) -> bool:
        """
        Check if the current path has degraded and migrate if necessary.
        
        :return: True if migration was performed
        """
        if not self.policy.enable_auto_migration:
            return False
            
        current_path = self.multipath_manager.get_primary_path()
        if current_path is None:
            return False
            
        # Check RTT degradation
        if (
            current_path.metrics.smoothed_rtt is not None
            and current_path.metrics.smoothed_rtt > self.policy.rtt_degradation_threshold
        ):
            log.info(
                f"Path {current_path.path_id} RTT degraded: "
                f"{current_path.metrics.smoothed_rtt} ms > "
                f"{self.policy.rtt_degradation_threshold} ms"
            )
            return self.migrate(MigrationTrigger.PATH_DEGRADATION)
            
        # Check loss rate degradation
        if current_path.metrics.loss_rate > self.policy.loss_degradation_threshold:
            log.info(
                f"Path {current_path.path_id} loss rate degraded: "
                f"{current_path.metrics.loss_rate:.2%} > "
                f"{self.policy.loss_degradation_threshold:.2%}"
            )
            return self.migrate(MigrationTrigger.PATH_DEGRADATION)
            
        return False
        
    def handle_network_change(self) -> bool:
        """
        Handle a network change event.
        
        :return: True if migration was performed
        """
        if not self.policy.enable_auto_migration:
            return False
            
        # Discover new paths
        self.multipath_manager._discover_additional_paths()
        
        # Migrate to a new path
        return self.migrate(MigrationTrigger.NETWORK_CHANGE)
        
    def get_migration_history(self) -> List[MigrationEvent]:
        """
        Get the migration history.
        
        :return: List of migration events
        """
        return self._migration_history.copy()
