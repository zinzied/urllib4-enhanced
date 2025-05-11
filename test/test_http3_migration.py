"""
Tests for HTTP/3 connection migration.
"""

import socket
import unittest
from unittest import mock

import pytest

from urllib4.http3.migration import (
    MigrationEvent,
    MigrationManager,
    MigrationPolicy,
    MigrationTrigger,
)
from urllib4.http3.multipath import MultipathManager, NetworkPath, PathStatus


# Skip all tests if aioquic is not available
try:
    import aioquic
    
    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False


@pytest.mark.skipif(not AIOQUIC_AVAILABLE, reason="aioquic not available")
class TestMigrationPolicy:
    """Tests for the MigrationPolicy class."""
    
    def test_init_default(self):
        """Test initialization with default parameters."""
        policy = MigrationPolicy()
        
        assert policy.enable_auto_migration is True
        assert policy.min_migration_interval == 5.0
        assert policy.rtt_degradation_threshold == 200.0
        assert policy.loss_degradation_threshold == 0.05
        assert policy.prefer_previous_path is True
        assert policy.max_migration_attempts == 3
        assert policy.migration_timeout == 10.0
        
    def test_init_custom(self):
        """Test initialization with custom parameters."""
        policy = MigrationPolicy(
            enable_auto_migration=False,
            min_migration_interval=10.0,
            rtt_degradation_threshold=300.0,
            loss_degradation_threshold=0.1,
            prefer_previous_path=False,
            max_migration_attempts=5,
            migration_timeout=20.0,
        )
        
        assert policy.enable_auto_migration is False
        assert policy.min_migration_interval == 10.0
        assert policy.rtt_degradation_threshold == 300.0
        assert policy.loss_degradation_threshold == 0.1
        assert policy.prefer_previous_path is False
        assert policy.max_migration_attempts == 5
        assert policy.migration_timeout == 20.0


@pytest.mark.skipif(not AIOQUIC_AVAILABLE, reason="aioquic not available")
class TestMigrationEvent:
    """Tests for the MigrationEvent class."""
    
    def test_init(self):
        """Test initialization."""
        event = MigrationEvent(
            trigger=MigrationTrigger.NETWORK_CHANGE,
        )
        
        assert event.trigger == MigrationTrigger.NETWORK_CHANGE
        assert event.old_path is None
        assert event.new_path is None
        assert event.timestamp is not None
        assert event.success is False
        assert event.error is None
        assert event.duration is None
        
    def test_init_with_paths(self):
        """Test initialization with paths."""
        old_path = mock.MagicMock(spec=NetworkPath)
        new_path = mock.MagicMock(spec=NetworkPath)
        
        event = MigrationEvent(
            trigger=MigrationTrigger.MANUAL,
            old_path=old_path,
            new_path=new_path,
        )
        
        assert event.trigger == MigrationTrigger.MANUAL
        assert event.old_path == old_path
        assert event.new_path == new_path
        
    def test_complete(self):
        """Test completing the event."""
        event = MigrationEvent(
            trigger=MigrationTrigger.PATH_DEGRADATION,
        )
        
        event.complete(success=True)
        
        assert event.success is True
        assert event.error is None
        assert event.duration is not None
        
    def test_complete_with_error(self):
        """Test completing the event with an error."""
        event = MigrationEvent(
            trigger=MigrationTrigger.PEER_MIGRATION,
        )
        
        error = ValueError("Test error")
        event.complete(success=False, error=error)
        
        assert event.success is False
        assert event.error == error
        assert event.duration is not None


@pytest.mark.skipif(not AIOQUIC_AVAILABLE, reason="aioquic not available")
class TestMigrationManager:
    """Tests for the MigrationManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Mock QUIC connection
        self.quic_connection = mock.MagicMock()
        self.quic_connection.disable_active_migration = False
        
        # Mock multipath manager
        self.multipath_manager = mock.MagicMock(spec=MultipathManager)
        
        # Create paths
        self.path1 = mock.MagicMock(spec=NetworkPath)
        self.path1.path_id = 1
        self.path1.is_usable.return_value = True
        self.path1.metrics.smoothed_rtt = 50.0
        self.path1.metrics.loss_rate = 0.01
        
        self.path2 = mock.MagicMock(spec=NetworkPath)
        self.path2.path_id = 2
        self.path2.is_usable.return_value = True
        self.path2.metrics.smoothed_rtt = 100.0
        self.path2.metrics.loss_rate = 0.02
        
        # Set up multipath manager
        self.multipath_manager.paths = {1: self.path1, 2: self.path2}
        self.multipath_manager.get_primary_path.return_value = self.path1
        self.multipath_manager.get_active_paths.return_value = [self.path1, self.path2]
        
        # Create migration manager
        self.migration_manager = MigrationManager(
            quic_connection=self.quic_connection,
            multipath_manager=self.multipath_manager,
        )
        
    def test_init(self):
        """Test initialization."""
        assert self.migration_manager.quic_connection == self.quic_connection
        assert self.migration_manager.multipath_manager == self.multipath_manager
        assert isinstance(self.migration_manager.policy, MigrationPolicy)
        
    def test_init_with_policy(self):
        """Test initialization with a custom policy."""
        policy = MigrationPolicy(enable_auto_migration=False)
        
        migration_manager = MigrationManager(
            quic_connection=self.quic_connection,
            multipath_manager=self.multipath_manager,
            policy=policy,
        )
        
        assert migration_manager.policy == policy
        
    def test_can_migrate(self):
        """Test checking if migration is possible."""
        assert self.migration_manager.can_migrate() is True
        
    def test_can_migrate_no_alternative_paths(self):
        """Test checking if migration is possible with no alternative paths."""
        self.multipath_manager.get_active_paths.return_value = [self.path1]
        
        assert self.migration_manager.can_migrate() is False
        
    def test_can_migrate_migration_in_progress(self):
        """Test checking if migration is possible while migration is in progress."""
        self.migration_manager._migration_in_progress = True
        
        assert self.migration_manager.can_migrate() is False
        
    def test_can_migrate_recent_migration(self):
        """Test checking if migration is possible after a recent migration."""
        self.migration_manager._last_migration_time = 0
        
        assert self.migration_manager.can_migrate() is False
        
    def test_can_migrate_disabled_migration(self):
        """Test checking if migration is possible with disabled migration."""
        self.quic_connection.disable_active_migration = True
        
        assert self.migration_manager.can_migrate() is False
        
    def test_migrate(self):
        """Test migrating to a new path."""
        result = self.migration_manager.migrate(MigrationTrigger.MANUAL)
        
        assert result is True
        assert self.multipath_manager.primary_path_id == 2
        assert self.quic_connection.change_connection_id.called
        assert len(self.migration_manager._migration_history) == 1
        
        event = self.migration_manager._migration_history[0]
        assert event.trigger == MigrationTrigger.MANUAL
        assert event.old_path == self.path1
        assert event.new_path == self.path2
        assert event.success is True
        
    def test_migrate_with_target_path(self):
        """Test migrating to a specific path."""
        result = self.migration_manager.migrate(
            MigrationTrigger.MANUAL, target_path_id=2
        )
        
        assert result is True
        assert self.multipath_manager.primary_path_id == 2
        
    def test_migrate_invalid_target_path(self):
        """Test migrating to an invalid path."""
        result = self.migration_manager.migrate(
            MigrationTrigger.MANUAL, target_path_id=3
        )
        
        assert result is False
        
    def test_check_path_degradation_rtt(self):
        """Test checking for path degradation based on RTT."""
        self.path1.metrics.smoothed_rtt = 300.0  # Above threshold
        
        result = self.migration_manager.check_path_degradation()
        
        assert result is True
        assert self.multipath_manager.primary_path_id == 2
        
    def test_check_path_degradation_loss(self):
        """Test checking for path degradation based on loss rate."""
        self.path1.metrics.loss_rate = 0.1  # Above threshold
        
        result = self.migration_manager.check_path_degradation()
        
        assert result is True
        assert self.multipath_manager.primary_path_id == 2
        
    def test_check_path_degradation_no_degradation(self):
        """Test checking for path degradation with no degradation."""
        result = self.migration_manager.check_path_degradation()
        
        assert result is False
        assert self.multipath_manager.primary_path_id != 2
        
    def test_handle_network_change(self):
        """Test handling a network change event."""
        result = self.migration_manager.handle_network_change()
        
        assert result is True
        assert self.multipath_manager._discover_additional_paths.called
        assert self.multipath_manager.primary_path_id == 2
        
    def test_callbacks(self):
        """Test pre and post migration callbacks."""
        pre_callback = mock.MagicMock()
        post_callback = mock.MagicMock()
        
        self.migration_manager.set_pre_migration_callback(pre_callback)
        self.migration_manager.set_post_migration_callback(post_callback)
        
        self.migration_manager.migrate(MigrationTrigger.MANUAL)
        
        assert pre_callback.called
        assert post_callback.called
        
        # Check that the callbacks were called with the same event
        pre_event = pre_callback.call_args[0][0]
        post_event = post_callback.call_args[0][0]
        assert pre_event is post_event
