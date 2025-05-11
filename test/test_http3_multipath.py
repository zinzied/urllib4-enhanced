"""
Tests for HTTP/3 multipath functionality.
"""

from __future__ import annotations

import socket
from unittest import mock

import pytest

# Skip tests if aioquic is not available
aioquic_available = True
try:
    import aioquic
except ImportError:
    aioquic_available = False

pytestmark = pytest.mark.skipif(not aioquic_available, reason="aioquic not available")

from urllib4.http3.multipath import MultipathManager, NetworkPath, PathStatus


class TestNetworkPath:
    """Tests for the NetworkPath class."""

    def test_init(self):
        """Test initialization."""
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = 1

        path = NetworkPath(path_id, local_addr, remote_addr)

        assert path.path_id == path_id
        assert path.local_addr == local_addr
        assert path.remote_addr == remote_addr
        assert path.socket is None
        assert path.status == PathStatus.UNKNOWN
        assert path.metrics is not None

    def test_is_active(self):
        """Test is_active method."""
        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443))

        # Initially not active
        assert not path.is_active()

        # Set to active
        path.status = PathStatus.ACTIVE
        assert path.is_active()

        # Set to other statuses
        path.status = PathStatus.STANDBY
        assert not path.is_active()

        path.status = PathStatus.VALIDATING
        assert not path.is_active()

        path.status = PathStatus.FAILED
        assert not path.is_active()

    def test_is_usable(self):
        """Test is_usable method."""
        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443))

        # Initially not usable
        assert not path.is_usable()

        # Set to active
        path.status = PathStatus.ACTIVE
        assert path.is_usable()

        # Set to standby
        path.status = PathStatus.STANDBY
        assert path.is_usable()

        # Set to other statuses
        path.status = PathStatus.VALIDATING
        assert not path.is_usable()

        path.status = PathStatus.FAILED
        assert not path.is_usable()

    def test_send(self):
        """Test send method."""
        # Create a mock socket
        mock_socket = mock.MagicMock()
        mock_socket.sendto.return_value = 10

        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443), mock_socket)

        # Send data
        data = b"test data"
        bytes_sent = path.send(data)

        # Check that the socket was used
        mock_socket.sendto.assert_called_once_with(data, ("example.com", 443))
        assert bytes_sent == 10

        # Check that metrics were updated
        assert path.metrics.packets_sent == 1
        assert path.metrics.bytes_in_flight == len(data)

    def test_send_no_socket(self):
        """Test send method with no socket."""
        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443))

        # Send data
        with pytest.raises(OSError):
            path.send(b"test data")

    def test_receive(self):
        """Test receive method."""
        # Create a mock socket
        mock_socket = mock.MagicMock()
        mock_socket.recvfrom.return_value = (b"test data", ("example.com", 443))

        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443), mock_socket)

        # Receive data
        data, addr = path.receive()

        # Check that the socket was used
        mock_socket.recvfrom.assert_called_once_with(2048)
        assert data == b"test data"
        assert addr == ("example.com", 443)

        # Check that metrics were updated
        assert path.metrics.packets_received == 1

    def test_receive_no_socket(self):
        """Test receive method with no socket."""
        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443))

        # Receive data
        with pytest.raises(OSError):
            path.receive()

    def test_close(self):
        """Test close method."""
        # Create a mock socket
        mock_socket = mock.MagicMock()

        path = NetworkPath(1, ("192.168.1.1", 12345), ("example.com", 443), mock_socket)

        # Close the path
        path.close()

        # Check that the socket was closed
        mock_socket.close.assert_called_once()
        assert path.socket is None
        assert path.status == PathStatus.FAILED


class TestMultipathManager:
    """Tests for the MultipathManager class."""

    def test_init(self):
        """Test initialization."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        assert manager.quic_connection == mock_quic_connection
        assert manager.max_paths == 4
        assert manager.paths == {}
        assert manager.primary_path_id is None

    def test_add_path(self):
        """Test add_path method."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Create a mock socket
        mock_socket = mock.MagicMock()

        # Add a path
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = manager.add_path(local_addr, remote_addr, mock_socket)

        # Check that the path was added
        assert path_id in manager.paths
        path = manager.paths[path_id]
        assert path.path_id == path_id
        assert path.local_addr == local_addr
        assert path.remote_addr == remote_addr
        assert path.socket == mock_socket

        # Check that it was set as the primary path
        assert manager.primary_path_id == path_id
        assert path.status == PathStatus.ACTIVE

    def test_add_path_no_socket(self):
        """Test add_path method with no socket."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Mock the _create_socket method
        mock_socket = mock.MagicMock()
        manager._create_socket = mock.MagicMock(return_value=mock_socket)

        # Add a path
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = manager.add_path(local_addr, remote_addr)

        # Check that the path was added
        assert path_id in manager.paths
        path = manager.paths[path_id]
        assert path.socket == mock_socket

        # Check that _create_socket was called
        manager._create_socket.assert_called_once_with(local_addr)

    def test_add_path_max_paths(self):
        """Test add_path method with maximum paths reached."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection, max_paths=1)

        # Add a path
        local_addr1 = ("192.168.1.1", 12345)
        remote_addr1 = ("example.com", 443)
        path_id1 = manager.add_path(local_addr1, remote_addr1)

        # Try to add another path
        local_addr2 = ("192.168.1.2", 12346)
        remote_addr2 = ("example.com", 443)
        with pytest.raises(ValueError):
            manager.add_path(local_addr2, remote_addr2)

    def test_remove_path(self):
        """Test remove_path method."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Add a path
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = manager.add_path(local_addr, remote_addr)

        # Remove the path
        manager.remove_path(path_id)

        # Check that the path was removed
        assert path_id not in manager.paths
        assert manager.primary_path_id is None

    def test_get_primary_path(self):
        """Test get_primary_path method."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Initially no primary path
        assert manager.get_primary_path() is None

        # Add a path
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = manager.add_path(local_addr, remote_addr)

        # Get the primary path
        primary_path = manager.get_primary_path()
        assert primary_path is not None
        assert primary_path.path_id == path_id

    def test_get_active_paths(self):
        """Test get_active_paths method."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Initially no active paths
        assert manager.get_active_paths() == []

        # Add a path
        local_addr1 = ("192.168.1.1", 12345)
        remote_addr1 = ("example.com", 443)
        path_id1 = manager.add_path(local_addr1, remote_addr1)

        # Add another path
        local_addr2 = ("192.168.1.2", 12346)
        remote_addr2 = ("example.com", 443)
        path_id2 = manager.add_path(local_addr2, remote_addr2)

        # Set the second path to standby
        manager.paths[path_id2].status = PathStatus.STANDBY

        # Get active paths
        active_paths = manager.get_active_paths()
        assert len(active_paths) == 1
        assert active_paths[0].path_id == path_id1

    def test_distribute_data(self):
        """Test distribute_data method."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Add a path
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = manager.add_path(local_addr, remote_addr)

        # Distribute data
        data = b"test data"
        path_data = manager.distribute_data(data)

        # Check that the data was distributed to the primary path
        assert len(path_data) == 1
        assert path_id in path_data
        assert path_data[path_id] == data

    def test_close_all_paths(self):
        """Test close_all_paths method."""
        # Create a mock QUIC connection
        mock_quic_connection = mock.MagicMock()

        manager = MultipathManager(mock_quic_connection)

        # Add a path
        local_addr = ("192.168.1.1", 12345)
        remote_addr = ("example.com", 443)
        path_id = manager.add_path(local_addr, remote_addr)

        # Close all paths
        manager.close_all_paths()

        # Check that all paths were closed
        assert manager.paths == {}
        assert manager.primary_path_id is None
