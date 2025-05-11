"""
Tests for HTTP/3 connection functionality.
"""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from urllib4.http3.connection import HTTP3Connection
from urllib4.http3.settings import HTTP3Settings, QUICSettings


# Skip tests if aioquic is not available
aioquic_available = True
try:
    import aioquic
except ImportError:
    aioquic_available = False

pytestmark = pytest.mark.skipif(not aioquic_available, reason="aioquic not available")


class TestHTTP3Connection:
    """Tests for the HTTP3Connection class."""

    def test_init(self):
        """Test initialization."""
        conn = HTTP3Connection("example.com")
        
        assert conn.host == "example.com"
        assert conn.port == 443
        assert conn.settings is not None
        assert conn.context is None
        assert conn.session_ticket is None
        assert not conn._connected
        assert not conn._closed
        assert conn._quic_connection is None
        assert conn._http3_connection is None
        assert conn._socket is None
        assert conn._multipath_manager is None
        
    def test_init_with_settings(self):
        """Test initialization with settings."""
        quic_settings = QUICSettings(
            max_datagram_size=1350,
            enable_multipath=True,
        )
        
        http3_settings = HTTP3Settings(
            quic=quic_settings,
        )
        
        conn = HTTP3Connection("example.com", settings=http3_settings)
        
        assert conn.settings == http3_settings
        assert conn.settings.quic.max_datagram_size == 1350
        assert conn.settings.quic.enable_multipath
        
    @mock.patch("urllib4.http3.connection.aioquic.quic.connection.QuicConnection")
    @mock.patch("urllib4.http3.connection.aioquic.h3.connection.H3Connection")
    @mock.patch("urllib4.http3.connection.socket.socket")
    def test_connect(self, mock_socket, mock_h3_connection, mock_quic_connection):
        """Test connect method."""
        # Mock the socket
        mock_socket_instance = mock.MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_socket_instance.getsockname.return_value = ("192.168.1.1", 12345)
        
        # Mock the QUIC connection
        mock_quic_connection_instance = mock.MagicMock()
        mock_quic_connection.return_value = mock_quic_connection_instance
        mock_quic_connection_instance.is_established = True
        mock_quic_connection_instance.tls.session_ticket = b"session ticket"
        
        # Mock the H3 connection
        mock_h3_connection_instance = mock.MagicMock()
        mock_h3_connection.return_value = mock_h3_connection_instance
        
        # Create a connection
        quic_settings = QUICSettings(
            enable_multipath=True,
        )
        
        http3_settings = HTTP3Settings(
            quic=quic_settings,
        )
        
        conn = HTTP3Connection("example.com", settings=http3_settings)
        
        # Connect
        with mock.patch.object(conn, "_perform_handshake") as mock_perform_handshake:
            with mock.patch.object(conn, "_discover_additional_paths") as mock_discover_paths:
                conn.connect()
                
                # Check that the socket was created
                mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Check that the socket was connected
                mock_socket_instance.connect.assert_called_once_with(("example.com", 443))
                
                # Check that the QUIC connection was created
                mock_quic_connection.assert_called_once()
                
                # Check that the H3 connection was created
                mock_h3_connection.assert_called_once_with(mock_quic_connection_instance)
                
                # Check that the handshake was performed
                mock_perform_handshake.assert_called_once()
                
                # Check that additional paths were discovered
                mock_discover_paths.assert_called_once()
                
                # Check that the connection is marked as connected
                assert conn._connected
                
                # Check that the session ticket was saved
                assert conn.session_ticket == b"session ticket"
                
                # Check that the multipath manager was created
                assert conn._multipath_manager is not None
                
    @mock.patch("urllib4.http3.connection.aioquic.quic.connection.QuicConnection")
    @mock.patch("urllib4.http3.connection.aioquic.h3.connection.H3Connection")
    @mock.patch("urllib4.http3.connection.socket.socket")
    def test_connect_no_multipath(self, mock_socket, mock_h3_connection, mock_quic_connection):
        """Test connect method without multipath."""
        # Mock the socket
        mock_socket_instance = mock.MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock the QUIC connection
        mock_quic_connection_instance = mock.MagicMock()
        mock_quic_connection.return_value = mock_quic_connection_instance
        mock_quic_connection_instance.is_established = True
        
        # Mock the H3 connection
        mock_h3_connection_instance = mock.MagicMock()
        mock_h3_connection.return_value = mock_h3_connection_instance
        
        # Create a connection
        quic_settings = QUICSettings(
            enable_multipath=False,
        )
        
        http3_settings = HTTP3Settings(
            quic=quic_settings,
        )
        
        conn = HTTP3Connection("example.com", settings=http3_settings)
        
        # Connect
        with mock.patch.object(conn, "_perform_handshake") as mock_perform_handshake:
            conn.connect()
            
            # Check that the multipath manager was not created
            assert conn._multipath_manager is None
            
    @mock.patch("urllib4.http3.connection.aioquic.quic.connection.QuicConnection")
    @mock.patch("urllib4.http3.connection.aioquic.h3.connection.H3Connection")
    @mock.patch("urllib4.http3.connection.socket.socket")
    def test_request(self, mock_socket, mock_h3_connection, mock_quic_connection):
        """Test request method."""
        # Mock the socket
        mock_socket_instance = mock.MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock the QUIC connection
        mock_quic_connection_instance = mock.MagicMock()
        mock_quic_connection.return_value = mock_quic_connection_instance
        mock_quic_connection_instance.is_established = True
        mock_quic_connection_instance.get_next_available_stream_id.return_value = 1
        
        # Mock the H3 connection
        mock_h3_connection_instance = mock.MagicMock()
        mock_h3_connection.return_value = mock_h3_connection_instance
        
        # Create a connection
        conn = HTTP3Connection("example.com")
        
        # Connect
        with mock.patch.object(conn, "_perform_handshake"):
            conn.connect()
            
        # Mock the _HTTP3Stream
        mock_stream = mock.MagicMock()
        mock_response = mock.MagicMock()
        mock_stream.get_response.return_value = mock_response
        
        # Mock the _send_data method
        with mock.patch.object(conn, "_send_data") as mock_send_data:
            # Mock the _HTTP3Stream class
            with mock.patch("urllib4.http3.connection._HTTP3Stream", return_value=mock_stream):
                # Make a request
                response = conn.request("GET", "/")
                
                # Check that the stream was created
                assert 1 in conn._streams
                
                # Check that the headers were sent
                mock_h3_connection_instance.send_headers.assert_called_once()
                
                # Check that the data was sent
                mock_send_data.assert_called_once()
                
                # Check that the response was returned
                assert response == mock_response
                
    @mock.patch("urllib4.http3.connection.aioquic.quic.connection.QuicConnection")
    @mock.patch("urllib4.http3.connection.aioquic.h3.connection.H3Connection")
    @mock.patch("urllib4.http3.connection.socket.socket")
    def test_close(self, mock_socket, mock_h3_connection, mock_quic_connection):
        """Test close method."""
        # Mock the socket
        mock_socket_instance = mock.MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock the QUIC connection
        mock_quic_connection_instance = mock.MagicMock()
        mock_quic_connection.return_value = mock_quic_connection_instance
        mock_quic_connection_instance.is_established = True
        
        # Mock the H3 connection
        mock_h3_connection_instance = mock.MagicMock()
        mock_h3_connection.return_value = mock_h3_connection_instance
        
        # Create a connection
        quic_settings = QUICSettings(
            enable_multipath=True,
        )
        
        http3_settings = HTTP3Settings(
            quic=quic_settings,
        )
        
        conn = HTTP3Connection("example.com", settings=http3_settings)
        
        # Connect
        with mock.patch.object(conn, "_perform_handshake"):
            with mock.patch.object(conn, "_discover_additional_paths"):
                conn.connect()
                
        # Mock the multipath manager
        mock_multipath_manager = mock.MagicMock()
        conn._multipath_manager = mock_multipath_manager
        
        # Mock the _send_data method
        with mock.patch.object(conn, "_send_data") as mock_send_data:
            # Close the connection
            conn.close()
            
            # Check that the QUIC connection was closed
            mock_quic_connection_instance.close.assert_called_once()
            
            # Check that the data was sent
            mock_send_data.assert_called_once()
            
            # Check that the multipath manager was closed
            mock_multipath_manager.close_all_paths.assert_called_once()
            
            # Check that the socket was closed
            mock_socket_instance.close.assert_called_once()
            
            # Check that the connection is marked as closed
            assert conn._closed
