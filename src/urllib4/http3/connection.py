"""
HTTP/3 connection implementation for urllib4.

This module provides an HTTP/3 connection class that can be used to make
HTTP/3 requests over QUIC.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
import typing
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from .._collections import HTTPHeaderDict
from ..connection import HTTPSConnection
from ..exceptions import ConnectionError, HTTPError, TimeoutError
from ..response import HTTPResponse
from .migration import MigrationManager, MigrationPolicy, MigrationTrigger
from .multipath import MultipathManager
from .settings import HTTP3Settings, QUICSettings

log = logging.getLogger(__name__)

# Import aioquic conditionally to avoid hard dependency
try:
    import aioquic
    import aioquic.h3.connection
    import aioquic.h3.events
    import aioquic.quic.configuration
    import aioquic.quic.connection
    import aioquic.quic.events
    import aioquic.tls

    AIOQUIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    AIOQUIC_AVAILABLE = False


class HTTP3Connection:
    """
    HTTP/3 connection implementation.

    This class provides an HTTP/3 connection that can be used to make
    HTTP/3 requests over QUIC.
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        timeout: socket._GLOBAL_DEFAULT_TIMEOUT = socket._GLOBAL_DEFAULT_TIMEOUT,
        settings: Optional[HTTP3Settings] = None,
        context: Optional[ssl.SSLContext] = None,
        session_ticket: Optional[bytes] = None,
    ) -> None:
        """
        Initialize a new HTTP3Connection.

        :param host: The hostname to connect to
        :param port: The port to connect to (default: 443)
        :param timeout: Socket timeout
        :param settings: HTTP/3 settings
        :param context: SSL context
        :param session_ticket: Session ticket for 0-RTT
        """
        if not AIOQUIC_AVAILABLE:
            raise ImportError(
                "HTTP/3 support requires the aioquic package. "
                "Install with: pip install aioquic"
            )

        self.host = host
        self.port = port or 443
        self.timeout = timeout
        self.settings = settings or HTTP3Settings()
        self.context = context
        self.session_ticket = session_ticket

        # Connection state
        self._connected = False
        self._closed = False
        self._lock = threading.RLock()

        # QUIC and HTTP/3 connections
        self._quic_connection: Optional[aioquic.quic.connection.QuicConnection] = None
        self._http3_connection: Optional[aioquic.h3.connection.H3Connection] = None

        # Socket
        self._socket: Optional[socket.socket] = None

        # Multipath manager
        self._multipath_manager: Optional[MultipathManager] = None

        # Migration manager
        self._migration_manager: Optional[MigrationManager] = None

        # Stream tracking
        self._streams: Dict[int, _HTTP3Stream] = {}

        # For compatibility with HTTPSConnection
        self.sock = None

    def connect(self) -> None:
        """
        Connect to the server.

        This method establishes a QUIC connection to the server and sets up
        the HTTP/3 connection.
        """
        if self._connected:
            return

        with self._lock:
            # Create SSL context if not provided
            context = self.context
            if context is None:
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            # Create QUIC configuration
            quic_config = aioquic.quic.configuration.QuicConfiguration(
                alpn_protocols=self.settings.quic.alpn_protocols,
                is_client=True,
                max_datagram_size=self.settings.quic.max_datagram_size,
                idle_timeout=self.settings.quic.idle_timeout / 1000.0,  # Convert to seconds
                disable_active_migration=not self.settings.quic.enable_active_migration,
            )

            # Set TLS certificate
            quic_config.verify_mode = context.verify_mode
            quic_config.ca_certs = context.get_ca_certs()

            # Set session ticket for 0-RTT
            if self.session_ticket and self.settings.quic.enable_0rtt:
                quic_config.session_ticket = self.session_ticket

            # Create QUIC connection
            self._quic_connection = aioquic.quic.connection.QuicConnection(
                configuration=quic_config,
                server_name=self.host,
            )

            # Create HTTP/3 connection
            self._http3_connection = aioquic.h3.connection.H3Connection(self._quic_connection)

            # Create UDP socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Initialize multipath manager if enabled
            if self.settings.quic.enable_multipath:
                self._multipath_manager = MultipathManager(
                    self._quic_connection,
                    max_paths=self.settings.quic.max_paths,
                )

                # Initialize migration manager if active migration is enabled
                if self.settings.quic.enable_active_migration:
                    self._migration_manager = MigrationManager(
                        self._quic_connection,
                        self._multipath_manager,
                        policy=MigrationPolicy(
                            enable_auto_migration=True,
                            min_migration_interval=5.0,
                            rtt_degradation_threshold=200.0,
                            loss_degradation_threshold=0.05,
                        ),
                    )

            # Set timeout
            if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                self._socket.settimeout(self.timeout)

            # Connect to the server
            try:
                self._socket.connect((self.host, self.port))

                # Add the primary path to the multipath manager
                if self._multipath_manager is not None:
                    local_addr = self._socket.getsockname()
                    remote_addr = (self.host, self.port)
                    self._multipath_manager.add_path(local_addr, remote_addr, self._socket)
            except socket.error as e:
                self._socket.close()
                self._socket = None
                raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")

            # Perform QUIC handshake
            self._perform_handshake()

            # Mark as connected
            self._connected = True

            # Discover and add additional paths if multipath is enabled
            if self._multipath_manager is not None:
                self._discover_additional_paths()

    def _perform_handshake(self) -> None:
        """
        Perform the QUIC handshake.

        This method performs the QUIC handshake with the server.
        """
        if self._quic_connection is None or self._socket is None:
            raise ConnectionError("Connection not initialized")

        # Send initial data
        data = self._quic_connection.send_data()
        if data:
            self._socket.send(data)

        # Wait for handshake to complete
        start_time = time.time()
        timeout = 10.0  # 10 seconds timeout for handshake

        while not self._quic_connection.is_established:
            # Check for timeout
            if time.time() - start_time > timeout:
                raise TimeoutError("QUIC handshake timed out")

            # Receive data
            try:
                data, addr = self._socket.recvfrom(2048)
                self._quic_connection.receive_data(data, addr)
            except socket.timeout:
                # Socket timeout, just continue
                pass

            # Send any pending data
            data = self._quic_connection.send_data()
            if data:
                self._socket.send(data)

        # Save session ticket for future 0-RTT
        if self._quic_connection.tls.session_ticket:
            self.session_ticket = self._quic_connection.tls.session_ticket

    def _discover_additional_paths(self) -> None:
        """
        Discover and add additional network paths.

        This method discovers additional network interfaces and adds them
        as paths to the multipath manager.
        """
        if self._multipath_manager is None:
            return

        try:
            # Import netifaces conditionally to avoid hard dependency
            try:
                import netifaces
            except ImportError:
                log.warning(
                    "Multipath QUIC requires the netifaces package for interface discovery. "
                    "Install with: pip install netifaces"
                )
                return

            # Get all network interfaces
            interfaces = netifaces.interfaces()

            # Get the primary path's local address
            primary_path = self._multipath_manager.get_primary_path()
            if primary_path is None:
                return

            primary_addr = primary_path.local_addr
            primary_family = socket.AF_INET6 if ":" in primary_addr[0] else socket.AF_INET

            # Find additional interfaces
            for interface in interfaces:
                # Skip loopback interfaces
                if interface.startswith(("lo", "Loopback")):
                    continue

                # Get addresses for this interface
                addresses = netifaces.ifaddresses(interface)

                # Process IPv4 addresses
                if netifaces.AF_INET in addresses and primary_family == socket.AF_INET:
                    for addr_info in addresses[netifaces.AF_INET]:
                        ip = addr_info["addr"]

                        # Skip the primary address
                        if ip == primary_addr[0]:
                            continue

                        # Skip loopback addresses
                        if ip.startswith("127."):
                            continue

                        # Create a socket for this interface
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            sock.bind((ip, 0))  # Bind to any port

                            # Add the path
                            local_addr = sock.getsockname()
                            remote_addr = (self.host, self.port)
                            self._multipath_manager.add_path(local_addr, remote_addr, sock)

                            log.debug(f"Added additional path: {local_addr} -> {remote_addr}")
                        except Exception as e:
                            log.warning(f"Failed to add path for {ip}: {e}")

                # Process IPv6 addresses
                if netifaces.AF_INET6 in addresses and primary_family == socket.AF_INET6:
                    for addr_info in addresses[netifaces.AF_INET6]:
                        ip = addr_info["addr"]

                        # Skip the primary address
                        if ip == primary_addr[0]:
                            continue

                        # Skip link-local addresses
                        if ip.startswith("fe80:"):
                            continue

                        # Create a socket for this interface
                        try:
                            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                            sock.bind((ip, 0))  # Bind to any port

                            # Add the path
                            local_addr = sock.getsockname()
                            remote_addr = (self.host, self.port)
                            self._multipath_manager.add_path(local_addr, remote_addr, sock)

                            log.debug(f"Added additional path: {local_addr} -> {remote_addr}")
                        except Exception as e:
                            log.warning(f"Failed to add path for {ip}: {e}")
        except Exception as e:
            log.warning(f"Failed to discover additional paths: {e}")

    def request(
        self,
        method: str,
        url: str,
        body: Optional[Union[bytes, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Send an HTTP/3 request.

        :param method: The HTTP method
        :param url: The URL to request
        :param body: The request body
        :param headers: The request headers
        :return: The HTTP response
        """
        if not self._connected:
            self.connect()

        if self._http3_connection is None or self._quic_connection is None:
            raise ConnectionError("HTTP/3 connection not established")

        # Prepare headers
        if headers is None:
            headers = {}

        h3_headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", f"{self.host}:{self.port}".encode()),
            (b":path", url.encode()),
        ]

        for name, value in headers.items():
            if name.lower() != "host":  # Skip Host, already handled in :authority
                h3_headers.append((name.lower().encode(), value.encode()))

        # Convert body to bytes
        if body is not None:
            if isinstance(body, str):
                body = body.encode("utf-8")
        else:
            body = b""

        # Create a new stream
        stream_id = self._quic_connection.get_next_available_stream_id()
        stream = _HTTP3Stream(stream_id, self)
        self._streams[stream_id] = stream

        # Send request
        self._http3_connection.send_headers(stream_id, h3_headers, end_stream=not body)

        if body:
            self._http3_connection.send_data(stream_id, body, end_stream=True)

        # Send the data
        data = self._quic_connection.send_data()
        if data:
            self._send_data(data)

        # Wait for response
        response = stream.get_response()

        # Remove stream
        del self._streams[stream_id]

        return response

    def _send_data(self, data: bytes) -> None:
        """
        Send data on the appropriate path(s).

        :param data: The data to send
        """
        if self._multipath_manager is not None:
            # Distribute data across multiple paths
            path_data = self._multipath_manager.distribute_data(data)

            # Send data on each path
            for path_id, chunk in path_data.items():
                path = self._multipath_manager.paths.get(path_id)
                if path and path.socket:
                    try:
                        path.send(chunk)
                    except Exception as e:
                        log.warning(f"Failed to send data on path {path_id}: {e}")
        elif self._socket:
            # Send data on the primary socket
            try:
                self._socket.send(data)
            except Exception as e:
                log.warning(f"Failed to send data: {e}")

    def migrate_connection(self, target_path_id: Optional[int] = None) -> bool:
        """
        Manually migrate the connection to a different network path.

        This method allows the application to manually trigger a connection
        migration, for example in response to a network change event.

        :param target_path_id: The ID of the path to migrate to, or None to select automatically
        :return: True if migration was successful
        :raises ConnectionError: If migration is not supported or fails
        """
        if self._migration_manager is None:
            raise ConnectionError("Connection migration not supported")

        if not self._migration_manager.can_migrate():
            raise ConnectionError("Connection migration not possible at this time")

        success = self._migration_manager.migrate(MigrationTrigger.MANUAL, target_path_id)
        if not success:
            raise ConnectionError("Connection migration failed")

        return success

    def handle_network_change(self) -> bool:
        """
        Handle a network change event.

        This method should be called when the network environment changes,
        for example when a new network interface becomes available or an
        existing one is disconnected.

        :return: True if migration was performed
        """
        if self._migration_manager is None:
            return False

        return self._migration_manager.handle_network_change()

    def close(self) -> None:
        """Close the connection."""
        if self._closed:
            return

        with self._lock:
            self._closed = True

            # Close QUIC connection
            if self._quic_connection:
                self._quic_connection.close()
                data = self._quic_connection.send_data()
                if data:
                    self._send_data(data)

            # Close multipath manager
            if self._multipath_manager:
                self._multipath_manager.close_all_paths()

            # Close socket
            if self._socket:
                self._socket.close()
                self._socket = None

            # Clear connections
            self._quic_connection = None
            self._http3_connection = None

            # Clear streams
            self._streams.clear()

    def process_events(self) -> None:
        """
        Process HTTP/3 events.

        This method processes any pending HTTP/3 events.
        """
        if self._http3_connection is None or self._quic_connection is None:
            return

        # Process QUIC events
        for event in self._quic_connection.handle_events():
            if isinstance(event, aioquic.quic.events.ConnectionTerminated):
                self._handle_connection_terminated(event)
            elif isinstance(event, aioquic.quic.events.StreamReset):
                self._handle_stream_reset(event)

        # Process HTTP/3 events
        for event in self._http3_connection.handle_events():
            if isinstance(event, aioquic.h3.events.HeadersReceived):
                self._handle_headers_received(event)
            elif isinstance(event, aioquic.h3.events.DataReceived):
                self._handle_data_received(event)
            elif isinstance(event, aioquic.h3.events.StreamReset):
                self._handle_stream_reset(event)

        # Send any pending data
        data = self._quic_connection.send_data()
        if data:
            self._send_data(data)

    def _handle_connection_terminated(self, event: aioquic.quic.events.ConnectionTerminated) -> None:
        """
        Handle a connection terminated event.

        :param event: The connection terminated event
        """
        log.warning(f"QUIC connection terminated: {event.error_code} {event.reason_phrase}")
        self._closed = True

    def _handle_stream_reset(self, event: Union[aioquic.quic.events.StreamReset, aioquic.h3.events.StreamReset]) -> None:
        """
        Handle a stream reset event.

        :param event: The stream reset event
        """
        stream_id = event.stream_id
        if stream_id in self._streams:
            self._streams[stream_id].handle_reset(event)

    def _handle_headers_received(self, event: aioquic.h3.events.HeadersReceived) -> None:
        """
        Handle a headers received event.

        :param event: The headers received event
        """
        stream_id = event.stream_id
        if stream_id in self._streams:
            self._streams[stream_id].handle_headers(event)

    def _handle_data_received(self, event: aioquic.h3.events.DataReceived) -> None:
        """
        Handle a data received event.

        :param event: The data received event
        """
        stream_id = event.stream_id
        if stream_id in self._streams:
            self._streams[stream_id].handle_data(event)

    def receive_datagram(self) -> None:
        """
        Receive and process a QUIC datagram.

        This method receives a datagram from the socket and processes it.
        """
        if self._quic_connection is None:
            return

        if self._multipath_manager is not None:
            # Receive datagrams from all paths
            active_paths = self._multipath_manager.get_active_paths()
            if not active_paths:
                return

            # Set up select to monitor all sockets
            import select
            read_sockets = []
            path_map = {}

            for path in active_paths:
                if path.socket is not None:
                    read_sockets.append(path.socket)
                    path_map[path.socket] = path

            if not read_sockets:
                return

            # Wait for data on any socket (with timeout)
            timeout = 0.1  # 100ms timeout
            ready, _, _ = select.select(read_sockets, [], [], timeout)

            # Process data from all ready sockets
            for sock in ready:
                path = path_map.get(sock)
                if path:
                    try:
                        data, addr = path.receive()
                        self._quic_connection.receive_data(data, addr)

                        # Update path metrics
                        rtt = getattr(self._quic_connection, "get_rtt", lambda: None)()
                        if rtt is not None:
                            self._multipath_manager.update_path_metrics(
                                path.path_id,
                                rtt=rtt,
                            )

                            # Check for path degradation and migrate if necessary
                            if self._migration_manager is not None:
                                self._migration_manager.check_path_degradation()
                    except Exception as e:
                        log.warning(f"Failed to receive datagram on path {path.path_id}: {e}")

            # Process events
            self.process_events()
        elif self._socket is not None:
            # Receive datagram from the primary socket
            try:
                data, addr = self._socket.recvfrom(2048)
                self._quic_connection.receive_data(data, addr)
                self.process_events()
            except socket.timeout:
                # Socket timeout, just continue
                pass
            except Exception as e:
                log.warning(f"Failed to receive datagram: {e}")


class _HTTP3Stream:
    """
    HTTP/3 stream.

    This class represents a single HTTP/3 stream.
    """

    def __init__(self, stream_id: int, connection: HTTP3Connection) -> None:
        """
        Initialize a new _HTTP3Stream.

        :param stream_id: The stream ID
        :param connection: The HTTP/3 connection
        """
        self.stream_id = stream_id
        self.connection = connection

        self.headers: List[Tuple[bytes, bytes]] = []
        self.data = bytearray()
        self.status: Optional[int] = None
        self.ended = False
        self.reset = False
        self.reset_code: Optional[int] = None

        self._event = threading.Event()

    def handle_headers(self, event: aioquic.h3.events.HeadersReceived) -> None:
        """
        Handle a headers received event.

        :param event: The headers received event
        """
        self.headers.extend(event.headers)

        # Extract status code
        for name, value in event.headers:
            if name == b":status":
                self.status = int(value.decode())
                break

    def handle_data(self, event: aioquic.h3.events.DataReceived) -> None:
        """
        Handle a data received event.

        :param event: The data received event
        """
        self.data.extend(event.data)

        if event.stream_ended:
            self.ended = True
            self._event.set()

    def handle_reset(self, event: Union[aioquic.quic.events.StreamReset, aioquic.h3.events.StreamReset]) -> None:
        """
        Handle a stream reset event.

        :param event: The stream reset event
        """
        self.reset = True
        self.reset_code = getattr(event, "error_code", None)
        self._event.set()

    def get_response(self, timeout: Optional[float] = None) -> HTTPResponse:
        """
        Get the HTTP response.

        :param timeout: Timeout in seconds
        :return: The HTTP response
        :raises TimeoutError: If the timeout is reached
        :raises ConnectionError: If the stream was reset
        """
        # Wait for the response to be complete
        while not self.ended and not self.reset:
            # Process events
            self.connection.process_events()

            # Receive datagrams
            self.connection.receive_datagram()

            # Wait for the response to be complete
            if not self._event.wait(timeout=0.1):
                if timeout is not None:
                    timeout -= 0.1
                    if timeout <= 0:
                        raise TimeoutError("Timed out waiting for response")

        # Check if the stream was reset
        if self.reset:
            raise ConnectionError(f"Stream was reset: {self.reset_code}")

        # Convert headers to HTTPHeaderDict
        headers = HTTPHeaderDict()
        for name, value in self.headers:
            if not name.startswith(b":"):  # Skip pseudo-headers
                headers[name.decode()] = value.decode()

        # Create response
        return HTTPResponse(
            body=bytes(self.data),
            headers=headers,
            status=self.status or 200,
            version=3,
            reason="",
            preload_content=True,
            decode_content=True,
            original_response=None,
            pool=None,
            connection=None,
        )
