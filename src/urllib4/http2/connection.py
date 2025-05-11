"""
HTTP/2 Connection implementation for urllib4.

This module provides an HTTP/2 connection class that can be used as a drop-in
replacement for HTTPSConnection, enabling HTTP/2 support for urllib4.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
import typing
from typing import Any, Dict, List, Optional, Tuple, Union, cast

# Import BaseHTTPConnection for type checking only
if typing.TYPE_CHECKING:
    from .._base_connection import BaseHTTPConnection
from ..connection import HTTPSConnection
from ..exceptions import ConnectionError, HTTPError
from .flow_control import FlowControlStrategy, WindowManager
from .push_manager import PushManager
from .settings import ConnectionProfile, HTTP2Settings, SettingsManager

# Import h2 conditionally to avoid hard dependency
try:
    import h2.connection
    import h2.events
    import h2.exceptions
    import h2.settings
    H2_AVAILABLE = True
except ImportError:  # pragma: no cover
    H2_AVAILABLE = False

log = logging.getLogger(__name__)


def _is_legal_header_name(name: bytes) -> bool:
    """
    Check if a header name is legal according to RFC 9113.

    :param name: The header name to check
    :return: True if the name is legal, False otherwise
    """
    if not name:
        return False

    # Header field names are case-insensitive ASCII strings
    # that cannot contain whitespace or control characters
    # and cannot start with ':' (ASCII 0x3a) or '@' (ASCII 0x40)
    for char in name:
        if char <= 32 or char > 127 or char == 58 or char == 64:
            return False

    return True


def _is_illegal_header_value(value: bytes) -> bool:
    """
    Check if a header value is illegal according to RFC 9113.

    :param value: The header value to check
    :return: True if the value is illegal, False otherwise
    """
    if not value:
        return False

    # A field value MUST NOT start or end with an ASCII whitespace character
    if value[0] in (9, 32) or value[-1] in (9, 32):
        return True

    # Field values MUST NOT contain control characters
    for char in value:
        if char < 32 or char == 127:
            return True

    return False


class H2Connection:
    """
    Wrapper for h2.connection.H2Connection.

    This class provides a wrapper around h2.connection.H2Connection to make it
    easier to use with urllib4.
    """

    def __init__(self, client_side: bool = True) -> None:
        """
        Initialize a new H2Connection.

        :param client_side: Whether this is a client-side connection
        """
        if not H2_AVAILABLE:  # pragma: no cover
            raise ImportError(
                "HTTP/2 support requires the h2 package. "
                "Install with: pip install h2"
            )

        self._obj = h2.connection.H2Connection(client_side=client_side)
        self._lock = threading.RLock()

    def __getattr__(self, name: str) -> Any:
        """
        Get an attribute from the wrapped H2Connection.

        :param name: The attribute name
        :return: The attribute value
        """
        return getattr(self._obj, name)


class HTTP2Connection(HTTPSConnection):
    """
    HTTP/2 connection implementation.

    This class provides an HTTP/2 connection that can be used as a drop-in
    replacement for HTTPSConnection.
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        key_file: Optional[str] = None,
        cert_file: Optional[str] = None,
        timeout: socket._GLOBAL_DEFAULT_TIMEOUT = socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address: Optional[Tuple[str, int]] = None,
        context: Optional[ssl.SSLContext] = None,
        blocksize: int = 8192,
        http2_settings: Optional[HTTP2Settings] = None,
        flow_control_strategy: FlowControlStrategy = FlowControlStrategy.ADAPTIVE,
        connection_profile: ConnectionProfile = ConnectionProfile.BALANCED,
    ) -> None:
        """
        Initialize a new HTTP2Connection.

        :param host: The hostname to connect to
        :param port: The port to connect to (default: 443)
        :param key_file: Path to the key file
        :param cert_file: Path to the certificate file
        :param timeout: Socket timeout
        :param source_address: Source address to bind to
        :param context: SSL context
        :param blocksize: Block size for reading
        :param http2_settings: HTTP/2 settings
        :param flow_control_strategy: Flow control strategy
        :param connection_profile: Connection profile
        """
        super().__init__(
            host=host,
            port=port,
            key_file=key_file,
            cert_file=cert_file,
            timeout=timeout,
            source_address=source_address,
            context=context,
            blocksize=blocksize,
        )

        # HTTP/2 specific attributes
        self._h2_conn: Optional[H2Connection] = None
        self._stream_id: Optional[int] = None
        self._headers: List[Tuple[bytes, bytes]] = []
        self._window_manager = WindowManager(strategy=flow_control_strategy)
        self._push_manager = PushManager()

        # HTTP/2 settings
        if http2_settings is None:
            self._settings = SettingsManager.get_settings(connection_profile)
        else:
            self._settings = http2_settings

        # Default socket options
        self.socket_options = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]

    def connect(self) -> None:
        """
        Connect to the server with HTTP/2 negotiation.

        This method connects to the server and performs ALPN negotiation
        to establish an HTTP/2 connection.
        """
        if self.sock:
            return

        # Create SSL context if not provided
        context = self.context
        if context is None:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Set ALPN protocols for HTTP/2 negotiation
        context.set_alpn_protocols(["h2", "http/1.1"])

        # Connect to the server
        super().connect()

        # Check if HTTP/2 was negotiated
        if not self.sock:
            raise ConnectionError("Failed to establish connection")

        negotiated_protocol = self.sock.selected_alpn_protocol()
        if negotiated_protocol != "h2":
            log.warning(
                "HTTP/2 not negotiated, falling back to HTTP/1.1 (ALPN: %s)",
                negotiated_protocol
            )
            return

        # Initialize HTTP/2 connection
        self._h2_conn = H2Connection()
        self._h2_conn.initiate_connection()

        # Apply HTTP/2 settings
        self._settings.apply_to_connection(self._h2_conn)

        # Send initial settings frame
        self.sock.sendall(self._h2_conn.data_to_send())

        log.debug("HTTP/2 connection established to %s:%s", self.host, self.port)

    def putrequest(
        self,
        method: str,
        url: str,
        skip_host: bool = False,
        skip_accept_encoding: bool = False,
    ) -> None:
        """
        Send a request to the server.

        :param method: The HTTP method
        :param url: The URL to request
        :param skip_host: Whether to skip the Host header
        :param skip_accept_encoding: Whether to skip the Accept-Encoding header
        """
        if self._stream_id is not None:
            raise HTTPError("Connection already in use")

        # Connect if not already connected
        if not self.sock:
            self.connect()

        # If HTTP/2 wasn't negotiated, fall back to HTTP/1.1
        if self._h2_conn is None:
            return super().putrequest(
                method, url, skip_host, skip_accept_encoding
            )

        # Reset headers
        self._headers = []

        # Add pseudo-headers
        self._headers.append((b":method", method.encode()))
        self._headers.append((b":scheme", b"https"))
        self._headers.append((b":authority", f"{self.host}:{self.port}".encode()))
        self._headers.append((b":path", url.encode()))

        # Add default headers
        if not skip_accept_encoding:
            self._headers.append((b"accept-encoding", b"gzip, deflate"))

        return None

    def putheader(self, header: str, *values: str) -> None:
        """
        Send a header to the server.

        :param header: The header name
        :param values: The header values
        """
        if self._h2_conn is None:
            return super().putheader(header, *values)

        # Convert header name to bytes
        header_bytes = header.lower().encode("ascii")

        # Check if header name is legal
        if not _is_legal_header_name(header_bytes):
            raise ValueError(f"Illegal header name: {header}")

        # Combine values
        value_bytes = b", ".join(v.encode("ascii") for v in values)

        # Check if header value is legal
        if _is_illegal_header_value(value_bytes):
            raise ValueError(f"Illegal header value: {value_bytes!r}")

        # Add header to list
        self._headers.append((header_bytes, value_bytes))

    def endheaders(self, message_body: Optional[Union[bytes, str, List[bytes]]] = None) -> None:
        """
        End the headers and send the request.

        :param message_body: The message body to send
        """
        if self._h2_conn is None:
            return super().endheaders(message_body)

        # Get a new stream ID
        self._stream_id = self._h2_conn.get_next_available_stream_id()

        # Send headers
        end_stream = message_body is None
        self._h2_conn.send_headers(self._stream_id, self._headers, end_stream=end_stream)

        # Send the data
        self.sock.sendall(self._h2_conn.data_to_send())

        # Send message body if provided
        if message_body is not None:
            self.send(message_body)

    def send(self, data: Union[bytes, str, List[bytes]]) -> None:
        """
        Send data to the server.

        :param data: The data to send
        """
        if not self.sock:
            raise ConnectionError("Connection not established")

        if self._h2_conn is None:
            return super().send(data)

        if self._stream_id is None:
            raise ConnectionError("No active stream")

        # Convert data to bytes
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif isinstance(data, list):
            data = b"".join(data)
        elif not isinstance(data, bytes):
            raise TypeError(f"Unsupported data type: {type(data)}")

        # Send data
        self._h2_conn.send_data(self._stream_id, data, end_stream=True)

        # Send the data
        self.sock.sendall(self._h2_conn.data_to_send())

    def getresponse(self) -> Any:
        """
        Get the response from the server.

        :return: The HTTP response
        """
        if not self.sock:
            raise ConnectionError("Connection not established")

        if self._h2_conn is None:
            return super().getresponse()

        if self._stream_id is None:
            raise ConnectionError("No active stream")

        # Process events until we get a response
        response_headers = None
        response_data = bytearray()
        stream_ended = False

        while not stream_ended:
            # Receive data
            data = self.sock.recv(self.blocksize)
            if not data:
                raise ConnectionError("Connection closed")

            # Process events
            events = self._h2_conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    if event.stream_id == self._stream_id:
                        response_headers = event.headers
                    else:
                        # This could be a response for a pushed stream
                        self._push_manager.handle_headers(event)
                elif isinstance(event, h2.events.DataReceived):
                    if event.stream_id == self._stream_id:
                        response_data.extend(event.data)
                        # Acknowledge data received
                        self._h2_conn.acknowledge_received_data(
                            len(event.data), event.stream_id
                        )
                    else:
                        # This could be data for a pushed stream
                        self._push_manager.handle_data(event)
                        # Acknowledge data received for pushed stream
                        self._h2_conn.acknowledge_received_data(
                            len(event.data), event.stream_id
                        )
                elif isinstance(event, h2.events.StreamEnded):
                    if event.stream_id == self._stream_id:
                        stream_ended = True
                    else:
                        # This could be the end of a pushed stream
                        self._push_manager.handle_stream_ended(event)
                elif isinstance(event, h2.events.StreamReset):
                    if event.stream_id == self._stream_id:
                        raise ConnectionError(
                            f"Stream reset by server: {event.error_code}"
                        )
                elif isinstance(event, h2.events.PushedStreamReceived):
                    # Handle push promise
                    self._push_manager.handle_push_promise(event)

            # Send any pending data (like WINDOW_UPDATE frames)
            pending_data = self._h2_conn.data_to_send()
            if pending_data:
                self.sock.sendall(pending_data)

        # Create response
        if response_headers is None:
            raise ConnectionError("No response headers received")

        # Extract status code
        status = None
        for name, value in response_headers:
            if name == b":status":
                status = int(value.decode())
                break

        if status is None:
            raise ConnectionError("No status code in response")

        # Create response object
        from ..response import HTTPResponse

        # Convert headers to HTTPHeaderDict
        from .._collections import HTTPHeaderDict
        headers = HTTPHeaderDict()
        for name, value in response_headers:
            if not name.startswith(b":"):  # Skip pseudo-headers
                headers[name.decode()] = value.decode()

        # Create response
        response = HTTPResponse(
            body=bytes(response_data),
            headers=headers,
            status=status,
            version=2,
            reason="",
            preload_content=True,
            decode_content=True,
            original_response=None,
            pool=None,
            connection=self,
        )

        # Add pushed resources to the response
        if self._stream_id is not None:
            pushed_responses = self._push_manager.get_pushed_responses(self._stream_id)
            if pushed_responses:
                response.pushed_responses = pushed_responses

        # Reset stream ID to allow reuse
        stream_id = self._stream_id
        self._stream_id = None

        return response

    def close(self) -> None:
        """Close the connection."""
        if self._h2_conn is not None and self.sock:
            try:
                self._h2_conn.close_connection()
                self.sock.sendall(self._h2_conn.data_to_send())
            except Exception:
                pass

            self._h2_conn = None
            self._stream_id = None

        super().close()
