"""
WebSocket connection implementation for urllib4.

This module provides a WebSocket client implementation that builds on
urllib4's connection infrastructure.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import queue
import random
import socket
import ssl
import struct
import threading
import time
import typing
from collections import deque
from urllib.parse import urlparse

from .._collections import HTTPHeaderDict
from ..connection import HTTPConnection, HTTPSConnection
from ..exceptions import ConnectTimeoutError, TimeoutError
from ..poolmanager import PoolManager
from ..response import HTTPResponse
from ..util.timeout import Timeout
from .backpressure import BackpressureHandler, BackpressureSettings, BackpressureStrategy
from .exceptions import (
    WebSocketClosedError,
    WebSocketError,
    WebSocketHandshakeError,
    WebSocketProtocolError,
    WebSocketTimeoutError,
)
from .extensions import WebSocketExtension, PerMessageDeflate, parse_extension_header
from .health import ConnectionState, HealthMonitor
from .protocol import (
    WebSocketCloseCode,
    WebSocketFrame,
    WebSocketFrameType,
    WebSocketMessage,
    WebSocketProtocol,
)
from .subprotocols import WebSocketSubprotocol, get_subprotocol, negotiate_subprotocol

log = logging.getLogger(__name__)


class WebSocketConnection:
    """
    WebSocket client connection.

    This class provides a WebSocket client implementation that builds on
    urllib4's connection infrastructure.
    """

    # WebSocket handshake constants
    WS_VERSION = 13
    WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        protocols: list[str] | None = None,
        extensions: list[str] | None = None,
        pool_manager: PoolManager | None = None,
        socket_options: list[tuple[int, int, int]] | None = None,
        timeout: Timeout | float | int | None = None,
        enable_compression: bool = True,
        compression_level: int = 9,
        enable_health_monitoring: bool = True,
        ping_interval: float = 30.0,
        ping_timeout: float = 10.0,
        max_ping_timeouts: int = 2,
        backpressure_settings: BackpressureSettings | None = None,
    ) -> None:
        """
        Initialize a new WebSocketConnection.

        :param url: The WebSocket URL to connect to (ws:// or wss://)
        :param headers: Additional HTTP headers to send with the handshake
        :param protocols: WebSocket subprotocols to request
        :param extensions: WebSocket extensions to request
        :param pool_manager: PoolManager to use for the connection
        :param socket_options: Socket options to set on the connection
        :param timeout: Connection timeout
        :param enable_compression: Whether to enable permessage-deflate compression
        :param compression_level: Compression level (0-9, higher is more compression)
        :param enable_health_monitoring: Whether to enable connection health monitoring
        :param ping_interval: Interval between pings in seconds
        :param ping_timeout: Timeout for pong responses in seconds
        :param max_ping_timeouts: Maximum number of consecutive ping timeouts
        :param backpressure_settings: Settings for backpressure handling
        """
        self.url = url
        self.headers = headers or {}
        self.protocols = protocols or []
        self.extensions = extensions or []
        self.pool_manager = pool_manager or PoolManager()
        self.socket_options = socket_options
        self.enable_compression = enable_compression
        self.compression_level = compression_level
        self.enable_health_monitoring = enable_health_monitoring
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout
        self.max_ping_timeouts = max_ping_timeouts

        # Handle timeout parameter
        if isinstance(timeout, (int, float)):
            self.timeout = Timeout(connect=timeout, read=timeout)
        elif timeout is None:
            self.timeout = Timeout.DEFAULT_TIMEOUT
        else:
            self.timeout = timeout

        # Parse URL
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ("ws", "wss"):
            raise ValueError(f"Invalid WebSocket URL scheme: {parsed_url.scheme}")

        self.scheme = parsed_url.scheme
        self.host = parsed_url.netloc
        self.path = parsed_url.path or "/"
        if parsed_url.query:
            self.path += f"?{parsed_url.query}"

        # Connection state
        self._sock: socket.socket | None = None
        self._protocol = WebSocketProtocol(mask_frames=True)
        self._connected = False
        self._closed = False
        self._close_code: WebSocketCloseCode | None = None
        self._close_reason: str = ""
        self._selected_protocol: str | None = None
        self._selected_extensions: list[str] = []
        self._extension_instances: list[WebSocketExtension] = []
        self._subprotocol_instance: WebSocketSubprotocol | None = None

        # Message handling
        self._message_queue: queue.Queue[WebSocketMessage | Exception] = queue.Queue()
        self._receiver_thread: threading.Thread | None = None
        self._receiver_running = False
        self._partial_message: list[WebSocketFrame] = []
        self._partial_opcode: WebSocketFrameType | None = None

        # Health monitoring
        if self.enable_health_monitoring:
            self._health_monitor = HealthMonitor(
                ping_interval=self.ping_interval,
                ping_timeout=self.ping_timeout,
                max_ping_timeouts=self.max_ping_timeouts,
            )
            self._health_monitor.set_ping_callback(self._send_frame)
            self._health_monitor.set_timeout_callback(self._handle_health_timeout)
        else:
            self._health_monitor = None

        # Backpressure handling
        self._backpressure_handler = BackpressureHandler(backpressure_settings)
        self._backpressure_handler.set_send_callback(self._send_frame_direct)
        self._backpressure_handler.set_drop_callback(self._handle_frame_dropped)
        self._backpressure_handler.set_backpressure_callback(self._handle_backpressure)

    def connect(self, timeout: float | None = None) -> None:
        """
        Connect to the WebSocket server.

        This method performs the WebSocket handshake and establishes
        the connection.

        :param timeout: Connection timeout in seconds
        :raises WebSocketHandshakeError: If the handshake fails
        :raises WebSocketError: If another error occurs
        """
        if self._connected:
            return

        # Determine HTTP scheme from WebSocket scheme
        http_scheme = "https" if self.scheme == "wss" else "http"

        # Generate the WebSocket key
        ws_key = base64.b64encode(random.randbytes(16)).decode()

        # Prepare handshake headers
        handshake_headers = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": str(self.WS_VERSION),
        }

        # Add subprotocols if specified
        if self.protocols:
            handshake_headers["Sec-WebSocket-Protocol"] = ", ".join(self.protocols)

        # Add extensions if specified
        if self.enable_compression:
            # Create permessage-deflate extension
            compression_ext = PerMessageDeflate(
                client_max_window_bits=15,
                server_max_window_bits=15,
                client_no_context_takeover=False,
                server_no_context_takeover=False,
                compression_level=self.compression_level,
            )
            self._extension_instances.append(compression_ext)

            # Add to extensions list if not already there
            if not self.extensions:
                self.extensions = [compression_ext.offer()]
            else:
                self.extensions.append(compression_ext.offer())

        if self.extensions:
            handshake_headers["Sec-WebSocket-Extensions"] = ", ".join(self.extensions)

        # Add user-specified headers
        handshake_headers.update(self.headers)

        # Set timeout for the handshake
        connect_timeout = timeout if timeout is not None else self.timeout.connect_timeout

        try:
            # Perform the handshake
            response = self.pool_manager.request(
                "GET",
                f"{http_scheme}://{self.host}{self.path}",
                headers=handshake_headers,
                timeout=connect_timeout,
                retries=False,
            )

            # Check for successful handshake
            if response.status != 101:
                raise WebSocketHandshakeError(
                    f"WebSocket handshake failed: {response.status} {response.reason}",
                    response=response,
                )

            # Verify the server's response
            if response.headers.get("Upgrade", "").lower() != "websocket":
                raise WebSocketHandshakeError(
                    "WebSocket handshake failed: 'Upgrade' header is not 'websocket'",
                    response=response,
                )

            if response.headers.get("Connection", "").lower() != "upgrade":
                raise WebSocketHandshakeError(
                    "WebSocket handshake failed: 'Connection' header is not 'upgrade'",
                    response=response,
                )

            # Verify the Sec-WebSocket-Accept header
            accept_key = base64.b64encode(
                hashlib.sha1((ws_key + self.WS_GUID).encode()).digest()
            ).decode()

            if response.headers.get("Sec-WebSocket-Accept") != accept_key:
                raise WebSocketHandshakeError(
                    "WebSocket handshake failed: Invalid 'Sec-WebSocket-Accept' header",
                    response=response,
                )

            # Check for selected protocol
            if self.protocols:
                self._selected_protocol = response.headers.get("Sec-WebSocket-Protocol")
                if self._selected_protocol and self._selected_protocol not in self.protocols:
                    raise WebSocketHandshakeError(
                        f"Server selected unsupported protocol: {self._selected_protocol}",
                        response=response,
                    )

                # Initialize the selected subprotocol
                if self._selected_protocol:
                    try:
                        self._subprotocol_instance = get_subprotocol(self._selected_protocol)
                        log.debug(f"Using subprotocol: {self._selected_protocol}")
                    except ValueError as e:
                        log.warning(f"Unknown subprotocol: {self._selected_protocol}")

            # Check for selected extensions
            if self._extension_instances:
                extensions_header = response.headers.get("Sec-WebSocket-Extensions", "")
                if extensions_header:
                    # Parse the extensions header
                    parsed_extensions = parse_extension_header(extensions_header)
                    self._selected_extensions = [ext[0] for ext in parsed_extensions]

                    # Process each extension
                    for ext_name, ext_params in parsed_extensions:
                        # Find the matching extension instance
                        for ext in self._extension_instances:
                            if ext.name == ext_name:
                                # Accept the extension
                                if ext.accept(extensions_header):
                                    log.debug(f"Using extension: {ext_name}")
                                else:
                                    log.warning(f"Failed to accept extension: {ext_name}")
                                break

            # Get the socket from the response
            self._sock = response.connection.sock  # type: ignore

            # Mark as connected
            self._connected = True

            # Start the health monitor
            if self._health_monitor:
                self._health_monitor.start()

            # Start the backpressure handler
            self._backpressure_handler.start()

            # Start the receiver thread
            self._start_receiver()

        except (ConnectTimeoutError, TimeoutError) as e:
            raise WebSocketTimeoutError(f"WebSocket connection timed out: {e}")
        except WebSocketError:
            raise
        except Exception as e:
            raise WebSocketError(f"WebSocket connection failed: {e}")

    def _start_receiver(self) -> None:
        """Start the background thread that receives WebSocket messages."""
        if self._receiver_thread is not None:
            return

        self._receiver_running = True
        self._receiver_thread = threading.Thread(
            target=self._receiver_loop,
            daemon=True,
            name="websocket-receiver",
        )
        self._receiver_thread.start()

    def _receiver_loop(self) -> None:
        """Background thread that receives WebSocket messages."""
        if self._sock is None:
            return

        buffer = bytearray()

        try:
            while self._receiver_running and not self._closed:
                # Read data from the socket
                try:
                    data = self._sock.recv(4096)
                    if not data:
                        # Connection closed by the server
                        self._handle_connection_closed()
                        break

                    buffer.extend(data)
                except socket.timeout:
                    # Socket timeout, just continue
                    continue
                except (socket.error, OSError) as e:
                    # Socket error
                    self._message_queue.put(WebSocketError(f"WebSocket receive error: {e}"))
                    self._handle_connection_closed()
                    break

                # Process all complete frames in the buffer
                while buffer:
                    try:
                        frame, consumed = self._protocol.decode_frame(buffer)
                        buffer = buffer[consumed:]
                        self._handle_frame(frame, consumed)
                    except ValueError:
                        # Incomplete frame, wait for more data
                        break
                    except Exception as e:
                        # Protocol error
                        if self._health_monitor:
                            self._health_monitor.protocol_error()
                        self._message_queue.put(
                            WebSocketProtocolError(f"WebSocket protocol error: {e}")
                        )
                        self._handle_connection_closed()
                        break

        finally:
            self._receiver_running = False

    def _handle_frame(self, frame: WebSocketFrame, encoded_size: int = 0) -> None:
        """
        Handle a received WebSocket frame.

        :param frame: The frame to handle
        :param encoded_size: The size of the encoded frame in bytes
        """
        # Apply extensions to decode the frame
        for ext in reversed(self._extension_instances):
            frame = ext.decode_frame(frame)

        # Update health monitoring
        if self._health_monitor:
            self._health_monitor.frame_received(frame, encoded_size)

        if frame.opcode == WebSocketFrameType.PING:
            # Automatically respond to pings
            self._send_frame(WebSocketFrame.create_pong(frame.payload))
            return

        elif frame.opcode == WebSocketFrameType.PONG:
            # Handle pongs for health monitoring
            if self._health_monitor:
                self._health_monitor.handle_pong(frame.payload)
            return

        elif frame.opcode == WebSocketFrameType.CLOSE:
            # Handle close frame
            if len(frame.payload) >= 2:
                code = WebSocketCloseCode(struct.unpack("!H", frame.payload[:2])[0])
                reason = frame.payload[2:].decode("utf-8", errors="replace")
            else:
                code = WebSocketCloseCode.NO_STATUS
                reason = ""

            self._close_code = code
            self._close_reason = reason

            # Echo the close frame if we didn't initiate the close
            if not self._closed:
                self._send_frame(WebSocketFrame.create_close(code, reason))

            self._handle_connection_closed()
            return

        elif frame.opcode in (WebSocketFrameType.TEXT, WebSocketFrameType.BINARY):
            # Start of a new message
            if self._partial_message:
                # Previous message wasn't completed
                self._message_queue.put(
                    WebSocketProtocolError("Received new message before previous was complete")
                )
                self._partial_message = []

            self._partial_opcode = frame.opcode
            self._partial_message.append(frame)

        elif frame.opcode == WebSocketFrameType.CONTINUATION:
            # Continuation of a message
            if not self._partial_message:
                # No message to continue
                self._message_queue.put(
                    WebSocketProtocolError("Received continuation frame with no message to continue")
                )
                return

            self._partial_message.append(frame)

        else:
            # Unknown opcode
            self._message_queue.put(
                WebSocketProtocolError(f"Received frame with unknown opcode: {frame.opcode}")
            )
            return

        # Check if the message is complete
        if frame.fin:
            # Combine all frames into a single message
            payload = b"".join(f.payload for f in self._partial_message)
            message = WebSocketMessage(opcode=self._partial_opcode, data=payload)  # type: ignore

            # Add to the message queue
            self._message_queue.put(message)

            # Reset partial message state
            self._partial_message = []
            self._partial_opcode = None

    def _handle_connection_closed(self) -> None:
        """Handle the WebSocket connection being closed."""
        self._closed = True

        # If we don't have a close code, use ABNORMAL
        if self._close_code is None:
            self._close_code = WebSocketCloseCode.ABNORMAL

        # Put a close error in the queue to notify readers
        self._message_queue.put(
            WebSocketClosedError(
                code=self._close_code,
                reason=self._close_reason,
            )
        )

    def _send_frame(self, frame: WebSocketFrame) -> None:
        """
        Send a WebSocket frame.

        :param frame: The frame to send
        :raises WebSocketClosedError: If the connection is closed
        :raises WebSocketError: If an error occurs while sending
        """
        if self._closed:
            raise WebSocketClosedError(
                code=self._close_code or WebSocketCloseCode.ABNORMAL,
                reason=self._close_reason,
            )

        if self._sock is None:
            raise WebSocketError("WebSocket is not connected")

        # Apply extensions to encode the frame
        for ext in self._extension_instances:
            frame = ext.encode_frame(frame)

        # Queue the frame for sending (handles backpressure)
        self._backpressure_handler.queue_frame(frame)

    def _send_frame_direct(self, frame: WebSocketFrame) -> None:
        """
        Send a WebSocket frame directly, bypassing the backpressure handler.

        This method is called by the backpressure handler when a frame is ready to be sent.

        :param frame: The frame to send
        :raises WebSocketError: If an error occurs while sending
        """
        if self._closed or self._sock is None:
            return

        try:
            # Encode the frame
            data = self._protocol.encode_frame(frame)

            # Send the data
            self._sock.sendall(data)

            # Update health monitoring
            if self._health_monitor:
                self._health_monitor.frame_sent(frame, len(data))
        except (socket.error, OSError) as e:
            self._handle_connection_closed()
            raise WebSocketError(f"Error sending WebSocket frame: {e}")

    def _handle_frame_dropped(self, frame: WebSocketFrame) -> None:
        """
        Handle a frame being dropped due to backpressure.

        :param frame: The frame that was dropped
        """
        log.warning(f"Frame dropped due to backpressure: {frame.opcode}")

    def _handle_backpressure(self) -> None:
        """Handle backpressure being applied."""
        log.warning("Backpressure applied to WebSocket connection")

    def _handle_health_timeout(self) -> None:
        """Handle a health monitoring timeout."""
        log.warning("WebSocket connection health check failed")
        self._handle_connection_closed()

    def send(self, data: str | bytes | object) -> None:
        """
        Send data over the WebSocket connection.

        :param data: The data to send (str for text, bytes for binary, object for subprotocol)
        :raises WebSocketClosedError: If the connection is closed
        :raises WebSocketError: If an error occurs while sending
        """
        # If we have a subprotocol and the data is not a string or bytes,
        # encode it using the subprotocol
        if self._subprotocol_instance and not isinstance(data, (str, bytes)):
            encoded_data = self._subprotocol_instance.encode_message(data)
            return self.send(encoded_data)

        if isinstance(data, str):
            frame = WebSocketFrame.create_text(data)
        else:
            frame = WebSocketFrame.create_binary(data)

        self._send_frame(frame)

    def receive(self, timeout: float | None = None, decode: bool = True) -> WebSocketMessage | object:
        """
        Receive a message from the WebSocket connection.

        :param timeout: Timeout in seconds, or None for no timeout
        :param decode: Whether to decode the message using the subprotocol
        :return: The received message or decoded object if using a subprotocol
        :raises WebSocketClosedError: If the connection is closed
        :raises WebSocketTimeoutError: If the timeout is reached
        :raises WebSocketError: If another error occurs
        """
        try:
            message = self._message_queue.get(timeout=timeout)

            # If we got an exception, raise it
            if isinstance(message, Exception):
                raise message

            # If we have a subprotocol and should decode, decode the message
            if decode and self._subprotocol_instance:
                try:
                    return self._subprotocol_instance.decode_message(message)
                except Exception as e:
                    log.warning(f"Failed to decode message with subprotocol: {e}")
                    # Fall back to returning the raw message

            return message
        except queue.Empty:
            raise WebSocketTimeoutError("Timed out waiting for WebSocket message")

    def close(self, code: WebSocketCloseCode = WebSocketCloseCode.NORMAL, reason: str = "") -> None:
        """
        Close the WebSocket connection.

        :param code: The close code to send
        :param reason: The close reason to send
        """
        if self._closed:
            return

        try:
            # Send close frame
            self._send_frame(WebSocketFrame.create_close(code, reason))

            # Wait for the server to acknowledge the close
            start_time = time.time()
            while not self._closed and time.time() - start_time < 5:
                try:
                    self.receive(timeout=0.1)
                except WebSocketTimeoutError:
                    continue
                except WebSocketClosedError:
                    break

        except Exception:
            # Ignore errors during close
            pass

        finally:
            # Ensure we're marked as closed
            self._closed = True
            self._close_code = code
            self._close_reason = reason

            # Stop the receiver thread
            self._receiver_running = False

            # Stop the health monitor
            if self._health_monitor:
                self._health_monitor.stop()

            # Stop the backpressure handler
            self._backpressure_handler.stop()

            # Close the socket
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def ping(self, data: bytes = b"") -> None:
        """
        Send a ping frame.

        :param data: Optional ping data
        :raises WebSocketClosedError: If the connection is closed
        :raises WebSocketError: If an error occurs while sending
        """
        self._send_frame(WebSocketFrame.create_ping(data))

    @property
    def closed(self) -> bool:
        """Check if the connection is closed."""
        return self._closed

    @property
    def connected(self) -> bool:
        """Check if the connection is established."""
        return self._connected and not self._closed

    @property
    def selected_protocol(self) -> str | None:
        """Get the subprotocol selected by the server."""
        return self._selected_protocol

    @property
    def selected_extensions(self) -> list[str]:
        """Get the extensions selected by the server."""
        return self._selected_extensions.copy()

    def __enter__(self) -> "WebSocketConnection":
        """Enter context manager."""
        if not self._connected:
            self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: typing.TracebackType | None,
    ) -> None:
        """Exit context manager."""
        self.close()
