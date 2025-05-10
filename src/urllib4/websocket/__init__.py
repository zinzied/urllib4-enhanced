"""
WebSocket support for urllib4.

This module provides WebSocket client functionality, allowing for real-time
bidirectional communication over a persistent connection.
"""

from __future__ import annotations

from .connection import WebSocketConnection
from .exceptions import (
    WebSocketError,
    WebSocketHandshakeError,
    WebSocketProtocolError,
    WebSocketTimeoutError,
)
from .protocol import (
    WebSocketCloseCode,
    WebSocketFrame,
    WebSocketFrameType,
    WebSocketMessage,
)

__all__ = [
    "WebSocketConnection",
    "WebSocketError",
    "WebSocketHandshakeError",
    "WebSocketProtocolError",
    "WebSocketTimeoutError",
    "WebSocketCloseCode",
    "WebSocketFrame",
    "WebSocketFrameType",
    "WebSocketMessage",
    "connect",
]


def connect(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    protocols: list[str] | None = None,
    timeout: float | None = None,
    **kwargs: object,
) -> WebSocketConnection:
    """
    Connect to a WebSocket server.
    
    This is a convenience function that creates a WebSocketConnection
    and performs the WebSocket handshake.
    
    :param url: The WebSocket URL to connect to (ws:// or wss://)
    :param headers: Additional HTTP headers to send with the handshake
    :param protocols: WebSocket subprotocols to request
    :param timeout: Connection timeout in seconds
    :param kwargs: Additional arguments to pass to WebSocketConnection
    :return: A connected WebSocketConnection
    :raises WebSocketHandshakeError: If the handshake fails
    :raises WebSocketError: If another error occurs
    """
    conn = WebSocketConnection(url, headers=headers, protocols=protocols, **kwargs)
    conn.connect(timeout=timeout)
    return conn
