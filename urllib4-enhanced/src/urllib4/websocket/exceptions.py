"""
WebSocket exceptions for urllib4.

This module defines exceptions that can be raised during WebSocket operations.
"""

from __future__ import annotations

from ..exceptions import HTTPError


class WebSocketError(HTTPError):
    """Base class for all WebSocket-related errors."""
    
    pass


class WebSocketHandshakeError(WebSocketError):
    """
    Raised when the WebSocket handshake fails.
    
    This can happen if the server doesn't support WebSockets or
    if the handshake request is invalid.
    """
    
    def __init__(self, message: str, response: object = None) -> None:
        super().__init__(message)
        self.response = response


class WebSocketProtocolError(WebSocketError):
    """
    Raised when a WebSocket protocol error occurs.
    
    This can happen if invalid frames are received or if the
    protocol is violated in some other way.
    """
    
    pass


class WebSocketTimeoutError(WebSocketError):
    """
    Raised when a WebSocket operation times out.
    
    This can happen during the initial connection or during
    send/receive operations.
    """
    
    pass


class WebSocketClosedError(WebSocketError):
    """
    Raised when trying to use a closed WebSocket connection.
    
    This can happen if you try to send data after the connection
    has been closed.
    """
    
    def __init__(self, code: int = 1006, reason: str = "") -> None:
        message = f"WebSocket is closed (code={code}, reason={reason})"
        super().__init__(message)
        self.code = code
        self.reason = reason
