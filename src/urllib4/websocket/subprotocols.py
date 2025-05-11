"""
WebSocket subprotocols for urllib4.

This module provides support for WebSocket subprotocols, which define
the format and semantics of messages exchanged over a WebSocket connection.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from .protocol import WebSocketMessage

log = logging.getLogger(__name__)


class WebSocketSubprotocol(ABC):
    """
    Base class for WebSocket subprotocols.
    
    WebSocket subprotocols define the format and semantics of messages
    exchanged over a WebSocket connection.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the subprotocol."""
        pass
    
    @abstractmethod
    def encode_message(self, message: Any) -> Union[str, bytes]:
        """
        Encode a message according to the subprotocol.
        
        :param message: The message to encode
        :return: The encoded message as a string or bytes
        """
        pass
    
    @abstractmethod
    def decode_message(self, message: WebSocketMessage) -> Any:
        """
        Decode a message according to the subprotocol.
        
        :param message: The message to decode
        :return: The decoded message
        """
        pass


class JSONSubprotocol(WebSocketSubprotocol):
    """
    JSON subprotocol for WebSocket.
    
    This subprotocol encodes messages as JSON strings.
    """
    
    @property
    def name(self) -> str:
        """Get the name of the subprotocol."""
        return "json"
    
    def encode_message(self, message: Any) -> str:
        """
        Encode a message as JSON.
        
        :param message: The message to encode
        :return: The JSON-encoded message
        """
        return json.dumps(message)
    
    def decode_message(self, message: WebSocketMessage) -> Any:
        """
        Decode a JSON message.
        
        :param message: The message to decode
        :return: The decoded message
        :raises ValueError: If the message is not valid JSON
        """
        if not message.is_text:
            raise ValueError("JSON messages must be text")
            
        return json.loads(message.text)


class MessagePackSubprotocol(WebSocketSubprotocol):
    """
    MessagePack subprotocol for WebSocket.
    
    This subprotocol encodes messages using MessagePack, a binary
    serialization format similar to JSON but more compact.
    """
    
    def __init__(self) -> None:
        """Initialize a new MessagePackSubprotocol."""
        try:
            import msgpack
            self._msgpack = msgpack
        except ImportError:
            raise ImportError(
                "MessagePack subprotocol requires the msgpack package. "
                "Install with: pip install msgpack"
            )
    
    @property
    def name(self) -> str:
        """Get the name of the subprotocol."""
        return "msgpack"
    
    def encode_message(self, message: Any) -> bytes:
        """
        Encode a message using MessagePack.
        
        :param message: The message to encode
        :return: The MessagePack-encoded message
        """
        return self._msgpack.packb(message, use_bin_type=True)
    
    def decode_message(self, message: WebSocketMessage) -> Any:
        """
        Decode a MessagePack message.
        
        :param message: The message to decode
        :return: The decoded message
        :raises ValueError: If the message is not valid MessagePack
        """
        if not message.is_binary:
            raise ValueError("MessagePack messages must be binary")
            
        return self._msgpack.unpackb(message.data, raw=False)


class CBORSubprotocol(WebSocketSubprotocol):
    """
    CBOR subprotocol for WebSocket.
    
    This subprotocol encodes messages using CBOR (Concise Binary Object
    Representation), a binary serialization format similar to JSON.
    """
    
    def __init__(self) -> None:
        """Initialize a new CBORSubprotocol."""
        try:
            import cbor2
            self._cbor2 = cbor2
        except ImportError:
            raise ImportError(
                "CBOR subprotocol requires the cbor2 package. "
                "Install with: pip install cbor2"
            )
    
    @property
    def name(self) -> str:
        """Get the name of the subprotocol."""
        return "cbor"
    
    def encode_message(self, message: Any) -> bytes:
        """
        Encode a message using CBOR.
        
        :param message: The message to encode
        :return: The CBOR-encoded message
        """
        return self._cbor2.dumps(message)
    
    def decode_message(self, message: WebSocketMessage) -> Any:
        """
        Decode a CBOR message.
        
        :param message: The message to decode
        :return: The decoded message
        :raises ValueError: If the message is not valid CBOR
        """
        if not message.is_binary:
            raise ValueError("CBOR messages must be binary")
            
        return self._cbor2.loads(message.data)


# Registry of known subprotocols
KNOWN_SUBPROTOCOLS = {
    "json": JSONSubprotocol,
    "msgpack": MessagePackSubprotocol,
    "cbor": CBORSubprotocol,
}


def get_subprotocol(name: str) -> WebSocketSubprotocol:
    """
    Get a subprotocol by name.
    
    :param name: The name of the subprotocol
    :return: The subprotocol instance
    :raises ValueError: If the subprotocol is not known
    """
    if name not in KNOWN_SUBPROTOCOLS:
        raise ValueError(f"Unknown subprotocol: {name}")
        
    return KNOWN_SUBPROTOCOLS[name]()


def negotiate_subprotocol(
    client_protocols: List[str], server_protocols: List[str]
) -> Optional[str]:
    """
    Negotiate a subprotocol between client and server.
    
    :param client_protocols: The protocols offered by the client
    :param server_protocols: The protocols supported by the server
    :return: The negotiated protocol, or None if no match
    """
    for protocol in client_protocols:
        if protocol in server_protocols:
            return protocol
            
    return None
