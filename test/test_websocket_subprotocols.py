"""
Tests for WebSocket subprotocols functionality.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from urllib4.websocket.protocol import WebSocketFrameType, WebSocketMessage
from urllib4.websocket.subprotocols import (
    CBORSubprotocol,
    JSONSubprotocol,
    MessagePackSubprotocol,
    WebSocketSubprotocol,
    get_subprotocol,
    negotiate_subprotocol,
    KNOWN_SUBPROTOCOLS,
)


class TestJSONSubprotocol:
    """Tests for the JSONSubprotocol class."""

    def test_name(self):
        """Test the name property."""
        protocol = JSONSubprotocol()
        assert protocol.name == "json"

    def test_encode_message(self):
        """Test encoding a message."""
        protocol = JSONSubprotocol()

        # Test with a simple object
        message = {"hello": "world", "number": 42, "bool": True, "null": None}
        encoded = protocol.encode_message(message)

        # Check that the result is a string
        assert isinstance(encoded, str)

        # Check that it can be decoded as JSON
        decoded = json.loads(encoded)
        assert decoded == message

    def test_decode_message(self):
        """Test decoding a message."""
        protocol = JSONSubprotocol()

        # Create a text message
        json_str = '{"hello":"world","number":42,"bool":true,"null":null}'
        message = WebSocketMessage(opcode=WebSocketFrameType.TEXT, data=json_str.encode())

        # Decode the message
        decoded = protocol.decode_message(message)

        # Check the result
        assert decoded == {"hello": "world", "number": 42, "bool": True, "null": None}

    def test_decode_binary_message(self):
        """Test decoding a binary message."""
        protocol = JSONSubprotocol()

        # Create a binary message
        json_bytes = b'{"hello":"world","number":42,"bool":true,"null":null}'
        message = WebSocketMessage(opcode=WebSocketFrameType.BINARY, data=json_bytes)

        # Decode the message should raise ValueError
        with pytest.raises(ValueError):
            protocol.decode_message(message)

    def test_decode_invalid_message(self):
        """Test decoding an invalid message."""
        protocol = JSONSubprotocol()

        # Create an invalid JSON message
        message = WebSocketMessage(opcode=WebSocketFrameType.TEXT, data=b"not json")

        # Decode the message
        with pytest.raises(json.JSONDecodeError):
            protocol.decode_message(message)


class TestMessagePackSubprotocol:
    """Tests for the MessagePackSubprotocol class."""

    def test_name(self):
        """Test the name property."""
        protocol = MessagePackSubprotocol()
        assert protocol.name == "msgpack"

    def test_encode_decode_message(self):
        """Test encoding and decoding a message."""
        # Skip if msgpack is not installed
        pytest.importorskip("msgpack")

        protocol = MessagePackSubprotocol()

        # Test with a simple object
        message = {"hello": "world", "number": 42, "bool": True, "null": None}
        encoded = protocol.encode_message(message)

        # Check that the result is bytes
        assert isinstance(encoded, bytes)

        # Create a binary message
        ws_message = WebSocketMessage(opcode=WebSocketFrameType.BINARY, data=encoded)

        # Decode the message
        decoded = protocol.decode_message(ws_message)

        # Check the result
        assert decoded == message

    def test_decode_text_message(self):
        """Test decoding a text message."""
        # Skip if msgpack is not installed
        pytest.importorskip("msgpack")

        protocol = MessagePackSubprotocol()

        # Create a text message
        message = WebSocketMessage(opcode=WebSocketFrameType.TEXT, data=b"not msgpack")

        # Decode the message
        with pytest.raises(ValueError):
            protocol.decode_message(message)


class TestCBORSubprotocol:
    """Tests for the CBORSubprotocol class."""

    def test_name(self):
        """Test the name property."""
        # Skip if cbor2 is not installed
        pytest.importorskip("cbor2")

        protocol = CBORSubprotocol()
        assert protocol.name == "cbor"

    def test_encode_decode_message(self):
        """Test encoding and decoding a message."""
        # Skip if cbor2 is not installed
        pytest.importorskip("cbor2")

        protocol = CBORSubprotocol()

        # Test with a simple object
        message = {"hello": "world", "number": 42, "bool": True, "null": None}
        encoded = protocol.encode_message(message)

        # Check that the result is bytes
        assert isinstance(encoded, bytes)

        # Create a binary message
        ws_message = WebSocketMessage(opcode=WebSocketFrameType.BINARY, data=encoded)

        # Decode the message
        decoded = protocol.decode_message(ws_message)

        # Check the result
        assert decoded == message

    def test_decode_text_message(self):
        """Test decoding a text message."""
        # Skip if cbor2 is not installed
        pytest.importorskip("cbor2")

        protocol = CBORSubprotocol()

        # Create a text message
        message = WebSocketMessage(opcode=WebSocketFrameType.TEXT, data=b"not cbor")

        # Decode the message
        with pytest.raises(ValueError):
            protocol.decode_message(message)


class TestSubprotocolRegistry:
    """Tests for the subprotocol registry functions."""

    def test_get_subprotocol(self):
        """Test getting a subprotocol by name."""
        # Get a built-in subprotocol
        protocol = get_subprotocol("json")
        assert isinstance(protocol, JSONSubprotocol)

        # Try to get a non-existent subprotocol
        with pytest.raises(ValueError):
            get_subprotocol("nonexistent")

    def test_register_subprotocol(self):
        """Test registering a custom subprotocol."""
        # Create a mock subprotocol class
        mock_protocol_class = mock.MagicMock(spec=WebSocketSubprotocol)
        mock_protocol_instance = mock.MagicMock(spec=WebSocketSubprotocol)
        mock_protocol_class.return_value = mock_protocol_instance

        # Register the subprotocol
        KNOWN_SUBPROTOCOLS["mock"] = mock_protocol_class

        # Get the registered subprotocol
        protocol = get_subprotocol("mock")
        assert protocol == mock_protocol_instance

        # Clean up
        del KNOWN_SUBPROTOCOLS["mock"]

    def test_negotiate_subprotocol(self):
        """Test negotiating a subprotocol."""
        # Test with a match
        client_protocols = ["json", "msgpack", "cbor"]
        server_protocols = ["cbor", "json"]

        result = negotiate_subprotocol(client_protocols, server_protocols)
        # The first match in client_protocols order is returned
        assert result == "json"

        # Test with no match
        client_protocols = ["json", "msgpack"]
        server_protocols = ["cbor", "xml"]

        result = negotiate_subprotocol(client_protocols, server_protocols)
        assert result is None

        # Test with empty lists
        client_protocols = []
        server_protocols = ["json"]

        result = negotiate_subprotocol(client_protocols, server_protocols)
        assert result is None

        client_protocols = ["json"]
        server_protocols = []

        result = negotiate_subprotocol(client_protocols, server_protocols)
        assert result is None
