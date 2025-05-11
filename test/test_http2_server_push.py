"""
Tests for HTTP/2 server push functionality.
"""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from urllib4.http2.connection import HTTP2Connection
from urllib4.http2.push_manager import PushManager, PushPromise


class TestPushManager:
    """Tests for the PushManager class."""

    def test_init(self):
        """Test initialization."""
        manager = PushManager()
        assert manager._promises == {}
        assert manager._cache == {}
        assert manager._parent_streams == {}

    def test_handle_push_promise(self):
        """Test handling a push promise event."""
        manager = PushManager()
        
        # Create a mock event
        event = mock.MagicMock()
        event.pushed_stream_id = 2
        event.parent_stream_id = 1
        event.headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/style.css"),
        ]
        
        # Handle the event
        manager.handle_push_promise(event)
        
        # Check that the promise was stored
        assert 2 in manager._promises
        assert manager._promises[2].stream_id == 2
        assert manager._promises[2].parent_stream_id == 1
        assert manager._promises[2].headers == event.headers
        assert manager._promises[2].url == "https://example.com/style.css"
        
        # Check that the parent stream was updated
        assert 1 in manager._parent_streams
        assert 2 in manager._parent_streams[1]

    def test_handle_headers(self):
        """Test handling a headers event."""
        manager = PushManager()
        
        # Create a promise
        promise = PushPromise(
            stream_id=2,
            parent_stream_id=1,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/style.css"),
            ],
        )
        manager._promises[2] = promise
        
        # Create a mock event
        event = mock.MagicMock()
        event.stream_id = 2
        event.headers = [
            (b":status", b"200"),
            (b"content-type", b"text/css"),
        ]
        
        # Handle the event
        manager.handle_headers(event)
        
        # Check that the headers were stored
        assert manager._promises[2].response_headers == event.headers

    def test_handle_data(self):
        """Test handling a data event."""
        manager = PushManager()
        
        # Create a promise
        promise = PushPromise(
            stream_id=2,
            parent_stream_id=1,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/style.css"),
            ],
        )
        manager._promises[2] = promise
        
        # Create a mock event
        event = mock.MagicMock()
        event.stream_id = 2
        event.data = b"body data"
        
        # Handle the event
        manager.handle_data(event)
        
        # Check that the data was stored
        assert bytes(manager._promises[2].data) == b"body data"

    def test_handle_stream_ended(self):
        """Test handling a stream ended event."""
        manager = PushManager()
        
        # Create a promise
        promise = PushPromise(
            stream_id=2,
            parent_stream_id=1,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/style.css"),
            ],
        )
        promise.response_headers = [
            (b":status", b"200"),
            (b"content-type", b"text/css"),
        ]
        promise.data = bytearray(b"body data")
        manager._promises[2] = promise
        manager._parent_streams[1] = {2}
        
        # Create a mock event
        event = mock.MagicMock()
        event.stream_id = 2
        
        # Handle the event
        manager.handle_stream_ended(event)
        
        # Check that the promise was marked as received
        assert manager._promises[2].received
        
        # Check that a response was created and cached
        assert "https://example.com/style.css" in manager._cache
        response = manager._cache["https://example.com/style.css"]
        assert response.status == 200
        assert response.headers["content-type"] == "text/css"
        assert response.data == b"body data"

    def test_get_pushed_responses(self):
        """Test getting pushed responses for a parent stream."""
        manager = PushManager()
        
        # Create a promise and response
        promise = PushPromise(
            stream_id=2,
            parent_stream_id=1,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
                (b":path", b"/style.css"),
            ],
        )
        promise.response_headers = [
            (b":status", b"200"),
            (b"content-type", b"text/css"),
        ]
        promise.data = bytearray(b"body data")
        promise.received = True
        manager._promises[2] = promise
        manager._parent_streams[1] = {2}
        
        # Create a response
        from urllib4.response import HTTPResponse
        response = HTTPResponse(
            body=b"body data",
            headers={"content-type": "text/css"},
            status=200,
            request_url="https://example.com/style.css",
        )
        manager._cache["https://example.com/style.css"] = response
        
        # Get pushed responses
        responses = manager.get_pushed_responses(1)
        
        # Check that the response was returned
        assert len(responses) == 1
        assert responses[0].status == 200
        assert responses[0].headers["content-type"] == "text/css"
        assert responses[0].data == b"body data"
        assert responses[0].request_url == "https://example.com/style.css"
