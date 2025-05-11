"""
Tests for enhanced WebSocket functionality.
"""

from __future__ import annotations

import socket
import threading
import time
from unittest import mock

import pytest

from urllib4.websocket.backpressure import (
    BackpressureHandler,
    BackpressureSettings,
    BackpressureStrategy,
)
from urllib4.websocket.connection import WebSocketConnection
from urllib4.websocket.health import ConnectionState, HealthMonitor, ConnectionStats
from urllib4.websocket.protocol import WebSocketCloseCode, WebSocketFrame, WebSocketFrameType


class TestBackpressureHandler:
    """Tests for the BackpressureHandler class."""

    def test_init_default_settings(self):
        """Test initialization with default settings."""
        handler = BackpressureHandler()

        assert handler.settings is not None
        assert handler.settings.max_queue_size == 1000
        assert handler.settings.strategy == BackpressureStrategy.BLOCK

    def test_init_custom_settings(self):
        """Test initialization with custom settings."""
        settings = BackpressureSettings(
            max_queue_size=50,
            strategy=BackpressureStrategy.DROP,
            max_message_size=1024,
        )

        handler = BackpressureHandler(settings)

        assert handler.settings == settings

    def test_queue_frame(self):
        """Test queueing a frame."""
        handler = BackpressureHandler()

        # Mock the send callback
        mock_send = mock.MagicMock()
        handler.set_send_callback(mock_send)

        # Start the handler
        handler.start()

        # Queue a frame
        frame = WebSocketFrame(
            fin=True,
            opcode=WebSocketFrameType.TEXT,
            payload=b"test",
        )

        result = handler.queue_frame(frame)

        # Check that the frame was queued
        assert result is True

        # Wait for the frame to be processed
        time.sleep(0.1)

        # Check that the send callback was called
        mock_send.assert_called_once_with(frame)

        # Stop the handler
        handler.stop()

    def test_queue_frame_backpressure_apply(self):
        """Test queueing a frame with backpressure (apply strategy)."""
        settings = BackpressureSettings(
            max_queue_size=1,
            strategy=BackpressureStrategy.APPLY,
        )

        handler = BackpressureHandler(settings)

        # Mock the send callback
        mock_send = mock.MagicMock()
        handler.set_send_callback(mock_send)

        # Mock the backpressure callback
        mock_backpressure = mock.MagicMock()
        handler.set_backpressure_callback(mock_backpressure)

        # Start the handler
        handler.start()

        # Queue a frame
        frame1 = WebSocketFrame(
            fin=True,
            opcode=WebSocketFrameType.TEXT,
            payload=b"test1",
        )

        # Fill the queue
        handler.queue.put(frame1)

        # Queue another frame to trigger backpressure
        frame2 = WebSocketFrame(
            fin=True,
            opcode=WebSocketFrameType.TEXT,
            payload=b"test2",
        )

        # Queue the frame (this should apply backpressure)
        handler.queue_frame(frame2)

        # Check that the backpressure callback was called
        mock_backpressure.assert_called_once()

        # Stop the handler
        handler.stop()

    def test_queue_frame_backpressure_drop(self):
        """Test queueing a frame with backpressure (drop strategy)."""
        settings = BackpressureSettings(
            max_queue_size=1,
            strategy=BackpressureStrategy.DROP,
        )

        handler = BackpressureHandler(settings)

        # Mock the send callback
        mock_send = mock.MagicMock()
        handler.set_send_callback(mock_send)

        # Mock the drop callback
        mock_drop = mock.MagicMock()
        handler.set_drop_callback(mock_drop)

        # Start the handler
        handler.start()

        # Queue a frame
        frame1 = WebSocketFrame(
            fin=True,
            opcode=WebSocketFrameType.TEXT,
            payload=b"test1",
        )

        # Queue another frame to trigger backpressure
        frame2 = WebSocketFrame(
            fin=True,
            opcode=WebSocketFrameType.TEXT,
            payload=b"test2",
        )

        # Fill the queue
        handler.queue.put(frame1)

        # Try to queue another frame
        handler.queue_frame(frame2)

        # Check that the drop callback was called
        mock_drop.assert_called_once_with(frame2)

        # Stop the handler
        handler.stop()


class TestHealthMonitor:
    """Tests for the HealthMonitor class."""

    def test_init(self):
        """Test initialization."""
        monitor = HealthMonitor()

        assert monitor.ping_interval == 30.0
        assert monitor.ping_timeout == 10.0
        assert monitor.max_ping_timeouts == 2
        assert monitor.state == ConnectionState.CONNECTING
        assert monitor.stats is not None

    def test_init_custom_settings(self):
        """Test initialization with custom settings."""
        monitor = HealthMonitor(
            ping_interval=60.0,
            ping_timeout=5.0,
            max_ping_timeouts=3,
        )

        assert monitor.ping_interval == 60.0
        assert monitor.ping_timeout == 5.0
        assert monitor.max_ping_timeouts == 3

    def test_start_stop(self):
        """Test starting and stopping the monitor."""
        monitor = HealthMonitor()

        # Mock the ping callback
        mock_ping = mock.MagicMock()
        monitor.set_ping_callback(mock_ping)

        # Start the monitor
        monitor.start()

        # Check that the monitor is started
        assert monitor.state == ConnectionState.OPEN

        # Stop the monitor
        monitor.stop()

        # Check that the monitor is stopped
        assert monitor.state == ConnectionState.CLOSED

    def test_handle_pong(self):
        """Test handling a pong."""
        monitor = HealthMonitor()

        # Create ping data
        ping_data = b"ping data"

        # Add to pending pings
        monitor._ping_data[ping_data] = time.time() - 1.0

        # Handle a pong
        monitor.handle_pong(ping_data)

        # Check that the ping was acknowledged
        assert ping_data not in monitor._ping_data
        assert monitor._consecutive_timeouts == 0
        assert monitor.stats.pongs_received == 1

    def test_handle_pong_wrong_data(self):
        """Test handling a pong with wrong data."""
        monitor = HealthMonitor()

        # Create ping data
        ping_data = b"ping data"

        # Add to pending pings
        monitor._ping_data[ping_data] = time.time() - 1.0

        # Handle a pong with wrong data
        monitor.handle_pong(b"wrong data")

        # Check that the ping was not acknowledged
        assert ping_data in monitor._ping_data
        assert monitor.stats.pongs_received == 0

    def test_protocol_error(self):
        """Test handling a protocol error."""
        monitor = HealthMonitor()

        # Set the state to open
        monitor.state = ConnectionState.OPEN

        # Handle a protocol error
        monitor.protocol_error()

        # Check that the state was updated
        assert monitor.state == ConnectionState.ERROR
        assert monitor.stats.protocol_errors == 1

    def test_frame_sent_received(self):
        """Test handling frame sent and received events."""
        monitor = HealthMonitor()

        # Set the state to open
        monitor.state = ConnectionState.OPEN

        # Create a frame
        frame = WebSocketFrame(
            fin=True,
            opcode=WebSocketFrameType.TEXT,
            payload=b"test",
        )

        # Handle frame sent
        monitor.frame_sent(frame, 10)

        # Check that the metrics were updated
        assert monitor.stats.bytes_sent == 10
        assert monitor.stats.frames_sent == 1

        # Handle frame received
        monitor.frame_received(frame, 10)

        # Check that the metrics were updated
        assert monitor.stats.bytes_received == 10
        assert monitor.stats.frames_received == 1
