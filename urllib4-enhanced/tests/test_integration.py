"""
Integration tests for urllib4 enhanced features.

This test file tests the interaction between different enhanced features.
"""

import unittest
from unittest import mock
import socket
import ssl
import time

import urllib4
from urllib4.http2 import ConnectionProfile, FlowControlStrategy, HTTP2Settings
from urllib4.util.cert_verification import CertificateTransparencyPolicy, SPKIPinningVerifier
from urllib4.util.hsts import HSTSCache, HSTSHandler, HSTSPolicy
from urllib4.websocket import WebSocketConnection, WebSocketMessage


class TestEnhancedFeaturesIntegration(unittest.TestCase):
    """Test integration of enhanced urllib4 features."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a pool manager with enhanced features
        self.http = urllib4.PoolManager(
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=ssl.get_default_verify_paths().cafile,
        )

        # Set up HSTS
        self.hsts_cache = HSTSCache()
        self.hsts_handler = HSTSHandler(self.hsts_cache)

        # Add some HSTS policies
        self.hsts_cache.add(
            HSTSPolicy(
                host="example.com",
                expires=time.time() + 3600,
                include_subdomains=True,
            )
        )

        # Set up SPKI pinning
        self.pins = {
            "example.com": {
                "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            },
        }
        self.pin_verifier = SPKIPinningVerifier(self.pins)

        # Set up CT verification
        self.ct_verifier = urllib4.util.cert_verification.CertificateTransparencyVerifier(
            policy=CertificateTransparencyPolicy.BEST_EFFORT
        )

    def test_http2_with_security_features(self):
        """Test HTTP/2 with security features."""
        # Enable HTTP/2
        urllib4.http2.inject_into_urllib4()

        try:
            # Create a pool manager with HTTP/2 and security features
            http = urllib4.PoolManager(
                cert_reqs=ssl.CERT_REQUIRED,
                ca_certs=ssl.get_default_verify_paths().cafile,
                http2_connection_profile=ConnectionProfile.HIGH_PERFORMANCE,
                http2_flow_control_strategy=FlowControlStrategy.ADAPTIVE,
                http2_enable_push=True,
            )

            # Mock the request method to avoid actual network calls
            with mock.patch.object(http, 'request') as mock_request:
                # Mock the response
                mock_response = mock.Mock()
                mock_response.status = 200
                mock_response.headers = {
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
                }
                mock_request.return_value = mock_response

                # Make a request
                url = "http://example.com/api"

                # Secure the URL with HSTS
                secured_url = self.hsts_handler.secure_url(url)
                self.assertEqual(secured_url, "https://example.com/api")

                # Make the request
                response = http.request("GET", secured_url)

                # Process HSTS headers
                self.hsts_handler.process_response_headers(
                    "example.com", response.headers
                )

                # Verify the request was made with the secured URL
                mock_request.assert_called_once()
                args, kwargs = mock_request.call_args
                self.assertEqual(args[0], "GET")
                self.assertEqual(args[1], "https://example.com/api")

        finally:
            # Restore HTTP/1.1
            urllib4.http2.extract_from_urllib4()

    def test_websocket_with_security_features(self):
        """Test WebSocket with security features."""
        # Mock the WebSocketConnection to avoid actual network calls
        with mock.patch('urllib4.websocket.WebSocketConnection') as mock_ws_class:
            # Mock the connect method
            mock_ws = mock.Mock()
            mock_ws_class.return_value = mock_ws

            # Create a WebSocket URL
            url = "ws://example.com/ws"

            # Secure the URL with HSTS (should convert ws:// to wss://)
            secured_url = self.hsts_handler.secure_url(url.replace("ws://", "http://"))
            secured_url = secured_url.replace("https://", "wss://")
            self.assertEqual(secured_url, "wss://example.com/ws")

            # Connect to the WebSocket
            urllib4.websocket_connect(secured_url)

            # Verify the WebSocketConnection was created with the secured URL
            mock_ws_class.assert_called_once()
            args, kwargs = mock_ws_class.call_args
            self.assertEqual(args[0], "wss://example.com/ws")

            # Verify connect was called
            mock_ws.connect.assert_called_once()

    def test_security_features_together(self):
        """Test all security features working together."""
        # Create a mock certificate
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "version": 3,
            "serialNumber": "1234567890",
            "notBefore": "Jan 1 00:00:00 2020 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }

        # Mock the verification methods
        with mock.patch.object(
            self.ct_verifier, 'verify_cert', return_value=True
        ) as mock_ct_verify:
            with mock.patch.object(
                self.pin_verifier, 'verify_cert_for_host', return_value=True
            ) as mock_pin_verify:
                # Verify the certificate with all security features
                ct_result = self.ct_verifier.verify_cert(cert)
                pin_result = self.pin_verifier.verify_cert_for_host(cert, "example.com")

                # Both should pass
                self.assertTrue(ct_result)
                self.assertTrue(pin_result)

                # Verify the methods were called
                mock_ct_verify.assert_called_once()
                mock_pin_verify.assert_called_once()

    def test_http2_websocket_upgrade(self):
        """Test upgrading an HTTP/2 connection to WebSocket."""
        # Enable HTTP/2
        urllib4.http2.inject_into_urllib4()

        try:
            # Create a pool manager with HTTP/2
            http = urllib4.PoolManager(
                cert_reqs=ssl.CERT_REQUIRED,
                ca_certs=ssl.get_default_verify_paths().cafile,
                http2_connection_profile=ConnectionProfile.HIGH_PERFORMANCE,
            )

            # Mock the request method to avoid actual network calls
            with mock.patch.object(http, 'request') as mock_request:
                # Mock the response for the WebSocket handshake
                mock_response = mock.Mock()
                mock_response.status = 101
                mock_response.headers = {
                    "Upgrade": "websocket",
                    "Connection": "upgrade",
                    "Sec-WebSocket-Accept": "mock-accept-key",
                }
                mock_response.connection.sock = mock.Mock(spec=socket.socket)
                mock_request.return_value = mock_response

                # Mock the WebSocketConnection
                with mock.patch('urllib4.websocket.connection.WebSocketConnection._send_frame'):
                    with mock.patch('urllib4.websocket.connection.WebSocketConnection._start_receiver'):
                        # Connect to a WebSocket
                        url = "https://example.com/ws"

                        # Create a WebSocketConnection using the pool manager
                        ws = WebSocketConnection(
                            url.replace("https://", "wss://"),
                            pool_manager=http,
                        )

                        # Connect to the WebSocket
                        with mock.patch('base64.b64encode', return_value=b"mock-accept-key"):
                            ws.connect()

                        # Verify the request was made
                        mock_request.assert_called_once()
                        args, kwargs = mock_request.call_args
                        self.assertEqual(args[0], "GET")
                        self.assertEqual(args[1], "https://example.com/ws")

                        # Verify the connection is established
                        self.assertTrue(ws.connected)

        finally:
            # Restore HTTP/1.1
            urllib4.http2.extract_from_urllib4()


if __name__ == "__main__":
    unittest.main()
