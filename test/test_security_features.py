"""
Tests for security features.
"""

from __future__ import annotations

import base64
import hashlib
from unittest import mock

import pytest

from urllib4.util.cert_verification import (
    CertificateTransparencyPolicy,
    CertificateTransparencyVerifier,
    SPKIPinningVerifier,
)


class TestSPKIPinningVerifier:
    """Tests for the SPKIPinningVerifier class."""

    def test_init(self):
        """Test initialization."""
        pins = {
            "example.com": {
                "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            },
            "*.google.com": {
                "pin-sha256:Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNQhj8=",
            },
        }
        verifier = SPKIPinningVerifier(pins)
        assert verifier.pins == pins

    def test_find_pins_for_hostname_exact_match(self):
        """Test finding pins for a hostname with an exact match."""
        pins = {
            "example.com": {
                "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            },
            "*.google.com": {
                "pin-sha256:Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNQhj8=",
            },
        }
        verifier = SPKIPinningVerifier(pins)
        
        result = verifier._get_pins_for_host("example.com")
        assert result == {"pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="}

    def test_find_pins_for_hostname_wildcard_match(self):
        """Test finding pins for a hostname with a wildcard match."""
        pins = {
            "example.com": {
                "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            },
            "*.google.com": {
                "pin-sha256:Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNQhj8=",
            },
        }
        verifier = SPKIPinningVerifier(pins)
        
        result = verifier._get_pins_for_host("www.google.com")
        assert result == {"pin-sha256:Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNQhj8="}

    def test_find_pins_for_hostname_no_match(self):
        """Test finding pins for a hostname with no match."""
        pins = {
            "example.com": {
                "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            },
            "*.google.com": {
                "pin-sha256:Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNQhj8=",
            },
        }
        verifier = SPKIPinningVerifier(pins)
        
        result = verifier._get_pins_for_host("github.com")
        assert result == set()

    def test_check_pin_valid(self):
        """Test checking a valid pin."""
        verifier = SPKIPinningVerifier({})
        
        # Create a mock certificate
        cert = mock.MagicMock()
        cert.public_key.return_value.public_bytes.return_value = b"test key"
        
        # Calculate the expected hash
        spki_hash = base64.b64encode(hashlib.sha256(b"test key").digest()).decode("ascii")
        pin = f"pin-sha256:{spki_hash}"
        
        # Check the pin
        result = verifier._check_pin(pin, spki_hash)
        assert result is True

    def test_check_pin_invalid(self):
        """Test checking an invalid pin."""
        verifier = SPKIPinningVerifier({})
        
        # Create a mock certificate
        cert = mock.MagicMock()
        cert.public_key.return_value.public_bytes.return_value = b"test key"
        
        # Calculate the expected hash
        spki_hash = base64.b64encode(hashlib.sha256(b"test key").digest()).decode("ascii")
        pin = f"pin-sha256:invalid hash"
        
        # Check the pin
        result = verifier._check_pin(pin, spki_hash)
        assert result is False

    def test_check_pin_invalid_format(self):
        """Test checking a pin with an invalid format."""
        verifier = SPKIPinningVerifier({})
        
        # Create a mock certificate
        cert = mock.MagicMock()
        cert.public_key.return_value.public_bytes.return_value = b"test key"
        
        # Calculate the expected hash
        spki_hash = base64.b64encode(hashlib.sha256(b"test key").digest()).decode("ascii")
        pin = f"invalid format"
        
        # Check the pin
        result = verifier._check_pin(pin, spki_hash)
        assert result is False


class TestCertificateTransparencyVerifier:
    """Tests for the CertificateTransparencyVerifier class."""

    def test_init(self):
        """Test initialization."""
        verifier = CertificateTransparencyVerifier()
        assert verifier.policy == CertificateTransparencyPolicy.BEST_EFFORT
        assert verifier.logs == []
        
        verifier = CertificateTransparencyVerifier(policy=CertificateTransparencyPolicy.STRICT)
        assert verifier.policy == CertificateTransparencyPolicy.STRICT

    def test_verify_cert_disabled(self):
        """Test verifying a certificate with the DISABLED policy."""
        verifier = CertificateTransparencyVerifier(policy=CertificateTransparencyPolicy.DISABLED)
        
        # Create a mock certificate
        cert = mock.MagicMock()
        
        # Verify the certificate
        result = verifier.verify_cert(cert)
        assert result is True

    def test_verify_cert_no_scts_best_effort(self):
        """Test verifying a certificate with no SCTs and the BEST_EFFORT policy."""
        verifier = CertificateTransparencyVerifier(policy=CertificateTransparencyPolicy.BEST_EFFORT)
        
        # Create a mock certificate
        cert = mock.MagicMock()
        
        # Mock the _extract_scts method
        verifier._extract_scts = mock.MagicMock(return_value=[])
        
        # Verify the certificate
        result = verifier.verify_cert(cert)
        assert result is True

    def test_verify_cert_no_scts_strict(self):
        """Test verifying a certificate with no SCTs and the STRICT policy."""
        verifier = CertificateTransparencyVerifier(policy=CertificateTransparencyPolicy.STRICT)
        
        # Create a mock certificate
        cert = mock.MagicMock()
        
        # Mock the _extract_scts method
        verifier._extract_scts = mock.MagicMock(return_value=[])
        
        # Verify the certificate
        result = verifier.verify_cert(cert)
        assert result is False
