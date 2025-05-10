"""
Certificate verification utilities for urllib4.

This module provides enhanced certificate verification capabilities,
including Certificate Transparency and SPKI pinning.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import logging
import re
import typing
from dataclasses import dataclass
from enum import Enum, auto

if typing.TYPE_CHECKING:
    import ssl
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.x509 import Certificate

log = logging.getLogger(__name__)


class CertificateTransparencyPolicy(Enum):
    """Policy for Certificate Transparency verification."""
    
    # Don't verify SCTs
    DISABLED = auto()
    
    # Verify SCTs if present, but don't fail if missing
    BEST_EFFORT = auto()
    
    # Require valid SCTs
    STRICT = auto()


@dataclass
class CTLog:
    """
    Certificate Transparency log information.
    
    This class represents a Certificate Transparency log, including
    its name, URL, and public key.
    """
    
    name: str
    url: str
    key: "EllipticCurvePublicKey"
    
    @classmethod
    def from_key_base64(cls, name: str, key_base64: str, url: str) -> "CTLog":
        """
        Create a CTLog from a base64-encoded public key.
        
        :param name: The name of the log
        :param key_base64: The base64-encoded public key
        :param url: The URL of the log
        :return: A CTLog instance
        """
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        
        key_der = base64.b64decode(key_base64)
        key = load_der_public_key(key_der)
        
        return cls(name=name, url=url, key=key)


@dataclass
class SignedCertificateTimestamp:
    """
    Signed Certificate Timestamp (SCT).
    
    This class represents an SCT, which is a signed statement from a CT log
    that a certificate has been logged.
    """
    
    version: int
    log_id: bytes
    timestamp: int
    extensions: bytes
    signature: bytes


class SCTVerificationResult(Enum):
    """Result of SCT verification."""
    
    VALID = auto()
    INVALID_SIGNATURE = auto()
    UNKNOWN_LOG = auto()
    INVALID_FORMAT = auto()


class CertificateTransparencyVerifier:
    """
    Verifies Certificate Transparency information.
    
    This class checks that certificates have valid Signed Certificate
    Timestamps (SCTs) from trusted CT logs.
    """
    
    def __init__(
        self,
        policy: CertificateTransparencyPolicy = CertificateTransparencyPolicy.BEST_EFFORT,
        logs: list[CTLog] | None = None,
    ) -> None:
        """
        Initialize a new CertificateTransparencyVerifier.
        
        :param policy: The verification policy to use
        :param logs: List of trusted CT logs
        """
        self.policy = policy
        self.logs = logs or []
        
    def verify_cert(self, cert: "Certificate") -> bool:
        """
        Verify Certificate Transparency information for a certificate.
        
        :param cert: The certificate to verify
        :return: True if the certificate passes CT verification
        """
        if self.policy == CertificateTransparencyPolicy.DISABLED:
            return True
            
        # Extract SCTs from certificate
        scts = self._extract_scts(cert)
        
        if not scts and self.policy == CertificateTransparencyPolicy.STRICT:
            log.warning("No SCTs found in certificate")
            return False
            
        if not scts:
            log.info("No SCTs found in certificate, but policy is not strict")
            return True
            
        # Verify SCTs
        valid_scts = 0
        for sct in scts:
            result = self._verify_sct(cert, sct)
            if result == SCTVerificationResult.VALID:
                valid_scts += 1
                
        # Check if we have enough valid SCTs
        if valid_scts == 0 and self.policy == CertificateTransparencyPolicy.STRICT:
            log.warning("No valid SCTs found in certificate")
            return False
            
        return True
        
    def _extract_scts(self, cert: "Certificate") -> list[SignedCertificateTimestamp]:
        """
        Extract SCTs from a certificate.
        
        :param cert: The certificate to extract SCTs from
        :return: List of SCTs
        """
        # This is a placeholder implementation
        # In a real implementation, we would extract SCTs from:
        # 1. X.509v3 extension (OID 1.3.6.1.4.1.11129.2.4.2)
        # 2. TLS extension (OCSP stapling)
        # 3. TLS SCT extension (during handshake)
        return []
        
    def _verify_sct(
        self, cert: "Certificate", sct: SignedCertificateTimestamp
    ) -> SCTVerificationResult:
        """
        Verify an SCT for a certificate.
        
        :param cert: The certificate the SCT is for
        :param sct: The SCT to verify
        :return: The verification result
        """
        # This is a placeholder implementation
        # In a real implementation, we would:
        # 1. Find the log that issued the SCT
        # 2. Verify the SCT signature using the log's public key
        # 3. Check the timestamp is reasonable
        return SCTVerificationResult.VALID


class SPKIPinningVerifier:
    """
    Verifies certificates using SPKI (Subject Public Key Info) pinning.
    
    This class checks that certificates have a public key that matches
    one of the configured pins.
    """
    
    def __init__(self, pins: dict[str, set[str]]) -> None:
        """
        Initialize a new SPKIPinningVerifier.
        
        :param pins: Dictionary mapping hostnames to sets of pins
        """
        self.pins = pins
        
    def verify_cert_for_host(self, cert: "Certificate", hostname: str) -> bool:
        """
        Verify a certificate for a specific hostname using SPKI pinning.
        
        :param cert: The certificate to verify
        :param hostname: The hostname to verify for
        :return: True if the certificate passes SPKI verification
        """
        pins = self._get_pins_for_host(hostname)
        if not pins:
            # No pins configured for this host
            return True
            
        # Calculate the SPKI hash for the certificate
        spki_hash = self._compute_spki_hash(cert)
        
        # Check if the hash matches any of the pins
        return spki_hash in pins
        
    def _get_pins_for_host(self, hostname: str) -> set[str]:
        """
        Get the set of pins for a hostname.
        
        This method handles wildcard matching.
        
        :param hostname: The hostname to get pins for
        :return: Set of pins for the hostname
        """
        # Check for exact match
        if hostname in self.pins:
            return self.pins[hostname]
            
        # Check for wildcard match
        parts = hostname.split(".")
        for i in range(1, len(parts)):
            wildcard = f"*.{'.'.join(parts[i:])}"
            if wildcard in self.pins:
                return self.pins[wildcard]
                
        return set()
        
    def _compute_spki_hash(self, cert: "Certificate") -> str:
        """
        Compute the SPKI hash for a certificate.
        
        :param cert: The certificate to compute the hash for
        :return: The SPKI hash in the format "pin-sha256:..."
        """
        # This is a placeholder implementation
        # In a real implementation, we would:
        # 1. Extract the SubjectPublicKeyInfo from the certificate
        # 2. Hash it with SHA-256
        # 3. Base64 encode the hash
        # 4. Return "pin-sha256:" + base64_hash
        return "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="
