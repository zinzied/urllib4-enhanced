"""
Certificate Transparency support for urllib4.

This module provides support for Certificate Transparency (CT) verification,
allowing applications to verify that certificates have been logged in CT logs.
"""

from __future__ import annotations

import base64
import enum
import logging
import struct
import threading
import typing
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union

log = logging.getLogger(__name__)

# Import cryptography conditionally to avoid hard dependency
try:
    import cryptography.hazmat.primitives.asymmetric.ec as ec
    import cryptography.hazmat.primitives.asymmetric.padding as padding
    import cryptography.hazmat.primitives.hashes as hashes
    import cryptography.hazmat.primitives.serialization as serialization
    import cryptography.x509 as x509
    from cryptography.x509.extensions import ExtensionNotFound

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False


class CertificateTransparencyPolicy(Enum):
    """Certificate Transparency verification policy."""

    # Do not verify SCTs
    DISABLED = auto()

    # Verify SCTs if present, but don't require them
    BEST_EFFORT = auto()

    # Require and verify SCTs
    ENFORCE = auto()


class SCTVerificationResult(Enum):
    """Result of SCT verification."""

    # SCT is valid
    VALID = auto()

    # SCT has an invalid signature
    INVALID_SIGNATURE = auto()

    # SCT is from an unknown log
    UNKNOWN_LOG = auto()

    # SCT verification failed for another reason
    ERROR = auto()


@dataclass
class SignedCertificateTimestamp:
    """
    Signed Certificate Timestamp (SCT).

    This class represents an SCT, which is a signed statement from a CT log
    that a certificate has been logged.
    """

    version: int
    log_id: bytes
    timestamp: datetime
    signature: bytes
    signature_algorithm: int

    def to_bytes(self) -> bytes:
        """
        Convert the SCT to bytes.

        :return: The SCT as bytes
        """
        # This is a simplified implementation
        # In a real implementation, we would properly serialize the SCT
        # according to RFC 6962
        return (
            bytes([self.version]) +
            struct.pack(">H", len(self.log_id)) +
            self.log_id +
            struct.pack(">Q", int(self.timestamp.timestamp() * 1000)) +
            struct.pack(">H", len(self.signature)) +
            self.signature
        )


@dataclass
class CTLog:
    """
    Certificate Transparency log.

    This class represents a CT log, including its name, URL, and public key.
    """

    name: str
    key: Union[ec.EllipticCurvePublicKey, "padding.AsymmetricPadding"]
    url: str

    @classmethod
    def from_key_base64(cls, name: str, key_base64: str, url: str) -> "CTLog":
        """
        Create a CTLog from a base64-encoded public key.

        :param name: The log name
        :param key_base64: The base64-encoded public key
        :param url: The log URL
        :return: A CTLog instance
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError(
                "Certificate Transparency support requires the cryptography package. "
                "Install with: pip install cryptography"
            )

        key_der = base64.b64decode(key_base64)
        key = serialization.load_der_public_key(key_der)

        return cls(name=name, key=key, url=url)


class CertificateTransparencyVerifier:
    """
    Verifies Certificate Transparency information.

    This class verifies that certificates have valid SCTs from trusted CT logs.
    """

    def __init__(
        self,
        policy: CertificateTransparencyPolicy = CertificateTransparencyPolicy.BEST_EFFORT,
    ) -> None:
        """
        Initialize a new CertificateTransparencyVerifier.

        :param policy: The CT verification policy
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            log.warning(
                "Certificate Transparency support requires the cryptography package. "
                "Install with: pip install cryptography"
            )
            self.policy = CertificateTransparencyPolicy.DISABLED
        else:
            self.policy = policy

        self._logs: Dict[bytes, CTLog] = {}
        self._lock = threading.RLock()

        # Load known logs
        self._load_known_logs()

    def _load_known_logs(self) -> None:
        """Load known CT logs."""
        # Google logs
        self._add_log(
            "Google 'Argon2023'",
            "https://ct.googleapis.com/logs/argon2023/",
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHqkVM4yyOcKWCu2yye5yYeqDpEXYoALIgtM3TmHtNlifmt+4iatGwLpF3eA=="
        )

        # Cloudflare logs
        self._add_log(
            "Cloudflare 'Nimbus2023'",
            "https://ct.cloudflare.com/logs/nimbus2023/",
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/8tkhjLRp0SXrlZdTzNkTd6HqmcmXiDJz3fAdWLgOhjmv4mohvRhwXul9bgW0ODgRwC9UGAgH/vpGHPvIS1qA=="
        )

        # DigiCert logs
        self._add_log(
            "DigiCert Log Server",
            "https://ct1.digicert-ct.com/log/",
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A=="
        )

    def _add_log(self, name: str, url: str, key_base64: str) -> None:
        """
        Add a CT log.

        :param name: The log name
        :param url: The log URL
        :param key_base64: The base64-encoded public key
        """
        try:
            log = CTLog.from_key_base64(name, key_base64, url)

            # Use the log ID (hash of the public key) as the key
            log_id = self._compute_log_id(log.key)

            with self._lock:
                self._logs[log_id] = log

            log.debug(f"Added CT log: {name} ({url})")
        except Exception as e:
            log.warning(f"Failed to add CT log {name}: {e}")

    def _compute_log_id(self, key: Union[ec.EllipticCurvePublicKey, "padding.AsymmetricPadding"]) -> bytes:
        """
        Compute the log ID for a public key.

        :param key: The public key
        :return: The log ID (SHA-256 hash of the public key)
        """
        # Get the SubjectPublicKeyInfo
        spki_bytes = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Hash with SHA-256
        digest = hashes.Hash(hashes.SHA256())
        digest.update(spki_bytes)
        return digest.finalize()

    def _find_log_by_id(self, log_id: bytes) -> Optional[CTLog]:
        """
        Find a CT log by its ID.

        :param log_id: The log ID
        :return: The CT log or None if not found
        """
        with self._lock:
            return self._logs.get(log_id)

    def verify_certificate(self, cert: x509.Certificate) -> bool:
        """
        Verify that a certificate has valid SCTs.

        :param cert: The certificate to verify
        :return: True if the certificate passes CT verification
        """
        if self.policy == CertificateTransparencyPolicy.DISABLED:
            return True

        # Extract SCTs from the certificate
        scts = self._extract_scts_from_cert(cert)

        # If no SCTs are found and policy is ENFORCE, fail
        if not scts and self.policy == CertificateTransparencyPolicy.ENFORCE:
            log.warning("No SCTs found in certificate and policy is ENFORCE")
            return False

        # If no SCTs are found and policy is BEST_EFFORT, pass
        if not scts and self.policy == CertificateTransparencyPolicy.BEST_EFFORT:
            log.info("No SCTs found in certificate but policy is BEST_EFFORT")
            return True

        # Verify each SCT
        valid_scts = 0
        for sct in scts:
            result = self._verify_sct(cert, sct)
            if result == SCTVerificationResult.VALID:
                valid_scts += 1

        # If at least one SCT is valid, pass
        if valid_scts > 0:
            log.info(f"Certificate has {valid_scts} valid SCTs")
            return True

        # If no SCTs are valid and policy is ENFORCE, fail
        if self.policy == CertificateTransparencyPolicy.ENFORCE:
            log.warning("No valid SCTs found in certificate and policy is ENFORCE")
            return False

        # If no SCTs are valid and policy is BEST_EFFORT, pass
        log.info("No valid SCTs found in certificate but policy is BEST_EFFORT")
        return True

    def _extract_scts_from_cert(self, cert: x509.Certificate) -> List[SignedCertificateTimestamp]:
        """
        Extract SCTs from a certificate's extensions.

        :param cert: The certificate to extract SCTs from
        :return: List of SCTs
        """
        scts = []

        try:
            # Check for embedded SCTs in certificate
            try:
                sct_ext = cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
                )

                # Parse the SCT list
                sct_list = sct_ext.value

                for sct_data in sct_list:
                    sct = SignedCertificateTimestamp(
                        version=sct_data.version.value,
                        log_id=sct_data.log_id,
                        timestamp=sct_data.timestamp,
                        signature=sct_data.signature,
                        signature_algorithm=sct_data.signature_algorithm
                    )
                    scts.append(sct)
            except (ExtensionNotFound, ValueError) as e:
                log.debug(f"No embedded SCTs found in certificate: {e}")

            return scts
        except Exception as e:
            log.warning(f"Error extracting SCTs from certificate: {e}")
            return []

    def _verify_sct(self, cert: x509.Certificate, sct: SignedCertificateTimestamp) -> SCTVerificationResult:
        """
        Verify an SCT for a certificate.

        :param cert: The certificate to verify
        :param sct: The SCT to verify
        :return: The verification result
        """
        # Find the log that issued the SCT
        log_entry = self._find_log_by_id(sct.log_id)
        if not log_entry:
            log.warning(f"Unknown CT log ID: {sct.log_id.hex()}")
            return SCTVerificationResult.UNKNOWN_LOG

        try:
            # Construct the data to be verified
            # This includes:
            # - SCT version
            # - Signature type (certificate_timestamp)
            # - Timestamp
            # - LogEntry type (x509_entry)
            # - Certificate data

            # Serialize the certificate
            cert_data = cert.public_bytes(serialization.Encoding.DER)

            # Construct the signed data
            signed_data = (
                bytes([sct.version]) +  # Version
                bytes([0]) +  # SignatureType (certificate_timestamp)
                struct.pack(">Q", int(sct.timestamp.timestamp() * 1000)) +  # Timestamp (milliseconds)
                bytes([0]) +  # LogEntryType (x509_entry)
                struct.pack(">H", len(cert_data)) +  # Length of certificate
                cert_data  # Certificate
            )

            # Verify the signature
            if isinstance(log_entry.key, ec.EllipticCurvePublicKey):
                # EC key verification
                try:
                    log_entry.key.verify(
                        sct.signature,
                        signed_data,
                        ec.ECDSA(hashes.SHA256())
                    )
                    return SCTVerificationResult.VALID
                except Exception as e:
                    log.warning(f"SCT signature verification failed: {e}")
                    return SCTVerificationResult.INVALID_SIGNATURE
            else:
                # RSA key verification
                try:
                    log_entry.key.verify(
                        sct.signature,
                        signed_data,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    return SCTVerificationResult.VALID
                except Exception as e:
                    log.warning(f"SCT signature verification failed: {e}")
                    return SCTVerificationResult.INVALID_SIGNATURE
        except Exception as e:
            log.warning(f"Error verifying SCT: {e}")
            return SCTVerificationResult.ERROR
