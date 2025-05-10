"""
HTTP connection handling for urllib4.

This module provides classes for handling HTTP connections.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import typing
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

log = logging.getLogger(__name__)

# Constants
RECENT_DATE = 2000  # For testing

# For backwards compatibility
CertificateError = ssl.SSLCertVerificationError

@dataclass
class ProxyConfig:
    """
    Configuration for a proxy connection.

    This class holds the configuration for a proxy connection.
    """

    proxy_url: Optional[str] = None
    proxy_headers: Optional[Dict[str, str]] = None
    proxy_ssl_context: Optional[ssl.SSLContext] = None
    use_forwarding_for_https: bool = False

    def __post_init__(self):
        """Initialize proxy headers if None."""
        if self.proxy_headers is None:
            self.proxy_headers = {}


class HTTPConnection(http.client.HTTPConnection):
    """
    HTTP connection that supports additional features.

    This class extends the standard library's HTTPConnection with
    additional features.
    """

    def __init__(
        self,
        host,
        port=None,
        timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address=None,
        blocksize=8192,
    ):
        """
        Initialize a new HTTPConnection.

        :param host: Host to connect to
        :param port: Port to connect to
        :param timeout: Socket timeout
        :param source_address: Source address to bind to
        :param blocksize: Block size for reading
        """
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize,
        )

    def connect(self):
        """Connect to the host and port specified in __init__."""
        return super().connect()


class HTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPS connection that supports additional features.

    This class extends the standard library's HTTPSConnection with
    additional features.
    """

    def __init__(
        self,
        host,
        port=None,
        key_file=None,
        cert_file=None,
        timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address=None,
        context=None,
        blocksize=8192,
    ):
        """
        Initialize a new HTTPSConnection.

        :param host: Host to connect to
        :param port: Port to connect to
        :param key_file: Path to the key file
        :param cert_file: Path to the certificate file
        :param timeout: Socket timeout
        :param source_address: Source address to bind to
        :param context: SSL context
        :param blocksize: Block size for reading
        """
        super().__init__(
            host=host,
            port=port,
            key_file=key_file,
            cert_file=cert_file,
            timeout=timeout,
            source_address=source_address,
            context=context,
            blocksize=blocksize,
        )

    def connect(self):
        """Connect to the host and port specified in __init__."""
        return super().connect()


class DummyConnection:
    """
    Dummy connection that does nothing.

    This class is used as a placeholder for connections that don't
    need to do anything.
    """

    def __init__(self):
        """Initialize a new DummyConnection."""
        pass

    def close(self):
        """Close the connection."""
        pass


# Exceptions for backwards compatibility
class HTTPException(Exception):
    """Base exception for HTTP errors."""
    pass


def _url_from_connection(conn: Union[HTTPConnection, HTTPSConnection]) -> str:
    """
    Get the URL from a connection.

    Args:
        conn: The connection to get the URL from.

    Returns:
        The URL.
    """
    scheme = "https" if isinstance(conn, HTTPSConnection) else "http"
    return f"{scheme}://{conn.host}:{conn.port}"


def _match_hostname(cert: Dict[str, Any], hostname: str) -> None:
    """
    Match a hostname to a certificate.

    Args:
        cert: The certificate to match.
        hostname: The hostname to match.

    Raises:
        CertificateError: If the hostname doesn't match the certificate.
    """
    try:
        ssl.match_hostname(cert, hostname)
    except ssl.CertificateError as e:
        raise CertificateError(str(e))


def _wrap_proxy_error(err: Exception) -> Exception:
    """
    Wrap a proxy error.

    Args:
        err: The error to wrap.

    Returns:
        The wrapped error.
    """
    from urllib4.exceptions import ProxyError

    return ProxyError("Error connecting to proxy", err)
