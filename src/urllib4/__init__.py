"""
urllib4 - A modern HTTP client library for Python.

urllib4 is a powerful, user-friendly HTTP client for Python. It provides:
- Connection pooling and thread safety
- Client-side SSL/TLS verification
- File uploads with multipart encoding
- Helpers for retrying requests and handling redirects
- HTTP/2 support with server push
- WebSocket support
- Enhanced security features
- And more!

:copyright: (c) 2025 by Augment Code.
:license: MIT, see LICENSE for more details.
"""

# Import version
from ._version import __version__

# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

logging.getLogger(__name__).addHandler(NullHandler())

# Import exceptions first to avoid circular imports
from . import exceptions

# Import core components
from ._collections import HTTPHeaderDict
from .poolmanager import PoolManager, ProxyManager, proxy_from_url
from .response import BaseHTTPResponse, HTTPResponse
from .util.timeout import Timeout

# Import HTTP/2 components
from .http2 import ConnectionProfile, FlowControlStrategy, HTTP2Settings

# Import WebSocket components
from .websocket import WebSocketConnection, connect as websocket_connect

# Import security components
from .util.cert_verification import CertificateTransparencyPolicy, SPKIPinningVerifier
from .util.hsts import HSTSCache, HSTSHandler

__all__ = (
    "HTTPHeaderDict",
    "PoolManager",
    "ProxyManager",
    "HTTPResponse",
    "BaseHTTPResponse",
    "Timeout",
    "proxy_from_url",
    # HTTP/2 features
    "ConnectionProfile",
    "FlowControlStrategy",
    "HTTP2Settings",
    # Security features
    "CertificateTransparencyPolicy",
    "SPKIPinningVerifier",
    "HSTSCache",
    "HSTSHandler",
    # WebSocket features
    "WebSocketConnection",
    "websocket_connect",
)

# Import specific exceptions for convenience
from .exceptions import (
    ConnectionError,
    ConnectTimeoutError,
    HTTPError,
    MaxRetryError,
    NewConnectionError,
    PoolError,
    ProtocolError,
    ProxyError,
    ReadTimeoutError,
    RequestError,
    ResponseError,
    SSLError,
    TimeoutError,
)


def add_stderr_logger(level=logging.DEBUG):
    """
    Helper for quickly adding a StreamHandler to the logger. Useful for
    debugging.

    Returns the handler after adding it.
    """
    # This method needs to be in this __init__.py to get the __name__ correct
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.debug("Added a stderr logging handler to logger: %s", __name__)
    return handler


def disable_warnings(category=exceptions.InsecureRequestWarning):
    """
    Disable urllib4 warnings.
    """
    import warnings

    warnings.filterwarnings("ignore", category=category)


def request(
    method,
    url,
    *,
    body=None,
    fields=None,
    headers=None,
    preload_content=True,
    decode_content=True,
    redirect=True,
    retries=None,
    timeout=Timeout.DEFAULT_TIMEOUT,
    json=None,
    **kw,
):
    """
    A convenience, top-level request method. It uses a module-global ``PoolManager``
    instance.
    """
    from .poolmanager import PoolManager

    if not _DEFAULT_POOL:
        _DEFAULT_POOL.set(PoolManager())
    return _DEFAULT_POOL.get().request(
        method,
        url,
        body=body,
        fields=fields,
        headers=headers,
        preload_content=preload_content,
        decode_content=decode_content,
        redirect=redirect,
        retries=retries,
        timeout=timeout,
        json=json,
        **kw,
    )


# Ensure that the default PoolManager is created only once
from threading import local as _local

_DEFAULT_POOL = _local()
