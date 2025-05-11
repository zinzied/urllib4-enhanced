"""
HTTP/3 support for urllib4.

This module provides HTTP/3 support for urllib4, using the QUIC protocol
for transport.
"""

from __future__ import annotations

import logging
import typing

from .connection import HTTP3Connection
from .settings import HTTP3Settings, QUICSettings

log = logging.getLogger(__name__)

__all__ = [
    "inject_into_urllib4",
    "extract_from_urllib4",
    "HTTP3Connection",
    "HTTP3Settings",
    "QUICSettings",
]


def inject_into_urllib4() -> None:
    """
    Inject HTTP/3 support into urllib4.
    
    This function modifies urllib4's connection classes to use HTTP/3
    when appropriate.
    """
    # Import here to avoid circular imports
    from .. import connection
    from ..poolmanager import PoolManager
    
    # Store original classes for later restoration
    if not hasattr(connection, "_original_HTTPSConnection"):
        connection._original_HTTPSConnection = connection.HTTPSConnection
        
    if not hasattr(PoolManager, "_original_connection_from_url"):
        PoolManager._original_connection_from_url = PoolManager.connection_from_url
        
    # Patch HTTPSConnection to use HTTP/3 when appropriate
    def patched_init(self, *args, **kwargs):
        http3_enabled = kwargs.pop("http3_enabled", True)
        http3_settings = kwargs.pop("http3_settings", None)
        
        # Call original __init__
        connection._original_HTTPSConnection.__init__(self, *args, **kwargs)
        
        # Store HTTP/3 settings
        self._http3_enabled = http3_enabled
        self._http3_settings = http3_settings
        
    def patched_connect(self):
        # Try HTTP/3 if enabled
        if getattr(self, "_http3_enabled", False):
            try:
                # Import here to avoid circular imports
                from .connection import HTTP3Connection
                
                # Create HTTP/3 connection
                self._http3_conn = HTTP3Connection(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                    settings=self._http3_settings,
                )
                
                # Connect
                self._http3_conn.connect()
                
                # If we got here, HTTP/3 connection succeeded
                log.debug("Using HTTP/3 connection to %s:%s", self.host, self.port)
                return
            except Exception as e:
                log.debug("HTTP/3 connection failed, falling back to TLS: %s", e)
                self._http3_conn = None
                
        # Fall back to original connect
        connection._original_HTTPSConnection.connect(self)
        
    def patched_request(self, method, url, body=None, headers=None, **kwargs):
        # Use HTTP/3 if available
        if hasattr(self, "_http3_conn") and self._http3_conn is not None:
            return self._http3_conn.request(method, url, body=body, headers=headers, **kwargs)
            
        # Fall back to original request
        return connection._original_HTTPSConnection.request(
            self, method, url, body=body, headers=headers, **kwargs
        )
        
    # Patch PoolManager to use HTTP/3 when appropriate
    def patched_connection_from_url(self, url, **kwargs):
        # Parse URL to determine if HTTP/3 should be used
        from urllib.parse import urlparse
        
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        
        # Add HTTP/3 settings to kwargs for HTTPS connections
        if scheme == "https":
            kwargs.setdefault("http3_enabled", True)
            
        # Call original method
        return PoolManager._original_connection_from_url(self, url, **kwargs)
        
    # Apply patches
    connection.HTTPSConnection.__init__ = patched_init
    connection.HTTPSConnection.connect = patched_connect
    connection.HTTPSConnection.request = patched_request
    PoolManager.connection_from_url = patched_connection_from_url
    
    log.debug("HTTP/3 support injected into urllib4")


def extract_from_urllib4() -> None:
    """
    Extract HTTP/3 support from urllib4.
    
    This function restores urllib4's original connection classes.
    """
    # Import here to avoid circular imports
    from .. import connection
    from ..poolmanager import PoolManager
    
    # Restore original classes
    if hasattr(connection, "_original_HTTPSConnection"):
        connection.HTTPSConnection = connection._original_HTTPSConnection
        delattr(connection, "_original_HTTPSConnection")
        
    if hasattr(PoolManager, "_original_connection_from_url"):
        PoolManager.connection_from_url = PoolManager._original_connection_from_url
        delattr(PoolManager, "_original_connection_from_url")
        
    log.debug("HTTP/3 support extracted from urllib4")
