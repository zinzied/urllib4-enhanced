"""
HTTP/2 probe module.

This module provides functionality to probe for HTTP/2 support.
"""

from __future__ import annotations

import typing
from typing import Dict, Optional, Set

# Cache of known HTTP/2 supported hosts
_HTTP2_SUPPORTED_HOSTS: Dict[str, bool] = {}

def _reset() -> None:
    """Reset the HTTP/2 probe cache."""
    _HTTP2_SUPPORTED_HOSTS.clear()

def supports_http2(host: str) -> bool:
    """
    Check if a host supports HTTP/2.
    
    Args:
        host: The hostname to check.
        
    Returns:
        True if the host supports HTTP/2, False otherwise.
    """
    if host in _HTTP2_SUPPORTED_HOSTS:
        return _HTTP2_SUPPORTED_HOSTS[host]
    
    # Default to True for now - in a real implementation, 
    # this would actually probe the host
    _HTTP2_SUPPORTED_HOSTS[host] = True
    return True

def record_http2_result(host: str, supported: bool) -> None:
    """
    Record whether a host supports HTTP/2.
    
    Args:
        host: The hostname.
        supported: Whether the host supports HTTP/2.
    """
    _HTTP2_SUPPORTED_HOSTS[host] = supported
