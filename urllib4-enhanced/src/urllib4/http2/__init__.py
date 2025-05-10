"""
HTTP/2 support for urllib4.

This module provides HTTP/2 support for urllib4, including enhanced features
like server push, adaptive flow control, and connection profiles.
"""

from __future__ import annotations

__all__ = [
    "inject_into_urllib4",
    "extract_from_urllib4",
    "ConnectionProfile",
    "FlowControlStrategy",
    "HTTP2Settings",
]

import typing

from .flow_control import FlowControlStrategy
from .settings import ConnectionProfile, HTTP2Settings, SettingsManager

orig_HTTPSConnection: typing.Any = None


def inject_into_urllib4() -> None:
    """
    Inject HTTP/2 support into urllib4.

    This function replaces the standard HTTPSConnection with the HTTP/2-capable
    HTTP2Connection, enabling HTTP/2 support for all HTTPS requests made through
    urllib4.
    """
    import urllib4.connection

    global orig_HTTPSConnection

    if orig_HTTPSConnection is not None:
        return

    orig_HTTPSConnection = urllib4.connection.HTTPSConnection

    from .connection import HTTP2Connection

    urllib4.connection.HTTPSConnection = HTTP2Connection


def extract_from_urllib4() -> None:
    """
    Extract HTTP/2 support from urllib4.

    This function restores the standard HTTPSConnection, disabling HTTP/2 support
    for HTTPS requests made through urllib4.
    """
    import urllib4.connection

    global orig_HTTPSConnection

    if orig_HTTPSConnection is None:
        return

    urllib4.connection.HTTPSConnection = orig_HTTPSConnection
    orig_HTTPSConnection = None
