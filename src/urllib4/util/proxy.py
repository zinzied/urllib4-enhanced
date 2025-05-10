"""
Proxy utilities for urllib4.
"""

from __future__ import annotations

import ssl
import typing
from typing import Dict, Optional, Union

from ..connection import ProxyConfig
from .url import parse_url


def connection_requires_http_tunnel(
    proxy_url: Optional[str] = None,
    proxy_config: Optional[ProxyConfig] = None,
    destination_scheme: Optional[str] = None,
) -> bool:
    """
    Returns True if the connection requires an HTTP CONNECT through the proxy.

    :param proxy_url:
        The URL of the proxy.
    :param proxy_config:
        The proxy configuration.
    :param destination_scheme:
        The scheme of the destination.
    """
    # If we're not using a proxy, no need for a tunnel
    if proxy_url is None and proxy_config is None:
        return False

    # If the destination scheme is HTTP or WS, we don't need a tunnel
    if destination_scheme in ("http", "ws"):
        return False

    # If the destination scheme is HTTPS or WSS, we need a tunnel
    if destination_scheme in ("https", "wss"):
        # If we're using a proxy config and it's set to use forwarding for HTTPS,
        # we don't need a tunnel
        if proxy_config is not None and proxy_config.use_forwarding_for_https:
            return False
        return True

    # If we're not sure, assume we need a tunnel
    return True


def create_proxy_ssl_context(
    proxy_config: Optional[ProxyConfig] = None,
) -> Optional[ssl.SSLContext]:
    """
    Creates an SSL context for use with a proxy.

    :param proxy_config:
        The proxy configuration.
    """
    if proxy_config is None or proxy_config.proxy_ssl_context is None:
        return None

    return proxy_config.proxy_ssl_context
