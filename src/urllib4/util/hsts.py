"""
HTTP Strict Transport Security (HSTS) implementation for urllib4.

This module provides HSTS support, automatically upgrading HTTP requests
to HTTPS for hosts that have previously specified an HSTS policy.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import typing
from dataclasses import dataclass
from urllib.parse import urlparse

log = logging.getLogger(__name__)


@dataclass
class HSTSPolicy:
    """
    HTTP Strict Transport Security policy.

    This class represents an HSTS policy for a host, including the
    max-age and whether to include subdomains.
    """

    host: str
    expires: float
    include_subdomains: bool = False

    @classmethod
    def from_header(cls, host: str, header_value: str) -> "HSTSPolicy":
        """
        Create an HSTS policy from an HSTS header value.

        :param host: The host the header was received from
        :param header_value: The value of the Strict-Transport-Security header
        :return: An HSTSPolicy instance
        """
        max_age = 0
        include_subdomains = False

        # Parse the header value
        for directive in header_value.split(";"):
            directive = directive.strip().lower()

            if directive == "includesubdomains":
                include_subdomains = True
            elif directive.startswith("max-age="):
                try:
                    max_age = int(directive[8:])
                except ValueError:
                    log.warning("Invalid max-age in HSTS header: %s", directive)

        # Calculate expiration time
        expires = time.time() + max_age

        return cls(
            host=host,
            expires=expires,
            include_subdomains=include_subdomains,
        )

    @property
    def is_expired(self) -> bool:
        """Check if the policy has expired."""
        return time.time() > self.expires


class HSTSCache:
    """
    Cache of HSTS policies.

    This class stores HSTS policies for hosts and provides methods
    to check if a host has a valid policy.
    """

    def __init__(self) -> None:
        """Initialize a new HSTSCache."""
        self._policies: dict[str, HSTSPolicy] = {}
        self._lock = threading.RLock()

    def add(self, policy: HSTSPolicy) -> None:
        """
        Add an HSTS policy to the cache.

        :param policy: The policy to add
        """
        with self._lock:
            self._policies[policy.host] = policy

    def get(self, host: str) -> HSTSPolicy | None:
        """
        Get the HSTS policy for a host.

        :param host: The host to get the policy for
        :return: The policy, or None if no policy exists
        """
        with self._lock:
            policy = self._policies.get(host)

            if policy and policy.is_expired:
                del self._policies[host]
                return None

            return policy

    def has_policy(self, host: str) -> bool:
        """
        Check if a host has a valid HSTS policy.

        :param host: The host to check
        :return: True if the host has a valid policy
        """
        return self.get(host) is not None

    def get_matching_policy(self, host: str) -> HSTSPolicy | None:
        """
        Get a matching HSTS policy for a host.

        This method handles subdomain matching.

        :param host: The host to get a policy for
        :return: The matching policy, or None if no policy matches
        """
        # Check for exact match
        policy = self.get(host)
        if policy:
            return policy

        # Check for subdomain match
        parts = host.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            parent_policy = self.get(parent)

            if parent_policy and parent_policy.include_subdomains:
                return parent_policy

        return None

    def clear(self) -> None:
        """Clear all policies from the cache."""
        with self._lock:
            self._policies.clear()


class HSTSHandler:
    """
    Handles HSTS policy enforcement.

    This class automatically upgrades HTTP requests to HTTPS for hosts
    that have a valid HSTS policy.
    """

    def __init__(self, cache: HSTSCache | None = None) -> None:
        """
        Initialize a new HSTSHandler.

        :param cache: The HSTS cache to use
        """
        self.cache = cache or HSTSCache()

    def process_response(self, url: str, headers: dict[str, str]) -> None:
        """
        Process a response to check for HSTS headers.

        :param url: The URL of the response
        :param headers: The response headers
        """
        # Only process HTTPS responses
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return

        # Check for HSTS header
        hsts_header = headers.get("Strict-Transport-Security")
        if not hsts_header:
            return

        # Create and add policy
        policy = HSTSPolicy.from_header(parsed_url.netloc, hsts_header)
        self.cache.add(policy)

    def secure_url(self, url: str) -> str:
        """
        Upgrade a URL to HTTPS if required by HSTS policy.

        :param url: The URL to potentially upgrade
        :return: The upgraded URL, or the original URL if no upgrade is needed
        """
        parsed_url = urlparse(url)

        # Already HTTPS
        if parsed_url.scheme == "https":
            return url

        # Check for matching policy
        if self.cache.get_matching_policy(parsed_url.netloc):
            # Upgrade to HTTPS
            parts = list(parsed_url)
            parts[0] = "https"

            # Remove default port if present
            if parts[1].endswith(":80"):
                parts[1] = parts[1][:-3]

            from urllib.parse import urlunparse
            return urlunparse(parts)

        return url
