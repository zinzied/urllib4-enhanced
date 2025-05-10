"""
Exceptions for urllib4.

This module contains all exceptions raised by urllib4.
"""

from __future__ import annotations


class HTTPError(Exception):
    """Base exception used by this module."""
    pass


class HTTPWarning(Warning):
    """Base warning used by this module."""
    pass


class PoolError(HTTPError):
    """Base exception for errors caused within a pool."""

    def __init__(self, pool, message):
        self.pool = pool
        super().__init__(f"{pool}: {message}")


class RequestError(PoolError):
    """Base exception for PoolErrors that have associated URLs."""

    def __init__(self, pool, url, message):
        self.url = url
        super().__init__(pool, f"{url}: {message}")


class SSLError(HTTPError):
    """Raised when SSL certificate fails verification."""
    pass


class ProxyError(HTTPError):
    """Raised when something goes wrong with a proxy."""
    pass


class TimeoutError(HTTPError):
    """Raised when a socket timeout occurs."""
    pass


class TimeoutStateError(Exception):
    """
    Raised when an attempt to set a socket timeout is made after the socket
    has been connected.
    """
    pass


class ConnectionError(HTTPError):
    """Raised when there is an error with a connection."""
    pass


class ConnectTimeoutError(ConnectionError, TimeoutError):
    """Raised when a socket timeout occurs while connecting to a server."""
    pass


class ReadTimeoutError(ConnectionError, TimeoutError):
    """Raised when a socket timeout occurs while receiving data from a server."""
    pass


class NewConnectionError(ConnectTimeoutError):
    """Raised when we fail to establish a new connection to a server."""
    pass


class EmptyPoolError(PoolError):
    """Raised when a pool runs out of connections and no more are allowed."""
    pass


class ClosedPoolError(PoolError):
    """Raised when a request is made on a closed pool."""
    pass


class LocationValueError(ValueError, HTTPError):
    """Raised when there is something wrong with a given URL input."""
    pass


class LocationParseError(LocationValueError):
    """Raised when get_host or similar fails to parse the URL input."""

    def __init__(self, location):
        message = f"Failed to parse: {location}"
        super().__init__(message)

        self.location = location


class URLSchemeUnknown(LocationValueError):
    """Raised when a URL input has an unsupported scheme."""

    def __init__(self, scheme):
        message = f"Not supported URL scheme {scheme}"
        super().__init__(message)

        self.scheme = scheme


class ResponseError(HTTPError):
    """Used as a container for an error reason supplied in a max_retries."""
    pass


class SecurityWarning(HTTPWarning):
    """Warned when performing security reducing operations."""
    pass


class SubjectAltNameWarning(SecurityWarning):
    """Warned when connecting to a host with a certificate missing a SAN."""
    pass


class InsecureRequestWarning(SecurityWarning):
    """Warned when making an unverified HTTPS request."""
    pass


class SystemTimeWarning(SecurityWarning):
    """Warned when system time is suspected to be wrong."""
    pass


class InsecurePlatformWarning(SecurityWarning):
    """Warned when certain TLS/SSL configuration is not available on a platform."""
    pass


class SNIMissingWarning(HTTPWarning):
    """Warned when making a HTTPS request without SNI available."""
    pass


class DependencyWarning(HTTPWarning):
    """
    Warned when an attempt is made to import a module with missing optional
    dependencies.
    """
    pass


class InvalidHeader(HTTPError):
    """The header provided was somehow invalid."""
    pass


class ProxySchemeUnsupported(AssertionError, URLSchemeUnknown):
    """Raised when a proxy scheme is not supported."""

    def __init__(self, message):
        super().__init__(message)


class ProxySchemeUnknown(AssertionError, URLSchemeUnknown):
    """ProxyManager does not support the supplied scheme."""
    # TODO(t-8ch): Stop inheriting from AssertionError in v2.0.

    def __init__(self, scheme):
        # 'localhost' is here because our URL parser parses
        # localhost:8080 -> scheme=localhost, remove if we fix this.
        if scheme == "localhost":
            scheme = None
        if scheme is None:
            message = "Proxy URL had no scheme, should start with http:// or https://"
        else:
            message = f"Proxy URL had unsupported scheme {scheme}, should use http:// or https://"
        super().__init__(message)


class InvalidProxyConfigurationWarning(HTTPWarning):
    """
    Warned when the provided proxy configuration is invalid.
    """
    pass


class MaxRetryError(RequestError):
    """Raised when the maximum number of retries is exceeded."""

    def __init__(self, pool, url, reason=None):
        self.reason = reason

        message = f"Max retries exceeded with url: {url}"
        if reason:
            message += f" (Caused by {reason})"

        super().__init__(pool, url, message)


class ProtocolError(HTTPError):
    """Raised when something unexpected happens mid-request/response."""
    pass


class DecodeError(HTTPError):
    """Raised when automatic decoding based on Content-Type fails."""
    pass


class IncompleteRead(HTTPError, IOError):
    """
    Raised when a response does not contain enough bytes.
    """

    def __init__(self, partial, expected=None):
        self.partial = partial
        self.expected = expected

        actual = len(partial)
        message = f"IncompleteRead({actual}"
        if expected is not None:
            message += f" bytes read, {expected} more expected"
        message += ")"

        super().__init__(message)


class UnrewindableBodyError(HTTPError):
    """
    Raised when a request body cannot be rewound.

    This error is raised when an attempt is made to rewind a request body
    that is not rewindable.
    """
    pass
