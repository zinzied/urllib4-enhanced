"""
SSL utilities for urllib4.
"""

from __future__ import annotations

import socket
import ssl
import sys
import warnings
from typing import Any, Dict, Optional, Tuple, Union, cast

from ..exceptions import ProxySchemeUnsupported, SSLError

_TYPE_PEER_CERT_RET_DICT = Dict[str, Union[str, Tuple[Tuple[str, str]]]]
_TYPE_VERSION_INFO = Tuple[int, int, int, str, int]

# For mocking in tests
SSLContext = ssl.SSLContext


def _is_has_never_check_common_name_reliable() -> bool:
    """
    Checks if the has_never_check_common_name attribute is reliable.

    Returns:
        True if the attribute is reliable, False otherwise.
    """
    return sys.version_info >= (3, 7, 0)


def resolve_cert_reqs(candidate: Optional[Union[int, str]]) -> int:
    """
    Resolves the certificate requirements.

    Args:
        candidate: The candidate certificate requirements.

    Returns:
        The resolved certificate requirements.
    """
    if candidate is None:
        return ssl.CERT_REQUIRED

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is None:
            res = getattr(ssl, "CERT_" + candidate)
        return res

    return candidate


def resolve_ssl_version(candidate: Optional[Union[int, str]]) -> int:
    """
    Resolves the SSL version.

    Args:
        candidate: The candidate SSL version.

    Returns:
        The resolved SSL version.
    """
    if candidate is None:
        return ssl.PROTOCOL_TLS

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is None:
            res = getattr(ssl, "PROTOCOL_" + candidate)
        return res

    return candidate


def ssl_wrap_socket(
    sock: socket.socket,
    keyfile: Optional[str] = None,
    certfile: Optional[str] = None,
    cert_reqs: Optional[Union[int, str]] = None,
    ca_certs: Optional[str] = None,
    server_hostname: Optional[str] = None,
    ssl_version: Optional[Union[int, str]] = None,
    ciphers: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    ca_cert_dir: Optional[str] = None,
    key_password: Optional[str] = None,
    ca_cert_data: Optional[Union[str, bytes]] = None,
    tls_in_tls: bool = False,
) -> ssl.SSLSocket:
    """
    All arguments except for server_hostname, ssl_context, and ca_cert_dir have
    the same meaning as they do when using :func:`ssl.wrap_socket`.

    :param server_hostname:
        When SNI is supported, the expected hostname of the certificate
    :param ssl_context:
        A pre-made :class:`SSLContext` object. If none is provided, one will
        be created using :func:`create_urllib3_context`.
    :param ciphers:
        A string of ciphers we wish the client to support.
    :param ca_cert_dir:
        A directory containing CA certificates in multiple separate files, as
        supported by OpenSSL's -CApath flag or the capath argument to
        SSLContext.load_verify_locations().
    :param key_password:
        Optional password if the keyfile is encrypted.
    :param ca_cert_data:
        Optional string containing CA certificates in PEM format suitable for
        passing as the cadata parameter to SSLContext.load_verify_locations()
    :param tls_in_tls:
        Use SSLTransport to wrap the existing socket.
    """
    context = ssl_context
    if context is None:
        # Note: This branch of code and all the variables in it are no longer
        # used by urllib3 itself. We should consider deprecating and removing
        # this code.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_REQUIRED

    if ca_certs or ca_cert_dir or ca_cert_data:
        try:
            context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
        except (IOError, OSError) as e:
            raise SSLError(e)

    # Attempt to detect if we get the goofy behavior where the
    # keyfile is encrypted but OpenSSL is trying to ask us for
    # the passphrase via the terminal and failing because we
    # can't see the terminal.
    if keyfile and key_password is None and certfile:
        # No password was explicitly set, but we've been given both
        # a keyfile and a certfile so we've probably got a encrypted
        # key. Unfortunately, OpenSSL doesn't give us a way to figure
        # out if the key is encrypted or not. We've got to attempt to
        # load it and see if it fails.
        try:
            context.load_cert_chain(certfile, keyfile)
        except ssl.SSLError as e:
            if "private key" in str(e):
                # We've got an encrypted key.
                raise SSLError(
                    "Client private key is encrypted, password is required. "
                    "Please provide the password in the key_password argument."
                )
            raise

    elif keyfile and certfile:
        context.load_cert_chain(certfile, keyfile, key_password)

    # If we detect server_hostname is an IP address then the SNI
    # extension should not be used according to RFC3546 Section 3.1
    # We shouldn't warn the user if SNI isn't available but we would
    # not be using SNI anyways due to IP address for server_hostname.
    if server_hostname is not None and not is_ipaddress(server_hostname):
        return context.wrap_socket(sock, server_hostname=server_hostname)

    return context.wrap_socket(sock)

def is_ipaddress(hostname: Union[str, bytes]) -> bool:
    """
    Detects whether the hostname given is an IP address.

    Args:
        hostname: The hostname to check.

    Returns:
        True if the hostname is an IP address, False otherwise.
    """
    if isinstance(hostname, bytes):
        # IDN A-label bytes are ASCII compatible.
        hostname = hostname.decode("ascii")

    # IPv6 addresses with zone IDs contain '%'
    if "%" in hostname:
        # Remove the zone ID before checking if it's a valid IPv6 address
        hostname_without_zone = hostname.split("%")[0]
        try:
            socket.inet_pton(socket.AF_INET6, hostname_without_zone)
            return True
        except (socket.error, ValueError):
            return False

    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return True
    except (socket.error, ValueError):
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except (socket.error, ValueError):
            return False

def create_urllib4_context(
    ssl_version: Optional[int] = None,
    cert_reqs: Optional[int] = None,
    options: Optional[int] = None,
    ciphers: Optional[str] = None,
    ssl_minimum_version: Optional[int] = None,
    ssl_maximum_version: Optional[int] = None,
    verify_flags: Optional[int] = None,
) -> ssl.SSLContext:
    """
    Creates and configures an :class:`ssl.SSLContext` instance for use with urllib4.

    Args:
        ssl_version: The SSL version to use.
        cert_reqs: The certificate requirements.
        options: The SSL options.
        ciphers: The ciphers to use.
        ssl_minimum_version: The minimum SSL version to use.
        ssl_maximum_version: The maximum SSL version to use.
        verify_flags: The verification flags.

    Returns:
        The configured SSL context.
    """
    if ssl_version is not None and (
        ssl_minimum_version is not None or ssl_maximum_version is not None
    ):
        if ssl_version != ssl.PROTOCOL_TLS and ssl_version != ssl.PROTOCOL_TLS_CLIENT:
            raise ValueError(
                "Can't specify both 'ssl_version' and either 'ssl_minimum_version' or 'ssl_maximum_version'"
            )
        warnings.warn(
            "'ssl_version' option is deprecated and will be removed in "
            "urllib4 v2.1.0. Instead use 'ssl_minimum_version'",
            DeprecationWarning,
            stacklevel=2,
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Setting the default here, as we may have no ssl module on import
    cert_reqs = ssl.CERT_REQUIRED if cert_reqs is None else cert_reqs

    if options is None:
        options = 0
        # SSLv2 is easily broken and is considered harmful and dangerous
        options |= ssl.OP_NO_SSLv2
        # SSLv3 has several problems and is now dangerous
        options |= ssl.OP_NO_SSLv3
        # Disable compression to prevent CRIME attacks for OpenSSL 1.0+
        # (issue #309)
        options |= getattr(ssl, "OP_NO_COMPRESSION", 0)

    context.options |= options

    if getattr(context, "post_handshake_auth", None) is not None:
        context.post_handshake_auth = True

    if cert_reqs:
        context.verify_mode = cert_reqs

    if ssl_minimum_version is not None:
        context.minimum_version = ssl_minimum_version

    if ssl_maximum_version is not None:
        context.maximum_version = ssl_maximum_version

    if verify_flags is not None:
        context.verify_flags |= verify_flags

    if ciphers:
        context.set_ciphers(ciphers)

    return context

def ssl_wrap_socket(
    sock: socket.socket,
    keyfile: Optional[str] = None,
    certfile: Optional[str] = None,
    cert_reqs: Optional[int] = None,
    ca_certs: Optional[str] = None,
    server_hostname: Optional[str] = None,
    ssl_version: Optional[int] = None,
    ciphers: Optional[str] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    ca_cert_dir: Optional[str] = None,
    key_password: Optional[str] = None,
    ca_cert_data: Optional[Union[str, bytes]] = None,
    tls_in_tls: bool = False,
) -> ssl.SSLSocket:
    """
    Wraps a socket with SSL.

    Args:
        sock: The socket to wrap.
        keyfile: The path to the key file.
        certfile: The path to the certificate file.
        cert_reqs: The certificate requirements.
        ca_certs: The path to the CA certificates file.
        server_hostname: The server hostname for SNI.
        ssl_version: The SSL version to use.
        ciphers: The ciphers to use.
        ssl_context: The SSL context to use.
        ca_cert_dir: The path to the CA certificates directory.
        key_password: The password for the key file.
        ca_cert_data: The CA certificates data.
        tls_in_tls: Whether to use TLS in TLS.

    Returns:
        The wrapped socket.
    """
    if ssl_context is None:
        if ca_certs and certfile:
            ssl_context = create_urllib4_context(
                ssl_version=ssl_version,
                cert_reqs=cert_reqs,
                ciphers=ciphers,
            )
        else:
            ssl_context = create_urllib4_context(
                ssl_version=ssl_version,
                cert_reqs=cert_reqs,
                ciphers=ciphers,
            )

    if ca_certs or ca_cert_dir or ca_cert_data:
        try:
            if ca_certs:
                ssl_context.load_verify_locations(cafile=ca_certs)
            if ca_cert_dir:
                ssl_context.load_verify_locations(capath=ca_cert_dir)
            if ca_cert_data:
                ssl_context.load_verify_locations(cadata=ca_cert_data)
        except (IOError, OSError) as e:
            raise SSLError(e)
    elif ssl_context.verify_mode != ssl.CERT_NONE:
        # While we're not loading CA certificates, we still want to verify that the
        # server's certificate is valid for the hostname. This requires CA certs, so
        # if they weren't explicitly provided, we need to load the default ones.
        ssl_context.load_default_certs()

    if certfile:
        try:
            if keyfile is not None:
                ssl_context.load_cert_chain(
                    certfile=certfile, keyfile=keyfile, password=key_password
                )
            else:
                ssl_context.load_cert_chain(
                    certfile=certfile, password=key_password
                )
        except (IOError, OSError) as e:
            raise SSLError(e)

    if tls_in_tls:
        try:
            from urllib4.util.ssltransport import SSLTransport
        except ImportError:
            raise ProxySchemeUnsupported(
                "TLS in TLS requires support for the 'ssl' module"
            )

        return SSLTransport(sock, ssl_context, server_hostname)

    return ssl_context.wrap_socket(sock, server_hostname=server_hostname)

def assert_fingerprint(cert: Optional[bytes], fingerprint: str) -> None:
    """
    Checks if the certificate fingerprint matches the expected fingerprint.

    Args:
        cert: The certificate to check.
        fingerprint: The expected fingerprint.

    Raises:
        SSLError: If the certificate doesn't match the fingerprint.
    """
    if cert is None:
        raise SSLError("No certificate for the peer.")

    # We only check the first certificate in the chain
    if isinstance(cert, list):
        cert = cert[0]

    # XXX: This is a bit of a hack, but it's the only way to get the
    # fingerprint from the cert object in Python 3.
    fingerprint = fingerprint.replace(":", "").lower()
    digest = "sha1"

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509 import load_der_x509_certificate

        cert_obj = load_der_x509_certificate(cert)
        fingerprint_bytes = bytes.fromhex(fingerprint)

        if len(fingerprint_bytes) == 20:
            digest = hashes.SHA1()
        elif len(fingerprint_bytes) == 32:
            digest = hashes.SHA256()
        else:
            raise SSLError("Fingerprint of invalid length: %s" % fingerprint)

        cert_digest = cert_obj.fingerprint(digest)

        if cert_digest != fingerprint_bytes:
            raise SSLError(
                'Fingerprints did not match. Expected "%s", got "%s"'
                % (fingerprint, cert_digest.hex())
            )
    except ImportError:
        from hashlib import sha1

        # Legacy fallback
        fingerprint_bytes = bytes.fromhex(fingerprint)
        cert_digest = sha1(cert).digest()

        if cert_digest != fingerprint_bytes:
            raise SSLError(
                'Fingerprints did not match. Expected "%s", got "%s"'
                % (fingerprint, cert_digest.hex())
            )
