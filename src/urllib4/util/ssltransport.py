"""
SSLTransport module for urllib4.

This module provides an SSLTransport implementation for use with urllib4.
"""

from __future__ import annotations

import io
import socket
import ssl
import typing
from typing import Any, Callable, List, Optional, Tuple, Union, cast

SSL_BLOCKSIZE = 16384


class SSLTransport:
    """
    The SSLTransport implements a buffered transport for SSL connections.
    """

    def __init__(
        self,
        sock: socket.socket,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> None:
        """
        Create an SSLTransport instance for a connection.
        
        Args:
            sock: The socket to wrap.
            ssl_context: The SSL context to use.
            server_hostname: The server hostname to use for SNI.
        """
        self.sock = sock
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        self.ssl_object = ssl_context.wrap_bio(
            ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname=server_hostname
        )
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.closed = False
        self.do_handshake()

    def do_handshake(self) -> None:
        """
        Perform the SSL handshake.
        """
        while True:
            try:
                self.ssl_object.do_handshake()
                break
            except ssl.SSLWantReadError:
                if self.outgoing.pending:
                    self.sock.sendall(self.outgoing.read())
                incoming_data = self.sock.recv(SSL_BLOCKSIZE)
                if not incoming_data:
                    raise ssl.SSLError("EOF during handshake")
                self.incoming.write(incoming_data)
                self.ssl_object.bio_write(self.incoming.read())
            except ssl.SSLWantWriteError:
                if self.outgoing.pending:
                    self.sock.sendall(self.outgoing.read())
                else:
                    raise ssl.SSLError("Unexpected SSLWantWriteError")

    def recv(self, bufsize: int) -> bytes:
        """
        Read up to bufsize bytes from the SSL connection.
        
        Args:
            bufsize: The maximum number of bytes to read.
            
        Returns:
            The bytes read.
        """
        if self.closed:
            raise OSError("Connection closed")
        
        try:
            return self.ssl_object.read(bufsize)
        except ssl.SSLWantReadError:
            if self.outgoing.pending:
                self.sock.sendall(self.outgoing.read())
            incoming_data = self.sock.recv(SSL_BLOCKSIZE)
            if not incoming_data:
                raise ssl.SSLError("EOF during read")
            self.incoming.write(incoming_data)
            self.ssl_object.bio_write(self.incoming.read())
            return self.recv(bufsize)
        except ssl.SSLWantWriteError:
            if self.outgoing.pending:
                self.sock.sendall(self.outgoing.read())
            else:
                raise ssl.SSLError("Unexpected SSLWantWriteError")
            return self.recv(bufsize)

    def send(self, data: bytes) -> int:
        """
        Send data to the SSL connection.
        
        Args:
            data: The data to send.
            
        Returns:
            The number of bytes sent.
        """
        if self.closed:
            raise OSError("Connection closed")
        
        try:
            self.ssl_object.write(data)
        except ssl.SSLWantReadError:
            if self.outgoing.pending:
                self.sock.sendall(self.outgoing.read())
            incoming_data = self.sock.recv(SSL_BLOCKSIZE)
            if not incoming_data:
                raise ssl.SSLError("EOF during write")
            self.incoming.write(incoming_data)
            self.ssl_object.bio_write(self.incoming.read())
            return self.send(data)
        except ssl.SSLWantWriteError:
            if self.outgoing.pending:
                self.sock.sendall(self.outgoing.read())
            else:
                raise ssl.SSLError("Unexpected SSLWantWriteError")
            return self.send(data)
        
        if self.outgoing.pending:
            self.sock.sendall(self.outgoing.read())
        return len(data)

    def close(self) -> None:
        """
        Close the SSL connection.
        """
        if self.closed:
            return
        
        try:
            self.ssl_object.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, ssl.SSLError):
            pass
        
        self.sock.close()
        self.closed = True

    def getpeercert(self, binary_form: bool = False) -> Union[dict, bytes, None]:
        """
        Get the peer certificate.
        
        Args:
            binary_form: Whether to return the certificate in binary form.
            
        Returns:
            The peer certificate.
        """
        return self.ssl_object.getpeercert(binary_form=binary_form)

    def version(self) -> Optional[str]:
        """
        Get the SSL protocol version.
        
        Returns:
            The SSL protocol version.
        """
        return self.ssl_object.version()

    def cipher(self) -> Optional[Tuple[str, str, int]]:
        """
        Get the current cipher.
        
        Returns:
            The current cipher.
        """
        return self.ssl_object.cipher()

    def fileno(self) -> int:
        """
        Get the file descriptor of the underlying socket.
        
        Returns:
            The file descriptor.
        """
        return self.sock.fileno()

    def settimeout(self, timeout: Optional[float]) -> None:
        """
        Set the timeout for the underlying socket.
        
        Args:
            timeout: The timeout value.
        """
        self.sock.settimeout(timeout)

    def gettimeout(self) -> Optional[float]:
        """
        Get the timeout for the underlying socket.
        
        Returns:
            The timeout value.
        """
        return self.sock.gettimeout()
