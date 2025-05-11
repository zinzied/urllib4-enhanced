"""
WebSocket extensions for urllib4.

This module provides support for WebSocket extensions as defined in RFC 6455.
"""

from __future__ import annotations

import logging
import re
import zlib
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Union

from .protocol import WebSocketFrame, WebSocketFrameType

log = logging.getLogger(__name__)


class WebSocketExtension(ABC):
    """
    Base class for WebSocket extensions.
    
    WebSocket extensions can modify the behavior of the WebSocket protocol,
    such as by compressing messages or adding new frame types.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the extension."""
        pass
    
    @abstractmethod
    def offer(self) -> str:
        """
        Generate the extension offer for the Sec-WebSocket-Extensions header.
        
        :return: The extension offer string
        """
        pass
    
    @abstractmethod
    def accept(self, response: str) -> bool:
        """
        Process the server's response to the extension offer.
        
        :param response: The server's response string
        :return: True if the extension was accepted, False otherwise
        """
        pass
    
    @abstractmethod
    def encode_frame(self, frame: WebSocketFrame) -> WebSocketFrame:
        """
        Apply the extension to an outgoing frame.
        
        :param frame: The frame to encode
        :return: The encoded frame
        """
        pass
    
    @abstractmethod
    def decode_frame(self, frame: WebSocketFrame) -> WebSocketFrame:
        """
        Apply the extension to an incoming frame.
        
        :param frame: The frame to decode
        :return: The decoded frame
        """
        pass


class PerMessageDeflate(WebSocketExtension):
    """
    Implementation of the permessage-deflate extension.
    
    This extension compresses WebSocket messages using the DEFLATE algorithm,
    as defined in RFC 7692.
    """
    
    def __init__(
        self,
        client_max_window_bits: Optional[int] = None,
        server_max_window_bits: Optional[int] = None,
        client_no_context_takeover: bool = False,
        server_no_context_takeover: bool = False,
        compression_level: int = 9,
    ) -> None:
        """
        Initialize a new PerMessageDeflate extension.
        
        :param client_max_window_bits: Maximum window bits for client
        :param server_max_window_bits: Maximum window bits for server
        :param client_no_context_takeover: Whether client context is reset after each message
        :param server_no_context_takeover: Whether server context is reset after each message
        :param compression_level: Compression level (0-9, higher is more compression)
        """
        self.client_max_window_bits = client_max_window_bits
        self.server_max_window_bits = server_max_window_bits
        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self.compression_level = compression_level
        
        # Negotiated parameters
        self._agreed_client_max_window_bits = 15  # Default
        self._agreed_server_max_window_bits = 15  # Default
        self._agreed_client_no_context_takeover = False
        self._agreed_server_no_context_takeover = False
        
        # Compression contexts
        self._deflator = None
        self._inflator = None
        
        # Extension state
        self._enabled = False
    
    @property
    def name(self) -> str:
        """Get the name of the extension."""
        return "permessage-deflate"
    
    def offer(self) -> str:
        """
        Generate the extension offer for the Sec-WebSocket-Extensions header.
        
        :return: The extension offer string
        """
        params = []
        
        if self.client_max_window_bits is not None:
            if self.client_max_window_bits == 0:
                params.append("client_max_window_bits")
            else:
                params.append(f"client_max_window_bits={self.client_max_window_bits}")
                
        if self.server_max_window_bits is not None:
            params.append(f"server_max_window_bits={self.server_max_window_bits}")
            
        if self.client_no_context_takeover:
            params.append("client_no_context_takeover")
            
        if self.server_no_context_takeover:
            params.append("server_no_context_takeover")
            
        if params:
            return f"{self.name}; {'; '.join(params)}"
        else:
            return self.name
    
    def accept(self, response: str) -> bool:
        """
        Process the server's response to the extension offer.
        
        :param response: The server's response string
        :return: True if the extension was accepted, False otherwise
        """
        # Parse the response
        if not response.startswith(self.name):
            return False
            
        # Extract parameters
        params_str = response[len(self.name):].strip()
        if params_str.startswith(";"):
            params_str = params_str[1:].strip()
            
        params = [p.strip() for p in params_str.split(";")]
        
        # Process parameters
        for param in params:
            if param == "client_no_context_takeover":
                self._agreed_client_no_context_takeover = True
            elif param == "server_no_context_takeover":
                self._agreed_server_no_context_takeover = True
            elif param.startswith("client_max_window_bits="):
                try:
                    bits = int(param.split("=")[1])
                    if 8 <= bits <= 15:
                        self._agreed_client_max_window_bits = bits
                    else:
                        return False  # Invalid value
                except (ValueError, IndexError):
                    return False  # Invalid format
            elif param.startswith("server_max_window_bits="):
                try:
                    bits = int(param.split("=")[1])
                    if 8 <= bits <= 15:
                        self._agreed_server_max_window_bits = bits
                    else:
                        return False  # Invalid value
                except (ValueError, IndexError):
                    return False  # Invalid format
        
        # Initialize compression contexts
        self._init_compression()
        
        # Mark as enabled
        self._enabled = True
        
        return True
    
    def _init_compression(self) -> None:
        """Initialize compression contexts."""
        # Initialize deflator (for outgoing messages)
        wbits = -self._agreed_client_max_window_bits  # Negative for raw deflate
        self._deflator = zlib.compressobj(
            level=self.compression_level,
            method=zlib.DEFLATED,
            wbits=wbits,
            memLevel=8,
            strategy=zlib.Z_DEFAULT_STRATEGY,
        )
        
        # Initialize inflator (for incoming messages)
        wbits = -self._agreed_server_max_window_bits  # Negative for raw deflate
        self._inflator = zlib.decompressobj(wbits)
    
    def encode_frame(self, frame: WebSocketFrame) -> WebSocketFrame:
        """
        Apply the extension to an outgoing frame.
        
        :param frame: The frame to encode
        :return: The encoded frame
        """
        if not self._enabled:
            return frame
            
        # Only compress text and binary frames
        if frame.opcode not in (WebSocketFrameType.TEXT, WebSocketFrameType.BINARY):
            return frame
            
        # Don't compress empty frames
        if not frame.payload:
            return frame
            
        # Compress the payload
        compressed = self._deflator.compress(frame.payload) + self._deflator.flush(zlib.Z_SYNC_FLUSH)
        
        # Remove the last 4 bytes (trailer)
        if len(compressed) >= 4:
            compressed = compressed[:-4]
            
        # Reset the context if needed
        if self._agreed_client_no_context_takeover:
            self._init_compression()
            
        # Create a new frame with the compressed payload
        return WebSocketFrame(
            opcode=frame.opcode,
            payload=compressed,
            fin=frame.fin,
            rsv1=True,  # RSV1 bit indicates compression
            rsv2=frame.rsv2,
            rsv3=frame.rsv3,
        )
    
    def decode_frame(self, frame: WebSocketFrame) -> WebSocketFrame:
        """
        Apply the extension to an incoming frame.
        
        :param frame: The frame to decode
        :return: The decoded frame
        """
        if not self._enabled:
            return frame
            
        # Only decompress frames with RSV1 bit set
        if not frame.rsv1:
            return frame
            
        # Only decompress text and binary frames
        if frame.opcode not in (WebSocketFrameType.TEXT, WebSocketFrameType.BINARY):
            return frame
            
        # Decompress the payload
        decompressed = self._inflator.decompress(frame.payload + b'\x00\x00\xff\xff')
        
        # Reset the context if needed
        if self._agreed_server_no_context_takeover:
            self._inflator = zlib.decompressobj(-self._agreed_server_max_window_bits)
            
        # Create a new frame with the decompressed payload
        return WebSocketFrame(
            opcode=frame.opcode,
            payload=decompressed,
            fin=frame.fin,
            rsv1=False,  # Clear RSV1 bit
            rsv2=frame.rsv2,
            rsv3=frame.rsv3,
        )


def parse_extension_header(header: str) -> List[Tuple[str, Dict[str, str]]]:
    """
    Parse the Sec-WebSocket-Extensions header.
    
    :param header: The header value
    :return: List of (extension_name, parameters) tuples
    """
    if not header:
        return []
        
    extensions = []
    
    for ext in header.split(","):
        ext = ext.strip()
        if not ext:
            continue
            
        # Split name and parameters
        parts = ext.split(";")
        name = parts[0].strip()
        
        # Parse parameters
        params = {}
        for param in parts[1:]:
            param = param.strip()
            if "=" in param:
                key, value = param.split("=", 1)
                params[key.strip()] = value.strip()
            else:
                params[param] = None
                
        extensions.append((name, params))
        
    return extensions
