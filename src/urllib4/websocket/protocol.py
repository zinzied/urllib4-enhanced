"""
WebSocket protocol implementation for urllib4.

This module implements the WebSocket protocol as defined in RFC 6455.
"""

from __future__ import annotations

import enum
import logging
import os
import struct
import typing
from dataclasses import dataclass
from enum import Enum, IntEnum, auto

log = logging.getLogger(__name__)


class WebSocketFrameType(IntEnum):
    """WebSocket frame types as defined in RFC 6455."""

    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class WebSocketCloseCode(IntEnum):
    """WebSocket close codes as defined in RFC 6455."""

    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED_DATA = 1003
    NO_STATUS = 1005
    ABNORMAL = 1006
    INVALID_PAYLOAD = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    EXTENSION_REQUIRED = 1010
    UNEXPECTED_CONDITION = 1011
    TLS_HANDSHAKE_FAILED = 1015


@dataclass
class WebSocketFrame:
    """
    Represents a WebSocket frame.

    This class encapsulates the data for a single WebSocket frame
    as defined in RFC 6455.
    """

    opcode: WebSocketFrameType
    payload: bytes
    fin: bool = True
    rsv1: bool = False
    rsv2: bool = False
    rsv3: bool = False

    @classmethod
    def create(
        cls,
        opcode: WebSocketFrameType,
        payload: bytes | str,
        fin: bool = True,
        rsv1: bool = False,
        rsv2: bool = False,
        rsv3: bool = False,
    ) -> "WebSocketFrame":
        """
        Create a WebSocket frame.

        :param opcode: The frame opcode
        :param payload: The frame payload
        :param fin: Whether this is the final frame in a message
        :param rsv1: RSV1 bit
        :param rsv2: RSV2 bit
        :param rsv3: RSV3 bit
        :return: A WebSocketFrame instance
        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        return cls(
            opcode=opcode,
            payload=payload,
            fin=fin,
            rsv1=rsv1,
            rsv2=rsv2,
            rsv3=rsv3,
        )

    @classmethod
    def create_text(cls, text: str, fin: bool = True) -> "WebSocketFrame":
        """
        Create a text frame.

        :param text: The text to send
        :param fin: Whether this is the final frame in a message
        :return: A WebSocketFrame instance
        """
        return cls.create(WebSocketFrameType.TEXT, text, fin=fin)

    @classmethod
    def create_binary(cls, data: bytes, fin: bool = True) -> "WebSocketFrame":
        """
        Create a binary frame.

        :param data: The binary data to send
        :param fin: Whether this is the final frame in a message
        :return: A WebSocketFrame instance
        """
        return cls.create(WebSocketFrameType.BINARY, data, fin=fin)

    @classmethod
    def create_close(
        cls, code: WebSocketCloseCode = WebSocketCloseCode.NORMAL, reason: str = ""
    ) -> "WebSocketFrame":
        """
        Create a close frame.

        :param code: The close code
        :param reason: The close reason
        :return: A WebSocketFrame instance
        """
        payload = struct.pack("!H", code) + reason.encode("utf-8")
        return cls.create(WebSocketFrameType.CLOSE, payload)

    @classmethod
    def create_ping(cls, data: bytes = b"") -> "WebSocketFrame":
        """
        Create a ping frame.

        :param data: Optional ping data
        :return: A WebSocketFrame instance
        """
        return cls.create(WebSocketFrameType.PING, data)

    @classmethod
    def create_pong(cls, data: bytes = b"") -> "WebSocketFrame":
        """
        Create a pong frame.

        :param data: Optional pong data (should match the ping data)
        :return: A WebSocketFrame instance
        """
        return cls.create(WebSocketFrameType.PONG, data)


@dataclass
class WebSocketMessage:
    """
    Represents a complete WebSocket message.

    A WebSocket message can consist of multiple frames.
    """

    opcode: WebSocketFrameType
    data: bytes

    @property
    def is_text(self) -> bool:
        """Check if this is a text message."""
        return self.opcode == WebSocketFrameType.TEXT

    @property
    def is_binary(self) -> bool:
        """Check if this is a binary message."""
        return self.opcode == WebSocketFrameType.BINARY

    @property
    def is_close(self) -> bool:
        """Check if this is a close message."""
        return self.opcode == WebSocketFrameType.CLOSE

    @property
    def text(self) -> str:
        """
        Get the message data as text.

        :return: The message data decoded as UTF-8
        :raises UnicodeDecodeError: If the data is not valid UTF-8
        """
        return self.data.decode("utf-8")

    @property
    def close_code(self) -> WebSocketCloseCode:
        """
        Get the close code from a close message.

        :return: The close code
        :raises ValueError: If this is not a close message or the data is invalid
        """
        if not self.is_close:
            raise ValueError("Not a close message")

        if len(self.data) < 2:
            return WebSocketCloseCode.NO_STATUS

        code = struct.unpack("!H", self.data[:2])[0]
        return WebSocketCloseCode(code)

    @property
    def close_reason(self) -> str:
        """
        Get the close reason from a close message.

        :return: The close reason
        :raises ValueError: If this is not a close message
        """
        if not self.is_close:
            raise ValueError("Not a close message")

        if len(self.data) <= 2:
            return ""

        return self.data[2:].decode("utf-8", errors="replace")


class WebSocketProtocol:
    """
    Implements the WebSocket protocol.

    This class handles encoding and decoding WebSocket frames
    according to RFC 6455.
    """

    def __init__(self, mask_frames: bool = True) -> None:
        """
        Initialize a new WebSocketProtocol.

        :param mask_frames: Whether to mask outgoing frames (required for clients)
        """
        self.mask_frames = mask_frames

    def encode_frame(self, frame: WebSocketFrame) -> bytes:
        """
        Encode a WebSocket frame to bytes.

        :param frame: The frame to encode
        :return: The encoded frame
        """
        # First byte: FIN bit, RSV bits, and opcode
        first_byte = (
            (0x80 if frame.fin else 0)
            | (0x40 if frame.rsv1 else 0)
            | (0x20 if frame.rsv2 else 0)
            | (0x10 if frame.rsv3 else 0)
            | (frame.opcode & 0x0F)
        )

        # Payload length
        payload_len = len(frame.payload)
        if payload_len < 126:
            length_bytes = bytes([payload_len | (0x80 if self.mask_frames else 0)])
        elif payload_len < 65536:
            length_bytes = bytes([126 | (0x80 if self.mask_frames else 0)]) + struct.pack(
                "!H", payload_len
            )
        else:
            length_bytes = bytes([127 | (0x80 if self.mask_frames else 0)]) + struct.pack(
                "!Q", payload_len
            )

        # Masking key
        if self.mask_frames:
            mask_key = os.urandom(4)
            masked_payload = self._apply_mask(frame.payload, mask_key)
            return bytes([first_byte]) + length_bytes + mask_key + masked_payload
        else:
            return bytes([first_byte]) + length_bytes + frame.payload

    def decode_frame(self, data: bytes) -> tuple[WebSocketFrame, int]:
        """
        Decode a WebSocket frame from bytes.

        :param data: The data to decode
        :return: The decoded frame and the number of bytes consumed
        :raises ValueError: If the data is not a valid WebSocket frame
        """
        if len(data) < 2:
            raise ValueError("Not enough data to decode frame header")

        # First byte: FIN bit, RSV bits, and opcode
        first_byte = data[0]
        fin = bool(first_byte & 0x80)
        rsv1 = bool(first_byte & 0x40)
        rsv2 = bool(first_byte & 0x20)
        rsv3 = bool(first_byte & 0x10)
        opcode = WebSocketFrameType(first_byte & 0x0F)

        # Second byte: MASK bit and payload length
        second_byte = data[1]
        masked = bool(second_byte & 0x80)
        payload_len = second_byte & 0x7F

        # Extended payload length
        header_len = 2
        if payload_len == 126:
            if len(data) < 4:
                raise ValueError("Not enough data to decode extended payload length")
            payload_len = struct.unpack("!H", data[2:4])[0]
            header_len = 4
        elif payload_len == 127:
            if len(data) < 10:
                raise ValueError("Not enough data to decode extended payload length")
            payload_len = struct.unpack("!Q", data[2:10])[0]
            header_len = 10

        # Masking key
        if masked:
            if len(data) < header_len + 4:
                raise ValueError("Not enough data to decode masking key")
            mask_key = data[header_len:header_len + 4]
            header_len += 4

        # Payload
        if len(data) < header_len + payload_len:
            raise ValueError("Not enough data to decode payload")

        payload = data[header_len:header_len + payload_len]

        # Unmask payload if needed
        if masked:
            payload = self._apply_mask(payload, mask_key)  # type: ignore

        frame = WebSocketFrame(
            opcode=opcode,
            payload=payload,
            fin=fin,
            rsv1=rsv1,
            rsv2=rsv2,
            rsv3=rsv3,
        )

        return frame, header_len + payload_len

    def _apply_mask(self, data: bytes, mask_key: bytes) -> bytes:
        """
        Apply a WebSocket mask to data.

        :param data: The data to mask
        :param mask_key: The 4-byte mask key
        :return: The masked data
        """
        masked = bytearray(len(data))
        for i in range(len(data)):
            masked[i] = data[i] ^ mask_key[i % 4]
        return bytes(masked)
