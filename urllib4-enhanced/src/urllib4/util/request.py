"""
Request utilities for urllib4.
"""

from __future__ import annotations

import base64
import binascii
import email.utils
import io
import logging
import os
import socket
import typing
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ..exceptions import UnrewindableBodyError
from .util import is_fp_closed

_FAILEDTELL = object()


def make_headers(
    keep_alive: Optional[bool] = None,
    accept_encoding: Optional[Union[str, List[str]]] = None,
    user_agent: Optional[str] = None,
    basic_auth: Optional[Union[str, Tuple[str, str]]] = None,
    proxy_basic_auth: Optional[Union[str, Tuple[str, str]]] = None,
    disable_cache: Optional[bool] = None,
) -> Dict[str, str]:
    """
    Shortcuts for generating request headers.

    :param keep_alive:
        If True, adds 'connection: keep-alive' header.

    :param accept_encoding:
        Can be a string, like "gzip,deflate", or a list of strings.

    :param user_agent:
        String representing the user-agent you want, such as
        "python-urllib4/0.6"

    :param basic_auth:
        Colon-separated username:password string for 'authorization: basic ...'
        auth, or a (username, password) tuple for basic auth.

    :param proxy_basic_auth:
        Colon-separated username:password string for 'proxy-authorization: basic ...'
        auth, or a (username, password) tuple for basic auth.

    :param disable_cache:
        If True, adds 'cache-control: no-cache' header.

    Example:

    .. code-block:: python

        import urllib4

        headers = urllib4.util.make_headers(keep_alive=True, user_agent="urllib4/1.0")
        # {'connection': 'keep-alive', 'user-agent': 'urllib4/1.0'}
    """
    headers: Dict[str, str] = {}
    if accept_encoding:
        if isinstance(accept_encoding, str):
            pass
        elif isinstance(accept_encoding, list):
            accept_encoding = ",".join(accept_encoding)
        else:
            accept_encoding = ",".join(accept_encoding)
        headers["accept-encoding"] = accept_encoding

    if user_agent:
        headers["user-agent"] = user_agent

    if keep_alive:
        headers["connection"] = "keep-alive"

    if basic_auth:
        if isinstance(basic_auth, str):
            basic_auth = basic_auth.encode("utf-8")
        else:
            basic_auth = f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
        headers["authorization"] = f"Basic {base64.b64encode(basic_auth).decode('utf-8')}"

    if proxy_basic_auth:
        if isinstance(proxy_basic_auth, str):
            proxy_basic_auth = proxy_basic_auth.encode("utf-8")
        else:
            proxy_basic_auth = f"{proxy_basic_auth[0]}:{proxy_basic_auth[1]}".encode("utf-8")
        headers["proxy-authorization"] = f"Basic {base64.b64encode(proxy_basic_auth).decode('utf-8')}"

    if disable_cache:
        headers["cache-control"] = "no-cache"

    return headers


def rewind_body(body: Any) -> None:
    """
    Attempt to rewind body to its beginning.

    :param body:
        The body to rewind.
    """
    body_pos = _get_body_position(body)
    if body_pos is not _FAILEDTELL:
        _rewind_body(body, body_pos)


def _get_body_position(body: Any) -> Any:
    """
    Get the position of the body.

    :param body:
        The body to get the position of.
    """
    pos = _FAILEDTELL
    if hasattr(body, "tell"):
        try:
            pos = body.tell()
        except (IOError, OSError, ValueError):
            # This differentiates from None, allowing us to catch
            # a failed `tell()` later when rewinding the body.
            pos = _FAILEDTELL
    return pos


def _rewind_body(body: Any, body_pos: Any) -> None:
    """
    Rewind the body to the position it was at before.

    :param body:
        The body to rewind.
    :param body_pos:
        The position to rewind to.
    """
    if body_pos is _FAILEDTELL:
        return

    # Attempt to rewind the file-like object.
    if hasattr(body, "seek"):
        try:
            body.seek(0)
        except (IOError, OSError):
            raise UnrewindableBodyError(
                "An error occurred when rewinding request body for redirect."
            )
    else:
        raise UnrewindableBodyError(
            "Unable to rewind request body for redirect."
        )
