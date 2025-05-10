"""
Response utilities for urllib4.
"""

from __future__ import annotations

import logging
import re
import typing
from typing import Dict, List, Optional, Tuple, Union

log = logging.getLogger(__name__)


def assert_header_parsing(headers: Union[bytes, List[bytes]]) -> None:
    """
    Asserts whether all headers have been successfully parsed.
    Extracts encountered errors from the result of parsing headers.

    Only works on Python 3.

    :param headers: Headers to verify.
    :raises urllib4.exceptions.HeaderParsingError:
        If parsing errors are found.
    """
    from ..exceptions import HeaderParsingError

    if not headers:
        return

    if isinstance(headers, bytes):
        headers = [headers]

    for header in headers:
        header_string = header.decode("utf-8", "replace")
        header_lines = header_string.split("\r\n")

        for header_line in header_lines:
            if not header_line:
                continue

            # Check for header parsing errors
            if "," in header_line and ";" in header_line:
                parts = header_line.split(";")
                for part in parts:
                    if "," in part and not re.search(r'"[^"]*"', part):
                        msg = (
                            f"Comma in header without quotes: {header_line}"
                        )
                        log.warning(msg)
                        raise HeaderParsingError(msg)


def is_response_to_head(response: typing.Any) -> bool:
    """
    Checks whether the request of a response has been a HEAD-request.
    Handles the quirks of AppEngine.

    :param response:
        The response to check.
    :return:
        True if the request was a HEAD-request, False otherwise.
    """
    # FIXME: Can we do better than this?
    # AppEngine doesn't provide a request attribute
    if not hasattr(response, "request"):
        return False
    return response.request.method.upper() == "HEAD"
