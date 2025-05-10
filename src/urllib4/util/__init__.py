"""
Utility functions for urllib4.
"""

from __future__ import annotations

import ssl
from typing import Any, Optional, Union

# Import utility functions from the ssl_ module
def resolve_cert_reqs(candidate: Union[None, int, str]) -> int:
    """
    Resolves the argument to a numeric constant, which can be passed to
    the wrap_socket function/method from the ssl module.
    Defaults to :data:`ssl.CERT_REQUIRED`.

    Args:
        candidate: The candidate to resolve.

    Returns:
        The resolved value.
    """
    if candidate is None:
        return ssl.CERT_REQUIRED

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is not None:
            return res
        res = getattr(ssl, "CERT_" + candidate)
        return res

    return candidate


def resolve_ssl_version(candidate: Union[None, int, str]) -> int:
    """
    Resolves the argument to a numeric constant, which can be passed to
    the wrap_socket function/method from the ssl module.
    Defaults to :data:`ssl.PROTOCOL_TLS`.

    Args:
        candidate: The candidate to resolve.

    Returns:
        The resolved value.
    """
    if candidate is None:
        return ssl.PROTOCOL_TLS

    if isinstance(candidate, str):
        res = getattr(ssl, candidate, None)
        if res is not None:
            return res
        res = getattr(ssl, "PROTOCOL_" + candidate)
        return res

    return candidate

# Import other utility functions
from .connection import (  # noqa: F401
    is_connection_dropped,
    create_connection,
    allowed_gai_family,
)
from .timeout import (  # noqa: F401
    Timeout,
    current_time,
)
from .url import (  # noqa: F401
    get_host,
    parse_url,
    split_first,
    Url,
)
from .proxy import (  # noqa: F401
    connection_requires_http_tunnel,
    create_proxy_ssl_context,
)
from .request import (  # noqa: F401
    _FAILEDTELL,
    make_headers,
    rewind_body,
)
from .response import (  # noqa: F401
    assert_header_parsing,
    is_response_to_head,
)
from .util import (  # noqa: F401
    is_fp_closed,
    to_bytes,
    to_str,
    reraise,
)
