from __future__ import annotations

import io
import typing
from types import TracebackType


def to_bytes(
    x: str | bytes, encoding: str | None = None, errors: str | None = None
) -> bytes:
    if isinstance(x, bytes):
        return x
    elif not isinstance(x, str):
        raise TypeError(f"not expecting type {type(x).__name__}")
    if encoding or errors:
        return x.encode(encoding or "utf-8", errors=errors or "strict")
    return x.encode()


def to_str(
    x: str | bytes, encoding: str | None = None, errors: str | None = None
) -> str:
    if isinstance(x, str):
        return x
    elif not isinstance(x, bytes):
        raise TypeError(f"not expecting type {type(x).__name__}")
    if encoding or errors:
        return x.decode(encoding or "utf-8", errors=errors or "strict")
    return x.decode()


def reraise(
    tp: type[BaseException] | None,
    value: BaseException,
    tb: TracebackType | None = None,
) -> typing.NoReturn:
    try:
        if value.__traceback__ is not tb:
            raise value.with_traceback(tb)
        raise value
    finally:
        value = None  # type: ignore[assignment]
        tb = None


def is_fp_closed(obj: typing.Any) -> bool:
    """
    Checks whether a given file-like object is closed.

    :param obj:
        The file-like object to check.
    """

    try:
        # Check `isclosed()` first, in case the object implements it.
        # Otherwise, check if the file-like object is iterable and has a `closed`
        # attribute.
        return obj.isclosed()
    except AttributeError:
        pass

    try:
        return obj.closed
    except AttributeError:
        pass

    try:
        return obj.fp is None
    except AttributeError:
        pass

    try:
        return obj.fp.closed
    except (AttributeError, ValueError):
        pass

    # This last check is specific to `io` module file-like objects.
    try:
        # Check if the file-like object is a `BytesIO` or `StringIO` instance
        # and if its cursor is at the end of the file.
        if isinstance(obj, (io.BytesIO, io.StringIO)):
            return obj.tell() == len(obj.getvalue())
    except (AttributeError, ValueError):
        pass

    # We don't know how to check if this file-like object is closed,
    # so we assume it's open.
    return False
