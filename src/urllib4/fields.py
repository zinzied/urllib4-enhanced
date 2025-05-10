from __future__ import annotations

import email.utils
import mimetypes
import re
import typing
import urllib.parse
import warnings

_TYPE_FIELD_VALUE = typing.Union[str, bytes]
_TYPE_FIELD_VALUE_TUPLE = typing.Union[
    _TYPE_FIELD_VALUE,
    tuple[str, _TYPE_FIELD_VALUE],
    tuple[str, _TYPE_FIELD_VALUE, str],
]

# These characters are not valid in HTTP headers
_INVALID_HEADER_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def guess_content_type(
    filename: str | None, default: str = "application/octet-stream"
) -> str:
    """
    Guess the "Content-Type" of a file.

    :param filename:
        The filename to guess the "Content-Type" of using :mod:`mimetypes`.
    :param default:
        If no "Content-Type" can be guessed, default to `default`.
    """
    if filename:
        return mimetypes.guess_type(filename)[0] or default
    return default


def format_header_param_rfc2231(name: str, value: _TYPE_FIELD_VALUE) -> str:
    """
    Format and quote a header parameter according to RFC 2231.

    Particularly useful for header parameters which might contain
    non-ASCII values, like file names. This follows RFC 2231, as
    suggested by RFC 2388 Section 4.4.

    :param name:
        The name of the parameter, a string expected to be ASCII only.
    :param value:
        The value of the parameter, provided as a unicode string.
    :returns:
        A string suitable for use as a header parameter.
    """
    warnings.warn(
        "format_header_param_rfc2231 will be removed in urllib4 v2.1.0",
        DeprecationWarning,
        stacklevel=2,
    )

    # Handle bytes
    if isinstance(value, bytes):
        try:
            value = value.decode('ascii')
            result = f'{name}="{value}"'
            return result
        except UnicodeDecodeError:
            # If it's not ASCII, we'll handle it below
            value = value.decode('utf-8', errors='replace')

    # Handle strings
    if not any(ch in value for ch in '"\\\r\n') and not _INVALID_HEADER_CHARS.search(value):
        result = f'{name}="{value}"'
        try:
            result.encode("ascii")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        else:
            return result

    # Handle non-ASCII strings
    value_bytes = value.encode("utf-8")
    quoted_value = urllib.parse.quote_from_bytes(value_bytes)
    return f'{name}*=utf-8\'\'{quoted_value}'


def format_header_param(name: str, value: _TYPE_FIELD_VALUE) -> str:
    """
    Format and quote a header parameter.

    Particularly useful for header parameters which might contain
    non-ASCII values, like file names. This follows RFC 2231, as
    suggested by RFC 2388 Section 4.4.

    :param name:
        The name of the parameter, a string expected to be ASCII only.
    :param value:
        The value of the parameter, provided as a unicode string.
    :returns:
        A string suitable for use as a header parameter.
    """
    return format_header_param_rfc2231(name, value)


def format_header_param_html5(name: str, value: _TYPE_FIELD_VALUE) -> str:
    """
    Format and quote a single multipart header parameter for HTML5 forms.

    This follows the `WHATWG HTML Standard`_ as of 2021/06/10, matching
    the behavior of current browser and curl versions. Values are
    assumed to be UTF-8. The ``\\n``, ``\\r``, and ``"`` characters are
    percent encoded.

    .. _WHATWG HTML Standard:
        https://html.spec.whatwg.org/multipage/
        form-control-infrastructure.html#multipart-form-data

    :param name:
        The name of the parameter, an ASCII-only ``str``.
    :param value:
        The value of the parameter, a ``str`` or UTF-8 encoded
        ``bytes``.
    :returns:
        A string ``name="value"`` with the escaped value.
    """
    warnings.warn(
        "format_header_param_html5 will be removed in urllib4 v2.1.0",
        DeprecationWarning,
        stacklevel=2,
    )

    if isinstance(value, bytes):
        value = value.decode("utf-8")

    # percent encode \n \r "
    value = value.translate({10: "%0A", 13: "%0D", 34: "%22"})
    return f'{name}="{value}"'


def format_multipart_header_param(name: str, value: _TYPE_FIELD_VALUE) -> str:
    """
    Format and quote a single multipart header parameter.

    This follows the `WHATWG HTML Standard`_ as of 2021/06/10, matching
    the behavior of current browser and curl versions. Values are
    assumed to be UTF-8. The ``\\n``, ``\\r``, and ``"`` characters are
    percent encoded.

    .. _WHATWG HTML Standard:
        https://html.spec.whatwg.org/multipage/
        form-control-infrastructure.html#multipart-form-data

    :param name:
        The name of the parameter, an ASCII-only ``str``.
    :param value:
        The value of the parameter, a ``str`` or UTF-8 encoded
        ``bytes``.
    :returns:
        A string ``name="value"`` with the escaped value.
    """
    return format_header_param_html5(name, value)


class RequestField:
    """
    A data container for request body parameters.

    :param name:
        The name of this request field. Must be unicode.
    :param data:
        The data/value body.
    :param filename:
        An optional filename of the request field. Must be unicode.
    :param headers:
        An optional dict-like object of headers to initially use for the field.
    """

    def __init__(
        self,
        name: str,
        data: _TYPE_FIELD_VALUE,
        filename: str | None = None,
        headers: typing.Mapping[str, str] | None = None,
        header_formatter: typing.Callable[[str, _TYPE_FIELD_VALUE], str] | None = None,
    ):
        self._name = name
        self._filename = filename
        self.data = data
        self.headers: dict[str, str | None] = {}
        if headers:
            self.headers = dict(headers)

        self.header_formatter = header_formatter or format_multipart_header_param

    @classmethod
    def from_tuples(
        cls,
        fieldname: str,
        value: _TYPE_FIELD_VALUE_TUPLE,
        header_formatter: typing.Callable[[str, _TYPE_FIELD_VALUE], str] | None = None,
    ) -> RequestField:
        """
        A :class:`~urllib4.fields.RequestField` factory from old-style tuple parameters.

        Supports constructing :class:`~urllib4.fields.RequestField` from
        parameter of key/value strings AND key/filetuple. A filetuple is a
        (filename, data, MIME type) tuple where the MIME type is optional.
        For example::

            'foo': 'bar',
            'fakefile': ('foofile.txt', 'contents of foofile'),
            'realfile': ('barfile.txt', open('realfile').read()),
            'typedfile': ('bazfile.bin', open('bazfile').read(), 'image/jpeg'),
            'nonamefile': 'contents of nonamefile field',

        Field names and filenames must be unicode.
        """
        # Add deprecation warning if using format_header_param_rfc2231
        if header_formatter is format_header_param_rfc2231:
            warnings.warn(
                "format_header_param_rfc2231 will be removed in urllib4 v2.1.0",
                DeprecationWarning,
                stacklevel=2,
            )

        filename: str | None
        content_type: str | None
        data: _TYPE_FIELD_VALUE

        if isinstance(value, tuple):
            if len(value) == 3:
                filename, data, content_type = value
            else:
                filename, data = value
                content_type = guess_content_type(filename)
        else:
            filename = None
            content_type = None
            data = value

        request_param = cls(
            fieldname, data, filename=filename, header_formatter=header_formatter
        )
        request_param.make_multipart(content_type=content_type)

        return request_param

    def _render_part(self, name: str, value: _TYPE_FIELD_VALUE) -> str:
        """
        Override this method to change how each multipart header
        parameter is formatted. By default, this calls
        :func:`format_multipart_header_param`.

        :param name:
            The name of the parameter, an ASCII-only ``str``.
        :param value:
            The value of the parameter, a ``str`` or UTF-8 encoded
            ``bytes``.

        :meta public:
        """
        return self.header_formatter(name, value)

    def _render_parts(
        self,
        header_parts: (
            dict[str, _TYPE_FIELD_VALUE | None]
            | typing.Sequence[tuple[str, _TYPE_FIELD_VALUE | None]]
        ),
    ) -> str:
        """
        Helper function to format and quote a single header.

        Useful for single headers that are composed of multiple items. E.g.,
        'Content-Disposition' fields.

        :param header_parts:
            A sequence of (k, v) tuples or a :class:`dict` of (k, v) to format
            as `k1="v1"; k2="v2"; ...`.
        """
        iterable: typing.Iterable[tuple[str, _TYPE_FIELD_VALUE | None]]

        parts = []
        if isinstance(header_parts, dict):
            iterable = header_parts.items()
        else:
            iterable = header_parts

        for name, value in iterable:
            if value is not None:
                parts.append(self._render_part(name, value))

        return "; ".join(parts)

    def render_headers(self) -> str:
        """
        Renders the headers for this request field.
        """
        lines = []

        sort_keys = ["Content-Disposition", "Content-Type", "Content-Location"]
        for sort_key in sort_keys:
            if self.headers.get(sort_key, False):
                lines.append(f"{sort_key}: {self.headers[sort_key]}")

        for header_name, header_value in self.headers.items():
            if header_name not in sort_keys:
                if header_value:
                    lines.append(f"{header_name}: {header_value}")

        lines.append("\r\n")
        return "\r\n".join(lines)

    def make_multipart(
        self,
        content_disposition: str | None = None,
        content_type: str | None = None,
        content_location: str | None = None,
    ) -> None:
        """
        Makes this request field into a multipart request field.

        This method overrides "Content-Disposition", "Content-Type" and
        "Content-Location" headers to the request parameter.

        :param content_disposition:
            The 'Content-Disposition' of the request body. Defaults to 'form-data'
        :param content_type:
            The 'Content-Type' of the request body.
        :param content_location:
            The 'Content-Location' of the request body.

        """
        content_disposition = (content_disposition or "form-data") + "; ".join(
            [
                "",
                self._render_parts(
                    (("name", self._name), ("filename", self._filename))
                ),
            ]
        )

        self.headers["Content-Disposition"] = content_disposition
        self.headers["Content-Type"] = content_type
        self.headers["Content-Location"] = content_location
