"""
Retry utility for urllib4.

This module provides classes for handling retry logic for HTTP requests.
"""

from __future__ import annotations

import datetime
import logging
import random
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from itertools import takewhile
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Type, Union, cast

from ..exceptions import (
    ConnectTimeoutError,
    InvalidHeader,
    MaxRetryError,
    ReadTimeoutError,
    ResponseError,
)
from ..response import HTTPResponse

log = logging.getLogger(__name__)


@dataclass
class RequestHistory:
    """Object to store information about previous requests."""

    method: str
    url: str
    error: Exception | None
    status: int | None
    redirect_location: str | None


class Retry:
    """Retry configuration.

    This class allows you to configure retry behavior for HTTP requests.

    :param total:
        Total number of retries to allow. Takes precedence over other counts.
        Set to ``None`` to remove this constraint and fall back on other counts.
        Set to ``0`` to fail on the first error.
        Set to ``False`` to disable and imply ``raise_on_redirect=False``.

    :param connect:
        How many connection-related errors to retry on.
        These are errors raised before the request is sent to the remote server,
        which we assume has not triggered the server to process the request.
        Set to ``0`` to fail on the first connection error.
        Set to ``False`` to disable and imply ``raise_on_redirect=False``.
        Set to ``None`` to use the value of ``total``.

    :param read:
        How many times to retry on read errors.
        These errors are raised after the request was sent to the server, so the
        request may have side-effects.
        Set to ``0`` to fail on the first read error.
        Set to ``False`` to disable and imply ``raise_on_redirect=False``.
        Set to ``None`` to use the value of ``total``.

    :param redirect:
        How many redirects to allow. A redirect is a HTTP response with a status
        code 301, 302, 303, 307 or 308.
        Set to ``0`` to fail on the first redirect.
        Set to ``False`` to disable and imply ``raise_on_redirect=False``.
        Set to ``None`` to use the value of ``total``.

    :param status:
        How many times to retry on bad status codes.
        Set to ``0`` to fail on the first status code.
        Set to ``False`` to disable and imply ``raise_on_status=False``.
        Set to ``None`` to use the value of ``total``.

    :param other:
        How many times to retry on other errors.
        Other errors are errors that are not connect, read, redirect or status errors.
        Set to ``0`` to fail on the first other error.
        Set to ``False`` to disable.
        Set to ``None`` to use the value of ``total``.

    :param allowed_methods:
        Set of HTTP method verbs that we should retry on.
        By default, we only retry on methods which are considered to be
        idempotent (multiple requests with the same parameters end with the
        same state). See :attr:`Retry.DEFAULT_ALLOWED_METHODS`.
        Set to a ``None`` value to retry on any verb.

    :param status_forcelist:
        A set of integer HTTP status codes that we should force a retry on.
        A retry is initiated if the request method is in ``allowed_methods``
        and the response status code is in ``status_forcelist``.
        By default, this is disabled with ``None``.

    :param backoff_factor:
        A backoff factor to apply between attempts after the second try
        (most errors are resolved immediately by a second try without a
        delay). urllib4 will sleep for::

            {backoff factor} * (2 ** ({number of total retries} - 1))

        seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
        for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
        than :attr:`Retry.DEFAULT_BACKOFF_MAX`.

        By default, backoff is disabled (set to 0).

    :param backoff_max:
        The maximum amount of time to sleep between retries.

    :param backoff_jitter:
        The maximum amount of jitter to add to the backoff factor.
        Jitter is added to the backoff factor as a random value between
        0 and backoff_jitter.

    :param raise_on_redirect:
        Whether, if the number of redirects is exhausted, to raise a
        :class:`~urllib4.exceptions.MaxRetryError`, or to return a response with a
        response code in the 3xx range.

    :param raise_on_status:
        Similar to ``raise_on_redirect``.
        Whether, if the status code is in ``status_forcelist``, to raise a
        :class:`~urllib4.exceptions.MaxRetryError`, or to return the response.

    :param respect_retry_after_header:
        Whether to respect Retry-After header on status codes defined as
        :attr:`Retry.RETRY_AFTER_STATUS_CODES` or not.

    :param remove_headers_on_redirect:
        Sequence of headers to remove from the request when a response
        indicating a redirect is returned before firing off the redirected
        request.
    """

    #: Default methods to be considered idempotent for retriable methods
    DEFAULT_ALLOWED_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"})

    #: Default status codes to be considered for retry
    RETRY_AFTER_STATUS_CODES = frozenset({413, 429, 503})

    #: Default maximum backoff time
    DEFAULT_BACKOFF_MAX = 120

    def __init__(
        self,
        total: int | None = 10,
        connect: int | None = None,
        read: int | None = None,
        redirect: int | None = None,
        status: int | None = None,
        other: int | None = None,
        allowed_methods: Iterable[str] | None = DEFAULT_ALLOWED_METHODS,
        status_forcelist: Iterable[int] | None = None,
        backoff_factor: float = 0,
        backoff_max: float = DEFAULT_BACKOFF_MAX,
        backoff_jitter: float = 0,
        raise_on_redirect: bool = True,
        raise_on_status: bool = True,
        respect_retry_after_header: bool = True,
        remove_headers_on_redirect: Iterable[str] | None = None,
    ) -> None:
        self.total = total
        self.connect = connect
        self.read = read
        self.redirect = redirect
        self.status = status
        self.other = other
        self.backoff_factor = backoff_factor
        self.backoff_max = backoff_max
        self.backoff_jitter = backoff_jitter
        self.raise_on_redirect = raise_on_redirect
        self.raise_on_status = raise_on_status
        self.respect_retry_after_header = respect_retry_after_header

        # Convert allowed_methods to a frozenset for immutability and efficiency
        if allowed_methods is None:
            self.allowed_methods = None
        else:
            self.allowed_methods = frozenset(method.upper() for method in allowed_methods)

        # Convert status_forcelist to a frozenset for immutability and efficiency
        if status_forcelist is None:
            self.status_forcelist = None
        else:
            self.status_forcelist = frozenset(int(status) for status in status_forcelist)

        # Convert remove_headers_on_redirect to a set for efficiency
        if remove_headers_on_redirect is None:
            self.remove_headers_on_redirect = {"authorization", "proxy-authorization", "cookie"}
        else:
            self.remove_headers_on_redirect = {
                header.lower() for header in remove_headers_on_redirect
            }

        # Initialize history
        self.history = tuple()

        # Track the number of redirects that have occurred in this set of retries
        self.redirect_count = 0

    def new(self, **kw: Any) -> Retry:
        """
        Create a new Retry object with the same settings.

        :param kw: Same arguments as for Retry constructor.
        :return: A new Retry object with the same settings and updated with the new parameters.
        """
        params = {
            "total": self.total,
            "connect": self.connect,
            "read": self.read,
            "redirect": self.redirect,
            "status": self.status,
            "other": self.other,
            "allowed_methods": self.allowed_methods,
            "status_forcelist": self.status_forcelist,
            "backoff_factor": self.backoff_factor,
            "backoff_max": self.backoff_max,
            "backoff_jitter": self.backoff_jitter,
            "raise_on_redirect": self.raise_on_redirect,
            "raise_on_status": self.raise_on_status,
            "respect_retry_after_header": self.respect_retry_after_header,
            "remove_headers_on_redirect": self.remove_headers_on_redirect,
        }
        params.update(kw)
        return type(self)(**params)

    def get_backoff_time(self) -> float:
        """
        Get the backoff time between failed requests.

        :return: The backoff time in seconds.
        """
        # We want to consider only the last consecutive errors sequence (Ignore redirects).
        consecutive_errors_len = len(
            list(
                takewhile(lambda x: x.redirect_location is None, reversed(self.history))
            )
        )
        if consecutive_errors_len <= 1:
            return 0

        backoff_value = self.backoff_factor * (2 ** (consecutive_errors_len - 1))
        if self.backoff_jitter:
            backoff_value += random.uniform(0, self.backoff_jitter)

        return min(self.backoff_max, backoff_value)

    def parse_retry_after(self, retry_after: str) -> float:
        """
        Parse the Retry-After header.

        :param retry_after: The Retry-After header value.
        :return: The number of seconds to wait.
        """
        try:
            seconds = int(retry_after)
            if seconds < 0:
                raise InvalidHeader("Retry-After header must be a positive integer")
            return float(seconds)
        except ValueError:
            # Not an integer, try HTTP date
            try:
                retry_date = parsedate_to_datetime(retry_after)
                if retry_date is None:
                    raise InvalidHeader("Invalid Retry-After header format")

                # Get the current time in UTC
                now = datetime.datetime.now(datetime.timezone.utc)

                # Calculate the delay
                delay = max(0, (retry_date - now).total_seconds())
                return delay
            except (TypeError, ValueError):
                raise InvalidHeader("Invalid Retry-After header format")

    def sleep(self, response: HTTPResponse | None = None) -> None:
        """
        Sleep between retry attempts.

        This method will respect a server's Retry-After response header
        and sleep the duration of the time requested. If that is not present, it
        will use an exponential backoff. By default, the backoff factor is 0 and
        this method will return immediately.

        :param response: The response from the server, if any.
        """
        retry_after = None

        if response is not None and response.status in self.RETRY_AFTER_STATUS_CODES and self.respect_retry_after_header:
            retry_after_header = response.headers.get("Retry-After")
            if retry_after_header:
                try:
                    retry_after = self.parse_retry_after(retry_after_header)
                except InvalidHeader:
                    # Invalid Retry-After header, ignore it
                    pass

        if retry_after is None:
            retry_after = self.get_backoff_time()

        if retry_after > 0:
            time.sleep(retry_after)

    def _is_connection_error(self, error: Exception) -> bool:
        """
        Check if the error is a connection error.

        :param error: The error to check.
        :return: True if the error is a connection error, False otherwise.
        """
        return isinstance(error, ConnectTimeoutError)

    def _is_read_error(self, error: Exception) -> bool:
        """
        Check if the error is a read error.

        :param error: The error to check.
        :return: True if the error is a read error, False otherwise.
        """
        return isinstance(error, ReadTimeoutError)

    def _is_method_retryable(self, method: str) -> bool:
        """
        Check if the HTTP method is retryable.

        :param method: The HTTP method.
        :return: True if the method is retryable, False otherwise.
        """
        if self.allowed_methods is None:
            return True

        return method.upper() in self.allowed_methods

    def is_retry(self, method: str, status_code: int | None = None, has_retry_after: bool = False) -> bool:
        """
        Check if a retry should be performed based on the method and status code.

        :param method: The HTTP method.
        :param status_code: The HTTP status code.
        :param has_retry_after: Whether the response has a Retry-After header.
        :return: True if a retry should be performed, False otherwise.
        """
        if self.total <= 0:
            return False

        # Check if the method is retryable
        if not self._is_method_retryable(method):
            return False

        # Check if the status code is in the status forcelist
        if status_code is not None and self.status_forcelist:
            return status_code in self.status_forcelist

        return False

    def is_exhausted(self) -> bool:
        """
        Check if the retry configuration is exhausted.

        :return: True if the retry configuration is exhausted, False otherwise.
        """
        retry_counts = [
            x for x in [self.total, self.connect, self.read, self.redirect, self.status, self.other]
            if x is not None
        ]

        if not retry_counts:
            return False

        return min(retry_counts) < 0

    def increment(
        self,
        method: str | None = None,
        url: str | None = None,
        response: HTTPResponse | None = None,
        error: Exception | None = None,
        _pool: Any = None,
        _stacktrace: Any = None,
    ) -> Retry:
        """
        Return a new Retry object with incremented retry counters.

        :param method: The HTTP method.
        :param url: The URL that was requested.
        :param response: The response from the server, if any.
        :param error: The error that occurred, if any.
        :param _pool: The connection pool (for internal use).
        :param _stacktrace: The traceback (for internal use).
        :return: A new Retry object with incremented retry counters.
        :raises MaxRetryError: If the retry configuration is exhausted.
        """
        if self.total is False or self.total <= 0:
            raise MaxRetryError(_pool, url, error or ResponseError("Exceeded retry limit"))

        total = self.total
        if total is not None:
            total -= 1

        # Create a copy of the current retry object
        retry = self.new(
            total=total,
            connect=self.connect,
            read=self.read,
            redirect=self.redirect,
            status=self.status,
            other=self.other,
        )

        # Check if this is a redirect
        if response and response.status in (301, 302, 303, 307, 308):
            # Update the redirect count
            retry.redirect_count += 1
            redirect = retry.redirect
            if redirect is not None:
                redirect -= 1
                retry.redirect = redirect
                if redirect <= 0 and retry.raise_on_redirect:
                    raise MaxRetryError(_pool, url, error or ResponseError("Exceeded redirect limit"))

            # Add the request to the history
            history = self.history + (RequestHistory(method, url, error, response.status, response.headers.get("location")),)
            retry.history = history

            return retry

        # Check if this is a retry due to a status code
        if response and response.status:
            status_count = retry.status
            if status_count is not None and retry.status_forcelist and response.status in retry.status_forcelist:
                status_count -= 1
                retry.status = status_count
                if status_count <= 0 and retry.raise_on_status:
                    raise MaxRetryError(_pool, url, error or ResponseError(f"Status {response.status}"))

            # Add the request to the history
            history = self.history + (RequestHistory(method, url, error, response.status, None),)
            retry.history = history

            return retry

        # Check if this is a retry due to an error
        if error:
            # Increment the appropriate error counter
            if self._is_connection_error(error):
                connect = retry.connect
                if connect is not None:
                    connect -= 1
                    retry.connect = connect
                    if connect <= 0:
                        raise MaxRetryError(_pool, url, error)
            elif self._is_read_error(error):
                read = retry.read
                if read is not None:
                    read -= 1
                    retry.read = read
                    if read <= 0:
                        raise MaxRetryError(_pool, url, error)
            else:
                other = retry.other
                if other is not None:
                    other -= 1
                    retry.other = other
                    if other <= 0:
                        raise MaxRetryError(_pool, url, error)

            # Add the request to the history
            history = self.history + (RequestHistory(method, url, error, None, None),)
            retry.history = history

            return retry

        # If we got here, it means we're incrementing without an error or response
        # This is typically used for a simple retry counter
        history = self.history
        if method and url:
            history = history + (RequestHistory(method, url, error, None, None),)

        retry.history = history

        return retry

    def __repr__(self) -> str:
        """
        Return a string representation of the Retry object.

        :return: A string representation of the Retry object.
        """
        return (
            f"Retry(total={self.total}, connect={self.connect}, "
            f"read={self.read}, redirect={self.redirect}, status={self.status})"
        )
