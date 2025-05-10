"""
HTTP/2 Server Push implementation for urllib4.

This module provides support for handling HTTP/2 server push promises,
allowing applications to benefit from server-initiated resource pushing.
"""

from __future__ import annotations

import logging
import threading
import typing
import weakref
from collections import defaultdict, deque

from .._collections import HTTPHeaderDict
from ..response import BaseHTTPResponse, HTTPResponse

if typing.TYPE_CHECKING:
    import h2.events  # type: ignore[import-untyped]

log = logging.getLogger(__name__)


class PushPromise:
    """
    Represents an HTTP/2 push promise from the server.
    
    This class stores information about a promised resource that the server
    intends to push to the client.
    """
    
    __slots__ = ["stream_id", "promised_stream_id", "request_headers", "received_data", 
                 "complete", "response", "_lock"]
    
    def __init__(
        self, 
        stream_id: int, 
        promised_stream_id: int, 
        request_headers: typing.List[typing.Tuple[bytes, bytes]]
    ) -> None:
        """
        Initialize a new PushPromise.
        
        :param stream_id: The stream ID that the push promise was sent on
        :param promised_stream_id: The stream ID that the promised resource will be sent on
        :param request_headers: The request headers for the promised resource
        """
        self.stream_id = stream_id
        self.promised_stream_id = promised_stream_id
        self.request_headers = request_headers
        self.received_data = bytearray()
        self.complete = False
        self.response: HTTPResponse | None = None
        self._lock = threading.Lock()
    
    @property
    def path(self) -> str:
        """
        Get the path of the promised resource.
        
        :return: The path from the :path pseudo-header
        """
        for name, value in self.request_headers:
            if name == b":path":
                return value.decode("ascii", errors="ignore")
        return ""
    
    @property
    def method(self) -> str:
        """
        Get the HTTP method of the promised resource.
        
        :return: The method from the :method pseudo-header
        """
        for name, value in self.request_headers:
            if name == b":method":
                return value.decode("ascii", errors="ignore")
        return "GET"  # Default to GET if not specified
    
    def add_data(self, data: bytes) -> None:
        """
        Add received data for this promised stream.
        
        :param data: The data received for the promised resource
        """
        with self._lock:
            self.received_data.extend(data)
    
    def mark_complete(self) -> None:
        """Mark this push promise as complete."""
        with self._lock:
            self.complete = True


class PushController:
    """
    Controls and manages HTTP/2 server push promises.
    
    This class keeps track of push promises received from the server and
    provides an interface for accessing pushed resources.
    """
    
    def __init__(self) -> None:
        """Initialize a new PushController."""
        self._promises: dict[int, PushPromise] = {}
        self._path_to_promise: dict[str, deque[PushPromise]] = defaultdict(deque)
        self._lock = threading.Lock()
    
    def handle_push_promise(
        self, event: "h2.events.PushPromisedReceived"
    ) -> PushPromise:
        """
        Handle a PushPromisedReceived event from the h2 library.
        
        :param event: The push promise event
        :return: The created PushPromise object
        """
        promise = PushPromise(
            event.parent_stream_id,
            event.pushed_stream_id,
            event.headers
        )
        
        with self._lock:
            self._promises[event.pushed_stream_id] = promise
            self._path_to_promise[promise.path].append(promise)
        
        log.debug(
            "Received push promise on stream %d for path %s (promised stream %d)",
            event.parent_stream_id,
            promise.path,
            event.pushed_stream_id
        )
        
        return promise
    
    def handle_data_received(self, stream_id: int, data: bytes) -> None:
        """
        Handle data received for a pushed stream.
        
        :param stream_id: The stream ID that received data
        :param data: The data received
        """
        with self._lock:
            if stream_id in self._promises:
                self._promises[stream_id].add_data(data)
    
    def handle_stream_ended(self, stream_id: int) -> None:
        """
        Handle a stream ended event for a pushed stream.
        
        :param stream_id: The stream ID that ended
        """
        with self._lock:
            if stream_id in self._promises:
                self._promises[stream_id].mark_complete()
    
    def get_response_for_url(self, url: str) -> HTTPResponse | None:
        """
        Get a pushed response for the given URL if available.
        
        :param url: The URL to look for in pushed resources
        :return: An HTTPResponse if a pushed resource matches, None otherwise
        """
        path = url.split("?")[0]  # Remove query parameters
        
        with self._lock:
            if path in self._path_to_promise and self._path_to_promise[path]:
                promise = self._path_to_promise[path].popleft()
                if promise.complete:
                    # Create an HTTPResponse from the pushed data
                    headers = HTTPHeaderDict()
                    for name, value in promise.request_headers:
                        if not name.startswith(b":"):
                            headers.add(name.decode("ascii"), value.decode("ascii"))
                    
                    response = HTTPResponse(
                        body=bytes(promise.received_data),
                        headers=headers,
                        status=200,  # Assume 200 OK for now
                        version=20,
                        version_string="HTTP/2",
                        reason=None,
                        decode_content=True,
                        request_url=url,
                        preload_content=True,
                    )
                    return response
        
        return None
