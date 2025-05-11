"""
HTTP/2 Server Push Manager for urllib4.

This module provides a manager for HTTP/2 server push resources,
allowing applications to benefit from server-initiated resource pushing.
"""

from __future__ import annotations

import logging
import threading
import typing
import weakref
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Union, cast
from urllib.parse import urljoin, urlparse

from .._collections import HTTPHeaderDict
from ..response import HTTPResponse

if typing.TYPE_CHECKING:
    import h2.events

log = logging.getLogger(__name__)


class PushPromise:
    """
    Represents an HTTP/2 push promise.
    
    This class stores information about a promised resource that
    will be pushed by the server.
    """
    
    def __init__(
        self,
        stream_id: int,
        parent_stream_id: int,
        headers: List[Tuple[bytes, bytes]],
    ) -> None:
        """
        Initialize a new PushPromise.
        
        :param stream_id: The stream ID for the pushed resource
        :param parent_stream_id: The parent stream ID
        :param headers: The request headers for the pushed resource
        """
        self.stream_id = stream_id
        self.parent_stream_id = parent_stream_id
        self.headers = headers
        self.received = False
        self.data = bytearray()
        self.response_headers: Optional[List[Tuple[bytes, bytes]]] = None
        
    @property
    def url(self) -> Optional[str]:
        """
        Get the URL of the pushed resource.
        
        :return: The URL or None if not available
        """
        scheme = authority = path = None
        
        for name, value in self.headers:
            if name == b":scheme":
                scheme = value.decode()
            elif name == b":authority":
                authority = value.decode()
            elif name == b":path":
                path = value.decode()
                
        if scheme and authority and path:
            return f"{scheme}://{authority}{path}"
            
        return None


class PushManager:
    """
    Manages HTTP/2 server push resources.
    
    This class tracks and manages resources pushed by the server,
    making them available to the application.
    """
    
    def __init__(self) -> None:
        """Initialize a new PushManager."""
        self._promises: Dict[int, PushPromise] = {}
        self._cache: Dict[str, HTTPResponse] = {}
        self._parent_streams: Dict[int, Set[int]] = defaultdict(set)
        self._lock = threading.RLock()
        
    def handle_push_promise(
        self, event: "h2.events.PushedStreamReceived"
    ) -> None:
        """
        Handle a push promise event.
        
        :param event: The push promise event
        """
        with self._lock:
            # Create a new push promise
            promise = PushPromise(
                stream_id=event.pushed_stream_id,
                parent_stream_id=event.parent_stream_id,
                headers=event.headers,
            )
            
            # Store the promise
            self._promises[event.pushed_stream_id] = promise
            self._parent_streams[event.parent_stream_id].add(event.pushed_stream_id)
            
            log.debug(
                "Received push promise for stream %d (parent: %d, URL: %s)",
                event.pushed_stream_id,
                event.parent_stream_id,
                promise.url,
            )
            
    def handle_headers(
        self, event: "h2.events.ResponseReceived"
    ) -> None:
        """
        Handle a headers event for a pushed stream.
        
        :param event: The headers event
        """
        with self._lock:
            if event.stream_id in self._promises:
                promise = self._promises[event.stream_id]
                promise.response_headers = event.headers
                
                log.debug(
                    "Received headers for pushed stream %d",
                    event.stream_id,
                )
                
    def handle_data(
        self, event: "h2.events.DataReceived"
    ) -> None:
        """
        Handle a data event for a pushed stream.
        
        :param event: The data event
        """
        with self._lock:
            if event.stream_id in self._promises:
                promise = self._promises[event.stream_id]
                promise.data.extend(event.data)
                
                log.debug(
                    "Received %d bytes for pushed stream %d",
                    len(event.data),
                    event.stream_id,
                )
                
    def handle_stream_ended(
        self, event: "h2.events.StreamEnded"
    ) -> None:
        """
        Handle a stream ended event for a pushed stream.
        
        :param event: The stream ended event
        """
        with self._lock:
            if event.stream_id in self._promises:
                promise = self._promises[event.stream_id]
                promise.received = True
                
                # Create a response object
                if promise.url and promise.response_headers:
                    response = self._create_response(promise)
                    if response:
                        self._cache[promise.url] = response
                        
                        log.debug(
                            "Completed pushed stream %d (URL: %s)",
                            event.stream_id,
                            promise.url,
                        )
                        
    def _create_response(self, promise: PushPromise) -> Optional[HTTPResponse]:
        """
        Create a response object from a push promise.
        
        :param promise: The push promise
        :return: The response object or None if not possible
        """
        if not promise.response_headers:
            return None
            
        # Extract status code
        status = None
        for name, value in promise.response_headers:
            if name == b":status":
                status = int(value.decode())
                break
                
        if status is None:
            return None
            
        # Convert headers to HTTPHeaderDict
        headers = HTTPHeaderDict()
        for name, value in promise.response_headers:
            if not name.startswith(b":"):  # Skip pseudo-headers
                headers[name.decode()] = value.decode()
                
        # Create response
        return HTTPResponse(
            body=bytes(promise.data),
            headers=headers,
            status=status,
            version=2,
            reason="",
            preload_content=True,
            decode_content=True,
            original_response=None,
            pool=None,
            connection=None,
            request_url=promise.url,
        )
        
    def get_pushed_responses(self, parent_stream_id: int) -> List[HTTPResponse]:
        """
        Get all pushed responses for a parent stream.
        
        :param parent_stream_id: The parent stream ID
        :return: List of pushed responses
        """
        with self._lock:
            responses = []
            
            for stream_id in self._parent_streams.get(parent_stream_id, set()):
                promise = self._promises.get(stream_id)
                if promise and promise.received and promise.url:
                    response = self._cache.get(promise.url)
                    if response:
                        responses.append(response)
                        
            return responses
            
    def get_response_for_url(self, url: str) -> Optional[HTTPResponse]:
        """
        Get a pushed response for a URL.
        
        :param url: The URL to look for
        :return: The response or None if not found
        """
        with self._lock:
            return self._cache.get(url)
