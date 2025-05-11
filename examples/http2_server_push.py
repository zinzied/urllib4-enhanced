#!/usr/bin/env python3
"""
Example demonstrating HTTP/2 server push with urllib4-enhanced.

This script shows how to use the HTTP/2 support in urllib4-enhanced,
including handling server push resources.
"""

import urllib4
from urllib4.http2 import inject_into_urllib4, ConnectionProfile, HTTP2Settings

def main():
    """Run the HTTP/2 server push example."""
    print("HTTP/2 Server Push Example")
    print("=========================")
    
    # Enable HTTP/2 support
    inject_into_urllib4()
    print("HTTP/2 support enabled")
    
    # Configure HTTP/2 settings
    settings = HTTP2Settings(
        max_concurrent_streams=100,
        initial_window_size=65535,
        max_frame_size=16384,
        header_table_size=4096,
        enable_push=True,
    )
    
    # Create a pool manager
    http = urllib4.PoolManager(http2_settings=settings)
    
    # Make a request to a server that supports HTTP/2 server push
    print("\nMaking request to nghttp2.org (supports HTTP/2)...")
    response = http.request(
        "GET",
        "https://nghttp2.org/",
        headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    )
    
    # Print response info
    print(f"Response status: {response.status}")
    print(f"HTTP version: {response.version}")
    print(f"Content length: {len(response.data)} bytes")
    
    # Check for pushed resources
    if hasattr(response, "pushed_responses") and response.pushed_responses:
        print(f"\nReceived {len(response.pushed_responses)} pushed resources:")
        for i, pushed in enumerate(response.pushed_responses, 1):
            print(f"  {i}. {pushed.request_url} ({len(pushed.data)} bytes)")
            
            # Print content type if available
            content_type = pushed.headers.get("content-type", "unknown")
            print(f"     Content-Type: {content_type}")
    else:
        print("\nNo pushed resources received")
        
    # Try to get a specific pushed resource
    css_url = "https://nghttp2.org/stylesheets/screen.css"
    pushed_css = response.get_pushed_response(css_url)
    if pushed_css:
        print(f"\nFound pushed CSS resource: {css_url}")
        print(f"CSS size: {len(pushed_css.data)} bytes")
        print(f"First 100 bytes: {pushed_css.data[:100]}")
    
    # Clean up
    print("\nCleaning up...")
    from urllib4.http2 import extract_from_urllib4
    extract_from_urllib4()
    print("HTTP/2 support disabled")

if __name__ == "__main__":
    main()
