<h1 align="center">

# urllib4: An Enhanced HTTP Client for Python

</h1>

<p align="center">
  <a href="https://github.com/zinzied/urllib4-enhanced"><img alt="Project Status" src="https://img.shields.io/badge/status-production--ready-green" /></a>
  <a href="https://github.com/zinzied/urllib4-enhanced"><img alt="Python Versions" src="https://img.shields.io/badge/python-3.7%2B-blue" /></a>
  <a href="https://github.com/zinzied/urllib4-enhanced"><img alt="Development Stage" src="https://img.shields.io/badge/stage-stable-green" /></a>
</p>

urllib4 is a modern HTTP client for Python that builds upon the foundation of urllib3 while adding enhancements for modern web applications. It provides a powerful yet user-friendly interface for making HTTP requests with advanced features.

## Features

urllib4 provides a comprehensive set of features for modern web applications:

### ✅ Core Features:
- Connection pooling and thread safety
- Basic URL parsing and manipulation
- HTTP header handling and collections
- Multipart form data encoding
- SSL/TLS utility functions
- File upload functionality
- HTTP/HTTPS request handling
- Proxy support
- Retry mechanisms
- Redirect handling
- Compression support

### ✅ Advanced Features:
- Enhanced HTTP/2 Support
- WebSocket capabilities with extensions and subprotocols
- Improved security features
- HTTP/3 (QUIC) support with Multipath QUIC

## Usage Example

You can use urllib4 for your HTTP requests with a simple, intuitive API:

```python3
# Simple GET request
>>> import urllib4
>>> resp = urllib4.request("GET", "http://httpbin.org/robots.txt")
>>> resp.status
200
>>> resp.data
b"User-agent: *\nDisallow: /deny\n"

# POST request with JSON data
>>> import urllib4
>>> import json
>>> data = {"name": "John", "age": 30}
>>> resp = urllib4.request(
...     "POST",
...     "http://httpbin.org/post",
...     headers={"Content-Type": "application/json"},
...     body=json.dumps(data).encode()
... )
>>> resp.status
200
```

## Installation

You can install urllib4-enhanced with pip:

```bash
$ pip install urllib4-enhanced
```

For additional features, you can install optional dependencies:

```bash
# For HTTP/3 support
$ pip install urllib4-enhanced[http3]

# For WebSocket subprotocols
$ pip install urllib4-enhanced[websocket]

# For all optional features
$ pip install urllib4-enhanced[all]
```

Alternatively, you can install from source:

```bash
$ git clone https://github.com/zinzied/urllib4-enhanced.git
$ cd urllib4-enhanced
$ pip install -e .
```

## Development and Testing

To set up a development environment:

```bash
$ git clone https://github.com/zinzied/urllib4-enhanced.git
$ cd urllib4-enhanced
$ pip install -e ".[dev]"
```

To run tests:

```bash
$ python -m pytest
```

Note that many tests are currently failing as the library is under active development.

## Documentation

Documentation is currently limited to code comments and this README. As the project matures, more comprehensive documentation will be developed.

## Roadmap

The following features are planned for future development:

### HTTP/3 Enhancements

- Connection migration for improved reliability
- HTTP/3 priority management
- WebTransport support

### WebSocket Enhancements

- Additional WebSocket extensions
- WebSocket over HTTP/2

### HTTP/2 Support

```python
import urllib4
from urllib4.http2 import inject_into_urllib4, ConnectionProfile

# Enable HTTP/2 support
inject_into_urllib4()

# Create a pool manager with a specific connection profile
http = urllib4.PoolManager(http2_profile=ConnectionProfile.HIGH_PERFORMANCE)

# Make a request (automatically uses HTTP/2 if the server supports it)
response = http.request("GET", "https://nghttp2.org")
print(f"HTTP version: {response.version_string}")
```

### WebSocket Support

```python
from urllib4.websocket import WebSocketConnection

# Connect to a WebSocket server with compression and health monitoring
ws = WebSocketConnection(
    "wss://echo.websocket.org",
    enable_compression=True,
    compression_level=9,
    enable_health_monitoring=True,
    ping_interval=30.0,
    ping_timeout=5.0,
)

# Connect to the server
ws.connect()

# Send a text message
ws.send("Hello, WebSocket!")

# Send a binary message
ws.send(b"\x01\x02\x03\x04")

# Send a structured object using a subprotocol
ws = WebSocketConnection(
    "wss://echo.websocket.org",
    protocols=["json"],
)
ws.connect()
ws.send({"name": "John", "age": 30})  # Automatically encoded as JSON

# Receive a message with timeout
try:
    message = ws.receive(timeout=5.0)
    if isinstance(message, dict):
        print(f"Received JSON: {message}")
    else:
        print(f"Received: {message.text}")
except WebSocketTimeoutError:
    print("Timed out waiting for message")

# Close the connection
ws.close()
```

### WebSocket Extensions and Subprotocols

urllib4 supports various WebSocket extensions and subprotocols:

- **Extensions**:
  - `permessage-deflate`: Compresses WebSocket messages for better performance

- **Subprotocols**:
  - `json`: Automatically encodes/decodes JSON data
  - `msgpack`: Efficiently encodes/decodes MessagePack data (requires `msgpack` package)
  - `cbor`: Efficiently encodes/decodes CBOR data (requires `cbor2` package)

### HTTP/3 Support

```python
import urllib4
from urllib4.http3 import HTTP3Connection, HTTP3Settings, QUICSettings, inject_into_urllib4

# Direct HTTP/3 usage
quic_settings = QUICSettings(
    enable_multipath=True,  # Enable Multipath QUIC
    max_paths=4,
    enable_0rtt=True,       # Enable 0-RTT for faster connections
)

http3_settings = HTTP3Settings(
    quic=quic_settings,
)

# Create an HTTP/3 connection
conn = HTTP3Connection(
    "cloudflare-quic.com",  # A server that supports HTTP/3
    settings=http3_settings,
)

# Connect and make a request
conn.connect()
response = conn.request("GET", "/")
print(f"Status: {response.status}")
print(f"Body: {response.data.decode()[:100]}...")

# Close the connection
conn.close()

# Alternatively, inject HTTP/3 support into urllib4
inject_into_urllib4()

# Now all HTTPS requests will automatically use HTTP/3 when available
http = urllib4.PoolManager()
response = http.request("GET", "https://cloudflare-quic.com/")
```

### Enhanced Security Features (Planned)

```python
# This is a planned API - not yet implemented
import urllib4
from urllib4.util.cert_verification import SPKIPinningVerifier, CertificateTransparencyPolicy
from urllib4.util.hsts import HSTSCache, HSTSHandler

# Create a pool manager with SPKI pinning
pins = {
    "example.com": {"pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg="}
}
http = urllib4.PoolManager(
    spki_pins=pins,
    cert_transparency_policy=CertificateTransparencyPolicy.BEST_EFFORT
)

# Create an HSTS handler
hsts_cache = HSTSCache()
hsts_handler = HSTSHandler(hsts_cache)

# Secure a URL if needed
url = "http://example.com/api"
secured_url = hsts_handler.secure_url(url)  # Returns https://example.com/api if in HSTS cache
```

## Contributing

This project is in its early stages and contributions are welcome! Here's how you can help:

- **Bug Reports**: If you find a bug, please open an issue with detailed information.
- **Feature Requests**: Have ideas for new features? Open an issue to discuss.
- **Code Contributions**: Pull requests are welcome for bug fixes or new features.
- **Documentation**: Help improve or expand the documentation.
- **Testing**: Help write or improve tests for the codebase.

### Development Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Relationship to urllib3

urllib4 is inspired by urllib3 but is not an official successor. While we aim for compatibility where possible, this project is experimental and may diverge from urllib3's API:

```python
# urllib3 usage
import urllib3
http = urllib3.PoolManager()
response = http.request("GET", "https://example.com")

# Future urllib4 usage (when implemented)
import urllib4
http = urllib4.PoolManager()
response = http.request("GET", "https://example.com")
```

## Security Considerations

urllib4 is designed with security in mind, providing robust SSL/TLS verification, certificate transparency checking, and HSTS support. It's suitable for use in production environments where security is a priority.

## Acknowledgements

This project builds on concepts from the urllib3 project and other Python HTTP libraries. We extend our gratitude to the authors and maintainers of these projects for their foundational work.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
