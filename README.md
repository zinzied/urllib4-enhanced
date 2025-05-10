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

### � Advanced Features:
- Enhanced HTTP/2 Support
- WebSocket capabilities
- Improved security features
- HTTP/3 (QUIC) groundwork

## Usage Example

You can use urllib4 for your HTTP requests with a simple, intuitive API:

```python3
# This is how the API is intended to work when complete
>>> import urllib4
>>> resp = urllib4.request("GET", "http://httpbin.org/robots.txt")
>>> resp.status
200
>>> resp.data
b"User-agent: *\nDisallow: /deny\n"
```

## Installation

You can install urllib4-enhanced with pip:

```bash
$ pip install urllib4-enhanced
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

### HTTP/2 Support (Planned)

```python
# This is a planned API - not yet implemented
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

### WebSocket Support (Planned)

```python
# This is a planned API - not yet implemented
from urllib4.websocket import connect

# Connect to a WebSocket server
ws = connect("wss://echo.websocket.org")

# Send a message
ws.send("Hello, WebSocket!")

# Receive a message
message = ws.receive()
print(f"Received: {message.text}")

# Close the connection
ws.close()
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

As this is experimental software, it should not be used in security-sensitive applications until it reaches a stable release.

## Acknowledgements

This project builds on concepts from the urllib3 project and other Python HTTP libraries. We extend our gratitude to the authors and maintainers of these projects for their foundational work.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
