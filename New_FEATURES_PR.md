# Enhanced Features for urllib4

This pull request adds four major enhancements to the urllib4 library:

1. Enhanced HTTP/2 Support
2. WebSocket Support
3. Improved Security Features
4. HTTP/3 (QUIC) Support (groundwork)

## 1. Enhanced HTTP/2 Support

The HTTP/2 implementation has been significantly improved with the following features:

### Server Push Support

HTTP/2 server push allows servers to proactively send resources to clients before they are requested. This can improve performance by eliminating the need for additional requests.

```python
import urllib4
from urllib4.http2 import ConnectionProfile

# Enable HTTP/2 support
urllib4.http2.inject_into_urllib4()

# Create a pool manager with server push enabled
http = urllib4.PoolManager(
    http2_enable_push=True
)

# Make a request
resp = http.request("GET", "https://example.com")

# Restore HTTP/1.1 as default
urllib4.http2.extract_from_urllib4()
```

### Adaptive Flow Control

Flow control in HTTP/2 manages the rate at which data is sent between client and server. Our implementation includes adaptive flow control that automatically adjusts window sizes based on network conditions.

```python
from urllib4.http2 import FlowControlStrategy

# Create a pool manager with adaptive flow control
http = urllib4.PoolManager(
    http2_flow_control_strategy=FlowControlStrategy.ADAPTIVE
)
```

### Connection Profiles

Different network conditions and usage patterns require different HTTP/2 settings. We've added predefined connection profiles to optimize performance.

```python
from urllib4.http2 import ConnectionProfile

# High performance profile for fast networks
http = urllib4.PoolManager(
    http2_connection_profile=ConnectionProfile.HIGH_PERFORMANCE
)

# Mobile profile for mobile networks
http = urllib4.PoolManager(
    http2_connection_profile=ConnectionProfile.MOBILE
)
```

## 2. WebSocket Support

WebSocket support allows for real-time bidirectional communication over a persistent connection.

### Basic Usage

```python
import urllib4

# Connect to a WebSocket server
ws = urllib4.websocket_connect("wss://echo.websocket.org")

# Send a message
ws.send("Hello, WebSocket!")

# Receive a message
response = ws.receive(timeout=5)
print(response.text)

# Close the connection
ws.close()
```

### Advanced Usage

```python
from urllib4.websocket import WebSocketConnection, WebSocketCloseCode

# Connect with custom headers and protocols
ws = WebSocketConnection(
    "wss://example.com/ws",
    headers={"Authorization": "Bearer token"},
    protocols=["chat", "superchat"],
)
ws.connect()

# Send binary data
ws.send(b"\x00\x01\x02\x03")

# Receive with timeout
try:
    response = ws.receive(timeout=5)
    if response.is_text:
        print(f"Text message: {response.text}")
    elif response.is_binary:
        print(f"Binary message: {response.data}")
except WebSocketTimeoutError:
    print("Timed out waiting for message")

# Close with custom code and reason
ws.close(WebSocketCloseCode.GOING_AWAY, "Client shutting down")
```

## 3. Improved Security Features

### Certificate Transparency (CT) Verification

Certificate Transparency helps detect misissued certificates by requiring them to be logged in public CT logs.

```python
import urllib4
from urllib4.util.cert_verification import CertificateTransparencyPolicy

# Create a pool manager with CT verification
http = urllib4.PoolManager(
    ct_policy=CertificateTransparencyPolicy.STRICT
)
```

### SPKI Pinning

SPKI (Subject Public Key Info) pinning provides a more flexible alternative to certificate pinning by pinning the public key rather than the entire certificate.

```python
from urllib4.util.cert_verification import SPKIPinningVerifier

# Define pins for hosts
pins = {
    "example.com": {
        "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
        "pin-sha256:Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=",
    },
    "*.wildcard.com": {
        "pin-sha256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=",
    },
}

# Create a pin verifier
pin_verifier = SPKIPinningVerifier(pins)

# Verify a certificate
if not pin_verifier.verify_cert_for_host(cert, "example.com"):
    raise Exception("Certificate failed pin verification")
```

### HSTS (HTTP Strict Transport Security)

HSTS helps protect websites against protocol downgrade attacks and cookie hijacking by enforcing secure connections.

```python
from urllib4.util.hsts import HSTSCache, HSTSHandler

# Create an HSTS handler
hsts_cache = HSTSCache()
hsts_handler = HSTSHandler(hsts_cache)

# Secure a URL according to HSTS policy
url = "http://example.com/api"
secured_url = hsts_handler.secure_url(url)  # https://example.com/api

# Process HSTS headers from a response
hsts_handler.process_response_headers(
    "example.com", response.headers
)
```

## 4. HTTP/3 (QUIC) Support

We've laid the groundwork for HTTP/3 support, which will be implemented in a future release. HTTP/3 uses QUIC as its transport protocol, offering improved performance especially on unreliable networks.

## Implementation Details

### Files Added

- `src/urllib4/http2/flow_control.py`: HTTP/2 flow control implementation
- `src/urllib4/http2/push.py`: HTTP/2 server push implementation
- `src/urllib4/http2/settings.py`: HTTP/2 settings management
- `src/urllib4/websocket/__init__.py`: WebSocket package initialization
- `src/urllib4/websocket/connection.py`: WebSocket connection implementation
- `src/urllib4/websocket/protocol.py`: WebSocket protocol implementation
- `src/urllib4/websocket/exceptions.py`: WebSocket exceptions
- `src/urllib4/util/cert_verification.py`: Certificate verification enhancements
- `src/urllib4/util/hsts.py`: HSTS implementation

### Files Modified

- `src/urllib4/http2/__init__.py`: Added exports for new HTTP/2 features
- `src/urllib4/http2/connection.py`: Enhanced with new HTTP/2 features
- `src/urllib4/__init__.py`: Added exports for new features

## Dependencies

- For HTTP/2 support: `h2>=4.0.0`
- For WebSocket support: No additional dependencies
- For security features: No additional dependencies
- For HTTP/3 support (future): Will require a QUIC implementation

## Testing

A verification script is included to demonstrate the functionality of these features. Run the script with:

```bash
python verify_features.py
```

This script verifies that all the enhanced features can be imported and used correctly.

## Compatibility

These enhancements are compatible with urllib4 v2.0.0 and later.
