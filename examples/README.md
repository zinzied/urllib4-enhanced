# urllib4-enhanced Examples

This directory contains examples demonstrating the features of the urllib4-enhanced library.

## HTTP/2 Examples

### HTTP/2 Server Push

The `http2_server_push.py` example demonstrates how to use HTTP/2 server push with urllib4-enhanced. It shows how to:

- Enable HTTP/2 support
- Configure HTTP/2 settings
- Make a request to a server that supports HTTP/2
- Access pushed resources

To run the example:

```bash
python examples/http2_server_push.py
```

## Security Features

### Certificate Verification

The `security_features.py` example demonstrates the enhanced security features in urllib4-enhanced, including:

- SPKI pinning
- Certificate Transparency verification
- Generating SPKI pins for certificates

To run the example:

```bash
python examples/security_features.py
```

## WebSocket Examples

### Enhanced WebSocket Features

The `websocket_enhanced.py` example demonstrates the enhanced WebSocket features in urllib4-enhanced, including:

- WebSocket compression with permessage-deflate
- WebSocket subprotocols (JSON)
- Connection health monitoring
- Backpressure handling

To run the example:

```bash
python examples/websocket_enhanced.py
```

## HTTP/3 Examples

### HTTP/3 Client

The `http3_client.py` example demonstrates HTTP/3 support in urllib4-enhanced, including:

- Direct HTTP/3 connections
- Injected HTTP/3 support through the urllib4 API
- 0-RTT connection establishment

To run the example:

```bash
python examples/http3_client.py
```

### Multipath QUIC

The `http3_multipath.py` example demonstrates Multipath QUIC support in urllib4-enhanced, which allows using multiple network paths simultaneously for improved performance and reliability.

To run the example:

```bash
python examples/http3_multipath.py
```

## Requirements

These examples require the following dependencies:

- urllib4-enhanced
- cryptography (for security features)
- h2 (for HTTP/2 support)
- aioquic (for HTTP/3 support)
- netifaces (for Multipath QUIC support)
- msgpack (for MessagePack WebSocket subprotocol)
- cbor2 (for CBOR WebSocket subprotocol)

You can install these dependencies with:

```bash
pip install urllib4-enhanced cryptography h2 aioquic netifaces msgpack cbor2
```

## Notes

- Some examples may require an internet connection to work properly.
- The HTTP/2 server push example requires a server that supports HTTP/2 server push.
- The security features example requires a server with a valid SSL certificate.
