#!/usr/bin/env python3
"""
Example demonstrating security features in urllib4-enhanced.

This script shows how to use the security features in urllib4-enhanced,
including SPKI pinning and Certificate Transparency verification.
"""

import ssl
import urllib4
from urllib4.util.cert_verification import (
    CertificateTransparencyPolicy,
    CertificateTransparencyVerifier,
    SPKIPinningVerifier,
)

def main():
    """Run the security features example."""
    print("Security Features Example")
    print("========================")
    
    # Create an SSL context
    context = ssl.create_default_context()
    
    # Configure SPKI pinning
    pins = {
        "example.com": {
            "pin-sha256:YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
            "pin-sha256:Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=",
        },
        "*.google.com": {
            "pin-sha256:YZPgTZ+woNCCCIW3LH2CxQeLzB/1m42QcCTBSdgayjs=",
            "pin-sha256:Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNQhj8=",
        },
    }
    pin_verifier = SPKIPinningVerifier(pins)
    
    # Configure Certificate Transparency verification
    ct_verifier = CertificateTransparencyVerifier(
        policy=CertificateTransparencyPolicy.BEST_EFFORT
    )
    
    # Create a pool manager with security features
    http = urllib4.PoolManager(
        ssl_context=context,
        cert_reqs=ssl.CERT_REQUIRED,
        ca_certs=ssl.get_default_verify_paths().cafile,
    )
    
    # Make a request to a secure site
    print("\nMaking request to https://example.com...")
    try:
        response = http.request("GET", "https://example.com")
        print(f"Response status: {response.status}")
        
        # Get the certificate
        import socket
        import ssl
        
        hostname = "example.com"
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
                # Convert to cryptography certificate
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                
                # Verify SPKI pinning
                print("\nVerifying SPKI pinning...")
                pin_result = pin_verifier.verify_cert_for_host(cert_obj, hostname)
                print(f"SPKI pinning result: {'PASS' if pin_result else 'FAIL'}")
                
                # Verify Certificate Transparency
                print("\nVerifying Certificate Transparency...")
                ct_result = ct_verifier.verify_cert(cert_obj)
                print(f"CT verification result: {'PASS' if ct_result else 'FAIL'}")
                
                # Print certificate information
                print("\nCertificate information:")
                print(f"  Subject: {cert_obj.subject}")
                print(f"  Issuer: {cert_obj.issuer}")
                print(f"  Valid from: {cert_obj.not_valid_before}")
                print(f"  Valid until: {cert_obj.not_valid_after}")
                
                # Generate a pin for this certificate
                spki_hash = pin_verifier._compute_spki_hash(cert_obj)
                print(f"\nGenerated pin for {hostname}: {spki_hash}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
