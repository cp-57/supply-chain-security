"""
Utility Module for Rekor Verification

Provides functions forextracting public keys from certificates and verifying artifact signatures.

This module provides functions to:
1. Extract a public key from an X.509 certificate in PEM format
2. Verify the signature of an artifact 

Functions:
    - extract_public_key(cert): Extracts and returns public key
    - verify_artifact_signature(signature, public_key, artifact_filename): Verifies artifact 
    signature using public key and artifact file.

Dependencies:
    - cryptography: Python library for cryptographic operations
    - x509, hashes, ec, serialization: Specific modules and primitives used from the 
    cryptography library

Exceptions:
    - InvalidSignature: Raised when artifact signature verification fails
    - ValueError: Raised when certificate cannot be loaded or is invalid

Usage:
    1. To extract the public key from a certificate:
        public_key = extract_public_key(cert_in_pem_format)

    2. To verify signature of an artifact:
        verify_artifact_signature(signature_bytes, public_key_bytes, "example.md")
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


def extract_public_key(cert):
    """
        Extracts and returns the public key from PEM certificate

        Args:
            cert (bytes): Certificate in PEM format

        Returns:
            bytes: Public key in PEM format.

        Raises:
            ValueError: If the certificate cannot be loaded or is invalid
    """
    certificate = x509.load_pem_x509_certificate(cert, default_backend())
    public_key = certificate.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_public_key

def verify_artifact_signature(signature, public_key, artifact_filename):
    """
    Verifies artifact signature using the public key and artifact file

    Args:
        signature (bytes): Signature to verify
        public_key (bytes): Public key used to verify the signature
        artifact_filename (str): Filename of the given artifact

    Returns:
        None

    Raises:
        InvalidSignature: If the signature is invalid

    Prints:
        "Signature is invalid" if the verification fails.
        "Signature is valid" if the verification succeeds.
    """
    public_key = load_pem_public_key(public_key)
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as e:
        raise ValueError(f"Validation failed {e}")
    print("Validation success.")
