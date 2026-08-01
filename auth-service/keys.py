"""
CyberMesh Auth Service — RSA Keypair Management

Generates a 2048-bit RSA keypair at container startup.
The private key NEVER leaves auth-service — it signs tokens.
The public key is exposed via GET /public-key so the proxy can verify tokens
without being able to forge them. This is a fundamental zero-trust property:
the enforcement layer (proxy) can verify identity but cannot impersonate it.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import logging

logger = logging.getLogger("auth-keys")

# Module-level keypair — generated once at import time (container startup)
_private_key = None
_public_key = None
_public_key_pem: bytes = b""
_private_key_pem: bytes = b""


def _generate_keypair():
    """Generate a fresh RSA-2048 keypair."""
    global _private_key, _public_key, _public_key_pem, _private_key_pem

    _private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    _public_key = _private_key.public_key()

    _private_key_pem = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    _public_key_pem = _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    logger.info("RSA-2048 keypair generated successfully")


def get_private_key_pem() -> bytes:
    """Return PEM-encoded private key for JWT signing."""
    if _private_key_pem == b"":
        _generate_keypair()
    return _private_key_pem


def get_public_key_pem() -> bytes:
    """Return PEM-encoded public key for JWT verification."""
    if _public_key_pem == b"":
        _generate_keypair()
    return _public_key_pem


# Generate on import so keys are ready before the first request
_generate_keypair()
