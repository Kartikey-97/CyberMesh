"""
CyberMesh SDK — Proof of Possession (PoP) Signer

Client-side half of the DPoP-style request signing system.

How it works:
    1. At startup, the service calls `generate_key_pair()` to get an ephemeral
       ECDSA P-256 key pair. The private key stays in process memory — it is
       NEVER transmitted anywhere.
    2. The public key PEM is sent to the proxy during `POST /register` via the
       `public_key_pem` field. The proxy stores it against the service name.
    3. On every outbound request, `MeshClient` calls `sign_request()` which
       produces a signature over:
           SHA256( METHOD + ":" + PATH + ":" + SHA256(body) + ":" + time_bucket )
    4. The signature is attached as `X-Mesh-Signature` and the timestamp as
       `X-Mesh-Sig-Ts`. The proxy's proof_of_possession.py verifies both.

An attacker who intercepts the JWT cannot forge this signature because they
don't have the private key — which never left the service process.

This module is intentionally standalone — it has no imports from other
cybermesh_sdk modules so it can be used independently.
"""

import base64
import hashlib
import logging
import time
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("cybermesh-sdk-pop")

BUCKET_SIZE_SECONDS = 5


def generate_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generate an ephemeral ECDSA P-256 key pair for this service instance.

    Call once at startup. The private key must never be persisted or transmitted.
    The public key is sent to the proxy during registration.

    Returns:
        (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    logger.info("CyberMesh SDK: PoP key pair generated (ECDSA P-256)")
    return private_key, public_key


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Serialize the public key to PEM format for transmission to the proxy.

    This is what gets sent in the `public_key_pem` field of POST /register.
    The PEM is safe to transmit — it contains only the public component.
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")


def sign_request(
    private_key: ec.EllipticCurvePrivateKey,
    method: str,
    path: str,
    body: bytes,
    timestamp: Optional[int] = None,
) -> Tuple[str, int]:
    """
    Sign a request to prove possession of the private key.

    Args:
        private_key: The service's ephemeral private key (generated at startup)
        method:      HTTP method (e.g. "POST")
        path:        Request path (e.g. "/payments/process")
        body:        Raw request body bytes (empty bytes for GET/DELETE)
        timestamp:   Unix timestamp override (defaults to now). Used in tests.

    Returns:
        (signature_b64, timestamp)
        — signature_b64: base64-encoded ECDSA signature, goes in X-Mesh-Signature
        — timestamp: the timestamp used, goes in X-Mesh-Sig-Ts

    The proxy will verify the signature using the registered public key.
    """
    if timestamp is None:
        timestamp = int(time.time())

    # Compute the canonical proof string (must match proxy's build_proof_string)
    body_hash = hashlib.sha256(body).hexdigest()
    bucket = timestamp // BUCKET_SIZE_SECONDS
    proof_string = f"{method.upper()}:{path}:{body_hash}:{bucket}"

    # Sign with ECDSA P-256 + SHA-256
    signature_bytes = private_key.sign(proof_string.encode(), ec.ECDSA(hashes.SHA256()))
    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    return signature_b64, timestamp
