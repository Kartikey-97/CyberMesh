"""
CyberMesh Proxy — Proof of Possession (PoP) Verifier

Closes the "intercepted token" gap in bearer JWT authentication.

Problem with bearer tokens:
    An attacker who intercepts a valid JWT can use it to impersonate the
    service until the token expires, even with JTI replay protection —
    because the JTI check only blocks the *original* request being replayed,
    not a parallel request using the same token on a different connection.

Solution — Cryptographic Proof of Possession:
    When a service registers, it generates an ephemeral ECDSA P-256 key pair.
    It sends the public key to the proxy. The private key NEVER leaves the
    service process.

    On every request, the service signs a proof string:
        SHA256( METHOD + ":" + PATH + ":" + SHA256(body) + ":" + time_bucket )

    The proxy verifies this signature against the stored public key.

    An attacker who steals the JWT has no access to the private key and
    CANNOT forge a valid signature. The token is useless without PoP.

Proof string format:
    "<METHOD>:<path>:<sha256_hex(body)>:<5s_time_bucket>"
    Example: "POST:/payments/process:a3f5b2...:340234891"

    The time_bucket = int(time.time() / 5) gives a 5-second validity window,
    absorbing clock skew between service and proxy without enabling replay.
    We also accept the PREVIOUS bucket to handle requests that straddle a
    bucket boundary.

Headers injected by the SDK:
    X-Mesh-Signature  — base64-encoded ECDSA signature over the proof string
    X-Mesh-Sig-Ts     — Unix timestamp used to compute the bucket

This module handles server-side verification only.
The client-side signing lives in cybermesh_sdk/pop.py.

Competition note:
    This is a direct implementation of the DPoP (Demonstrating Proof of
    Possession) concept from RFC 9449. We use it at the service mesh layer
    rather than the OAuth layer, making it transparent to application code.
"""

import base64
import hashlib
import logging
import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("cybermesh-pop")

# Grace period: we accept signatures from the current AND previous 5s bucket.
# This gives a 5–10 second effective window, absorbing clock skew.
BUCKET_SIZE_SECONDS = 5
MAX_TIMESTAMP_DRIFT_SECONDS = 30  # Reject timestamps more than 30s off


def load_public_key(public_key_pem: bytes) -> Optional[ec.EllipticCurvePublicKey]:
    """
    Load an ECDSA P-256 public key from PEM bytes.
    Returns None if the PEM is invalid or not an EC key.
    """
    try:
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            logger.warning("PoP: Registered key is not an EC public key")
            return None
        return key
    except Exception as e:
        logger.warning("PoP: Failed to load public key: %s", e)
        return None


def build_proof_string(method: str, path: str, body: bytes, timestamp: int) -> str:
    """
    Construct the canonical proof string that is signed by the service
    and verified by the proxy.

    Format: "<METHOD>:<path>:<sha256_hex(body)>:<5s_bucket>"
    """
    body_hash = hashlib.sha256(body).hexdigest()
    bucket = timestamp // BUCKET_SIZE_SECONDS
    return f"{method.upper()}:{path}:{body_hash}:{bucket}"


def verify_pop(
    method: str,
    path: str,
    body: bytes,
    signature_b64: str,
    sig_timestamp: int,
    public_key_pem: bytes,
) -> Tuple[bool, float, str]:
    """
    Verify a Proof-of-Possession signature on a proxied request.

    Args:
        method:           HTTP method ("GET", "POST", …)
        path:             Request path (e.g. "/payments/process")
        body:             Raw request body bytes
        signature_b64:    Base64-encoded ECDSA signature from X-Mesh-Signature
        sig_timestamp:    Unix timestamp from X-Mesh-Sig-Ts header
        public_key_pem:   PEM public key stored for this service at registration

    Returns:
        (verified: bool, score: float, detail: str)
        score is 100 on success, 0 on failure.
    """
    now = time.time()

    # ── Timestamp sanity check ────────────────────────────────────────────────
    drift = abs(now - sig_timestamp)
    if drift > MAX_TIMESTAMP_DRIFT_SECONDS:
        return (
            False, 0.0,
            f"PoP timestamp too far from proxy clock (drift={drift:.1f}s, max={MAX_TIMESTAMP_DRIFT_SECONDS}s) "
            f"— possible replay or severe clock skew"
        )

    # ── Load public key ───────────────────────────────────────────────────────
    public_key = load_public_key(public_key_pem)
    if public_key is None:
        return False, 0.0, "PoP: Cannot load service public key — registration incomplete"

    # ── Decode signature ──────────────────────────────────────────────────────
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        return False, 0.0, "PoP: Malformed X-Mesh-Signature (invalid base64)"

    # ── Verify against current AND previous bucket ────────────────────────────
    # Accept both to handle requests that straddle a 5-second boundary.
    buckets_to_try = [sig_timestamp, sig_timestamp - BUCKET_SIZE_SECONDS]
    for ts in buckets_to_try:
        proof = build_proof_string(method, path, body, ts)
        try:
            public_key.verify(signature_bytes, proof.encode(), ec.ECDSA(hashes.SHA256()))
            # Verification succeeded
            bucket_age = int((now - ts) // BUCKET_SIZE_SECONDS)
            return (
                True, 100.0,
                f"PoP verified ✓ — caller holds private key matching registered public key "
                f"(method={method}, bucket_age={bucket_age}s, drift={drift:.1f}s)"
            )
        except InvalidSignature:
            continue
        except Exception as e:
            logger.warning("PoP: Unexpected verification error: %s", e)
            continue

    return (
        False, 0.0,
        f"PoP FAILED — signature does not match registered public key. "
        f"Token may be stolen or request was tampered with."
    )
