"""
CyberMesh Proxy — Identity Verification (v2.1)

Key changes from v2:
- JTI replay protection: every token can only be used ONCE
- Replay attempts are detected and scored at 0 with detailed reason

Key changes from v1:
- RS256 asymmetric verification using the auth-service's public key
- The proxy CANNOT forge tokens — it only holds the public key
- Public key is fetched from auth-service at startup and cached

This is the core zero-trust claim: cryptographic identity verification
on every single request, using asymmetric keys where the verifier
cannot impersonate the issuer. Plus replay protection so intercepted
tokens can't be reused.
"""

import jwt
import time
from typing import Tuple, List, Optional
from shared.config import JWT_ALGORITHM, TOKEN_TTL_SECONDS
from shared.event_schema import ReasonDetail
from proxy.jti_store import consume_async as jti_consume

# Public key for RS256 verification — set at startup by main.py
_public_key_pem: Optional[bytes] = None


def set_public_key(pem: bytes):
    """Called once at proxy startup after fetching from auth-service."""
    global _public_key_pem
    _public_key_pem = pem


def get_public_key() -> Optional[bytes]:
    """Return the cached public key."""
    return _public_key_pem


async def verify_token(token: str) -> Tuple[str, float, List[ReasonDetail], bool]:
    """
    Verify a JWT token using RS256 public key verification + JTI replay check.
    
    Returns:
        (service_name, identity_score, reasons, jti_replayed)
        
    Score logic:
        - Valid + fresh (< 50% TTL elapsed) + first use: 100.0
        - Valid + aging (50-80% TTL) + first use: 80.0
        - Valid + stale (> 80% TTL) + first use: 60.0
        - Valid but REPLAYED (jti already consumed): 0.0
        - Any failure: 0.0
    """
    reasons = []

    if _public_key_pem is None:
        reasons.append(ReasonDetail(
            "identity", "FAIL",
            "Proxy has no public key — auth-service may be unreachable", 0
        ))
        return ("", 0.0, reasons, False)

    try:
        payload = jwt.decode(
            token,
            _public_key_pem,
            algorithms=[JWT_ALGORITHM],
            issuer="cybermesh-auth",
            audience="cybermesh-proxy",
        )

        service_name = payload.get("sub", "")
        exp = payload.get("exp")
        iat = payload.get("iat")
        jti = payload.get("jti")

        # Validate all required claims are present
        if not all([service_name, exp, iat, jti]):
            reasons.append(ReasonDetail(
                "identity", "FAIL",
                "Missing required claims (sub, exp, iat, jti)", 0
            ))
            return ("", 0.0, reasons, False)

        # ─── JTI Replay Protection ────────────────────────────────────────
        # This is the key v2.1 addition. A valid token that has been
        # seen before is a REPLAY ATTACK — score it at 0.
        is_new, jti_detail = await jti_consume(jti, float(exp))

        if not is_new:
            reasons.append(ReasonDetail(
                "identity", "FAIL",
                jti_detail,
                -100
            ))
            # Still return the service name so the event stream shows
            # WHO attempted the replay (useful for forensics / dashboard)
            return (service_name, 0.0, reasons, True)

        # ─── Token Freshness Scoring ──────────────────────────────────────
        # Continuous assessment, not binary pass/fail
        current_time = time.time()
        elapsed = current_time - iat
        ttl_fraction = elapsed / TOKEN_TTL_SECONDS

        if ttl_fraction < 0.5:
            score = 100.0
            freshness = "fresh"
        elif ttl_fraction < 0.8:
            score = 80.0
            freshness = "aging"
        else:
            score = 60.0
            freshness = "stale"

        reasons.append(ReasonDetail(
            "identity", "PASS",
            f"RS256 token valid ({freshness}, {ttl_fraction:.0%} of TTL elapsed, "
            f"jti={jti[:8]}… first-use ✓)",
            int(score)
        ))
        return (service_name, score, reasons, False)

    except jwt.ExpiredSignatureError:
        reasons.append(ReasonDetail("identity", "FAIL", "Token expired", 0))
        return ("", 0.0, reasons, False)

    except jwt.InvalidIssuerError:
        reasons.append(ReasonDetail(
            "identity", "FAIL",
            "Token issuer mismatch — not issued by cybermesh-auth", 0
        ))
        return ("", 0.0, reasons, False)

    except jwt.InvalidAudienceError:
        reasons.append(ReasonDetail(
            "identity", "FAIL",
            "Token audience mismatch — not intended for cybermesh-proxy", 0
        ))
        return ("", 0.0, reasons, False)

    except jwt.InvalidSignatureError:
        reasons.append(ReasonDetail(
            "identity", "FAIL",
            "Invalid signature — token was not signed by the trusted auth-service private key", 0
        ))
        return ("", 0.0, reasons, False)

    except jwt.InvalidTokenError as e:
        reasons.append(ReasonDetail("identity", "FAIL", f"Invalid token: {str(e)}", 0))
        return ("", 0.0, reasons, False)

    except Exception as e:
        reasons.append(ReasonDetail("identity", "FAIL", f"Token verification error: {str(e)}", 0))
        return ("", 0.0, reasons, False)
