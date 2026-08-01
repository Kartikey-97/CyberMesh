"""
CyberMesh Auth Service — Token Issuance & Service Registration (v2)

Key changes from v1:
- RS256 asymmetric signing (private key never leaves this container)
- Dynamic service registration at runtime (no hardcoded SERVICE_SECRETS)
- Public key endpoint for proxy to fetch at startup
"""

import sys
sys.path.insert(0, '/app')

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import logging

from auth_service.keys import get_private_key_pem, get_public_key_pem
from shared.config import TOKEN_TTL_SECONDS, JWT_ALGORITHM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth-service")

app = FastAPI(title="CyberMesh Auth Service", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Runtime Service Registry ─────────────────────────────────────────────────
# Replaces the old hardcoded SERVICE_SECRETS dict.
# Services register themselves at startup via POST /register-service.
registered_services: dict[str, dict] = {}

# Revoked services
revoked_services: set = set()


# ─── Request Models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    service_name: str
    internal_url: str    # e.g. "http://my-service:8001"
    secret: str          # any string the service chooses

class TokenRequest(BaseModel):
    service_name: str
    secret: str

class RevokeRequest(BaseModel):
    service_name: str


# ─── Service Registration ─────────────────────────────────────────────────────

@app.post("/register-service")
async def register_service(req: RegisterRequest):
    """
    Register a new microservice with the auth system.
    Any service on the Docker network can call this at startup.
    This is the integration contract — see README.
    """
    if req.service_name in registered_services:
        # Allow re-registration (service restart) if secret matches
        if registered_services[req.service_name]["secret"] != req.secret:
            raise HTTPException(
                status_code=409,
                detail=f"Service '{req.service_name}' already registered with a different secret"
            )
        # Update the URL (container might have a new IP after restart)
        registered_services[req.service_name]["internal_url"] = req.internal_url
        logger.info("Service re-registered: %s → %s", req.service_name, req.internal_url)
    else:
        registered_services[req.service_name] = {
            "secret": req.secret,
            "internal_url": req.internal_url,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info("NEW service registered: %s → %s", req.service_name, req.internal_url)

    return {
        "status": "registered",
        "service_name": req.service_name,
        "internal_url": req.internal_url,
    }


# ─── Token Issuance ───────────────────────────────────────────────────────────

@app.post("/token")
async def get_token(request: TokenRequest):
    """
    Issue an RS256-signed JWT for a registered service.
    The token contains: sub (service name), iss, aud, iat, exp, jti.
    """
    svc = registered_services.get(request.service_name)
    if not svc or svc["secret"] != request.secret:
        raise HTTPException(status_code=401, detail="Invalid service name or secret")

    if request.service_name in revoked_services:
        raise HTTPException(status_code=403, detail="Service revoked")

    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=TOKEN_TTL_SECONDS)
    jti = str(uuid4())

    payload = {
        "sub": request.service_name,
        "iss": "cybermesh-auth",
        "aud": "cybermesh-proxy",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
    }

    token = jwt.encode(payload, get_private_key_pem(), algorithm=JWT_ALGORITHM)

    logger.info("RS256 token issued for %s (jti: %s, ttl: %ds)", request.service_name, jti, TOKEN_TTL_SECONDS)

    return {"token": token, "expires_in": TOKEN_TTL_SECONDS, "jti": jti}


# ─── Public Key Endpoint ──────────────────────────────────────────────────────

@app.get("/public-key")
async def public_key():
    """
    Return the PEM-encoded RSA public key.
    The proxy fetches this at startup to verify tokens.
    This is the core zero-trust property: the proxy can VERIFY identity
    but can NEVER FORGE it — it doesn't have the private key.
    """
    return PlainTextResponse(
        content=get_public_key_pem().decode("utf-8"),
        media_type="application/x-pem-file",
    )


# ─── Revocation ───────────────────────────────────────────────────────────────

@app.post("/revoke")
async def revoke(request: RevokeRequest):
    if request.service_name not in registered_services:
        raise HTTPException(status_code=404, detail="Service not found")

    revoked_services.add(request.service_name)
    revoked_at = datetime.now(timezone.utc).isoformat()
    logger.warning("Service %s REVOKED at %s", request.service_name, revoked_at)

    return {"revoked": request.service_name, "revoked_at": revoked_at}


@app.get("/revoked")
async def get_revoked():
    return {"revoked_services": list(revoked_services)}


# ─── Registered Services List ─────────────────────────────────────────────────

@app.get("/services")
async def list_services():
    """Return all registered services (without secrets)."""
    return {
        name: {
            "internal_url": info["internal_url"],
            "registered_at": info["registered_at"],
            "revoked": name in revoked_services,
        }
        for name, info in registered_services.items()
    }


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "auth-service",
        "version": "2.0",
        "registered_services": len(registered_services),
        "signing_algorithm": JWT_ALGORITHM,
    }
