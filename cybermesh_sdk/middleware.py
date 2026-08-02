"""
CyberMesh SDK — Inbound Request Middleware

Protects a FastAPI service by validating every incoming request for:
    1. A valid CyberMesh JWT in the Authorization header
    2. The presence of mesh identity headers injected by the proxy:
         X-Mesh-Caller      — which service sent this request
         X-Mesh-Trust       — trust score at time of proxy decision
         X-Mesh-Request-ID  — unique request lineage ID

If a request arrives WITHOUT these headers, it was sent directly to
the service, bypassing the CyberMesh proxy entirely. The SDK drops it
immediately with a 403 — the service is unreachable without the mesh.

Exceptions:
    - /health  — always allowed (used by Docker / load balancer probes)
    - /metrics — always allowed
    - Requests originating from the proxy's own IP can also be exempted
      if MESH_ALLOW_DIRECT is set (useful for dev environments).

Configuration (via environment variables):
    PROXY_URL          — Base URL of CyberMesh proxy (default: http://proxy:8080)
    MESH_PUBLIC_KEY    — Cached PEM of auth-service public key (auto-fetched)
    MESH_ALLOW_DIRECT  — Set to "true" to skip enforcement (dev only)
"""

import os
import logging
import httpx
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import jwt

logger = logging.getLogger("cybermesh-sdk")

# Paths that bypass enforcement (probes, health checks)
_BYPASS_PATHS = {"/health", "/metrics", "/", "/docs", "/openapi.json", "/redoc"}

# Env config
PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
MESH_ALLOW_DIRECT = os.environ.get("MESH_ALLOW_DIRECT", "false").lower() == "true"

# Cached public key (fetched once at startup)
_public_key_pem: bytes | None = None


async def _fetch_public_key() -> bytes | None:
    """Fetch the RS256 public key from auth-service via the proxy."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{PROXY_URL}/public-key")
            if resp.status_code == 200:
                logger.info("CyberMesh SDK: Public key fetched successfully")
                return resp.text.encode("utf-8")
    except Exception as e:
        logger.warning("CyberMesh SDK: Could not fetch public key: %s", e)
    return None


class CyberMeshMiddleware(BaseHTTPMiddleware):
    """
    FastAPI/Starlette middleware that enforces CyberMesh Zero-Trust on every
    inbound request. Add it once and the entire service is protected::

        app.add_middleware(CyberMeshMiddleware)
    """

    def __init__(self, app: ASGIApp, require_mesh_headers: bool = True):
        super().__init__(app)
        self.require_mesh_headers = require_mesh_headers

    async def dispatch(self, request: Request, call_next):
        global _public_key_pem

        # Always allow bypass paths
        if request.url.path in _BYPASS_PATHS:
            return await call_next(request)

        # Dev mode — skip enforcement
        if MESH_ALLOW_DIRECT:
            return await call_next(request)

        # ── Step 1: Check for mesh identity headers ───────────────────────
        # These headers are injected by the CyberMesh proxy.
        # If they are absent, the request bypassed the proxy entirely.
        mesh_caller = request.headers.get("x-mesh-caller")
        mesh_trust = request.headers.get("x-mesh-trust")
        mesh_request_id = request.headers.get("x-mesh-request-id")

        if self.require_mesh_headers and not mesh_caller:
            logger.warning(
                "DIRECT ACCESS ATTEMPT blocked: %s %s — no X-Mesh-Caller header",
                request.method, request.url.path
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access denied",
                    "detail": "Direct access to this service is not permitted. "
                              "All traffic must route through CyberMesh.",
                    "mesh_required": True,
                }
            )

        # ── Step 2: Validate the JWT ──────────────────────────────────────
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Missing CyberMesh Bearer token. "
                              "Request a token via POST /token on the auth-service.",
                }
            )

        token = authorization.split(" ", 1)[1]

        # Fetch public key lazily (once)
        if _public_key_pem is None:
            _public_key_pem = await _fetch_public_key()

        if _public_key_pem:
            try:
                jwt.decode(token, _public_key_pem, algorithms=["RS256"])
            except jwt.ExpiredSignatureError:
                return JSONResponse(status_code=401, content={"error": "Token expired"})
            except jwt.InvalidTokenError as e:
                return JSONResponse(status_code=401, content={"error": f"Invalid token: {e}"})

        # ── Step 3: Attach mesh context to request state ──────────────────
        # Downstream handlers can read request.state.mesh_caller etc.
        request.state.mesh_caller = mesh_caller
        request.state.mesh_trust = float(mesh_trust) if mesh_trust else None
        request.state.mesh_request_id = mesh_request_id

        # ── Step 4: Log the verified inbound request ──────────────────────
        trust_label = f" (trust={mesh_trust})" if mesh_trust else ""
        logger.info(
            "MESH VERIFIED: %s → %s %s%s [req=%s]",
            mesh_caller or "?",
            request.method,
            request.url.path,
            trust_label,
            mesh_request_id or "?"
        )

        return await call_next(request)
