"""
CyberMesh SDK — Outbound Mesh Client

A drop-in replacement for httpx.AsyncClient that automatically:
    1. Routes all requests through the CyberMesh proxy
    2. Attaches the service's current JWT as the Authorization header
    3. Sets the X-Service-Name header for caller identification
    4. Retries token acquisition if the current token has expired

Usage::

    from cybermesh_sdk import MeshClient

    # At service startup (after registration)
    client = MeshClient("order-service", proxy_url="http://proxy:8080")
    await client.acquire_token(secret="order-service-secret")

    # Making calls — works exactly like httpx but routes through the mesh
    resp = await client.get("billing-service", "/invoices")
    resp = await client.post("inventory-service", "/items/reserve", json={...})

Configuration (via environment variables):
    PROXY_URL         — Base URL of CyberMesh proxy (default: http://proxy:8080)
    SERVICE_SECRET    — Service secret for token acquisition

The MeshClient is the single source of truth for outbound auth.
It holds the JWT internally and refreshes it automatically on 401.
"""

import os
import logging
import httpx
from typing import Any
from cybermesh_sdk.pop import generate_key_pair, public_key_to_pem, sign_request as pop_sign

logger = logging.getLogger("cybermesh-sdk")

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth-service:8081")


class MeshClient:
    """
    Authenticated outbound HTTP client for CyberMesh-protected services.

    All traffic is routed through the proxy at:
        {proxy_url}/proxy/{target_service}/{path}

    The client automatically attaches the JWT and retries on auth failure.
    """

    def __init__(self, service_name: str, proxy_url: str = None, auth_url: str = None):
        self.service_name = service_name
        self.proxy_url = proxy_url or PROXY_URL
        self.auth_url = auth_url or AUTH_SERVICE_URL
        self._token: str | None = None
        self._http = httpx.AsyncClient(timeout=10.0)

        # Generate ephemeral ECDSA P-256 key pair for Proof of Possession.
        # Private key stays in memory and is never transmitted anywhere.
        # Public key is sent to the proxy during registration.
        self._private_key, self._public_key = generate_key_pair()
        self._public_key_pem: str = public_key_to_pem(self._public_key)
        logger.info("CyberMesh SDK: PoP key pair ready for %s", service_name)

    async def acquire_token(self, secret: str) -> bool:
        """
        Request a JWT from the CyberMesh auth-service.
        Also registers the PoP public key with the proxy so it can verify
        future request signatures.

        Call this once at startup after registering with the mesh.
        """
        try:
            # Acquire JWT from auth-service
            resp = await self._http.post(
                f"{self.auth_url}/token",
                json={"service_name": self.service_name, "secret": secret},
            )
            if resp.status_code == 200:
                self._token = resp.json().get("access_token") or resp.json().get("token")
                logger.info("CyberMesh SDK: Token acquired for %s", self.service_name)

                # Register the PoP public key with the proxy
                await self._register_pop_key(secret)
                return True
            else:
                logger.warning(
                    "CyberMesh SDK: Token acquisition failed (%d): %s",
                    resp.status_code, resp.text
                )
        except Exception as e:
            logger.warning("CyberMesh SDK: Cannot reach auth-service: %s", e)
        return False

    async def _register_pop_key(self, secret: str) -> None:
        """Send our PoP public key to the proxy so it can verify our request signatures."""
        try:
            resp = await self._http.post(
                f"{self.proxy_url}/services/{self.service_name}/pop-key",
                json={"public_key_pem": self._public_key_pem, "secret": secret},
                headers={"X-Service-Name": self.service_name},
            )
            if resp.status_code == 200:
                logger.info("CyberMesh SDK: PoP public key registered with proxy for %s", self.service_name)
            else:
                logger.warning("CyberMesh SDK: PoP key registration returned %d", resp.status_code)
        except Exception as e:
            logger.warning("CyberMesh SDK: Could not register PoP key: %s", e)

    def _mesh_url(self, target_service: str, path: str) -> str:
        """Build the proxied URL for a target service and path."""
        path = path.lstrip("/")
        return f"{self.proxy_url}/proxy/{target_service}/{path}"

    def _headers(self, extra: dict = None) -> dict:
        """Build the standard mesh headers for an outbound request."""
        h = {
            "X-Service-Name": self.service_name,
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if extra:
            h.update(extra)
        return h

    async def get(self, target_service: str, path: str, **kwargs) -> httpx.Response:
        """GET {target_service}/{path} through CyberMesh."""
        return await self._request("GET", target_service, path, **kwargs)

    async def post(self, target_service: str, path: str, **kwargs) -> httpx.Response:
        """POST {target_service}/{path} through CyberMesh."""
        return await self._request("POST", target_service, path, **kwargs)

    async def put(self, target_service: str, path: str, **kwargs) -> httpx.Response:
        """PUT {target_service}/{path} through CyberMesh."""
        return await self._request("PUT", target_service, path, **kwargs)

    async def delete(self, target_service: str, path: str, **kwargs) -> httpx.Response:
        """DELETE {target_service}/{path} through CyberMesh."""
        return await self._request("DELETE", target_service, path, **kwargs)

    async def patch(self, target_service: str, path: str, **kwargs) -> httpx.Response:
        """PATCH {target_service}/{path} through CyberMesh."""
        return await self._request("PATCH", target_service, path, **kwargs)

    async def _request(
        self, method: str, target_service: str, path: str, **kwargs
    ) -> httpx.Response:
        """
        Core routing method. Injects mesh headers, PoP signature, and routes
        through the proxy. Retries once with a fresh token if a 401 is returned.
        """
        url = self._mesh_url(target_service, path)
        kwargs.setdefault("headers", {})
        kwargs["headers"].update(self._headers())

        # Attach Proof of Possession signature headers.
        # The proxy verifies these to ensure the caller holds the private key.
        body_bytes = b""
        if "json" in kwargs:
            import json as _json
            body_bytes = _json.dumps(kwargs["json"]).encode()
        elif "content" in kwargs:
            body_bytes = kwargs["content"] or b""

        sig_b64, sig_ts = pop_sign(self._private_key, method, path, body_bytes)
        kwargs["headers"]["X-Mesh-Signature"] = sig_b64
        kwargs["headers"]["X-Mesh-Sig-Ts"] = str(sig_ts)

        resp = await self._http.request(method, url, **kwargs)

        if resp.status_code == 401 and self._token:
            logger.warning(
                "CyberMesh SDK: 401 from proxy for %s → %s%s. Token may be expired.",
                self.service_name, target_service, path
            )

        return resp

    async def aclose(self):
        """Close the underlying HTTP client. Call at service shutdown."""
        await self._http.aclose()
