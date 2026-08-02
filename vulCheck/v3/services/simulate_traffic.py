#!/usr/bin/env python3
"""
CyberMesh Traffic Simulator (Normal & Attack Phases)

Routes ALL traffic through the CyberMesh proxy at http://localhost:8080.
Each "service" acquires its own JWT and injects proper headers so the
proxy can enforce zero-trust policy, rate limits, and injection detection.

Usage:
    python simulate_traffic.py normal   # Phase 1: baseline learning traffic
    python simulate_traffic.py attack   # Phase 2: attack simulation
    python simulate_traffic.py all      # Both phases (default)
"""

import httpx
import asyncio
import sys
sys.path.insert(0, '../../..')  # Ensure cybermesh_sdk can be imported
from cybermesh_sdk.client import MeshClient

# CyberMesh proxy endpoint — all traffic routes here
PROXY = "http://localhost:8080"
# Auth-service endpoint for token acquisition
AUTH = "http://localhost:8081"  # Note: auth-service is on 8081

# Map each service to its secret (matches docker-compose env)
SERVICE_SECRETS = {
    "user-service":           "user-service-secret",
    "billing-service":        "billing-service-secret",
    "order-service":          "order-service-secret",
    "inventory-service":      "inventory-service-secret",
    "notification-service":   "notification-service-secret",
    "auth-service":           "auth-service-secret",
    "shipping-service":       "shipping-service-secret",
    "analytics-service":      "analytics-service-secret",
    "recommendation-service": "recommendation-service-secret",
    "search-service":         "search-service-secret",
}

# Cache of MeshClients keyed by service name
_clients: dict[str, MeshClient] = {}


async def get_client(service_name: str) -> MeshClient | None:
    """Get or create a MeshClient for the given service."""
    if service_name in _clients:
        return _clients[service_name]
    secret = SERVICE_SECRETS.get(service_name)
    if not secret:
        return None
    client = MeshClient(service_name, proxy_url=PROXY)
    success = await client.acquire_token(secret)
    if success:
        _clients[service_name] = client
        return client
    return None


async def mesh_request(
    client: httpx.AsyncClient,  # Ignored now, kept for signature compatibility
    caller_service: str,
    target_service: str,
    path: str,
    method: str = "GET",
    payload: dict = None,
    label: str = None,
):
    """
    Send a request through the CyberMesh proxy using MeshClient.
    This ensures PoP signatures and JWTs are correctly attached.
    """
    mesh = await get_client(caller_service)
    if not mesh:
        print(f"  [!] Failed to get MeshClient for {caller_service}")
        return

    try:
        kwargs = {}
        if payload is not None:
            kwargs["json"] = payload
            
        if method == "POST":
            resp = await mesh.post(target_service, path, **kwargs)
        elif method == "PUT":
            resp = await mesh.put(target_service, path, **kwargs)
        elif method == "DELETE":
            resp = await mesh.delete(target_service, path, **kwargs)
        else:
            resp = await mesh.get(target_service, path, **kwargs)

        tag = label or f"{caller_service} → {target_service}{path}"
        status_symbol = "✓" if resp.status_code < 400 else "✗" if resp.status_code == 403 else "?"
        print(f"  {status_symbol} [{method}] {tag} => {resp.status_code}")
    except Exception as e:
        print(f"  [!] {caller_service} → {target_service}{path} => Failed ({e})")


async def run_normal_traffic(client: httpx.AsyncClient):
    print("\n--- PHASE 1: Normal Inter-Service Traffic (Learning Baseline) ---")
    print("(Routing through CyberMesh proxy with JWT authentication)\n")

    # These are the legitimate, expected call patterns — the proxy will learn them
    await mesh_request(client, "order-service",   "inventory-service", "/items")
    await mesh_request(client, "order-service",   "inventory-service", "/items/reserve", "POST", {"item_id": 201, "quantity": 1})
    await mesh_request(client, "order-service",   "billing-service",   "/invoices")
    await mesh_request(client, "order-service",   "notification-service", "/notify", "POST", {"event": "order_created"})
    await mesh_request(client, "billing-service", "user-service",      "/users/1")
    await mesh_request(client, "user-service",    "billing-service",   "/invoices")
    await mesh_request(client, "analytics-service", "order-service",   "/orders")
    await mesh_request(client, "analytics-service", "billing-service", "/invoices")
    await mesh_request(client, "shipping-service",  "order-service",   "/orders/501")
    await mesh_request(client, "recommendation-service", "analytics-service", "/metrics")
    await mesh_request(client, "search-service",  "inventory-service", "/items")

    print("\n  ✓ Baseline traffic complete. Switching proxy to enforce mode...")


async def run_attack_traffic(client: httpx.AsyncClient):
    print("\n--- PHASE 2: Attack Simulation (CyberMesh Anomaly Detection) ---")
    print("(Attacks route through proxy — CyberMesh enforces Zero-Trust)\n")

    print("1. Lateral Movement — Services calling services they've never called:")
    # billing-service has never called analytics-service — Tier 3 BLOCK
    await mesh_request(client, "billing-service",  "analytics-service",    "/metrics",        label="billing → analytics (lateral move)")
    # notification-service has never called auth-service — Tier 3 BLOCK
    await mesh_request(client, "notification-service", "auth-service",      "/admin/master-key", label="notification → auth (credential theft)")
    # search-service has never called billing — Tier 3 BLOCK
    await mesh_request(client, "search-service",   "billing-service",      "/internal/report", label="search → billing/internal (unauthorized)")

    print("\n2. Sensitive Path Recon — Known pairs, but probing admin endpoints:")
    # order-service is known to call inventory — but /admin/dump is novel + sensitive
    await mesh_request(client, "order-service",    "inventory-service",    "/admin/dump",     label="order → inventory/admin (recon)")
    await mesh_request(client, "order-service",    "billing-service",      "/internal/report",label="order → billing/internal (recon)")
    await mesh_request(client, "order-service",    "billing-service",      "/admin/config",   label="order → billing/admin (recon)")
    await mesh_request(client, "order-service",    "notification-service", "/internal/smtp-credentials", label="order → notification/credentials (recon)")
    await mesh_request(client, "order-service",    "auth-service",         "/admin/master-key", label="order → auth/master-key (recon)")

    print("\n3. Rate Limit Abuse — 20 rapid requests from same caller:")
    tasks = [
        mesh_request(client, "analytics-service", "user-service", "/users", label=f"rate burst #{i+1}")
        for i in range(20)
    ]
    await asyncio.gather(*tasks)

    print("\n4. SQLi & Payload Injection via query params:")
    token = await get_token(client, "order-service")
    headers = {"X-Service-Name": "order-service", "Authorization": f"Bearer {token}" if token else ""}
    try:
        resp = await client.get(
            f"{PROXY}/proxy/user-service/users",
            params={"id": "1' OR '1'='1"},
            headers=headers,
        )
        print(f"  {'✗' if resp.status_code == 403 else '?'} [GET] SQLi tautology in query param => {resp.status_code}")
    except Exception as e:
        print(f"  [!] SQLi test failed: {e}")

    print("\n5. Large Payload Anomaly (10KB body to billing/payments):")
    large_body = {"invoice_id": 101, "data": "A" * 10000}
    await mesh_request(client, "order-service", "billing-service", "/payments/process", "POST", large_body, label="large payload anomaly")


async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    async with httpx.AsyncClient(timeout=10.0) as client:
        if mode in ("normal", "all"):
            await run_normal_traffic(client)
        if mode in ("attack", "all"):
            await run_attack_traffic(client)
    print("\n--- Simulation complete ---")


if __name__ == "__main__":
    asyncio.run(main())
