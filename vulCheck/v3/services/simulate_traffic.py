#!/usr/bin/env python3
"""
CyberMesh Traffic Simulator (Normal & Attack Phases)
Demonstrates baseline learning vs Zero-Trust anomaly detection.
"""

import httpx
import asyncio
import sys

BASE_PORT_MAP = {
    "user-service": 8001,
    "billing-service": 8002,
    "order-service": 8003,
    "inventory-service": 8004,
    "notification-service": 8005,
    "auth-service": 8006,
    "shipping-service": 8007,
    "analytics-service": 8008,
    "recommendation-service": 8009,
    "search-service": 8010,
}

async def send_req(client: httpx.AsyncClient, target_service: str, path: str, method: str = "GET", payload: dict = None):
    port = BASE_PORT_MAP[target_service]
    url = f"http://localhost:{port}{path}"
    try:
        if method == "POST":
            res = await client.post(url, json=payload or {})
        elif method == "PUT":
            res = await client.put(url, json=payload or {})
        elif method == "DELETE":
            res = await client.delete(url)
        else:
            res = await client.get(url)
        print(f"[{method}] {target_service}{path} => Status {res.status_code}")
    except Exception as e:
        print(f"[{method}] {target_service}{path} => Failed ({e})")

async def run_normal_traffic():
    print("\n--- PHASE 1: Normal Inter-Service Traffic (Learning Baseline) ---")
    async with httpx.AsyncClient() as client:
        # Legitimate traffic calls
        await send_req(client, "billing-service", "/invoices")
        await send_req(client, "user-service", "/users/1")
        await send_req(client, "order-service", "/orders")
        await send_req(client, "inventory-service", "/items")
        await send_req(client, "inventory-service", "/items/reserve", method="POST", payload={"item_id": 201, "quantity": 1})
        await send_req(client, "shipping-service", "/shipments/701/track")
        await send_req(client, "analytics-service", "/metrics")
        await send_req(client, "recommendation-service", "/recommendations/1")
        await send_req(client, "search-service", "/search?q=laptop")

async def run_attack_traffic():
    print("\n--- PHASE 2: Attack Simulation (CyberMesh Anomaly Detection) ---")
    async with httpx.AsyncClient() as client:
        print("\n1. Lateral Movement & Sensitive Path Access:")
        await send_req(client, "order-service", "/admin/shutdown")
        await send_req(client, "user-service", "/admin/config")
        await send_req(client, "notification-service", "/internal/smtp-credentials")
        await send_req(client, "inventory-service", "/admin/dump")
        await send_req(client, "auth-service", "/admin/master-key")

        print("\n2. Rate Limit Abuse (20 Rapid Requests):")
        tasks = [send_req(client, "user-service", "/users") for _ in range(20)]
        await asyncio.gather(*tasks)

        print("\n3. Payload Anomaly Demo (Large Payment Payload):")
        large_body = {"invoice_id": 101, "data": "A" * 10000}
        await send_req(client, "billing-service", "/payments/process", method="POST", payload=large_body)

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("normal", "all"):
        await run_normal_traffic()
    if mode in ("attack", "all"):
        await run_attack_traffic()

if __name__ == "__main__":
    asyncio.run(main())
