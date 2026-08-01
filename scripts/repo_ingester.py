import asyncio
import httpx
import sys
import json
import random
import time
from pathlib import Path

PROXY_URL = "http://127.0.0.1:8080"
AUTH_URL = "http://auth-service:8081"

SERVICE_SECRETS = {
    "user-service": "user-service-secret-key",
    "billing-service": "billing-service-secret-key",
    "admin-service": "admin-service-secret-key",
    "hacker-service": "hacker-secret",
    "ingested-service-1": "ingest-1-secret",
    "ingested-service-2": "ingest-2-secret"
}

# The goal is to simulate realistic traffic so the proxy's learning mode can ingest it.
# We will simulate endpoints being discovered and hit.

async def get_token(client: httpx.AsyncClient, service_name: str) -> str:
    secret = SERVICE_SECRETS.get(service_name, "default-secret")
    resp = await client.post(f"{AUTH_URL}/token", json={"service_name": service_name, "secret": secret})
    if resp.status_code == 200:
        return resp.json()["token"]
    return "invalid-token"

async def simulate_repo_traffic():
    print("\n[REPO INGESTER] Starting traffic ingestion for learning mode...")
    
    async with httpx.AsyncClient() as client:
        # Switch proxy to learning mode
        await client.post(f"{PROXY_URL}/mode", json={"mode": "learning"})
        print("[REPO INGESTER] Proxy set to LEARNING mode.")
        time.sleep(1)

        # Get tokens
        user_token = await get_token(client, "user-service")
        billing_token = await get_token(client, "billing-service")
        admin_token = await get_token(client, "admin-service")
        
        # Simulating standard microservices traffic pattern discovered from a repo
        print("[REPO INGESTER] Injecting discovered API schema traffic...")
        
        requests_to_make = [
            ("user-service", user_token, "billing-service", "/invoices"),
            ("user-service", user_token, "billing-service", "/charge"),
            ("billing-service", billing_token, "user-service", "/users/1"),
            ("admin-service", admin_token, "user-service", "/users"),
            ("admin-service", admin_token, "billing-service", "/invoices"),
        ]

        for _ in range(3):
            for caller, token, target, path in requests_to_make:
                headers = {"Authorization": f"Bearer {token}", "x-service-name": caller}
                print(f"   -> [{caller}] calling [{target}{path}]")
                try:
                    await client.get(f"{PROXY_URL}/proxy/{target}{path}", headers=headers)
                except Exception as e:
                    pass
                await asyncio.sleep(0.2)
                
        print("\n[REPO INGESTER] Switching proxy to ENFORCE mode to auto-generate policy...")
        await client.post(f"{PROXY_URL}/mode", json={"mode": "enforce"})
        print("[REPO INGESTER] Ingestion complete. Policy locked.")

if __name__ == "__main__":
    asyncio.run(simulate_repo_traffic())
