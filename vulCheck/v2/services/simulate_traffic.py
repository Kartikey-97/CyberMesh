import asyncio
import httpx

PROXY_GATEWAY = "http://localhost:8080" # CyberMesh Proxy Gateway URL

async def run_normal_traffic():
    print("--- [Learning Phase] Simulating Normal Service Traffic ---")
    async with httpx.AsyncClient() as client:
        # 1. user-service calls billing-service /invoices
        print("1. user-service -> billing-service /invoices")
        # 2. billing-service calls user-service /users/1
        print("2. billing-service -> user-service /users/1")
        # 3. order-service calls user-service /users/1
        print("3. order-service -> user-service /users/1")
        # 4. order-service calls inventory-service /items/1
        print("4. order-service -> inventory-service /items/1")
        # 5. notification-service calls user-service /users/2
        print("5. notification-service -> user-service /users/2")
    print("✓ Normal baseline traffic completed.\n")

async def run_attack_simulations():
    print("--- [Attack Phase] Simulating Anomaly & Lateral Movement Attacks ---")
    async with httpx.AsyncClient() as client:
        # Attack 1: Lateral Movement + Sensitive Path Access
        # billing-service -> order-service /admin/shutdown
        print("🚨 Attack 1: billing-service -> order-service /admin/shutdown (Lateral movement + sensitive path)")
        
        # Attack 2: Novel Sensitive Endpoint Access
        # order-service -> user-service /admin/config
        print("🚨 Attack 2: order-service -> user-service /admin/config (Novel sensitive path probing)")

        # Attack 3: Inventory Dump Leak Attempt
        # notification-service -> inventory-service /admin/dump
        print("🚨 Attack 3: notification-service -> inventory-service /admin/dump (Unauthorized data exfiltration)")

        # Attack 4: Rate Limit Abuse
        # Rapid repeated requests from billing-service
        print("🚨 Attack 4: Rapid bursts to billing-service (Rate limit abuse)")

    print("✓ Attack simulations complete.")

if __name__ == "__main__":
    asyncio.run(run_normal_traffic())
    asyncio.run(run_attack_simulations())
