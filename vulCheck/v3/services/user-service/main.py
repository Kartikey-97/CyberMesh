import os
import asyncio
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI, Body

# ── CyberMesh SDK Integration ───────────────────────────────────────
import sys
sys.path.insert(0, "/app")
from cybermesh_sdk import CyberMeshMiddleware, MeshClient

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "user-service"
SERVICE_PORT = 8001
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "user-service-secret")

# Shared MeshClient for all outbound calls
mesh = MeshClient(SERVICE_NAME, proxy_url=PROXY_URL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient() as client:
        for attempt in range(10):
            try:
                r = await client.post(f"{PROXY_URL}/register", json={
                    "service_name": SERVICE_NAME,
                    "internal_url": f"http://{SERVICE_NAME}:{SERVICE_PORT}",
                    "secret": SERVICE_SECRET,
                })
                if r.status_code == 200:
                    print(f"✓ Registered with CyberMesh mesh")
                    # Acquire JWT for outbound calls through the mesh
                    await mesh.acquire_token(SERVICE_SECRET)
                    break
            except Exception:
                pass
            await asyncio.sleep(2)
    yield
    await mesh.aclose()

app = FastAPI(title="User Service (CyberMesh Protected)", lifespan=lifespan)

# ── CyberMesh SDK: Protect all inbound traffic ──────────────────────
# Any request that bypasses the proxy will be rejected automatically.
app.add_middleware(CyberMeshMiddleware)

users_db = {1: "Alice", 2: "Bob"}

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/users")
async def get_users():
    return [{"id": uid, "name": name} for uid, name in users_db.items()]

@app.get("/users/{id}")
async def get_user(id: int):
    name = users_db.get(id, f"User-{id}")
    return {"id": id, "name": name}

@app.post("/users")
async def create_user(user: dict = Body(...)):
    new_id = max(users_db.keys(), default=0) + 1
    users_db[new_id] = user.get("name", f"User-{new_id}")
    return {"id": new_id, "name": users_db[new_id]}

@app.delete("/users/{id}")
async def delete_user(id: int):
    users_db.pop(id, None)
    return {"message": f"User {id} deleted"}

@app.get("/admin/config")
async def admin_config():
    return {"db_host": "postgres:5432", "debug": False}

@app.get("/users/{id}/invoices")
async def get_user_invoices(id: int):
    """
    Fetch invoices from billing-service via the CyberMesh proxy.
    MeshClient routes through http://proxy:8080/proxy/billing-service/invoices
    and automatically attaches this service's JWT.
    """
    resp = await mesh.get("billing-service", "/invoices")
    if resp.status_code == 200:
        return {"user_id": id, "invoices": resp.json()}
    return {"user_id": id, "invoices": [], "error": f"billing-service returned {resp.status_code}"}
