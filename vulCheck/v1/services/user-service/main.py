import os
import asyncio
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "user-service"
SERVICE_PORT = 8001
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "user-service-secret")
BILLING_SERVICE_URL = os.environ.get("BILLING_SERVICE_URL", "http://billing-service:8002")

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
                    break
            except Exception:
                pass
            await asyncio.sleep(2)
    yield

app = FastAPI(lifespan=lifespan)

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
async def create_user(user: dict):
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
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{BILLING_SERVICE_URL}/invoices")
            return {"user_id": id, "invoices": r.json()}
        except Exception as e:
            return {"user_id": id, "invoices": [], "error": str(e)}
