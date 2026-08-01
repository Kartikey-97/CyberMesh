import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "user-service"
SERVICE_PORT = 8001
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "user-service-secret")

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

app = FastAPI(title="User Service", lifespan=lifespan)

users_db = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com"}
}

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/users")
async def list_users():
    return list(users_db.values())

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    return users_db[user_id]

@app.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(payload: dict = Body(...)):
    new_id = max(users_db.keys(), default=0) + 1
    user = {"id": new_id, "name": payload.get("name", "Unknown"), "email": payload.get("email", "")}
    users_db[new_id] = user
    return user

@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    deleted = users_db.pop(user_id)
    return {"message": "User deleted", "user": deleted}

@app.get("/admin/config")
async def get_admin_config():
    return {"db_host": "postgres:5432", "debug": False, "secret_key": "super-secret-user-key"}
