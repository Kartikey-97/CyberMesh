import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "user-service"
SERVICE_PORT = 8001
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "user-service-secret")

users_db = [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"}
]

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

@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/users")
def get_users():
    return users_db

@app.get("/users/{user_id}")
def get_user(user_id: int):
    user = next((u for u in users_db if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/users")
def create_user(user: dict):
    new_user = {"id": len(users_db) + 1, "name": user.get("name", "Unknown")}
    users_db.append(new_user)
    return new_user

@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    global users_db
    users_db = [u for u in users_db if u["id"] != user_id]
    return {"message": f"User {user_id} deleted"}

@app.get("/admin/config")
def admin_config():
    return {"db_host": "postgres:5432", "debug": False}
