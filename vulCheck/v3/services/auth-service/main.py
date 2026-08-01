import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "auth-service"
SERVICE_PORT = 8006
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "auth-service-secret")

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

app = FastAPI(title="Auth Service", lifespan=lifespan)

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.post("/auth/login")
async def login(payload: dict = Body(...)):
    username = payload.get("username", "user")
    return {"token": f"mock_jwt_token_for_{username}", "expires_in": 3600}

@app.post("/tokens/verify")
async def verify_token(payload: dict = Body(...)):
    token = payload.get("token", "")
    return {"valid": True, "claims": {"sub": "1", "role": "user"}}

@app.get("/keys")
async def get_public_keys():
    return {"alg": "RS256", "kty": "RSA", "use": "sig", "n": "mock_public_key_n", "e": "AQAB"}

@app.get("/admin/master-key")
async def get_master_key():
    return {"master_signing_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...", "environment": "production"}
