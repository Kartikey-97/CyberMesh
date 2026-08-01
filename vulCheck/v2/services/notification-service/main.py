import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "notification-service"
SERVICE_PORT = 8005
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "notification-service-secret")

notifications_db = [
    {"id": 1, "recipient": "alice@example.com", "channel": "email", "status": "sent"},
    {"id": 2, "recipient": "+15550199", "channel": "sms", "status": "delivered"}
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

@app.get("/notifications")
def get_notifications():
    return notifications_db

@app.post("/notifications/send")
def send_notification(payload: dict):
    new_notif = {
        "id": len(notifications_db) + 1,
        "recipient": payload.get("recipient", "user@example.com"),
        "channel": payload.get("channel", "email"),
        "status": "queued"
    }
    notifications_db.append(new_notif)
    return new_notif

@app.get("/templates")
def get_templates():
    return [
        {"name": "order_confirmation", "type": "email"},
        {"name": "payment_receipt", "type": "pdf_email"},
        {"name": "security_alert", "type": "sms"}
    ]

@app.get("/internal/logs")
def internal_logs():
    return {
        "logs": [
            "INFO: Boot sequence finished",
            "WARN: Token cache miss for user 4",
            "SECRET_KEY_ENV=cybermesh_master_key_998"
        ],
        "sensitive": True
    }
