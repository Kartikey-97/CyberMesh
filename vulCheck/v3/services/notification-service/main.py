import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "notification-service"
SERVICE_PORT = 8005
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "notification-service-secret")

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

app = FastAPI(title="Notification Service", lifespan=lifespan)

notifications_log = []

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.post("/notifications/send")
async def send_notification(payload: dict = Body(...)):
    entry = {
        "id": len(notifications_log) + 1,
        "recipient": payload.get("recipient", "user@example.com"),
        "channel": payload.get("channel", "email"),
        "message": payload.get("message", "Welcome!"),
        "status": "SENT"
    }
    notifications_log.append(entry)
    return entry

@app.get("/notifications/history")
async def get_history():
    return notifications_log

@app.get("/templates")
async def get_templates():
    return {
        "welcome": "Hello {{name}}, welcome to our platform!",
        "invoice_paid": "Your invoice #{{id}} has been paid.",
        "order_shipped": "Your order #{{id}} is on its way!"
    }

@app.get("/internal/smtp-credentials")
async def get_smtp_credentials():
    return {"smtp_host": "smtp.internal.local", "smtp_user": "admin_notify", "smtp_pass": "P@ssw0rd123!"}
