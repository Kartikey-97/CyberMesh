import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "analytics-service"
SERVICE_PORT = 8008
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "analytics-service-secret")

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

app = FastAPI(title="Analytics Service", lifespan=lifespan)

events_log = []

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/metrics")
async def get_metrics():
    return {"total_events": len(events_log), "cpu_utilization": "14.2%", "memory_mb": 128}

@app.post("/events")
async def record_event(payload: dict = Body(...)):
    event = {"id": len(events_log) + 1, "type": payload.get("event_type", "page_view"), "details": payload}
    events_log.append(event)
    return {"status": "recorded", "event_id": event["id"]}

@app.get("/reports/daily")
async def daily_report():
    return {"date": "2026-08-01", "active_users": 1420, "orders_count": 89, "total_sales": 15400.50}

@app.get("/admin/raw-export")
async def raw_export():
    return {"export_url": "s3://analytics-raw-bucket/dump-2026-08-01.csv", "records": len(events_log), "confidential": True}
