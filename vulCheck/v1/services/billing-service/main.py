import os
import asyncio
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "billing-service"
SERVICE_PORT = 8002
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "billing-service-secret")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "http://user-service:8001")

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

invoices_db = [
    {"id": 1, "user_id": 1, "amount": 100.0, "status": "paid"},
    {"id": 2, "user_id": 2, "amount": 250.0, "status": "unpaid"}
]

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/invoices")
async def get_invoices():
    return invoices_db

@app.get("/invoices/{id}")
async def get_invoice(id: int):
    inv = next((i for i in invoices_db if i["id"] == id), None)
    if not inv:
        return {"error": "Invoice not found"}
    owner_info = None
    async with httpx.AsyncClient() as client:
        try:
            res = await client.get(f"{USER_SERVICE_URL}/users/{inv['user_id']}")
            if res.status_code == 200:
                owner_info = res.json()
        except Exception:
            pass
    return {**inv, "owner": owner_info}

@app.post("/invoices")
async def create_invoice(invoice: dict):
    new_id = len(invoices_db) + 1
    new_inv = {"id": new_id, "user_id": invoice.get("user_id", 1), "amount": invoice.get("amount", 0.0), "status": "unpaid"}
    invoices_db.append(new_inv)
    return new_inv

@app.get("/payments/{id}")
async def get_payment(id: int):
    return {"payment_id": id, "invoice_id": 1, "amount": 100.0, "status": "completed"}

@app.post("/payments/process")
async def process_payment(payload: dict):
    return {"status": "success", "transaction_id": "tx_998877", "processed_bytes": len(str(payload))}

@app.get("/internal/report")
async def internal_report():
    return {"total_revenue": 50000.0, "unpaid_total": 250.0, "classification": "internal_confidential"}
