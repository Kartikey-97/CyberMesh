import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
USER_SERVICE_URL = os.environ.get("USER_SERVICE_URL", "http://user-service:8001")
SERVICE_NAME = "billing-service"
SERVICE_PORT = 8002
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "billing-service-secret")

invoices_db = [
    {"id": 101, "user_id": 1, "amount": 150.0, "status": "paid"},
    {"id": 102, "user_id": 2, "amount": 300.5, "status": "pending"}
]
payments_db = {
    101: {"payment_id": "pay_991", "method": "credit_card", "status": "completed"}
}

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

@app.get("/invoices")
def get_invoices():
    return invoices_db

@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int):
    inv = next((i for i in invoices_db if i["id"] == invoice_id), None)
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return inv

@app.post("/invoices")
def create_invoice(invoice: dict):
    new_inv = {
        "id": len(invoices_db) + 101,
        "user_id": invoice.get("user_id", 1),
        "amount": invoice.get("amount", 0.0),
        "status": "pending"
    }
    invoices_db.append(new_inv)
    return new_inv

@app.get("/payments/{payment_id}")
def get_payment(payment_id: int):
    pay = payments_db.get(payment_id)
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    return pay

@app.post("/payments/process")
async def process_payment(request: Request):
    payload = await request.json()
    invoice_id = payload.get("invoice_id", 102)
    return {
        "status": "processed",
        "invoice_id": invoice_id,
        "payload_bytes": len(str(payload))
    }

@app.get("/internal/report")
def internal_report():
    return {
        "total_revenue": 450.50,
        "pending_invoices": 1,
        "confidential": True
    }
