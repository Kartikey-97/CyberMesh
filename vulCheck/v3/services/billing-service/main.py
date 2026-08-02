import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Body

# ── CyberMesh SDK Integration ───────────────────────────────────────
import sys
sys.path.insert(0, "/app")
from cybermesh_sdk import CyberMeshMiddleware, MeshClient

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "billing-service"
SERVICE_PORT = 8002
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "billing-service-secret")

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
                    await mesh.acquire_token(SERVICE_SECRET)
                    break
            except Exception:
                pass
            await asyncio.sleep(2)
    yield
    await mesh.aclose()

app = FastAPI(title="Billing Service (CyberMesh Protected)", lifespan=lifespan)
app.add_middleware(CyberMeshMiddleware)

invoices_db = {
    101: {"id": 101, "user_id": 1, "amount": 150.00, "status": "PAID"},
    102: {"id": 102, "user_id": 2, "amount": 299.99, "status": "UNPAID"}
}
payments_db = {
    "pmt_1": {"id": "pmt_1", "invoice_id": 101, "method": "credit_card", "status": "SUCCESS"}
}

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/invoices")
async def list_invoices():
    return list(invoices_db.values())

@app.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: int):
    if invoice_id not in invoices_db:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoices_db[invoice_id]

@app.post("/invoices", status_code=status.HTTP_201_CREATED)
async def create_invoice(payload: dict = Body(...)):
    new_id = max(invoices_db.keys(), default=100) + 1
    inv = {"id": new_id, "user_id": payload.get("user_id", 1), "amount": payload.get("amount", 0.0), "status": "UNPAID"}
    invoices_db[new_id] = inv
    return inv

@app.get("/payments/{payment_id}")
async def get_payment(payment_id: str):
    if payment_id not in payments_db:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payments_db[payment_id]

@app.post("/payments/process")
async def process_payment(payload: dict = Body(...)):
    pmt_id = f"pmt_{len(payments_db) + 1}"
    record = {"id": pmt_id, "invoice_id": payload.get("invoice_id"), "size_bytes": len(str(payload)), "status": "SUCCESS"}
    payments_db[pmt_id] = record
    return record

@app.get("/internal/report")
async def internal_report():
    return {"total_revenue": 449.99, "unpaid_invoices": 1, "ledger_status": "reconciled"}
