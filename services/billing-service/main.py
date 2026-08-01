import sys
sys.path.insert(0, '/app')

from fastapi import FastAPI
from pydantic import BaseModel
from uuid import uuid4

app = FastAPI(title="Billing Service")

INVOICES = [
    {"id": "INV-001", "amount": 299.99, "status": "paid", "customer_id": 1},
    {"id": "INV-002", "amount": 150.00, "status": "pending", "customer_id": 2},
    {"id": "INV-003", "amount": 99.99, "status": "paid", "customer_id": 3},
    {"id": "INV-004", "amount": 1200.50, "status": "overdue", "customer_id": 4},
    {"id": "INV-005", "amount": 49.99, "status": "paid", "customer_id": 5},
]

class ChargeRequest(BaseModel):
    customer_id: int
    amount: float

@app.get("/invoices")
async def get_invoices():
    return INVOICES

@app.post("/charge")
async def process_charge(request: ChargeRequest):
    return {"charge_id": str(uuid4()), "status": "processed"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "billing-service"}
