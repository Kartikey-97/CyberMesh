import os
import asyncio
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "order-service"
SERVICE_PORT = 8003
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "order-service-secret")
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

orders_db = [
    {"id": 101, "user_id": 1, "item": "CyberMesh Gateway License", "price": 499.99, "status": "shipped"},
    {"id": 102, "user_id": 2, "item": "Security Audit Report", "price": 1200.00, "status": "processing"}
]

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/orders")
async def get_orders():
    return orders_db

@app.get("/orders/{id}")
async def get_order(id: int):
    order = next((o for o in orders_db if o["id"] == id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@app.post("/orders")
async def create_order(order: dict):
    user_id = order.get("user_id", 1)
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{USER_SERVICE_URL}/users/{user_id}")
            if r.status_code != 200:
                raise HTTPException(status_code=400, detail="User verification failed")
        except Exception:
            pass
    new_id = max((o["id"] for o in orders_db), default=100) + 1
    new_order = {"id": new_id, "user_id": user_id, "item": order.get("item", "Default Item"), "price": order.get("price", 0.0), "status": "processing"}
    orders_db.append(new_order)
    return new_order

@app.get("/orders/{id}/status")
async def get_order_status(id: int):
    order = next((o for o in orders_db if o["id"] == id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"id": id, "status": order["status"]}

@app.delete("/orders/{id}")
async def cancel_order(id: int):
    global orders_db
    orders_db = [o for o in orders_db if o["id"] != id]
    return {"message": f"Order {id} cancelled"}

@app.get("/admin/shutdown")
async def admin_shutdown():
    return {"message": "shutdown endpoint (demo)"}
