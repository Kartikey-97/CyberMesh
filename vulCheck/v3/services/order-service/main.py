import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "order-service"
SERVICE_PORT = 8003
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "order-service-secret")

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

app = FastAPI(title="Order Service", lifespan=lifespan)

orders_db = {
    501: {"id": 501, "user_id": 1, "item_id": 201, "quantity": 2, "status": "COMPLETED"},
    502: {"id": 502, "user_id": 2, "item_id": 202, "quantity": 1, "status": "PROCESSING"}
}

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/orders")
async def list_orders():
    return list(orders_db.values())

@app.get("/orders/{order_id}")
async def get_order(order_id: int):
    if order_id not in orders_db:
        raise HTTPException(status_code=404, detail="Order not found")
    return orders_db[order_id]

@app.post("/orders", status_code=status.HTTP_201_CREATED)
async def create_order(payload: dict = Body(...)):
    new_id = max(orders_db.keys(), default=500) + 1
    order = {
        "id": new_id,
        "user_id": payload.get("user_id", 1),
        "item_id": payload.get("item_id", 101),
        "quantity": payload.get("quantity", 1),
        "status": "PROCESSING"
    }
    orders_db[new_id] = order
    return order

@app.get("/orders/{order_id}/status")
async def get_order_status(order_id: int):
    if order_id not in orders_db:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"order_id": order_id, "status": orders_db[order_id]["status"]}

@app.delete("/orders/{order_id}")
async def cancel_order(order_id: int):
    if order_id not in orders_db:
        raise HTTPException(status_code=404, detail="Order not found")
    orders_db[order_id]["status"] = "CANCELLED"
    return {"message": "Order cancelled", "order": orders_db[order_id]}

@app.get("/admin/shutdown")
async def admin_shutdown():
    return {"message": "shutdown endpoint (demo)"}
