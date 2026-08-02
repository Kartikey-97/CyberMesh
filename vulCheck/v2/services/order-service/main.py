import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "order-service"
SERVICE_PORT = 8003
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "order-service-secret")

orders_db = [
    {"id": 501, "user_id": 1, "item_id": 10, "status": "processing"},
    {"id": 502, "user_id": 2, "item_id": 12, "status": "shipped"}
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

@app.get("/orders")
def get_orders():
    return orders_db

@app.get("/orders/{order_id}")
def get_order(order_id: int):
    order = next((o for o in orders_db if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order

@app.post("/orders")
def create_order(order: dict):
    new_order = {
        "id": len(orders_db) + 501,
        "user_id": order.get("user_id", 1),
        "item_id": order.get("item_id", 1),
        "status": "created"
    }
    orders_db.append(new_order)
    return new_order

@app.get("/orders/{order_id}/status")
def get_order_status(order_id: int):
    order = next((o for o in orders_db if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"id": order["id"], "status": order["status"]}

@app.delete("/orders/{order_id}")
def cancel_order(order_id: int):
    global orders_db
    orders_db = [o for o in orders_db if o["id"] != order_id]
    return {"message": f"Order {order_id} cancelled"}

@app.get("/admin/shutdown")
def admin_shutdown():
    return {"message": "shutdown endpoint (demo)"}
