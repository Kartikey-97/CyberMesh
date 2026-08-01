import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "inventory-service"
SERVICE_PORT = 8004
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "inventory-service-secret")

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

app = FastAPI(title="Inventory Service", lifespan=lifespan)

inventory_db = {
    201: {"id": 201, "name": "Laptop Pro", "stock": 45, "price": 1200.00},
    202: {"id": 202, "name": "Smart Phone", "stock": 100, "price": 800.00}
}

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/items")
async def list_items():
    return list(inventory_db.values())

@app.get("/items/{item_id}")
async def get_item(item_id: int):
    if item_id not in inventory_db:
        raise HTTPException(status_code=404, detail="Item not found")
    return inventory_db[item_id]

@app.put("/items/{item_id}/stock")
async def update_stock(item_id: int, payload: dict = Body(...)):
    if item_id not in inventory_db:
        raise HTTPException(status_code=404, detail="Item not found")
    new_stock = payload.get("stock", inventory_db[item_id]["stock"])
    inventory_db[item_id]["stock"] = new_stock
    return inventory_db[item_id]

@app.post("/items/reserve")
async def reserve_item(payload: dict = Body(...)):
    item_id = payload.get("item_id")
    quantity = payload.get("quantity", 1)
    if item_id not in inventory_db or inventory_db[item_id]["stock"] < quantity:
        raise HTTPException(status_code=400, detail="Insufficient stock")
    inventory_db[item_id]["stock"] -= quantity
    return {"reserved": True, "item_id": item_id, "remaining_stock": inventory_db[item_id]["stock"]}

@app.get("/admin/dump")
async def admin_dump():
    return {"inventory_db_backup": "s3://backups/inventory.dump", "status": "sensitive_data_exported"}
