import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "inventory-service"
SERVICE_PORT = 8004
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "inventory-service-secret")

items_db = [
    {"id": 1, "name": "Laptop", "stock": 45, "price": 999.99},
    {"id": 2, "name": "Headphones", "stock": 120, "price": 149.50}
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

@app.get("/items")
def get_items():
    return items_db

@app.get("/items/{item_id}")
def get_item(item_id: int):
    item = next((i for i in items_db if i["id"] == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.post("/items")
def create_item(item: dict):
    new_item = {
        "id": len(items_db) + 1,
        "name": item.get("name", "Item"),
        "stock": item.get("stock", 0),
        "price": item.get("price", 0.0)
    }
    items_db.append(new_item)
    return new_item

@app.put("/items/{item_id}/stock")
def update_stock(item_id: int, body: dict):
    item = next((i for i in items_db if i["id"] == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item["stock"] = body.get("stock", item["stock"])
    return item

@app.get("/admin/dump")
def admin_dump():
    return {
        "warehouse_access_keys": ["WH-KEY-9912", "WH-KEY-0034"],
        "supplier_credentials": {"provider": "global_logistics", "auth": "sensitive"}
    }
