import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "search-service"
SERVICE_PORT = 8010
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "search-service-secret")

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

app = FastAPI(title="Search Service", lifespan=lifespan)

search_index = [
    {"id": 1, "title": "Laptop Pro 15 inch", "category": "electronics"},
    {"id": 2, "title": "Wireless Headset", "category": "audio"}
]

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/search")
async def general_search(q: str = Query(default="")):
    results = [item for item in search_index if q.lower() in item["title"].lower()] if q else search_index
    return {"query": q, "count": len(results), "results": results}

@app.get("/search/products")
async def search_products(category: str = Query(default="electronics")):
    filtered = [item for item in search_index if item["category"] == category]
    return {"category": category, "products": filtered}

@app.post("/search/index")
async def index_document(payload: dict = Body(...)):
    new_doc = {"id": len(search_index) + 1, "title": payload.get("title", ""), "category": payload.get("category", "general")}
    search_index.append(new_doc)
    return {"indexed": True, "document": new_doc}

@app.get("/admin/elasticsearch-credentials")
async def es_credentials():
    return {"cluster_host": "elasticsearch.internal:9200", "user": "elastic_admin", "api_key": "es_secret_key_889900"}
