import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "recommendation-service"
SERVICE_PORT = 8009
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "recommendation-service-secret")

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

app = FastAPI(title="Recommendation Service", lifespan=lifespan)

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/recommendations/{user_id}")
async def get_recommendations(user_id: int):
    return {
        "user_id": user_id,
        "recommended_items": [
            {"item_id": 201, "score": 0.95, "name": "Laptop Pro"},
            {"item_id": 202, "score": 0.88, "name": "Smart Phone"}
        ]
    }

@app.post("/recommendations/train")
async def train_model(payload: dict = Body(...)):
    epochs = payload.get("epochs", 5)
    return {"status": "training_scheduled", "epochs": epochs, "job_id": "job_rec_99"}

@app.get("/internal/model-weights")
async def get_model_weights():
    return {"model_version": "v2.4.1", "weights_url": "s3://models/rec_weights_v2.bin", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
