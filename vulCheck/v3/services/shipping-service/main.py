import httpx, asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Body

PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:8080")
SERVICE_NAME = "shipping-service"
SERVICE_PORT = 8007
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "shipping-service-secret")

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

app = FastAPI(title="Shipping Service", lifespan=lifespan)

shipments_db = {
    701: {"id": 701, "order_id": 501, "carrier": "FedEx", "tracking_number": "TRK987654", "status": "IN_TRANSIT"}
}

@app.get("/health")
async def health():
    return {"status": "ok", "service": SERVICE_NAME}

@app.get("/shipments")
async def list_shipments():
    return list(shipments_db.values())

@app.get("/shipments/{shipment_id}")
async def get_shipment(shipment_id: int):
    if shipment_id not in shipments_db:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return shipments_db[shipment_id]

@app.post("/shipments", status_code=status.HTTP_201_CREATED)
async def create_shipment(payload: dict = Body(...)):
    new_id = max(shipments_db.keys(), default=700) + 1
    shipment = {
        "id": new_id,
        "order_id": payload.get("order_id", 501),
        "carrier": payload.get("carrier", "DHL"),
        "tracking_number": f"TRK{new_id * 123}",
        "status": "LABEL_CREATED"
    }
    shipments_db[new_id] = shipment
    return shipment

@app.get("/shipments/{shipment_id}/track")
async def track_shipment(shipment_id: int):
    if shipment_id not in shipments_db:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return {"shipment_id": shipment_id, "status": shipments_db[shipment_id]["status"], "location": "Distribution Center A"}

@app.post("/internal/carrier-override")
async def carrier_override(payload: dict = Body(...)):
    return {"override_applied": True, "forced_carrier": payload.get("carrier", "INTERNAL_EXPRESS"), "bypass_routing": True}
