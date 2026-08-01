import sys
sys.path.insert(0, '/app')

from fastapi import FastAPI

app = FastAPI(title="Admin Service")

@app.get("/admin/config")
async def get_config():
    return {
        "database_url": "postgres://internal:5432/prod",
        "api_keys": ["sk-789234789237489237489237"],
        "debug_mode": False
    }

@app.post("/admin/shutdown")
async def shutdown():
    return {"status": "shutdown_initiated", "countdown": 30}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "admin-service"}
