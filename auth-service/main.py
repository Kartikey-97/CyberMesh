import sys
sys.path.insert(0, '/app')

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import logging

from auth_service.config import JWT_SECRET, JWT_ALGORITHM, TOKEN_TTL_SECONDS, SERVICE_SECRETS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth-service")

app = FastAPI(title="Auth Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

revoked_services = set()

class TokenRequest(BaseModel):
    service_name: str
    secret: str

class RevokeRequest(BaseModel):
    service_name: str

@app.post("/token")
async def get_token(request: TokenRequest):
    if request.service_name not in SERVICE_SECRETS or SERVICE_SECRETS[request.service_name] != request.secret:
        raise HTTPException(status_code=401, detail="Invalid service name or secret")

    if request.service_name in revoked_services:
        raise HTTPException(status_code=403, detail="Service revoked")

    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=TOKEN_TTL_SECONDS)
    jti = str(uuid4())

    payload = {
        "sub": request.service_name,
        "iss": "cybermesh-auth",
        "aud": "cybermesh-proxy",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    logger.info(f"Token issued for {request.service_name} (jti: {jti})")
    
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS}

@app.post("/revoke")
async def revoke(request: RevokeRequest):
    if request.service_name not in SERVICE_SECRETS:
        raise HTTPException(status_code=404, detail="Service not found")
        
    revoked_services.add(request.service_name)
    revoked_at = datetime.now(timezone.utc).isoformat()
    logger.info(f"Service {request.service_name} revoked at {revoked_at}")
    
    return {"revoked": request.service_name, "revoked_at": revoked_at}

@app.get("/revoked")
async def get_revoked():
    return {"revoked_services": list(revoked_services)}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "auth-service"}
