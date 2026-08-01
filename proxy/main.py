import sys
sys.path.insert(0, '/app')

import time
import asyncio
import logging
import httpx
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel
from typing import Optional
import os

from proxy.identity import verify_token
from proxy.policy_engine import check as policy_check, update_learned_policy, HARDCODED_POLICY, learned_policy
from proxy.learning_mode import record as record_observation, generate_policy, get_observations, start_learning
from proxy.trust_score import compute as compute_trust
from proxy.context_checks import evaluate as check_context
from proxy.risk_explanation import build as build_explanation
from proxy.event_stream import broadcaster
from proxy.revocation import revoke, is_revoked, get_revoked
from proxy.fallback_replay import replay_events
from shared.event_schema import (
    CyberMeshEvent, ReasonDetail,
    DECISION_ALLOW, DECISION_STEP_UP, DECISION_BLOCK,
    EVENT_REQUEST_DECISION, EVENT_MODE_CHANGED, EVENT_SERVICE_REVOKED, EVENT_POLICY_GENERATED
)
from shared.config import SERVICE_REGISTRY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybermesh-proxy")

app = FastAPI(title="CyberMesh Proxy", description="Zero-Trust Service Mesh Proxy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Persistent async HTTP client for forwarding requests
http_client: httpx.AsyncClient = None

# Proxy state
proxy_mode = "enforce"
active_replay_task = None
stats = {
    "total_requests": 0,
    "allowed": 0,
    "blocked": 0,
    "step_ups": 0,
    "total_latency_ms": 0.0,
}


@app.on_event("startup")
async def startup_event():
    global http_client
    http_client = httpx.AsyncClient(timeout=10.0)
    logger.info("CyberMesh Proxy started in '%s' mode", proxy_mode)


@app.on_event("shutdown")
async def shutdown_event():
    if http_client:
        await http_client.aclose()


# ─── Health & Metrics ────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "cybermesh-proxy", "mode": proxy_mode}


@app.get("/metrics")
async def get_metrics():
    avg_latency = 0.0
    if stats["total_requests"] > 0:
        avg_latency = round(stats["total_latency_ms"] / stats["total_requests"], 2)
    return {
        "total_requests": stats["total_requests"],
        "allowed": stats["allowed"],
        "blocked": stats["blocked"],
        "step_ups": stats["step_ups"],
        "avg_latency_ms": avg_latency,
        "mode": proxy_mode,
    }


# ─── Policy ──────────────────────────────────────────────────────────────────

@app.get("/policy")
async def get_policy():
    return {
        "mode": proxy_mode,
        "learned_policy": get_observations(),
        "hardcoded_policy": {f"{k[0]} → {k[1]}": v for k, v in HARDCODED_POLICY.items()},
        "active_learned": {f"{k[0]} → {k[1]}": True for k in learned_policy.keys()},
    }


# ─── Mode Switching ──────────────────────────────────────────────────────────

class ModeRequest(BaseModel):
    mode: str


@app.post("/mode")
async def set_mode(body: ModeRequest):
    global proxy_mode, active_replay_task
    new_mode = body.mode
    if new_mode not in ("learning", "enforce", "demo-replay"):
        raise HTTPException(status_code=400, detail=f"Invalid mode: {new_mode}. Use 'learning', 'enforce', or 'demo-replay'")

    # Cancel any active replay task
    if active_replay_task and not active_replay_task.done():
        active_replay_task.cancel()
        active_replay_task = None

    old_mode = proxy_mode
    proxy_mode = new_mode
    logger.info("Mode changed: %s → %s", old_mode, new_mode)

    if new_mode == "learning":
        start_learning()

    # When switching from learning to enforce, auto-generate policy
    if old_mode == "learning" and new_mode == "enforce":
        new_policy = generate_policy()
        if len(new_policy) > 0:
            update_learned_policy(new_policy)
            logger.info("Policy auto-generated with %d rules", len(new_policy))

            # Broadcast policy generated event
            policy_event = CyberMeshEvent(
                event_type=EVENT_POLICY_GENERATED,
                mode=new_mode,
                data={"learned_policy": get_observations(), "message": "Policy auto-generated from observed traffic"},
            )
            broadcaster.broadcast(policy_event)
        else:
            logger.warning("No traffic observed during learning mode. Keeping old policy.")

    if new_mode == "demo-replay":
        fixture_path = "/app/scripts/fallback_fixture.json"
        active_replay_task = asyncio.create_task(replay_events(broadcaster, fixture_path))

    # Broadcast mode change event
    mode_event = CyberMeshEvent(
        event_type=EVENT_MODE_CHANGED,
        mode=new_mode,
        data={"previous_mode": old_mode, "message": f"Switched to {new_mode} mode"},
    )
    broadcaster.broadcast(mode_event)

    return {
        "status": "success",
        "mode": proxy_mode,
        "previous_mode": old_mode,
        "learned_policy": get_observations() if new_mode == "enforce" and old_mode == "learning" else None,
    }


# ─── Revocation ──────────────────────────────────────────────────────────────

@app.post("/revoke/{service_name}")
async def revoke_service(service_name: str):
    revoke(service_name)
    logger.warning("Service REVOKED: %s", service_name)

    # Broadcast revocation event
    revoke_event = CyberMeshEvent(
        event_type=EVENT_SERVICE_REVOKED,
        caller=service_name,
        mode=proxy_mode,
        data={"service": service_name, "message": f"{service_name} identity revoked via kill-switch"},
    )
    broadcaster.broadcast(revoke_event)

    return {"status": "revoked", "service": service_name}


@app.get("/revoked")
async def get_revoked_services():
    return {"revoked_services": get_revoked()}


# ─── SSE Event Stream ────────────────────────────────────────────────────────

@app.get("/events")
async def sse_events(request: Request):
    async def event_generator():
        q = broadcaster.subscribe()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield {"event": "message", "data": data}
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield {"event": "ping", "data": "keepalive"}
        finally:
            broadcaster.unsubscribe(q)

    return EventSourceResponse(event_generator())


# ─── Core Proxy Route ────────────────────────────────────────────────────────

@app.api_route(
    "/proxy/{target_service}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
)
async def catch_all_proxy(
    target_service: str,
    path: str,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_service_name: Optional[str] = Header(None),
):
    start_time = time.perf_counter()
    stats["total_requests"] += 1

    reasons = []
    caller_service = x_service_name or "unknown"
    identity_score = 0.0

    # ─── Step 1: Identity Verification ────────────────────────────────────
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        token_service, identity_score, id_reasons = await verify_token(token)
        reasons.extend(id_reasons)

        # Use the service name from the token (cryptographic identity)
        if token_service:
            caller_service = token_service

        # ─── Step 2: Revocation Check ─────────────────────────────────────
        if is_revoked(caller_service):
            identity_score = 0.0
            reasons.append(ReasonDetail(
                "revocation", "FAIL",
                f"{caller_service} identity has been REVOKED — all requests denied", -100
            ))
    else:
        reasons.append(ReasonDetail("identity", "FAIL", "Missing Authorization header — no cryptographic identity", -100))

    # ─── Step 3: Policy Check ─────────────────────────────────────────────
    policy_allow, behavior_score, pol_reasons = policy_check(caller_service, target_service, proxy_mode)
    reasons.extend(pol_reasons)

    # ─── Step 3b: Record in Learning Mode ─────────────────────────────────
    if proxy_mode == "learning" and caller_service != "unknown":
        record_observation(caller_service, target_service)

    # ─── Step 4: Context Checks ───────────────────────────────────────────
    body = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()

    context_score, ctx_reasons = check_context(
        caller=caller_service,
        target=target_service,
        payload=body.decode("utf-8", errors="ignore"),
        content_length=len(body),
        request_time=time.time(),
    )
    reasons.extend(ctx_reasons)

    # ─── Step 5: Trust Score ──────────────────────────────────────────────
    trust_score, decision, band = compute_trust(identity_score, behavior_score, context_score)

    # ─── Step 6: Risk Explanation ─────────────────────────────────────────
    explanation = build_explanation(
        identity_reasons=[r for r in reasons if r.check in ("identity", "revocation")],
        policy_reasons=[r for r in reasons if r.check == "policy"],
        context_reasons=[r for r in reasons if r.check in ("rate_limit", "time_window", "payload")],
        trust_score=trust_score,
        decision=decision,
    )

    # ─── Measure Proxy Overhead ───────────────────────────────────────────
    latency_ms = (time.perf_counter() - start_time) * 1000
    stats["total_latency_ms"] += latency_ms

    # ─── Broadcast Event ──────────────────────────────────────────────────
    event = CyberMeshEvent(
        event_type=EVENT_REQUEST_DECISION,
        caller=caller_service,
        target=target_service,
        path=f"/{path}",
        method=request.method,
        decision=decision,
        trust_score=round(trust_score, 1),
        identity_score=round(identity_score, 1),
        behavior_score=round(behavior_score, 1),
        context_score=round(context_score, 1),
        band=band,
        latency_ms=round(latency_ms, 2),
        reasons=reasons,
        mode=proxy_mode,
    )
    broadcaster.broadcast(event)

    response_headers = {"X-CyberMesh-Latency-Ms": f"{latency_ms:.2f}"}

    # ─── Decision: BLOCK ──────────────────────────────────────────────────
    if decision == DECISION_BLOCK:
        stats["blocked"] += 1
        logger.warning("BLOCKED: %s → %s%s (trust=%.1f)", caller_service, target_service, f"/{path}", trust_score)
        return JSONResponse(
            status_code=403,
            content={
                "error": "Access denied by CyberMesh",
                "trust_score": round(trust_score, 1),
                "band": band,
                "decision": decision,
                "reasons": [{"check": r.check, "result": r.result, "detail": r.detail} for r in reasons],
                **explanation,
            },
            headers=response_headers,
        )

    # ─── Decision: STEP_UP ────────────────────────────────────────────────
    if decision == DECISION_STEP_UP:
        stats["step_ups"] += 1
        logger.info("STEP-UP: %s → %s%s (trust=%.1f)", caller_service, target_service, f"/{path}", trust_score)
        return JSONResponse(
            status_code=401,
            content={
                "action": "re-authenticate",
                "message": "Trust score in medium band — re-authentication required",
                "trust_score": round(trust_score, 1),
                "band": band,
                "decision": decision,
                "reasons": [{"check": r.check, "result": r.result, "detail": r.detail} for r in reasons],
            },
            headers=response_headers,
        )

    # ─── Decision: ALLOW — Forward to Target ──────────────────────────────
    stats["allowed"] += 1

    target_url = SERVICE_REGISTRY.get(target_service)
    if not target_url:
        raise HTTPException(status_code=404, detail=f"Target service '{target_service}' not found in registry")

    req_url = f"{target_url}/{path}"

    # Build forwarding headers (strip host to avoid conflicts)
    fwd_headers = {}
    for key, value in request.headers.items():
        if key.lower() not in ("host", "content-length", "transfer-encoding"):
            fwd_headers[key] = value

    try:
        resp = await http_client.request(
            method=request.method,
            url=req_url,
            params=dict(request.query_params),
            headers=fwd_headers,
            content=body if body else None,
        )

        # Return forwarded response with CyberMesh headers
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers={
                "content-type": resp.headers.get("content-type", "application/json"),
                **response_headers,
            },
        )
    except httpx.ConnectError as e:
        logger.error("Connection failed to %s: %s", req_url, e)
        raise HTTPException(status_code=502, detail=f"Cannot reach {target_service}: connection refused")
    except Exception as e:
        logger.error("Forward error to %s: %s", req_url, e)
        raise HTTPException(status_code=502, detail=f"Bad Gateway: {str(e)}")
