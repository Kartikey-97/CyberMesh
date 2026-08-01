"""
CyberMesh Proxy — Main Application (v2)

The central enforcement engine of CyberMesh. Every service-to-service
request routes through here and undergoes a 4-layer verification pipeline:

    1. Identity Verification (RS256 JWT)
    2. Revocation Check (kill-switch)
    3. Policy / Behavior Check (learned + hardcoded)
    4. Context Inspection (rate limit, payload, timing)

Key v2 changes:
- Fetches RS256 public key from auth-service at startup
- Uses dynamic registry instead of hardcoded SERVICE_REGISTRY
- Service registration endpoint
- Active replay task management
"""

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

from proxy.identity import verify_token, set_public_key
from proxy.jti_store import start_cleanup_task as jti_start_cleanup, get_stats as jti_get_stats
from proxy.registry import register as registry_register, resolve as registry_resolve, list_all as registry_list_all, count as registry_count
from proxy.policy_engine import check as policy_check, update_learned_policy, learned_policy
from proxy.learning_mode import record as record_observation, generate_policy, get_observations, get_observation_count, start_learning
from proxy.trust_score import compute as compute_trust
from proxy.trust_decay import set_demo_mode as decay_set_demo_mode, decay_stats as get_decay_stats
from proxy.context_checks import evaluate as check_context
from proxy.baseline_stats import get_all_baselines
from proxy.endpoint_scan_detector import (
    record_novel_hit, check_scan, get_all_scan_stats,
    reset_caller as scan_reset_caller,
    NOVEL_HIT_SCORE_THRESHOLD,
)
from proxy.path_template import templatize
from proxy.shadow_mode import is_shadow, promote as shadow_promote, demote as shadow_demote, get_shadow_stats
from proxy.policy_versioning import save_snapshot, list_versions, rollback_policy
from proxy.policy_persistence import load_state, save_state
from proxy.risk_explanation import build as build_explanation
from proxy.event_stream import broadcaster
from proxy.revocation import revoke, is_revoked, get_revoked
from proxy.fallback_replay import replay_events
from shared.event_schema import (
    CyberMeshEvent, ReasonDetail,
    DECISION_ALLOW, DECISION_STEP_UP, DECISION_BLOCK,
    EVENT_REQUEST_DECISION, EVENT_MODE_CHANGED, EVENT_SERVICE_REVOKED,
    EVENT_POLICY_GENERATED, EVENT_SERVICE_PROMOTED
)
from shared.config import AUTH_SERVICE_URL

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cybermesh-proxy")

app = FastAPI(title="CyberMesh Proxy", description="Zero-Trust Service Mesh Proxy", version="2.0")

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
    # Shadow mode counters — requests that would have been blocked/stepped up
    # but were forwarded anyway because the caller is in shadow mode.
    "shadow_blocked": 0,
    "shadow_step_ups": 0,
    "shadow_allowed": 0,
}



# ─── Startup / Shutdown ──────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    global http_client
    http_client = httpx.AsyncClient(timeout=10.0)

    # Load persisted policy & snapshots
    load_state()

    # Fetch the RS256 public key from auth-service
    # Retry a few times in case auth-service isn't ready yet
    for attempt in range(10):
        try:
            resp = await http_client.get(f"{AUTH_SERVICE_URL}/public-key")
            if resp.status_code == 200:
                public_key_pem = resp.text.encode("utf-8")
                set_public_key(public_key_pem)
                logger.info("✓ RS256 public key fetched from auth-service (%d bytes)", len(public_key_pem))
                break
            else:
                logger.warning("Auth-service returned %d on /public-key (attempt %d)", resp.status_code, attempt + 1)
        except Exception as e:
            logger.warning("Cannot reach auth-service for public key (attempt %d): %s", attempt + 1, e)

        if attempt < 9:
            await asyncio.sleep(2)
        else:
            logger.error("FAILED to fetch public key after 10 attempts — identity verification will reject all tokens")

    # Start JTI replay protection background cleanup
    asyncio.create_task(jti_start_cleanup())
    logger.info("✓ JTI replay protection active")

    logger.info("CyberMesh Proxy v2 started in '%s' mode", proxy_mode)


@app.on_event("shutdown")
async def shutdown_event():
    if http_client:
        await http_client.aclose()


# ─── Health & Metrics ─────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "cybermesh-proxy",
        "version": "2.0",
        "mode": proxy_mode,
        "registered_services": registry_count(),
    }


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
        "registered_services": registry_count(),
        "jti_replay_protection": jti_get_stats(),
        "trust_decay": get_decay_stats(),
        "payload_baselines": get_all_baselines(),
        "scan_detector": get_all_scan_stats(),
        "shadow_mode": get_shadow_stats(),
        "shadow_counters": {
            "shadow_blocked": stats["shadow_blocked"],
            "shadow_step_ups": stats["shadow_step_ups"],
            "shadow_allowed": stats["shadow_allowed"],
        },
    }


# ─── Service Registration ────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    service_name: str
    internal_url: str
    secret: str

@app.post("/register")
async def register_service(req: RegisterRequest):
    """
    Register a service with the mesh.
    This forwards to auth-service (for token issuance) and also
    registers the service in the proxy's local registry (for routing).
    """
    # Forward registration to auth-service
    try:
        resp = await http_client.post(
            f"{AUTH_SERVICE_URL}/register-service",
            json={"service_name": req.service_name, "internal_url": req.internal_url, "secret": req.secret},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.json().get("detail", "Registration failed at auth-service"))
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Cannot reach auth-service for registration")

    # Register in local proxy registry for routing
    registry_register(req.service_name, req.internal_url)
    logger.info("Service registered in mesh: %s → %s", req.service_name, req.internal_url)

    return {
        "status": "registered",
        "service_name": req.service_name,
        "internal_url": req.internal_url,
        "message": f"{req.service_name} is now part of the CyberMesh. It can request tokens via POST /token."
    }


@app.get("/services")
async def list_services():
    """List all registered services with their mode and status."""
    services = registry_list_all()
    return {
        name: {
            "internal_url": svc.internal_url,
            "mode": svc.mode,
            "registered_at": svc.registered_at,
            "revoked": is_revoked(name),
        }
        for name, svc in services.items()
    }


@app.post("/services/{service_name}/promote")
async def promote_service(service_name: str):
    """
    Promote a service from shadow → enforced mode.

    After promotion, all BLOCK/STEP_UP decisions are enforced for
    requests coming from this service. Before promotion, they are
    computed and broadcast but the traffic is always forwarded.
    """
    if not shadow_promote(service_name):
        raise HTTPException(
            status_code=404,
            detail=f"Service '{service_name}' is not registered in CyberMesh"
        )
    logger.info("Service PROMOTED to enforced mode: %s", service_name)

    promote_event = CyberMeshEvent(
        event_type=EVENT_SERVICE_PROMOTED,
        caller=service_name,
        mode=proxy_mode,
        data={"service": service_name, "message": f"{service_name} promoted: shadow → enforced"},
    )
    broadcaster.broadcast(promote_event)

    return {
        "status": "promoted",
        "service": service_name,
        "mode": "enforced",
        "message": f"{service_name} is now under full zero-trust enforcement.",
    }


@app.post("/services/{service_name}/demote")
async def demote_service(service_name: str):
    """
    Demote a service from enforced → shadow mode.

    Used during rollbacks or when a service's learned policy needs
    to be rebuilt after a major config change. Use with caution.
    """
    if not shadow_demote(service_name):
        raise HTTPException(
            status_code=404,
            detail=f"Service '{service_name}' is not registered in CyberMesh"
        )
    logger.warning("Service DEMOTED to shadow mode: %s", service_name)
    return {
        "status": "demoted",
        "service": service_name,
        "mode": "shadow",
        "message": f"{service_name} is back in shadow mode (observational only).",
    }


# ─── Policy ──────────────────────────────────────────────────────────────────

@app.get("/policy")
async def get_policy():
    # Serialize 4-tuple keys as human-readable strings for the dashboard
    active = {
        f"{k[0]}→{k[1]} {k[2]} {k[3]}": {
            "count": v.get("count", 1),
            "last_seen": v.get("last_seen"),
        }
        for k, v in learned_policy.items()
    }
    return {
        "mode": proxy_mode,
        "learned_policy": get_observations(),
        "active_learned_count": len(learned_policy),
        "active_learned": active,
    }


@app.get("/policy/versions")
async def get_policy_versions():
    """List all available policy snapshots for rollback."""
    return {"versions": list_versions()}


@app.post("/policy/rollback/{version}")
async def rollback_to_version(version: int):
    """
    Roll back the active policy to a previous version snapshot.
    Instantly updates the policy engine and saves state.
    """
    restored = rollback_policy(version)
    if restored is None:
        raise HTTPException(status_code=404, detail=f"Policy version {version} not found")
    
    update_learned_policy(restored)
    save_state()
    logger.info("Rolled back to policy version %d", version)
    return {
        "status": "success",
        "message": f"Rolled back to version {version}",
        "rule_count": len(restored)
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
            
            # Phase 8+9: Snapshot and save
            ver = save_snapshot(new_policy, "Auto-generated after learning phase")
            save_state()
            
            logger.info("Policy auto-generated with %d rules (Saved as v%d)", len(new_policy), ver)

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
    scan_reset_caller(service_name)  # Clear any scan window for this service
    logger.warning("Service REVOKED: %s", service_name)

    revoke_event = CyberMeshEvent(
        event_type=EVENT_SERVICE_REVOKED,
        caller=service_name,
        mode=proxy_mode,
        data={"service": service_name, "message": f"{service_name} identity revoked via kill-switch"},
    )
    broadcaster.broadcast(revoke_event)

    return {"status": "revoked", "service": service_name}


@app.get("/scan-stats")
async def get_scan_stats():
    """Return real-time endpoint scan/recon detection state per caller."""
    return {
        "window_seconds": 5.0,
        "threshold": 4,
        "callers": get_all_scan_stats(),
    }


@app.get("/revoked")
async def get_revoked_services():
    return {"revoked_services": get_revoked()}


# ─── Decay Configuration ───────────────────────────────────────────────

class DecayConfigRequest(BaseModel):
    demo_mode: bool

@app.post("/decay-config")
async def configure_decay(body: DecayConfigRequest):
    """
    Toggle trust decay between production mode (10min half-life) and
    demo mode (2min half-life).

    Demo mode makes trust decay visibly observable in a live presentation
    without waiting 10 minutes for idle routes to drift.
    """
    decay_set_demo_mode(body.demo_mode)
    stats_snapshot = get_decay_stats()
    logger.info("Trust decay mode changed: demo_mode=%s", body.demo_mode)
    return {
        "status": "updated",
        "decay_config": stats_snapshot,
        "message": f"Half-life set to {stats_snapshot['half_life_seconds']}s ({stats_snapshot['mode_label']})",
    }


@app.get("/decay-config")
async def get_decay_config():
    """Return current trust decay configuration."""
    return get_decay_stats()


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
    jti_replayed = False

    # ─── Step 1: Identity Verification ────────────────────────────────────
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        token_service, identity_score, id_reasons, jti_replayed = await verify_token(token)
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
    policy_allow, behavior_score, pol_reasons, last_seen = policy_check(
        caller_service, target_service, request.method, f"/{path}", proxy_mode
    )
    reasons.extend(pol_reasons)

    # ─── Step 3b: Record in Learning Mode ─────────────────────────────────
    if proxy_mode == "learning" and caller_service != "unknown":
        record_observation(caller_service, target_service, request.method, f"/{path}")

    # ─── Step 3c: Endpoint Scan / Recon Detection ────────────────────────────
    # Only runs in enforce mode. Novel hits (Tier 2/3) are recorded into
    # a sliding window. If >=4 distinct novel endpoints are hit within 5s,
    # it's flagged as reconnaissance and scan_score overrides behavior_score.
    recon_alert = False
    if proxy_mode == "enforce" and behavior_score <= NOVEL_HIT_SCORE_THRESHOLD:
        record_novel_hit(
            caller_service,
            target_service,
            request.method,
            templatize(f"/{path}"),
        )
        scan_score, recon_alert, scan_detail = check_scan(caller_service)

        if recon_alert or scan_score < 100.0:
            # Override behavior_score with scan_score — recon overrides policy tier
            # The lower of the two wins (recon finding is more severe)
            behavior_score = min(behavior_score, scan_score)
            reasons.append(ReasonDetail(
                "endpoint_scan",
                "FAIL" if recon_alert else "WARN",
                scan_detail,
                int(scan_score),
            ))
            if recon_alert:
                logger.warning("RECON DETECTED: %s — %s", caller_service, scan_detail)

    # ─── Step 4: Context Checks ───────────────────────────────────────────
    body = b""
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()

    # Extract query string for injection scanning
    query_string = str(request.url.query) if request.url.query else ""

    context_score, ctx_reasons = check_context(
        caller=caller_service,
        target=target_service,
        payload=body.decode("utf-8", errors="ignore"),
        content_length=len(body),
        request_time=time.time(),
        method=request.method,
        query_string=query_string,
    )
    reasons.extend(ctx_reasons)

    # ─── Step 5: Trust Score + Decay ─────────────────────────────────────────
    # Decay is applied to behavior_score inside compute_trust based on last_seen.
    # decay_reasons are emitted into the event stream so the dashboard can
    # show the "trust drifting" visualization.
    trust_score, decision, band, decayed_behavior, decay_reasons = compute_trust(
        identity_score, behavior_score, context_score, last_seen
    )
    reasons.extend(decay_reasons)

    # ─── Step 5b: Shadow Mode Check ──────────────────────────────────────────
    caller_in_shadow = is_shadow(caller_service)
    if caller_in_shadow and decision != DECISION_ALLOW:
        would_have_been = decision
        actual_decision = DECISION_ALLOW
        # Count what the pipeline wanted to do (for shadow analytics)
        if decision == DECISION_BLOCK:
            stats["shadow_blocked"] += 1
        else:
            stats["shadow_step_ups"] += 1
        logger.info("SHADOW: %s \u2192 %s %s \u2014 would have been %s", caller_service, target_service, path, decision)
    else:
        would_have_been = ""
        actual_decision = decision
        if caller_in_shadow:
            # Pipeline said ALLOW and caller is in shadow — count as shadow_allowed
            stats["shadow_allowed"] += 1

    # ─── Step 6: Risk Explanation ─────────────────────────────────────────
    explanation = build_explanation(
        identity_reasons=[r for r in reasons if r.check in ("identity", "revocation")],
        policy_reasons=[r for r in reasons if r.check == "policy"],
        context_reasons=[r for r in reasons if r.check in (
            "rate_limit", "time_window", "payload", "payload_baseline", "behavior_decay"
        )],
        trust_score=trust_score,
        decision=actual_decision,
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
        decision=actual_decision,
        trust_score=round(trust_score, 1),
        identity_score=round(identity_score, 1),
        behavior_score=round(decayed_behavior, 1),
        context_score=round(context_score, 1),
        band=band,
        latency_ms=round(latency_ms, 2),
        reasons=reasons,
        mode=proxy_mode,
        jti_replayed=jti_replayed,
        shadow=caller_in_shadow,
        would_have_been=would_have_been,
        data={
            "behavior_score_raw": round(behavior_score, 1),
            "behavior_score_decayed": round(decayed_behavior, 1),
            "decay_applied": round(behavior_score - decayed_behavior, 1),
            "recon_alert": recon_alert,
        } if (behavior_score != decayed_behavior or recon_alert) else {"recon_alert": recon_alert},
    )
    broadcaster.broadcast(event)

    response_headers = {"X-CyberMesh-Latency-Ms": f"{latency_ms:.2f}"}
    if caller_in_shadow:
        response_headers["X-CyberMesh-Shadow"] = "true"
        response_headers["X-CyberMesh-Would-Have-Been"] = would_have_been or decision

    # ─── Decision: BLOCK ──────────────────────────────────────────────────
    if actual_decision == DECISION_BLOCK:
        stats["blocked"] += 1
        logger.warning("BLOCKED: %s \u2192 %s/%s (trust=%.1f)", caller_service, target_service, path, trust_score)
        return JSONResponse(
            status_code=403,
            content={
                "error": "Access denied by CyberMesh",
                "trust_score": round(trust_score, 1),
                "band": band,
                "decision": actual_decision,
                "reasons": [{"check": r.check, "result": r.result, "detail": r.detail} for r in reasons],
                **explanation,
            },
            headers=response_headers,
        )

    # ─── Decision: STEP_UP ────────────────────────────────────────────────
    if actual_decision == DECISION_STEP_UP:
        stats["step_ups"] += 1
        logger.info("STEP-UP: %s \u2192 %s/%s (trust=%.1f)", caller_service, target_service, path, trust_score)
        return JSONResponse(
            status_code=401,
            content={
                "action": "re-authenticate",
                "message": "Trust score in medium band — re-authentication required",
                "trust_score": round(trust_score, 1),
                "band": band,
                "decision": actual_decision,
                "reasons": [{"check": r.check, "result": r.result, "detail": r.detail} for r in reasons],
            },
            headers=response_headers,
        )

    # ─── Decision: ALLOW — Forward to Target ─────────────────────────────────
    stats["allowed"] += 1

    target_url = registry_resolve(target_service)
    if not target_url:
        raise HTTPException(status_code=404, detail=f"Target service '{target_service}' not registered in CyberMesh")

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
