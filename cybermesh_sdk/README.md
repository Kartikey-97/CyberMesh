# CyberMesh SDK

> **Zero-Trust protection for any Python microservice — two lines of code.**

## Installation

```bash
pip install cybermesh-sdk
# or, during development, mount the cybermesh_sdk/ directory
```

## Quick Start

```python
from fastapi import FastAPI
from cybermesh_sdk import CyberMeshMiddleware, MeshClient

app = FastAPI()

# 1. Protect ALL inbound endpoints — one line
#    Any request that bypasses the CyberMesh proxy is automatically blocked (403).
#    Any request without a valid JWT is rejected (401).
app.add_middleware(CyberMeshMiddleware)

# 2. Make outbound calls through the mesh
#    MeshClient routes automatically: proxy/proxy/{target}/{path}
#    and injects your service's JWT into every request.
mesh = MeshClient("my-service")

@app.get("/my-endpoint")
async def handler():
    # This call goes through CyberMesh — logged, scored, policy-enforced
    response = await mesh.get("other-service", "/some/path")
    return response.json()
```

## Why the SDK?

Without the SDK, services accept any traffic on their open ports.
An attacker who gains access to the internal network can bypass the CyberMesh
proxy entirely by calling `http://billing-service:8002/invoices` directly.

**With the SDK installed**, every inbound request is checked for:

| Check | Mechanism |
|-------|-----------|
| Came through the proxy | `X-Mesh-Caller` header must be present |
| Valid JWT | RS256 signature verified against auth-service public key |
| Trust score | `X-Mesh-Trust` header exposed on `request.state.mesh_trust` |
| Request lineage | `X-Mesh-Request-ID` for full distributed tracing |

Direct access attempts receive a **403 Access denied** immediately — the service
is unreachable without the mesh, regardless of network topology.

## Mesh Identity Headers

The CyberMesh proxy injects these headers on every forwarded request:

| Header | Example | Description |
|--------|---------|-------------|
| `X-Mesh-Caller` | `order-service` | Identity of the calling service |
| `X-Mesh-Trust` | `87.5` | Trust score at time of proxy decision |
| `X-Mesh-Request-ID` | `abc-123-xyz` | Unique lineage ID for distributed tracing |

Inside your handler, these are available via `request.state`:

```python
@app.get("/data")
async def handler(request: Request):
    caller = request.state.mesh_caller     # "order-service"
    trust  = request.state.mesh_trust      # 87.5
    req_id = request.state.mesh_request_id # "abc-123-xyz"
```

## MeshClient Reference

```python
mesh = MeshClient("my-service", proxy_url="http://proxy:8080")
await mesh.acquire_token(secret="my-service-secret")  # Call once at startup

await mesh.get("billing-service",    "/invoices")
await mesh.post("inventory-service", "/items/reserve", json={"item_id": 1})
await mesh.put("user-service",       "/users/1", json={"name": "Alice"})
await mesh.delete("order-service",   "/orders/501")
await mesh.aclose()  # Call at shutdown
```

## Adoption Story

For judges / investors: this is how any company adopts CyberMesh:

```
Without CyberMesh SDK          With CyberMesh SDK
──────────────────────         ──────────────────────────────────
Reconfigure every service      pip install cybermesh-sdk
Manually attach JWTs           app.add_middleware(CyberMeshMiddleware)
Build custom routing logic     client = MeshClient("my-service")
Handle token refresh           Done. Zero-trust enforced everywhere.
```
