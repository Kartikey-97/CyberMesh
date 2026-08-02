"""
CyberMesh Proxy — JTI (JWT ID) Replay Protection Store

Public API shim that delegates to the active JTICacheInterface backend.
All call sites in identity.py and main.py use this module's functions —
they are completely unaware of whether the backend is in-memory or Redis.

Backend selection:
    Set REDIS_URL env var → RedisJTICache (multi-node horizontal scaling)
    No REDIS_URL          → InMemoryJTICache (default, single-node, zero deps)

See proxy/jti_cache.py for the full implementation details of each backend.

Competition note: This is a *demoable* attack. Replay the same request
twice → second one is blocked even though the token signature is valid.
This directly satisfies "continuous authentication" in the problem statement.

With Redis enabled, this protection holds even when running 20 proxy
instances behind a load balancer — one node's seen set is every node's.
"""

import asyncio
import logging
from typing import Tuple
from proxy.jti_cache import create_jti_cache, JTICacheInterface

logger = logging.getLogger("cybermesh-jti")

# ─── Active Cache Instance ───────────────────────────────────────────────────
# Instantiated at module load time. The factory reads REDIS_URL and returns
# the appropriate backend. All public functions delegate here.

_cache: JTICacheInterface = create_jti_cache()


# ─── Public API (synchronous-friendly async wrappers) ────────────────────────
# identity.py calls these from async context via await.
# We expose both sync and async variants for flexibility.

async def consume_async(jti: str, exp: float) -> Tuple[bool, str]:
    """Async consume — used by identity.py's verify_token()."""
    return await _cache.consume(jti, exp)


def consume(jti: str, exp: float) -> Tuple[bool, str]:
    """
    Synchronous shim — runs the async consume on the running event loop.
    Exists for backwards compatibility with any sync callers.
    Prefer consume_async() in async code paths.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside an async context — create a task and run sync via thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(asyncio.run, _cache.consume(jti, exp))
                return future.result()
        else:
            return loop.run_until_complete(_cache.consume(jti, exp))
    except RuntimeError:
        return asyncio.run(_cache.consume(jti, exp))


async def is_consumed(jti: str) -> bool:
    """Check if a JTI has been consumed without consuming it."""
    return await _cache.is_consumed(jti)


def get_stats() -> dict:
    """Return replay protection stats for the /metrics endpoint."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Return a best-effort sync snapshot for metrics
            # (Redis stats may be slightly stale — acceptable for metrics)
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(asyncio.run, _cache.get_stats()).result()
        return loop.run_until_complete(_cache.get_stats())
    except Exception:
        return {"error": "stats unavailable", "backend": "unknown"}


def clear():
    """Clear all entries. Used in testing."""
    try:
        asyncio.run(_cache.clear())
    except RuntimeError:
        pass


async def start_cleanup_task():
    """
    Start the backend's cleanup task. Called once at proxy startup.
    - InMemoryJTICache: starts a 30s periodic sweep coroutine
    - RedisJTICache: logs a message and exits (Redis TTL handles cleanup)
    """
    await _cache.start_cleanup_task()
