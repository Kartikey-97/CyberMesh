"""
CyberMesh Proxy — JTI (JWT ID) Replay Protection Store

Prevents token replay attacks by tracking consumed JTI values.
A replayed token is one where the JWT is cryptographically valid but has
already been presented — i.e. the attacker intercepted or copied a
legitimate request and is re-sending it.

Design decisions:
    - Separate module from identity.py for single-responsibility
    - Thread-safe via threading.Lock (async code runs on the event loop
      but we guard against concurrent access patterns)
    - Automatic expiry cleanup via periodic asyncio task
    - Max-size bound to prevent memory exhaustion under brute-force DoS
    - Returns rich detail strings for the event stream / dashboard

Competition note: This is a *demoable* attack. Replay the same request
twice → second one is blocked even though the token signature is valid.
This directly satisfies "continuous authentication" in the problem statement.
"""

import time
import asyncio
import threading
import logging
from datetime import datetime, timezone
from typing import Tuple, Optional

logger = logging.getLogger("cybermesh-jti")

# ─── Configuration ────────────────────────────────────────────────────────────

# Max JTIs to track. Beyond this, oldest entries are evicted.
# At 60s TTL and 100 req/s, worst case is ~6000 entries.
# We set 50k as a generous ceiling — ~2MB of memory.
MAX_JTI_ENTRIES = 50_000

# How often the cleanup task runs (seconds)
CLEANUP_INTERVAL_SECONDS = 30

# ─── Store ────────────────────────────────────────────────────────────────────

# jti_string → expiry_timestamp
_consumed: dict[str, float] = {}
_lock = threading.Lock()

# Stats for observability
_stats = {
    "total_checked": 0,
    "replays_blocked": 0,
    "entries_cleaned": 0,
    "evictions_forced": 0,
}


def consume(jti: str, exp: float) -> Tuple[bool, str]:
    """
    Attempt to consume a JTI. Returns (is_new, detail_message).

    - If jti has never been seen → record it, return (True, ...)
    - If jti was already consumed → return (False, ...) — this is a replay

    Args:
        jti: The JWT ID claim from the token
        exp: The token's expiry timestamp (we store this so cleanup
             knows when to garbage-collect the entry)
    """
    # Reject empty/missing JTIs — shouldn't happen with proper auth-service
    # but a forged token might try this
    if not jti or not isinstance(jti, str):
        return (
            False,
            "Missing or empty JTI claim — possible forged token"
        )

    exp_human = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%H:%M:%S UTC")

    with _lock:
        _stats["total_checked"] += 1

        if jti in _consumed:
            _stats["replays_blocked"] += 1
            return (
                False,
                f"Token reuse detected (jti={jti[:8]}… already consumed). "
                f"This is a replay attack — the token was valid but has already been used."
            )

        # Enforce size bound — evict oldest if at capacity
        if len(_consumed) >= MAX_JTI_ENTRIES:
            _evict_oldest_locked()

        _consumed[jti] = exp

    return (
        True,
        f"JTI {jti[:8]}… accepted (first use, valid until {exp_human})"
    )


def is_consumed(jti: str) -> bool:
    """Check if a JTI has already been consumed (without consuming it)."""
    with _lock:
        return jti in _consumed


def get_stats() -> dict:
    """Return replay protection stats for the metrics endpoint."""
    with _lock:
        return {
            **_stats,
            "active_entries": len(_consumed),
            "max_entries": MAX_JTI_ENTRIES,
        }


def clear():
    """Clear all entries. Used in testing."""
    with _lock:
        _consumed.clear()
        for key in _stats:
            _stats[key] = 0


# ─── Internal: Eviction ──────────────────────────────────────────────────────

def _evict_oldest_locked():
    """
    Evict the 10% oldest entries when at capacity.
    Called with _lock held. This is the safety valve against OOM under DoS.
    """
    evict_count = max(1, len(_consumed) // 10)
    # Sort by expiry (oldest first) and remove
    sorted_jtis = sorted(_consumed.items(), key=lambda x: x[1])
    for jti, _ in sorted_jtis[:evict_count]:
        del _consumed[jti]
    _stats["evictions_forced"] += evict_count
    logger.warning("JTI store at capacity (%d) — evicted %d oldest entries", MAX_JTI_ENTRIES, evict_count)


def _cleanup_expired():
    """Remove all entries whose token has expired. No point tracking them."""
    now = time.time()
    with _lock:
        expired = [jti for jti, exp in _consumed.items() if exp <= now]
        for jti in expired:
            del _consumed[jti]
        if expired:
            _stats["entries_cleaned"] += len(expired)
            logger.info("JTI cleanup: removed %d expired entries, %d remaining", len(expired), len(_consumed))


# ─── Background Cleanup Task ─────────────────────────────────────────────────

async def start_cleanup_task():
    """
    Run periodic cleanup of expired JTIs. Called once at proxy startup.
    This prevents unbounded memory growth — expired tokens are useless
    to track since they'll fail JWT verification anyway.
    """
    logger.info("JTI cleanup task started (interval=%ds)", CLEANUP_INTERVAL_SECONDS)
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
        _cleanup_expired()
