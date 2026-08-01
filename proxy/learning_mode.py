"""
CyberMesh Proxy — Learning Mode (v3)

Records (caller, target, METHOD, path_template) observations during the
learning window so that the policy engine has a meaningful, path-aware
baseline to enforce against.

Key changes from v2:
    - record() now takes method + path, stores templatized form
    - Observation key is a 4-tuple matching policy_engine's lookup key
    - generate_policy() emits RouteRecord dicts (with count, timestamps)
      instead of bare True booleans — the engine uses count for confidence
    - Serialization helpers produce clean JSON for the dashboard and
      for policy_history.py (Phase 8) snapshots

Why this matters for the competition:
    The old engine stored ("user-service", "billing-service") → True.
    Any call between those two services was 100% trusted forever.
    That means a compromised billing-service could call /admin/secrets
    on user-service and the policy would give it a perfect 100 score.

    Now we store ("user-service", "billing-service", "GET", "/invoices") → {count: 47}.
    A call to GET /admin/secrets gets a Tier 2 SENSITIVE (15 score) even
    though the pair is known — and a DELETE /users/{id} also gets scored
    as novel+sensitive unless the DELETE method was specifically observed.
"""

import time
import threading
from typing import Dict, Tuple, Optional

from proxy.path_template import templatize, policy_key

# ─── Type alias ───────────────────────────────────────────────────────────────

# Key: (caller, target, METHOD, path_template)
PolicyKey = Tuple[str, str, str, str]

RouteRecord = Dict  # {"count", "first_seen", "last_seen", "methods", "paths_seen"}

# ─── State ────────────────────────────────────────────────────────────────────

observations: Dict[PolicyKey, RouteRecord] = {}
learning_start_time: Optional[float] = None
_lock = threading.Lock()


# ─── Control ──────────────────────────────────────────────────────────────────

def start_learning():
    """Reset observations and start a new learning window."""
    global learning_start_time, observations
    with _lock:
        learning_start_time = time.time()
        observations = {}


# ─── Recording ────────────────────────────────────────────────────────────────

def record(caller: str, target: str, method: str, path: str):
    """
    Record a single observed request during learning mode.

    Stores the templatized path so that /users/123 and /users/456 both
    contribute to the same route record.

    Args:
        caller: Service making the request
        target: Service receiving the request
        method: HTTP method (stored as uppercase)
        path:   Raw request path (will be templatized)
    """
    key = policy_key(caller, target, method, path)
    template = templatize(path)
    now = time.time()

    with _lock:
        if key not in observations:
            observations[key] = {
                "count": 1,
                "first_seen": now,
                "last_seen": now,
                "template": template,
                "method": method.upper(),
            }
        else:
            rec = observations[key]
            rec["count"] += 1
            rec["last_seen"] = now


# ─── Policy generation ────────────────────────────────────────────────────────

def generate_policy() -> Dict[PolicyKey, RouteRecord]:
    """
    Convert current observations into the policy dict consumed by
    policy_engine.update_learned_policy().

    Returns a copy — the live observations dict remains intact.
    """
    with _lock:
        return dict(observations)


# ─── Serialization (for dashboard + policy_history) ──────────────────────────

def get_observations() -> Dict:
    """
    Return observations as a JSON-serializable dict.

    Key format: "caller→target METHOD /template"
    e.g. "user-service→billing-service GET /invoices"
    """
    with _lock:
        return {
            f"{k[0]}→{k[1]} {k[2]} {k[3]}": {
                "count": v["count"],
                "first_seen": v["first_seen"],
                "last_seen": v["last_seen"],
                "template": v.get("template", k[3]),
                "method": k[2],
            }
            for k, v in observations.items()
        }


def get_observation_count() -> int:
    """Return number of distinct routes observed."""
    with _lock:
        return len(observations)


# ─── Timing ───────────────────────────────────────────────────────────────────

def is_learning_complete(window_seconds: int) -> bool:
    if not learning_start_time:
        return True
    return (time.time() - learning_start_time) >= window_seconds
