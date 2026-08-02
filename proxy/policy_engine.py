"""
CyberMesh Proxy — Path-Aware Policy Engine (v3)

Key changes from v2 (binary allow/deny):
    - Policy keys: (caller, target, METHOD, path_template) — 4-tuple
    - Three-tier scoring based on observation confidence + path sensitivity
    - last_seen tracking per route for trust decay (Phase 4)
    - Observation count → score mapping (more observations = higher confidence)
    - Sensitive endpoint penalty on novel routes

Scoring model (enforce mode):
─────────────────────────────────────────────────────────────────────
  Tier 1 — EXACT MATCH (caller+target+method+path all known)
    obs=1:   55   (seen once, low confidence)
    obs=2-4: 70   (emerging pattern)
    obs=5-9: 85   (established route)
    obs≥10:  100  (well-established, high-confidence)

  Tier 2 — KNOWN PAIR, NOVEL ENDPOINT
    The caller↔target pair has been seen, but this specific method/path
    combination is new. Could be legitimate (new feature) or probing.
    - Sensitive path/method: 15  (policy:WARN, needs re-auth)
    - Normal path:           45  (policy:WARN, allowed but noted)

  Tier 3 — UNKNOWN PAIR
    This caller has never talked to this target. Score 0, BLOCK.
    This is the core lateral movement detection case.
─────────────────────────────────────────────────────────────────────

The returned `last_seen` timestamp feeds into trust_decay.py (Phase 4)
to apply temporal decay to the behavior score.

Competition note: This directly answers "Detecting and preventing
unauthorized lateral movement across microservices" in the PS.
An unknown pair (Tier 3) is lateral movement. A novel sensitive endpoint
(Tier 2 sensitive) is likely reconnaissance. Neither was detectable with
the old binary engine.
"""

import threading
from typing import Tuple, List, Dict, Optional
from shared.event_schema import ReasonDetail
from proxy.path_template import templatize, is_sensitive, policy_key

# ─── Type aliases ─────────────────────────────────────────────────────────────

# 4-tuple key: (caller, target, METHOD, path_template)
PolicyKey = Tuple[str, str, str, str]

# Per-route observation record
RouteRecord = Dict  # {"count": int, "first_seen": float, "last_seen": float}

# ─── Policy stores ────────────────────────────────────────────────────────────

# Learned policy: populated from learning_mode.generate_policy()
# Key → RouteRecord (with count for confidence scoring)
learned_policy: Dict[PolicyKey, RouteRecord] = {}

# Known pairs: set of (caller, target) that have been seen together at all.
# Used for Tier 2 detection — if the pair is known but the route is new.
known_pairs: set = set()

# Lock for thread-safe mutation during policy updates
_lock = threading.Lock()


def update_learned_policy(policy: Dict[PolicyKey, RouteRecord]):
    """
    Replace the active learned policy with a new one.
    Called when switching from learning → enforce mode, or on rollback.
    """
    global learned_policy, known_pairs
    with _lock:
        learned_policy.clear()
        learned_policy.update(policy)
        # Rebuild known_pairs from the new policy
        known_pairs = {(k[0], k[1]) for k in policy.keys()}


# ─── Scoring constants ────────────────────────────────────────────────────────

# Tier 1: Exact match — score based on observation count
def _obs_to_score(obs_count: int) -> float:
    """Map observation count to a behavior score (55–100)."""
    if obs_count >= 10:
        return 100.0
    elif obs_count >= 5:
        return 85.0
    elif obs_count >= 2:
        return 70.0
    else:
        return 55.0  # seen once — tentatively allow, low confidence


TIER2_SENSITIVE_SCORE = 15.0   # Known pair, novel sensitive endpoint
TIER2_NORMAL_SCORE = 45.0      # Known pair, novel normal endpoint
TIER3_SCORE = 0.0              # Unknown pair — BLOCK


# ─── Core check function ──────────────────────────────────────────────────────

def check(
    caller: str,
    target: str,
    method: str,
    path: str,
    mode: str,
) -> Tuple[bool, float, List[ReasonDetail], Optional[float]]:
    """
    Evaluate whether a request should be allowed based on learned policy.

    Args:
        caller:  Service name making the request
        target:  Service name being called
        method:  HTTP method (GET, POST, ...)
        path:    Raw request path (will be templatized internally)
        mode:    Proxy mode ("learning" | "enforce")

    Returns:
        (policy_allow, behavior_score, reasons, last_seen_timestamp)

        last_seen_timestamp: when this route was last observed during learning,
        or None if never seen. Fed into trust_decay.py.
    """
    reasons = []
    template = templatize(path)
    key = policy_key(caller, target, method, path)

    # ─── Learning mode: always pass, record nothing here ─────────────────────
    if mode == "learning":
        reasons.append(ReasonDetail(
            "policy", "PASS",
            f"Learning mode — observing {method} {template}",
            100
        ))
        return (True, 100.0, reasons, None)

    # ─── Enforce mode ─────────────────────────────────────────────────────────
    with _lock:
        record = learned_policy.get(key)
        pair_known = (caller, target) in known_pairs

    # ─── Tier 1: Exact match ──────────────────────────────────────────────────
    if record is not None:
        count = record.get("count", 1)
        last_seen = record.get("last_seen")
        score = _obs_to_score(count)

        reasons.append(ReasonDetail(
            "policy", "PASS",
            f"Known route: {caller} → {target} {method} {template} "
            f"(seen {count}× — confidence {'HIGH' if score >= 85 else 'MEDIUM' if score >= 70 else 'LOW'})",
            int(score)
        ))
        return (True, score, reasons, last_seen)

    # ─── Tier 2: Known pair, novel endpoint ───────────────────────────────────
    if pair_known:
        sensitive = is_sensitive(path, method)
        score = TIER2_SENSITIVE_SCORE if sensitive else TIER2_NORMAL_SCORE
        tier2_label = "SENSITIVE" if sensitive else "NORMAL"

        reasons.append(ReasonDetail(
            "policy", "WARN",
            f"Novel endpoint on known pair: {caller} → {target} {method} {template} "
            f"[{tier2_label}] — pair trusted but route unlearned",
            int(score)
        ))
        return (True, score, reasons, None)

    # ─── Tier 3: Unknown pair — lateral movement ─────────────────────────────
    reasons.append(ReasonDetail(
        "policy", "FAIL",
        f"Unknown service pair: {caller} has never been authorized to call {target}. "
        f"Possible lateral movement — BLOCK.",
        0
    ))
    return (False, TIER3_SCORE, reasons, None)
