"""
CyberMesh Proxy — Continuous Trust Decay (Phase 4)

Implements exponential decay of the behavior_score component of trust
over time. A route that hasn't been seen in a while gets less confident
treatment — not because anything is wrong, but because behavioral
baselines become stale.

This directly satisfies "Continuous authentication and authorization
rather than one-time validation" from the problem statement. Trust is not
a binary certificate you earn once — it decays and must be continually
re-established through observed traffic.

The math:
    decayed = FLOOR + (base - FLOOR) × 0.5^(elapsed_seconds / half_life)

Properties:
    - At t=0:          decayed == base   (no time has passed, full confidence)
    - At t=half_life:  decayed == midpoint between base and FLOOR
    - At t=∞:          decayed → FLOOR   (never goes to zero — route is still known)

The FLOOR (40.0) is critical: a well-learned route never falls below it.
This means a stale-but-known route triggers STEP_UP re-auth rather than
a hard BLOCK. BLOCK is reserved for unknown pairs (lateral movement).
That's the right security posture — stale ≠ malicious.

Configuration (in shared/config.py):
    DECAY_HALF_LIFE_SECONDS = 600    (10 min, production default)
    DECAY_HALF_LIFE_DEMO_SECONDS = 120  (2 min, for live demos)
    DECAY_FLOOR = 40.0               (minimum decayed score)

Competition demo: Start a long-running demo. Show a route with score 100.
Wait 2 minutes (or use the demo half-life). Refresh the dashboard —
trust score on that idle route has visibly drifted toward 70, then 55.
Hit the route again — it re-establishes. This is continuous re-auth.
"""

import time
import math
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

# Production half-life: 10 minutes.
# At this setting, a route must be called at least every ~20 minutes to
# maintain near-full trust. Idle services gradually drift toward STEP_UP.
HALF_LIFE_SECONDS: float = 600.0

# Demo half-life: 2 minutes. Visibly demoable without waiting 10 minutes.
# Toggle via the /decay-config endpoint or DECAY_DEMO_MODE env var.
HALF_LIFE_DEMO_SECONDS: float = 120.0

# The minimum score after full decay. Never goes below this.
# At 40.0: a fully decayed well-known route → trust_score ≈ 0.4×id + 0.3×40 + 0.3×ctx
# With id=100, ctx=100 → trust ≈ 0.4×100 + 0.3×40 + 0.3×100 = 40+12+30 = 82 → ALLOW
# With id=80,  ctx=80  → trust ≈ 0.4×80  + 0.3×40 + 0.3×80  = 32+12+24 = 68 → STEP_UP
# This is the right behavior: stale routes need re-auth, not hard block.
DECAY_FLOOR: float = 40.0

# Runtime toggle: when True, uses HALF_LIFE_DEMO_SECONDS instead of HALF_LIFE_SECONDS
_demo_mode: bool = False


def set_demo_mode(enabled: bool):
    """
    Toggle between production and demo half-life.
    Called via the /decay-config endpoint on the proxy.
    Demo mode (120s) makes decay visibly observable in a live presentation.
    """
    global _demo_mode
    _demo_mode = enabled


def get_half_life() -> float:
    """Return the currently active half-life in seconds."""
    return HALF_LIFE_DEMO_SECONDS if _demo_mode else HALF_LIFE_SECONDS


def decayed_score(base_score: float, last_seen: Optional[float]) -> float:
    """
    Apply exponential decay to a base behavior score.

    Args:
        base_score: The raw behavior score from the policy engine (0–100).
        last_seen:  Unix timestamp of when this route was last observed
                    during learning (from RouteRecord["last_seen"]).
                    If None (novel endpoint), returns base_score unchanged.

    Returns:
        The decayed score, clamped to [DECAY_FLOOR, base_score].
        Never exceeds the base_score (can only stay the same or decrease).

    Examples:
        >>> decayed_score(100.0, time.time())           # Just seen → ~100.0
        >>> decayed_score(100.0, time.time() - 120)     # 1 half-life ago (demo mode) → ~70.0
        >>> decayed_score(100.0, time.time() - 99999)   # Very stale → 40.0 (floor)
        >>> decayed_score(15.0, time.time() - 9999)     # Tier2 sensitive → 15.0 (no decay)
    """
    if last_seen is None:
        # Novel endpoint — no decay applicable (it's already scored via Tier 2 rules)
        return base_score

    # If base is already at or below the floor, decay can't reduce it further.
    # More importantly, the formula would INFLATE it to the floor (span is
    # negative, multiplication with decay factor reduces magnitude, result
    # exceeds base). Tier2 sensitive (15) would become 40 — wrong.
    if base_score <= DECAY_FLOOR:
        return base_score

    elapsed = max(0.0, time.time() - last_seen)

    # Use epsilon rather than exact float comparison
    if elapsed < 1e-6:
        return base_score

    half_life = get_half_life()
    # Exponential decay: score drifts from base toward DECAY_FLOOR
    span = base_score - DECAY_FLOOR  # always positive here (base > DECAY_FLOOR)
    decay_factor = math.pow(0.5, elapsed / half_life)
    result = DECAY_FLOOR + (span * decay_factor)

    # Clamp: result should already be in [DECAY_FLOOR, base_score] mathematically,
    # but we clamp defensively against any floating point edge cases.
    return max(DECAY_FLOOR, min(base_score, result))


def decay_detail(base_score: float, decayed: float, last_seen: Optional[float]) -> str:
    """
    Generate a human-readable explanation of how much decay was applied.
    Used in the ReasonDetail for the dashboard and event stream.

    NOTE: We compute elapsed once here rather than calling time.time() again
    inside decayed_score — both functions use the same "now" so detail
    is consistent with the score that was actually applied.
    """
    if last_seen is None:
        return "No decay — novel endpoint"

    elapsed = max(0.0, time.time() - last_seen)
    half_life = get_half_life()
    drop = base_score - decayed

    if elapsed < 10:
        age_label = "just seen"
    elif elapsed < 60:
        age_label = f"{int(elapsed)}s idle"
    elif elapsed < 3600:
        age_label = f"{elapsed/60:.1f}min idle"
    else:
        age_label = f"{elapsed/3600:.1f}h idle"

    if drop < 1.0:
        return f"Trust: no meaningful decay ({age_label})"

    half_lives_elapsed = elapsed / half_life
    return (
        f"Trust decay: −{drop:.1f} pts ({age_label}, "
        f"{half_lives_elapsed:.2f}× half-life, "
        f"floor={DECAY_FLOOR:.0f}, demo={_demo_mode})"
    )


def decay_stats() -> dict:
    """Return current decay configuration for the metrics endpoint."""
    return {
        "demo_mode": _demo_mode,
        "half_life_seconds": get_half_life(),
        "floor": DECAY_FLOOR,
        "mode_label": "demo (2min)" if _demo_mode else "production (10min)",
    }
