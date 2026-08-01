"""
CyberMesh Proxy — Trust Score Computation (v4)

Combines three component scores into a final trust score that drives the
allow/step-up/block decision. Phase 4 adds exponential decay to the
behavior_score component.

Component weights (from shared/config.py):
    identity_score × 0.40   (cryptographic proof — who are you?)
    behavior_score × 0.30   (behavioral baseline — do you act normally?)
    context_score  × 0.30   (contextual signals — does this request look clean?)

The behavior_score from the policy engine represents "how well-established
is this route?" (Tier 1: 55–100, Tier 2: 15–45, Tier 3: 0). Phase 4 adds
temporal decay to this score: a route that was well-known but hasn't been
hit in a while gets a lower behavior_score, reflecting reduced confidence.

Decision bands:
    trust ≥ 80 → ALLOW
    trust 50–79 → STEP_UP (re-authenticate)
    trust < 50 → BLOCK

The decay design is intentional: even a fully decayed well-established
route (behavior=40) with a valid fresh token (identity=100) and clean
context (context=100) scores:
    0.4×100 + 0.3×40 + 0.3×100 = 40 + 12 + 30 = 82 → ALLOW (barely)

This means stale-but-known routes stay up, just barely. A slightly
suspicious context (context=70) tips it into STEP_UP territory — which
is exactly right. Continuous re-auth kicks in when *multiple* signals
are slightly off, not just one.
"""

import time
from typing import Tuple, Optional
from shared.config import (
    IDENTITY_WEIGHT, BEHAVIOR_WEIGHT, CONTEXT_WEIGHT,
    TRUST_ALLOW_THRESHOLD, TRUST_STEP_UP_THRESHOLD
)
from shared.event_schema import (
    BAND_HIGH, BAND_MEDIUM, BAND_LOW,
    DECISION_ALLOW, DECISION_STEP_UP, DECISION_BLOCK,
    ReasonDetail
)
from proxy.trust_decay import decayed_score, decay_detail


def compute(
    identity_score: float,
    behavior_score: float,
    context_score: float,
    last_seen: Optional[float] = None,
) -> Tuple[float, str, str, float, list]:
    """
    Compute the final trust score, applying temporal decay to behavior_score.

    Args:
        identity_score: RS256 JWT verification score (0–100)
        behavior_score: Policy engine score (0–100), reflects route confidence tier
        context_score:  Context check score (0–100)
        last_seen:      Unix timestamp of last policy observation for this route.
                        Used to apply exponential decay. None = no decay.

    Returns:
        (trust_score, decision, band, decayed_behavior_score, decay_reasons)

        decay_reasons: list of ReasonDetail entries describing decay applied.
        The caller should extend the main reasons list with these.
    """
    decay_reasons = []

    # Apply temporal decay to the behavior component only.
    # Identity and context are evaluated fresh on every request.
    # Behavior is the baseline — it's the only component that can go stale.
    decayed_behavior = decayed_score(behavior_score, last_seen)

    # Emit a decay reason if any decay occurred
    drop = behavior_score - decayed_behavior
    if drop >= 1.0:
        detail = decay_detail(behavior_score, decayed_behavior, last_seen)
        decay_reasons.append(ReasonDetail(
            check="behavior_decay",
            result="WARN",
            detail=detail,
            score_impact=int(-drop),
        ))

    trust_score = (
        (identity_score * IDENTITY_WEIGHT)
        + (decayed_behavior * BEHAVIOR_WEIGHT)
        + (context_score * CONTEXT_WEIGHT)
    )

    # Clamp to valid range
    trust_score = max(0.0, min(100.0, trust_score))

    if trust_score >= TRUST_ALLOW_THRESHOLD:
        decision, band = DECISION_ALLOW, BAND_HIGH
    elif trust_score >= TRUST_STEP_UP_THRESHOLD:
        decision, band = DECISION_STEP_UP, BAND_MEDIUM
    else:
        decision, band = DECISION_BLOCK, BAND_LOW

    return (trust_score, decision, band, decayed_behavior, decay_reasons)
