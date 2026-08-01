from typing import Tuple, Optional
from shared.config import (
    IDENTITY_WEIGHT, BEHAVIOR_WEIGHT, CONTEXT_WEIGHT,
    TRUST_ALLOW_THRESHOLD, TRUST_STEP_UP_THRESHOLD
)
from shared.event_schema import BAND_HIGH, BAND_MEDIUM, BAND_LOW, DECISION_ALLOW, DECISION_STEP_UP, DECISION_BLOCK

def compute(
    identity_score: float,
    behavior_score: float,
    context_score: float,
    last_seen: Optional[float] = None,  # Phase 4: trust decay will use this
) -> Tuple[float, str, str]:
    """
    Compute final trust score from three component scores.

    last_seen: timestamp of last policy observation for this route.
    Currently unused here — Phase 4 (trust_decay.py) will apply
    exponential decay to behavior_score based on this timestamp.
    """
    trust_score = (
        (identity_score * IDENTITY_WEIGHT)
        + (behavior_score * BEHAVIOR_WEIGHT)
        + (context_score * CONTEXT_WEIGHT)
    )

    if trust_score >= TRUST_ALLOW_THRESHOLD:
        return (trust_score, DECISION_ALLOW, BAND_HIGH)
    elif trust_score >= TRUST_STEP_UP_THRESHOLD:
        return (trust_score, DECISION_STEP_UP, BAND_MEDIUM)
    else:
        return (trust_score, DECISION_BLOCK, BAND_LOW)
