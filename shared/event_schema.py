"""
CyberMesh — Shared Event Schema
Defines the JSON structure for all events flowing through the SSE stream.
Used by both the proxy (producer) and dashboard (consumer).
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime, timezone
import uuid
import json


# Event Types
EVENT_REQUEST_DECISION = "request_decision"
EVENT_POLICY_GENERATED = "policy_generated"
EVENT_SERVICE_REVOKED = "service_revoked"
EVENT_MODE_CHANGED = "mode_changed"
EVENT_LEARNING_PROGRESS = "learning_progress"

# Decision Types
DECISION_ALLOW = "ALLOW"
DECISION_STEP_UP = "STEP_UP"
DECISION_BLOCK = "BLOCK"

# Trust Bands
BAND_HIGH = "high-trust"
BAND_MEDIUM = "medium-trust"
BAND_LOW = "low-trust"


@dataclass
class ReasonDetail:
    check: str          # "identity", "policy", "rate_limit", "time_window", "payload", "revocation"
    result: str         # "PASS" or "FAIL"
    detail: str         # Human-readable explanation
    score_impact: int = 0  # How much this affected the component score

    def to_dict(self):
        return asdict(self)


@dataclass
class CyberMeshEvent:
    event_type: str
    caller: str = ""
    target: str = ""
    path: str = ""
    method: str = ""
    decision: str = ""
    trust_score: float = 0.0
    identity_score: float = 0.0
    behavior_score: float = 0.0
    context_score: float = 0.0
    band: str = ""
    latency_ms: float = 0.0
    reasons: List[ReasonDetail] = field(default_factory=list)
    mode: str = "enforce"
    # Metadata
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Extra data for non-request events
    data: Optional[dict] = None

    def to_dict(self):
        d = asdict(self)
        d["reasons"] = [r.to_dict() if isinstance(r, ReasonDetail) else r for r in self.reasons]
        return d

    def to_json(self):
        return json.dumps(self.to_dict())
