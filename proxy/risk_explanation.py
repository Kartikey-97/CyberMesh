from typing import List, Dict
from shared.event_schema import ReasonDetail

def build(identity_reasons: List[ReasonDetail], policy_reasons: List[ReasonDetail], context_reasons: List[ReasonDetail], trust_score: float, decision: str) -> Dict:
    all_reasons = identity_reasons + policy_reasons + context_reasons
    
    if trust_score >= 80:
        band = "high-trust"
    elif trust_score >= 50:
        band = "medium-trust"
    else:
        band = "low-trust"
        
    checks = []
    for r in all_reasons:
        checks.append({
            "check": r.check,
            "result": r.result,
            "detail": r.detail
        })
        
    return {
        "verdict": decision,
        "trust_score": trust_score,
        "band": band,
        "checks": checks
    }
