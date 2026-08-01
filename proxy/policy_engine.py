from typing import Tuple, List, Dict
from shared.event_schema import ReasonDetail

HARDCODED_POLICY: Dict[Tuple[str, str], bool] = {
    ("user-service", "billing-service"): True,
    ("billing-service", "user-service"): True,
    ("admin-service", "user-service"): True,
    ("admin-service", "billing-service"): True,
}

learned_policy: Dict[Tuple[str, str], bool] = {}

def update_learned_policy(policy: Dict[Tuple[str, str], bool]):
    global learned_policy
    learned_policy = policy

def check(caller: str, target: str, mode: str) -> Tuple[bool, float, List[ReasonDetail]]:
    reasons = []
    
    if mode == "learning":
        reasons.append(ReasonDetail("policy", "PASS", "Learning mode always allows", 100))
        return (True, 100.0, reasons)
        
    # Enforce mode
    pair = (caller, target)
    
    if pair in learned_policy:
        reasons.append(ReasonDetail("policy", "PASS", "Allowed by learned policy", 100))
        return (True, 100.0, reasons)
        
    if pair in HARDCODED_POLICY:
        reasons.append(ReasonDetail("policy", "PASS", "Allowed by hardcoded fallback policy", 50))
        return (True, 50.0, reasons)
        
    reasons.append(ReasonDetail("policy", "FAIL", f"No policy allows {caller} -> {target}", 0))
    return (False, 0.0, reasons)
