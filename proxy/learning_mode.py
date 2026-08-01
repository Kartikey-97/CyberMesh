import time
from typing import Dict, Tuple

observations: Dict[Tuple[str, str], Dict] = {}
learning_start_time = None

def start_learning():
    global learning_start_time, observations
    learning_start_time = time.time()
    observations = {}

def record(caller: str, target: str):
    pair = (caller, target)
    now = time.time()
    if pair not in observations:
        observations[pair] = {"count": 1, "first_seen": now, "last_seen": now}
    else:
        observations[pair]["count"] += 1
        observations[pair]["last_seen"] = now

def generate_policy() -> Dict[Tuple[str, str], bool]:
    policy = {}
    for pair in observations.keys():
        policy[pair] = True
    return policy

def get_observations() -> Dict:
    # Convert keys to strings for JSON serialization
    return {f"{k[0]}->{k[1]}": v for k, v in observations.items()}

def is_learning_complete(window_seconds: int) -> bool:
    if not learning_start_time:
        return True
    return (time.time() - learning_start_time) >= window_seconds
