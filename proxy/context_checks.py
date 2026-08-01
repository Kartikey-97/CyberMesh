import time
from collections import deque
from typing import Tuple, List, Dict
from shared.config import RATE_LIMIT_PER_SECOND, ALLOWED_HOURS_START, ALLOWED_HOURS_END
from shared.event_schema import ReasonDetail
from datetime import datetime, timezone

# Rate limit state: caller -> deque of timestamps
rate_limits: Dict[str, deque] = {}

def evaluate(caller: str, target: str, payload: str, content_length: int, request_time: float) -> Tuple[float, List[ReasonDetail]]:
    reasons = []
    
    # 1. Rate Limiting
    now = time.time()
    if caller not in rate_limits:
        rate_limits[caller] = deque()
    
    # Clean up old timestamps (older than 1 second)
    while rate_limits[caller] and rate_limits[caller][0] < now - 1.0:
        rate_limits[caller].popleft()
        
    rate_limits[caller].append(now)
        
    if len(rate_limits[caller]) > RATE_LIMIT_PER_SECOND:
        rl_score = 0.0
        reasons.append(ReasonDetail("rate_limit", "FAIL", f"Exceeded {RATE_LIMIT_PER_SECOND} req/s", 0))
    else:
        rl_score = 100.0
        reasons.append(ReasonDetail("rate_limit", "PASS", "Under rate limit", 100))
        
    # 2. Time-of-day
    current_hour = datetime.fromtimestamp(request_time, timezone.utc).hour
    if ALLOWED_HOURS_START <= current_hour < ALLOWED_HOURS_END:
        time_score = 100.0
        reasons.append(ReasonDetail("time_window", "PASS", "Within allowed hours", 100))
    else:
        time_score = 60.0
        reasons.append(ReasonDetail("time_window", "FAIL", "Outside allowed hours", 60))
        
    # 3. Payload anomaly
    payload_score = 100.0
    payload_upper = payload.upper()
    suspicious_patterns = ["SELECT ", "DROP ", "UNION ", "INSERT ", "DELETE ", "UPDATE ", "ALTER ", "EXEC ", "../", "<SCRIPT", "JAVASCRIPT:"]
    
    if content_length > 10240:
        payload_score = 0.0
        reasons.append(ReasonDetail("payload", "FAIL", "Payload too large (>10KB)", 0))
    else:
        is_clean = True
        for pattern in suspicious_patterns:
            if pattern in payload_upper:
                is_clean = False
                payload_score = 0.0
                reasons.append(ReasonDetail("payload", "FAIL", f"Suspicious pattern detected: {pattern.strip()}", 0))
                break
                
        if is_clean:
            reasons.append(ReasonDetail("payload", "PASS", "Payload looks clean", 100))
            
    # Calculate average context score
    context_score = (rl_score + time_score + payload_score) / 3.0
    
    return (context_score, reasons)
