import jwt
import time
from typing import Tuple, List
from shared.config import JWT_SECRET, JWT_ALGORITHM, TOKEN_TTL_SECONDS
from shared.event_schema import ReasonDetail

async def verify_token(token: str) -> Tuple[str, float, List[ReasonDetail]]:
    reasons = []
    try:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
            issuer="cybermesh-auth", audience="cybermesh-proxy"
        )
        service_name = payload.get("sub", "")
        exp = payload.get("exp")
        iat = payload.get("iat")
        jti = payload.get("jti")
        
        if not all([service_name, exp, iat, jti]):
            reasons.append(ReasonDetail("identity", "FAIL", "Missing required claims (sub, exp, iat, jti)", 0))
            return ("", 0.0, reasons)
            
        current_time = time.time()
        elapsed = current_time - iat
        
        if elapsed < (TOKEN_TTL_SECONDS * 0.5):
            score = 100.0
            reasons.append(ReasonDetail("identity", "PASS", "Token valid and fresh", 100))
        else:
            score = 70.0
            reasons.append(ReasonDetail("identity", "PASS", "Token valid but older than 50% TTL", 70))
            
        return (service_name, score, reasons)
        
    except jwt.ExpiredSignatureError:
        reasons.append(ReasonDetail("identity", "FAIL", "Token expired", 0))
        return ("", 0.0, reasons)
    except jwt.InvalidTokenError as e:
        reasons.append(ReasonDetail("identity", "FAIL", f"Invalid token: {str(e)}", 0))
        return ("", 0.0, reasons)
    except Exception as e:
        reasons.append(ReasonDetail("identity", "FAIL", f"Token error: {str(e)}", 0))
        return ("", 0.0, reasons)
