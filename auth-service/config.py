"""
Auth-service local config — v2.

No more importing secrets from shared config.
Auth-service only needs to know its own tuning parameters.
The shared config is read for JWT_ALGORITHM and TOKEN_TTL_SECONDS.
"""
import sys
sys.path.insert(0, '/app')

from shared.config import JWT_ALGORITHM, TOKEN_TTL_SECONDS
