# CyberMesh — Shared Configuration
# Only tuning constants. No secrets, no registry — those are runtime-populated.

import os

# ─── Auth Service Location ────────────────────────────────────────────────────
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth-service:8081")

# ─── JWT Configuration ────────────────────────────────────────────────────────
# Algorithm is always RS256 in v2. No shared secret exists.
JWT_ALGORITHM = "RS256"
TOKEN_TTL_SECONDS = 60

# ─── Trust Score Weights ──────────────────────────────────────────────────────
IDENTITY_WEIGHT = 0.4
BEHAVIOR_WEIGHT = 0.3
CONTEXT_WEIGHT = 0.3

# ─── Trust Score Decision Bands ───────────────────────────────────────────────
TRUST_ALLOW_THRESHOLD = 80
TRUST_STEP_UP_THRESHOLD = 50

# ─── Rate Limiting ────────────────────────────────────────────────────────────
RATE_LIMIT_PER_SECOND = 10

# ─── Time Window (allowed hours, 24h format, UTC) ─────────────────────────────
ALLOWED_HOURS_START = 6
ALLOWED_HOURS_END = 22

# ─── Proxy ────────────────────────────────────────────────────────────────────
PROXY_PORT = 8080

# ─── Learning Mode ────────────────────────────────────────────────────────────
LEARNING_WINDOW_SECONDS = 30
