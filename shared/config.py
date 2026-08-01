# CyberMesh — Shared Configuration
# These values MUST match across auth-service, proxy, and attack script.

# JWT Configuration
JWT_SECRET = "cybermesh-hackathon-secret-key-2026"
JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 60

# Pre-shared keys for service authentication with auth-service
SERVICE_SECRETS = {
    "user-service": "user-service-secret-key",
    "billing-service": "billing-service-secret-key",
    "admin-service": "admin-service-secret-key",
}

# Service Registry (internal Docker network URLs)
SERVICE_REGISTRY = {
    "user-service": "http://user-service:8001",
    "billing-service": "http://billing-service:8002",
    "admin-service": "http://admin-service:8003",
}

# Proxy Configuration
PROXY_PORT = 8080
AUTH_SERVICE_URL = "http://auth-service:8081"

# Learning Mode
LEARNING_WINDOW_SECONDS = 30

# Trust Score Weights
IDENTITY_WEIGHT = 0.4
BEHAVIOR_WEIGHT = 0.3
CONTEXT_WEIGHT = 0.3

# Trust Score Decision Bands
TRUST_ALLOW_THRESHOLD = 80
TRUST_STEP_UP_THRESHOLD = 50

# Rate Limiting
RATE_LIMIT_PER_SECOND = 10

# Time Window (allowed hours, 24h format)
ALLOWED_HOURS_START = 6
ALLOWED_HOURS_END = 22
