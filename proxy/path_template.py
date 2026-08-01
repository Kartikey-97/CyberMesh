"""
CyberMesh Proxy — Path Template Normalization

Replaces dynamic identifiers in URL paths with `{id}` so that the
policy engine can recognize the same *route shape* regardless of
which specific resource is being accessed.

Without this, a policy learned from `GET /users/1` would not match
`GET /users/2`, forcing an impossible-to-maintain per-resource policy.
With it, `/users/{id}` becomes the stable, learnable policy key.

Recognized patterns (applied in priority order):
    1. UUID v4:          /resources/550e8400-e29b-41d4-a716-446655440000
    2. MongoDB ObjectID: /docs/507f1f77bcf86cd799439011  (24 hex chars)
    3. Pure numeric ID:  /orders/12345
    4. Short hex token:  /sessions/a3f5b2  (8-40 hex chars)

Competition note: This is what makes the 3-tier policy engine work at all.
Without path normalization, every unique resource ID creates a new policy
entry, the learned policy explodes in size, and false-positives on "novel
endpoint" checks become endemic. Normalizing paths is the prerequisite
for meaningful behavioral analysis.
"""

import re
from typing import Tuple

# ─── Regex patterns (applied left-to-right, first match wins) ────────────────

# UUID v4:  xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# MongoDB ObjectID: exactly 24 hex chars (standalone path segment)
_OBJECTID_RE = re.compile(r"(?<=/)[0-9a-f]{24}(?=/|$)", re.IGNORECASE)

# Pure numeric ID: one or more digits as a standalone path segment
_NUMERIC_RE = re.compile(r"(?<=/)\d+(?=/|$)")

# Short hex token: 8–40 hex chars as standalone path segment (session tokens etc.)
# Must not overlap with ObjectID (already handled above) and UUID
_HEX_RE = re.compile(r"(?<=/)[0-9a-f]{8,40}(?=/|$)", re.IGNORECASE)


# ─── Sensitive endpoint detection ────────────────────────────────────────────
#
# These patterns flag endpoints that carry elevated risk if accessed by an
# unexpected caller. Used by policy_engine.py to apply the SENSITIVE tier
# penalty on novel endpoint hits.
#
# Design: compiled once at import time for zero per-request overhead.

SENSITIVE_PATTERNS = re.compile(
    r"/(admin|root|superuser|internal|debug|shutdown|restart|config|secret|"
    r"password|passwd|credential|token|key|private|privileged|management|"
    r"backdoor|exec|execute|rce|exploit|shell)",
    re.IGNORECASE,
)

# DELETE method on any path is inherently sensitive
_SENSITIVE_METHODS = frozenset({"DELETE"})


def templatize(path: str) -> str:
    """
    Normalize a URL path by replacing dynamic ID segments with `{id}`.

    Args:
        path: Raw request path, e.g. ``/users/123/orders/abc-def``

    Returns:
        Templatized path, e.g. ``/users/{id}/orders/{id}``

    Examples:
        >>> templatize("/users/123")
        '/users/{id}'
        >>> templatize("/users/550e8400-e29b-41d4-a716-446655440000/orders")
        '/users/{id}/orders'
        >>> templatize("/docs/507f1f77bcf86cd799439011")
        '/docs/{id}'
        >>> templatize("/api/v2/health")
        '/api/v2/health'
        >>> templatize("/sessions/a3f5b2c1")
        '/sessions/{id}'
    """
    if not path:
        return "/"

    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path

    # Strip query string — we only template the path portion
    path = path.split("?")[0]

    # Apply substitutions in priority order
    result = _UUID_RE.sub("{id}", path)
    result = _OBJECTID_RE.sub("{id}", result)
    result = _NUMERIC_RE.sub("{id}", result)
    result = _HEX_RE.sub("{id}", result)

    # Collapse duplicate {id}/{id} that can appear in chained patterns
    result = re.sub(r"(\{id\}/)+\{id\}", "{id}/{id}", result)

    return result


def is_sensitive(path: str, method: str = "GET") -> bool:
    """
    Return True if this path+method combination is considered sensitive.

    Sensitive = elevated privilege risk if accessed by an unexpected caller.
    Used by the policy engine to apply the SENSITIVE scoring tier on novel hits.
    """
    if method.upper() in _SENSITIVE_METHODS:
        return True
    return bool(SENSITIVE_PATTERNS.search(path))


def policy_key(caller: str, target: str, method: str, path: str) -> Tuple[str, str, str, str]:
    """
    Build the canonical policy key for a request.

    Returns:
        (caller, target, METHOD, templatized_path)

    This is the 4-tuple used as the dict key in both learned_policy
    and the policy engine's lookup tables.
    """
    return (caller, target, method.upper(), templatize(path))
