"""
CyberMesh — Dynamic Service Registry (v2)

Replaces the static SERVICE_REGISTRY dict from shared/config.py.
Services register themselves at runtime via the auth-service,
and the proxy syncs with this registry to know where to route traffic.

Unregistered targets are unreachable by construction — this is itself
a zero-trust property, not just a routing convenience.
"""

from dataclasses import dataclass, field
from typing import Optional
import time
import logging

logger = logging.getLogger("cybermesh-registry")


@dataclass
class RegisteredService:
    name: str
    internal_url: str
    registered_at: float = field(default_factory=time.time)
    mode: str = "shadow"  # "shadow" | "enforced" — see shadow_mode.py


# The live registry — populated at runtime
_registry: dict[str, RegisteredService] = {}


def register(name: str, internal_url: str, mode: str = "shadow"):
    """Register or update a service in the proxy's local registry."""
    if name in _registry:
        _registry[name].internal_url = internal_url
        logger.info("Registry updated: %s → %s", name, internal_url)
    else:
        _registry[name] = RegisteredService(name=name, internal_url=internal_url, mode=mode)
        logger.info("Registry added: %s → %s (mode=%s)", name, internal_url, mode)


def resolve(name: str) -> Optional[str]:
    """Resolve a service name to its internal URL. Returns None if unregistered."""
    svc = _registry.get(name)
    return svc.internal_url if svc else None


def get_service(name: str) -> Optional[RegisteredService]:
    """Get the full RegisteredService object."""
    return _registry.get(name)


def list_all() -> dict[str, RegisteredService]:
    """Return the full registry."""
    return dict(_registry)


def set_mode(name: str, mode: str) -> bool:
    """Set a service's mode (shadow/enforced). Returns False if service not found."""
    svc = _registry.get(name)
    if not svc:
        return False
    svc.mode = mode
    logger.info("Registry mode changed: %s → %s", name, mode)
    return True


def is_registered(name: str) -> bool:
    """Check if a service is registered."""
    return name in _registry


def count() -> int:
    """Return number of registered services."""
    return len(_registry)
