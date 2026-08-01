"""In-flight identity revocation — the kill switch."""

revoked_services: set = set()


def revoke(service_name: str):
    """Revoke a service's identity immediately."""
    revoked_services.add(service_name)


def is_revoked(service_name: str) -> bool:
    """Check if a service has been revoked."""
    return service_name in revoked_services


def get_revoked() -> list:
    """Return list of all revoked services."""
    return list(revoked_services)


def unrevoke(service_name: str):
    """Restore a service's identity (for testing/demo reset)."""
    revoked_services.discard(service_name)


def clear_all():
    """Clear all revocations (for testing/demo reset)."""
    revoked_services.clear()
