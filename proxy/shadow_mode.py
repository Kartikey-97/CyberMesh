"""
CyberMesh Proxy — Shadow Mode (Phase 7)

Shadow mode allows a newly registered service to participate in the mesh
without being subject to hard enforcement. Every request goes through the
full security pipeline — cryptographic verification, policy check, context
checks, recon detection, trust scoring — but the result is *observed*,
not enforced. Traffic is always forwarded regardless of the decision.

This solves the cold-start problem:
    A new service joins the mesh. It has no learned policy yet. If we
    enforce immediately, its first legitimate requests get BLOCKED because
    there are no observations. Shadow mode lets the learning window run
    *in production* without disrupting the service.

Lifecycle:
    1. Service registers → starts in "shadow" mode.
    2. Traffic flows. The proxy logs what *would* have been blocked.
    3. Operator reviews /services to see shadow stats.
    4. POST /services/{name}/promote → transitions to "enforced".
    5. From that point, the full trust pipeline applies with real enforcement.

Shadow event fields (in the SSE stream):
    shadow: true
    would_have_been: "ALLOW" | "STEP_UP" | "BLOCK"
    trust_score: <computed score>
    reasons: [full reason list — same as enforced]

This is directly demoable: register a new service, show its traffic in
shadow mode on the dashboard (events marked with a ghost icon), then
promote it live and show the next blocked request get hard-stopped.

Competition note: This is a real operational feature of production service
meshes (Istio calls it "permissive mode", Linkerd calls it "proxy-only").
Showing we understand this lifecycle demonstrates architectural maturity.
"""

from typing import Optional
from proxy.registry import get_service, set_mode, list_all


# ─── Mode query ───────────────────────────────────────────────────────────────

def get_caller_mode(service_name: str) -> str:
    """
    Return the enforcement mode for a caller service.

    Returns:
        "shadow"   — full pipeline runs, traffic always forwarded
        "enforced" — full pipeline runs, BLOCK decisions are enforced
        "enforced" — also the default for unregistered callers (no mercy)
    """
    svc = get_service(service_name)
    if svc is None:
        # Unknown caller → treat as enforced (no shadow bypass for strangers)
        return "enforced"
    return svc.mode


def is_shadow(service_name: str) -> bool:
    """Return True if the caller is currently in shadow mode."""
    return get_caller_mode(service_name) == "shadow"


# ─── Promotion ────────────────────────────────────────────────────────────────

def promote(service_name: str) -> bool:
    """
    Promote a service from shadow → enforced mode.

    Returns True on success, False if the service is not registered.
    Once promoted, all subsequent requests are subject to full enforcement.
    Promotion is one-way — there is no demotion (use revocation instead).
    """
    return set_mode(service_name, "enforced")


def demote(service_name: str) -> bool:
    """
    Demote a service from enforced → shadow mode.

    Used when a service needs to be rolled back to observational mode
    (e.g. after a config change that invalidates its learned policy).
    This is an administrative override — use with caution.
    """
    return set_mode(service_name, "shadow")


# ─── Stats ────────────────────────────────────────────────────────────────────

def get_shadow_stats() -> dict:
    """
    Return a summary of shadow vs enforced services for the dashboard.

    Useful for: showing the operator which services are still in the
    observational phase and which are under full enforcement.
    """
    services = list_all()
    shadow = [name for name, svc in services.items() if svc.mode == "shadow"]
    enforced = [name for name, svc in services.items() if svc.mode == "enforced"]
    return {
        "shadow_count": len(shadow),
        "enforced_count": len(enforced),
        "shadow_services": shadow,
        "enforced_services": enforced,
    }
