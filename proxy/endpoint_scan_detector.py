"""
CyberMesh Proxy — Endpoint Scan / Reconnaissance Detector (Phase 6)

Detects when a caller is rapidly probing novel endpoints — a classic
attacker behavior after compromising a service. Each individual probe
looks like a Tier-2 policy miss (novel route on a known pair), which
individually triggers a STEP_UP. But the *pattern* — 4+ distinct
unknown routes in 5 seconds — is reconnaissance.

Detection algorithm:
    Maintain a per-caller sliding window of novel endpoint hits.
    A hit is "novel" if the policy engine returned Tier 2 or Tier 3
    (behavior_score ≤ TIER2_NORMAL_SCORE = 45).

    If a caller accumulates N_RECON_THRESHOLD distinct (target, method,
    template) tuples within WINDOW_SECONDS → RECON_DETECTED.

    "Distinct" means the endpoint shape is unique — hitting the same
    novel endpoint 4 times is not a scan, it's one miss repeated.

Score impact:
    When recon is detected, the scan_score component is returned as 0.
    This is combined with behavior and context scores in main.py to
    drive the request to BLOCK regardless of other checks.

    Crucially: the BLOCK happens on the request that tips the counter
    over the threshold — not the first hit. This gives legitimate
    services 3 chances before being flagged.

Demo attack: the attack_simulation.py script sends 5 rapid GET requests
to distinct, unlearned paths on a known service. First 3 pass (low trust,
STEP_UP). Hit 4 crosses the threshold — RECON fires, score → 0, BLOCK.

Competition note: This answers "Detecting and preventing unauthorized
lateral movement" at a behavioral pattern level. Individually clean
requests, caught as a coordinated pattern. This is what network IDS/IPS
tools do — CyberMesh does it inside the proxy at the service mesh layer.

Thread safety: all window mutations happen under a per-caller deque + a
global dict lock. Reads of the distinct count happen under the same lock.
"""

import time
import threading
from collections import deque
from typing import Dict, Deque, Tuple, Optional

# ─── Configuration ────────────────────────────────────────────────────────────

# Time window for recon detection (seconds)
WINDOW_SECONDS: float = 5.0

# Minimum distinct novel endpoints within the window to flag as recon
RECON_THRESHOLD: int = 4

# Score returned to the caller when scan is detected.
# 0 → plugged into behavior scoring → drives trust to BLOCK territory.
RECON_DETECTED_SCORE: float = 0.0

# Score when the caller is approaching but hasn't crossed the threshold.
# Slightly penalizes repeated novel hits even before full recon is flagged.
RECON_WARNING_SCORE: float = 30.0

# Behavior score threshold below which a hit counts as "novel".
# Tier 1 (known route) is 55–100. Tier 2 is 15–45. Tier 3 is 0.
# We treat anything ≤ TIER2_NORMAL_SCORE as novel for scan tracking.
NOVEL_HIT_SCORE_THRESHOLD: float = 45.0


# ─── Window state ─────────────────────────────────────────────────────────────

# Per-caller: deque of (timestamp, endpoint_fingerprint)
# endpoint_fingerprint = (target, method, path_template)
_windows: Dict[str, Deque[Tuple[float, Tuple[str, str, str]]]] = {}
_lock = threading.Lock()


def _evict_old_entries(window: Deque, now: float):
    """Remove entries older than WINDOW_SECONDS from the left of the deque."""
    while window and window[0][0] < now - WINDOW_SECONDS:
        window.popleft()


def _distinct_endpoints(window: Deque) -> int:
    """Count distinct endpoint fingerprints currently in the window."""
    return len({entry[1] for entry in window})


# ─── Public interface ─────────────────────────────────────────────────────────

def record_novel_hit(
    caller: str,
    target: str,
    method: str,
    path_template: str,
):
    """
    Record a novel endpoint hit for the given caller.

    Should be called from main.py when the policy engine returns Tier 2
    or Tier 3 (behavior_score ≤ NOVEL_HIT_SCORE_THRESHOLD).

    Args:
        caller:        Calling service name
        target:        Target service being called
        method:        HTTP method (uppercase)
        path_template: Templatized path (from path_template.templatize())
    """
    fingerprint = (target, method.upper(), path_template)
    now = time.time()

    with _lock:
        if caller not in _windows:
            _windows[caller] = deque()
        window = _windows[caller]
        _evict_old_entries(window, now)
        window.append((now, fingerprint))


def check_scan(
    caller: str,
) -> Tuple[float, bool, str]:
    """
    Check whether the caller's recent novel-endpoint hits constitute
    a reconnaissance pattern.

    Returns:
        (scan_score, is_scanning, detail_message)

        scan_score:  0.0 if recon confirmed, 30.0 if warning, 100.0 if clean
        is_scanning: True if recon threshold crossed
        detail:      Human-readable description for ReasonDetail
    """
    now = time.time()

    with _lock:
        if caller not in _windows:
            return (100.0, False, "No novel endpoint pattern detected")

        window = _windows[caller]
        _evict_old_entries(window, now)
        distinct = _distinct_endpoints(window)
        total_hits = len(window)

    if distinct >= RECON_THRESHOLD:
        return (
            RECON_DETECTED_SCORE,
            True,
            f"RECON DETECTED: {distinct} distinct novel endpoints probed "
            f"in {WINDOW_SECONDS:.0f}s window ({total_hits} total hits). "
            f"Threshold={RECON_THRESHOLD}. Possible endpoint enumeration.",
        )

    if distinct >= RECON_THRESHOLD - 1:
        # One away from threshold — issue a pre-emptive warning
        return (
            RECON_WARNING_SCORE,
            False,
            f"Scan warning: {distinct}/{RECON_THRESHOLD} distinct novel endpoints "
            f"in {WINDOW_SECONDS:.0f}s window — approaching recon threshold",
        )

    return (
        100.0,
        False,
        f"Novel endpoint pattern: {distinct} distinct in {WINDOW_SECONDS:.0f}s window (threshold={RECON_THRESHOLD})",
    )


def get_caller_stats(caller: str) -> dict:
    """Return current scan window stats for a caller (for diagnostics/dashboard)."""
    now = time.time()
    with _lock:
        if caller not in _windows:
            return {"distinct_novel_hits": 0, "total_hits": 0, "window_seconds": WINDOW_SECONDS}
        window = _windows[caller]
        _evict_old_entries(window, now)
        return {
            "distinct_novel_hits": _distinct_endpoints(window),
            "total_hits": len(window),
            "window_seconds": WINDOW_SECONDS,
            "threshold": RECON_THRESHOLD,
        }


def get_all_scan_stats() -> dict:
    """Return scan window stats for all callers (for /metrics endpoint)."""
    now = time.time()
    with _lock:
        result = {}
        for caller, window in _windows.items():
            _evict_old_entries(window, now)
            if window:  # Only include callers with active windows
                result[caller] = {
                    "distinct_novel_hits": _distinct_endpoints(window),
                    "total_hits": len(window),
                }
        return result


def reset_caller(caller: str):
    """
    Clear scan history for a caller. Called after a service re-registers
    or an admin manually clears a flag.
    """
    with _lock:
        if caller in _windows:
            _windows[caller].clear()
