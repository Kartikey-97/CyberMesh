"""
Tests for CyberMesh Phase 6 — Endpoint Scan / Recon Detection

Covers:
    - record_novel_hit() + check_scan() sliding window mechanics
    - Threshold-crossing behavior (warning at N-1, detected at N)
    - Window expiry (old hits evicted after WINDOW_SECONDS)
    - Repeated same endpoint does NOT count as distinct (no false positive)
    - Thread safety under concurrent novel hits
    - reset_caller() clears state
    - get_all_scan_stats() accuracy

Competition significance: These tests verify the core recon detection claim.
A failure in test_threshold_crossed would mean a compromised service can
enumerate N-1 endpoints without ever triggering the recon flag — a
serious gap against real lateral movement.

No Docker required — pure unit tests.
"""

import sys
import os
import time
import threading
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from proxy.endpoint_scan_detector import (
    record_novel_hit, check_scan, get_caller_stats, get_all_scan_stats,
    reset_caller, WINDOW_SECONDS, RECON_THRESHOLD,
    RECON_DETECTED_SCORE, RECON_WARNING_SCORE,
    _windows,
)


@pytest.fixture(autouse=True)
def clear_windows():
    """Reset all scan windows between tests."""
    _windows.clear()
    yield
    _windows.clear()


CALLER = "attacker-svc"
TARGET = "victim-svc"


def hit(path: str, method: str = "GET", caller: str = CALLER, target: str = TARGET):
    """Helper: record one novel hit."""
    record_novel_hit(caller, target, method, path)


class TestCleanState:
    def test_no_history_returns_clean(self):
        score, is_scanning, detail = check_scan(CALLER)
        assert score == 100.0
        assert is_scanning is False

    def test_single_hit_clean(self):
        hit("/api/users")
        score, is_scanning, _ = check_scan(CALLER)
        assert score == 100.0
        assert is_scanning is False

    def test_two_hits_clean(self):
        hit("/api/users")
        hit("/api/orders")
        score, is_scanning, _ = check_scan(CALLER)
        assert score == 100.0
        assert is_scanning is False


class TestWarningThreshold:
    """One below threshold → warning (not recon)."""

    def test_n_minus_1_triggers_warning(self):
        # RECON_THRESHOLD = 4 → 3 distinct hits should warn
        for i in range(RECON_THRESHOLD - 1):
            hit(f"/novel/endpoint/{i}")
        score, is_scanning, detail = check_scan(CALLER)
        assert is_scanning is False
        assert score == RECON_WARNING_SCORE
        assert "warning" in detail.lower() or "approaching" in detail.lower()


class TestReconDetection:
    """Threshold crossed → RECON_DETECTED."""

    def test_threshold_crossed(self):
        for i in range(RECON_THRESHOLD):
            hit(f"/novel/endpoint/{i}")
        score, is_scanning, detail = check_scan(CALLER)
        assert is_scanning is True
        assert score == RECON_DETECTED_SCORE
        assert "RECON" in detail or "recon" in detail.lower()

    def test_beyond_threshold_still_detected(self):
        for i in range(RECON_THRESHOLD + 5):
            hit(f"/endpoint/{i}")
        score, is_scanning, _ = check_scan(CALLER)
        assert is_scanning is True
        assert score == RECON_DETECTED_SCORE

    def test_detail_mentions_count(self):
        for i in range(RECON_THRESHOLD):
            hit(f"/path/{i}")
        _, _, detail = check_scan(CALLER)
        assert str(RECON_THRESHOLD) in detail

    def test_score_is_zero_on_recon(self):
        for i in range(RECON_THRESHOLD):
            hit(f"/path/{i}")
        score, _, _ = check_scan(CALLER)
        assert score == 0.0


class TestDistinctEndpoints:
    """Only distinct endpoints count — repeated same path is one hit."""

    def test_same_path_repeated_not_distinct(self):
        # Hit the same path 10 times
        for _ in range(10):
            hit("/api/users")
        score, is_scanning, _ = check_scan(CALLER)
        # Only 1 distinct endpoint — should NOT trigger recon
        assert is_scanning is False
        assert score == 100.0

    def test_same_path_different_method_counts_separately(self):
        # GET /secret and POST /secret are different fingerprints
        hit("/secret", method="GET")
        hit("/secret", method="POST")
        stats = get_caller_stats(CALLER)
        assert stats["distinct_novel_hits"] == 2

    def test_same_path_different_target_counts_separately(self):
        # Hitting /path on two different targets
        hit("/config", target="svc-a")
        hit("/config", target="svc-b")
        # Both are under the same caller window
        stats = get_caller_stats(CALLER)
        assert stats["distinct_novel_hits"] == 2


class TestWindowExpiry:
    """Entries older than WINDOW_SECONDS should be evicted."""

    def test_expired_hits_not_counted(self, monkeypatch):
        """Simulate old hits by backfating their timestamps."""
        now = time.time()
        # Inject 3 already-expired entries directly
        from collections import deque
        import proxy.endpoint_scan_detector as det
        det._windows[CALLER] = deque()
        old_ts = now - WINDOW_SECONDS - 1
        for i in range(RECON_THRESHOLD):
            det._windows[CALLER].append((old_ts, (TARGET, "GET", f"/old/{i}")))

        # Now check — all entries should be evicted
        score, is_scanning, _ = check_scan(CALLER)
        assert is_scanning is False
        assert score == 100.0

    def test_mixed_fresh_and_stale(self, monkeypatch):
        """Only fresh hits count toward threshold."""
        from collections import deque
        import proxy.endpoint_scan_detector as det

        now = time.time()
        det._windows[CALLER] = deque()
        old_ts = now - WINDOW_SECONDS - 1

        # 3 stale + 1 fresh
        for i in range(3):
            det._windows[CALLER].append((old_ts, (TARGET, "GET", f"/stale/{i}")))
        det._windows[CALLER].append((now, (TARGET, "GET", "/fresh/endpoint")))

        score, is_scanning, _ = check_scan(CALLER)
        # Only 1 fresh → below warning threshold
        assert is_scanning is False
        assert score == 100.0


class TestIsolationBetweenCallers:
    """Each caller has an independent window."""

    def test_one_caller_does_not_affect_another(self):
        # Fill up CALLER1 to recon threshold
        for i in range(RECON_THRESHOLD):
            record_novel_hit("attacker-1", TARGET, "GET", f"/path/{i}")

        # CALLER2 has zero hits
        score2, is_scanning2, _ = check_scan("attacker-2")
        assert is_scanning2 is False
        assert score2 == 100.0

    def test_two_callers_independent_counts(self):
        record_novel_hit("attacker-1", TARGET, "GET", "/path/a")
        record_novel_hit("attacker-2", TARGET, "GET", "/path/b")
        record_novel_hit("attacker-2", TARGET, "GET", "/path/c")

        stats1 = get_caller_stats("attacker-1")
        stats2 = get_caller_stats("attacker-2")

        assert stats1["distinct_novel_hits"] == 1
        assert stats2["distinct_novel_hits"] == 2


class TestReset:
    def test_reset_clears_window(self):
        for i in range(RECON_THRESHOLD):
            hit(f"/path/{i}")
        _, is_scanning, _ = check_scan(CALLER)
        assert is_scanning is True

        reset_caller(CALLER)
        score, is_scanning, _ = check_scan(CALLER)
        assert is_scanning is False
        assert score == 100.0

    def test_reset_nonexistent_caller_no_error(self):
        reset_caller("does-not-exist")  # Should not raise


class TestStats:
    def test_get_caller_stats_accuracy(self):
        hit("/a")
        hit("/b")
        hit("/b")  # Duplicate
        stats = get_caller_stats(CALLER)
        assert stats["distinct_novel_hits"] == 2
        assert stats["total_hits"] == 3
        assert stats["threshold"] == RECON_THRESHOLD

    def test_get_caller_stats_empty(self):
        stats = get_caller_stats("nobody")
        assert stats["distinct_novel_hits"] == 0
        assert stats["total_hits"] == 0

    def test_get_all_scan_stats_includes_active_callers(self):
        hit("/path/a")
        hit("/path/b")
        all_stats = get_all_scan_stats()
        assert CALLER in all_stats
        assert all_stats[CALLER]["distinct_novel_hits"] == 2


class TestThreadSafety:
    def test_concurrent_hits_no_corruption(self):
        """Multiple threads recording hits simultaneously should not corrupt state."""
        errors = []

        def worker(path_suffix: int):
            try:
                for j in range(10):
                    hit(f"/path/{path_suffix}/{j}")
                    check_scan(CALLER)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"
        # Should definitely be in RECON state after 8×10=80 hits on 80 distinct paths
        score, is_scanning, _ = check_scan(CALLER)
        assert is_scanning is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
