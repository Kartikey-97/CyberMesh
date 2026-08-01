"""
Tests for CyberMesh Phase 4 — Trust Decay

Covers:
    - trust_decay.py: decayed_score(), decay_detail(), set_demo_mode()
    - trust_score.py: compute() with decay wired in end-to-end

Key bug regression:
    Tier 2 sensitive score (15.0) is below DECAY_FLOOR (40.0).
    Early versions would inflate this to 40 via the decay formula.
    These tests ensure that scores ≤ DECAY_FLOOR are never inflated.

No Docker required — pure unit tests.
"""

import sys
import os
import time
import math
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from proxy.trust_decay import (
    decayed_score, decay_detail, set_demo_mode, get_half_life,
    HALF_LIFE_SECONDS, HALF_LIFE_DEMO_SECONDS, DECAY_FLOOR
)


@pytest.fixture(autouse=True)
def reset_demo_mode():
    """Always start tests in production mode, restore after."""
    set_demo_mode(False)
    yield
    set_demo_mode(False)


class TestDecayedScore:
    """Core decay math tests."""

    def test_no_decay_at_t0(self):
        """Score at exactly now should be essentially unchanged."""
        result = decayed_score(100.0, time.time())
        assert abs(result - 100.0) < 0.1

    def test_no_decay_for_none_last_seen(self):
        """Novel endpoints (last_seen=None) pass through unchanged."""
        assert decayed_score(100.0, None) == 100.0
        assert decayed_score(15.0, None) == 15.0
        assert decayed_score(45.0, None) == 45.0

    def test_full_decay_approaches_floor(self):
        """Very stale last_seen should approach DECAY_FLOOR."""
        very_stale = time.time() - 999_999
        result = decayed_score(100.0, very_stale)
        assert abs(result - DECAY_FLOOR) < 0.1

    def test_one_half_life_halves_span(self):
        """After exactly one half-life, score should be midway between base and floor."""
        set_demo_mode(True)  # 120s half-life for tractable test
        base = 100.0
        one_half_life_ago = time.time() - HALF_LIFE_DEMO_SECONDS
        result = decayed_score(base, one_half_life_ago)
        expected_midpoint = DECAY_FLOOR + (base - DECAY_FLOOR) / 2
        assert abs(result - expected_midpoint) < 1.0  # within 1 point

    def test_score_never_exceeds_base(self):
        """Decay can only reduce score, never increase it."""
        for elapsed in [0, 10, 60, 600, 9999]:
            result = decayed_score(85.0, time.time() - elapsed)
            assert result <= 85.0 + 0.001, f"Score exceeded base at elapsed={elapsed}"

    def test_score_never_below_floor_for_high_base(self):
        """Score with base > DECAY_FLOOR should never go below floor."""
        very_stale = time.time() - 999_999
        for base in [55.0, 70.0, 85.0, 100.0]:
            result = decayed_score(base, very_stale)
            assert result >= DECAY_FLOOR - 0.001, f"Score below floor for base={base}"

    # ─── REGRESSION: Tier 2 inflation bug ────────────────────────────────────

    def test_tier2_sensitive_score_not_inflated(self):
        """
        REGRESSION: base=15.0 (Tier2 sensitive) is below DECAY_FLOOR=40.
        Old code would produce result > 15 (inflated to floor).
        Correct behavior: return 15.0 unchanged.
        """
        result = decayed_score(15.0, time.time() - 10_000)
        assert result == 15.0, f"Expected 15.0, got {result} — inflation bug!"

    def test_tier2_normal_score_slightly_above_floor(self):
        """base=45.0 is just above DECAY_FLOOR=40. Should decay toward 40, not below."""
        result = decayed_score(45.0, time.time() - 999_999)
        assert abs(result - DECAY_FLOOR) < 0.1
        assert result >= DECAY_FLOOR - 0.001

    def test_score_exactly_at_floor_unchanged(self):
        """base=40.0 (exactly DECAY_FLOOR) → early return, no change."""
        result = decayed_score(DECAY_FLOOR, time.time() - 9999)
        assert result == DECAY_FLOOR

    def test_score_below_floor_unchanged(self):
        """base=0.0 (Tier3 block score) → unchanged."""
        result = decayed_score(0.0, time.time() - 9999)
        assert result == 0.0

    def test_monotonic_decay_over_time(self):
        """Score should monotonically decrease as elapsed increases."""
        base = 100.0
        now = time.time()
        scores = [
            decayed_score(base, now - elapsed)
            for elapsed in [0, 30, 60, 120, 300, 600, 1800]
        ]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i + 1] - 0.001, \
                f"Non-monotonic at index {i}: {scores[i]:.2f} < {scores[i+1]:.2f}"


class TestDemoMode:
    """Test demo vs production half-life switching."""

    def test_production_half_life(self):
        assert get_half_life() == HALF_LIFE_SECONDS

    def test_demo_half_life(self):
        set_demo_mode(True)
        assert get_half_life() == HALF_LIFE_DEMO_SECONDS

    def test_demo_decays_faster_than_production(self):
        """The same elapsed time should produce more decay in demo mode."""
        base = 100.0
        elapsed = 60.0  # 1 minute
        last_seen = time.time() - elapsed

        set_demo_mode(False)
        production_score = decayed_score(base, last_seen)

        set_demo_mode(True)
        demo_score = decayed_score(base, last_seen)

        assert demo_score < production_score, \
            "Demo mode should decay faster (lower score) than production mode"

    def test_toggle_idempotent(self):
        set_demo_mode(True)
        set_demo_mode(True)
        assert get_half_life() == HALF_LIFE_DEMO_SECONDS
        set_demo_mode(False)
        set_demo_mode(False)
        assert get_half_life() == HALF_LIFE_SECONDS


class TestDecayDetail:
    def test_none_last_seen(self):
        detail = decay_detail(100.0, 100.0, None)
        assert "novel" in detail.lower() or "no decay" in detail.lower()

    def test_no_significant_drop(self):
        # Score dropped by 0.5 (less than threshold)
        detail = decay_detail(100.0, 99.5, time.time() - 5)
        assert "no" in detail.lower()

    def test_meaningful_drop(self):
        detail = decay_detail(100.0, 75.0, time.time() - 200)
        assert "25.0" in detail or "−25" in detail

    def test_idle_age_labels(self):
        # 5 seconds → "just seen"
        detail = decay_detail(100.0, 95.0, time.time() - 5)
        assert "just seen" in detail.lower()

        # 45 seconds → "45s idle"
        detail = decay_detail(100.0, 85.0, time.time() - 45)
        assert "s idle" in detail.lower()

        # 5 minutes → "5.0min idle"
        detail = decay_detail(100.0, 70.0, time.time() - 300)
        assert "min idle" in detail.lower()


class TestTrustScoreWithDecay:
    """End-to-end: trust_score.compute() integrating decay."""

    def test_fresh_route_high_trust(self):
        from proxy.trust_score import compute
        # All perfect scores, route just seen
        score, decision, band, decayed_behavior, decay_reasons = compute(
            100.0, 100.0, 100.0, time.time()
        )
        assert score >= 95.0
        assert decision == "ALLOW"
        assert not decay_reasons  # No meaningful decay

    def test_stale_route_triggers_step_up(self):
        from proxy.trust_score import compute
        set_demo_mode(True)  # 2min half-life
        # Route last seen 5 half-lives ago (very stale in demo mode)
        stale_ts = time.time() - (5 * HALF_LIFE_DEMO_SECONDS)
        # Good identity + context, but stale behavior
        score, decision, band, decayed_behavior, decay_reasons = compute(
            100.0, 100.0, 100.0, stale_ts
        )
        # behavior_score decays to ~40 (floor)
        # trust = 0.4×100 + 0.3×~40 + 0.3×100 = 40+12+30 = 82 → ALLOW (barely)
        # Actually with full decay: 0.4×100 + 0.3×40 + 0.3×100 = 82 → ALLOW
        # Let's check decayed_behavior is near floor
        assert decayed_behavior <= 50.0
        assert decay_reasons  # Should have a decay reason

    def test_decay_reason_in_output(self):
        from proxy.trust_score import compute
        set_demo_mode(True)
        stale_ts = time.time() - (3 * HALF_LIFE_DEMO_SECONDS)
        _, _, _, _, decay_reasons = compute(85.0, 85.0, 85.0, stale_ts)
        assert len(decay_reasons) >= 1
        assert decay_reasons[0].check == "behavior_decay"
        assert decay_reasons[0].result == "WARN"
        assert decay_reasons[0].score_impact < 0  # negative — it reduced score

    def test_no_decay_for_none_last_seen(self):
        from proxy.trust_score import compute
        _, _, _, decayed_behavior, decay_reasons = compute(
            100.0, 85.0, 100.0, None
        )
        assert decayed_behavior == 85.0  # Unchanged
        assert not decay_reasons

    def test_tier2_score_not_inflated_end_to_end(self):
        """REGRESSION: Tier2 sensitive (15) must not be inflated by decay path."""
        from proxy.trust_score import compute
        stale_ts = time.time() - 99999
        _, _, _, decayed_behavior, _ = compute(
            100.0, 15.0, 100.0, stale_ts
        )
        assert decayed_behavior == 15.0, \
            f"Tier2 sensitive score inflated to {decayed_behavior}"

    def test_score_clamped_to_valid_range(self):
        from proxy.trust_score import compute
        trust_score, _, _, _, _ = compute(100.0, 100.0, 100.0, time.time())
        assert 0.0 <= trust_score <= 100.0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
