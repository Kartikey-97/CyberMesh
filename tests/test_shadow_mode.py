"""
Tests for CyberMesh Phase 7 — Shadow Mode

Covers:
    - shadow_mode.py: is_shadow(), promote(), demote(), get_shadow_stats()
    - Registry integration: mode transitions reflected correctly
    - Default mode for unregistered callers (enforced, not shadow)
    - Promotion is idempotent
    - Demotion on non-existent service returns False (no crash)

No Docker required — pure unit tests.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from proxy.registry import register, _registry
from proxy.shadow_mode import (
    is_shadow, promote, demote, get_shadow_stats, get_caller_mode
)


@pytest.fixture(autouse=True)
def clean_registry():
    """Reset registry between tests."""
    _registry.clear()
    yield
    _registry.clear()


class TestDefaultMode:
    def test_new_service_registers_in_shadow(self):
        register("svc-a", "http://svc-a:8001")
        assert is_shadow("svc-a") is True

    def test_unregistered_caller_defaults_to_enforced(self):
        """Unregistered strangers get no shadow bypass."""
        assert is_shadow("unknown-attacker") is False

    def test_get_caller_mode_unregistered(self):
        assert get_caller_mode("nobody") == "enforced"

    def test_get_caller_mode_shadow(self):
        register("svc-new", "http://svc-new:8002")
        assert get_caller_mode("svc-new") == "shadow"


class TestPromotion:
    def test_promote_moves_to_enforced(self):
        register("svc-a", "http://svc-a:8001")
        assert is_shadow("svc-a") is True

        result = promote("svc-a")
        assert result is True
        assert is_shadow("svc-a") is False
        assert get_caller_mode("svc-a") == "enforced"

    def test_promote_nonexistent_returns_false(self):
        result = promote("does-not-exist")
        assert result is False

    def test_promote_already_enforced_is_idempotent(self):
        register("svc-a", "http://svc-a:8001")
        promote("svc-a")
        result = promote("svc-a")  # promote again
        assert result is True
        assert get_caller_mode("svc-a") == "enforced"  # Still enforced, no error


class TestDemotion:
    def test_demote_moves_back_to_shadow(self):
        register("svc-a", "http://svc-a:8001")
        promote("svc-a")
        assert is_shadow("svc-a") is False

        result = demote("svc-a")
        assert result is True
        assert is_shadow("svc-a") is True

    def test_demote_nonexistent_returns_false(self):
        result = demote("does-not-exist")
        assert result is False

    def test_demote_already_shadow_is_idempotent(self):
        register("svc-a", "http://svc-a:8001")
        result = demote("svc-a")  # already shadow
        assert result is True
        assert is_shadow("svc-a") is True


class TestShadowStats:
    def test_empty_registry(self):
        stats = get_shadow_stats()
        assert stats["shadow_count"] == 0
        assert stats["enforced_count"] == 0
        assert stats["shadow_services"] == []
        assert stats["enforced_services"] == []

    def test_all_shadow(self):
        register("svc-a", "http://svc-a:8001")
        register("svc-b", "http://svc-b:8002")
        stats = get_shadow_stats()
        assert stats["shadow_count"] == 2
        assert stats["enforced_count"] == 0
        assert set(stats["shadow_services"]) == {"svc-a", "svc-b"}

    def test_mixed_modes(self):
        register("svc-a", "http://svc-a:8001")
        register("svc-b", "http://svc-b:8002")
        register("svc-c", "http://svc-c:8003")
        promote("svc-a")
        promote("svc-c")

        stats = get_shadow_stats()
        assert stats["shadow_count"] == 1
        assert stats["enforced_count"] == 2
        assert "svc-b" in stats["shadow_services"]
        assert "svc-a" in stats["enforced_services"]
        assert "svc-c" in stats["enforced_services"]

    def test_promote_then_demote_reflects_in_stats(self):
        register("svc-a", "http://svc-a:8001")
        promote("svc-a")
        assert get_shadow_stats()["enforced_count"] == 1

        demote("svc-a")
        assert get_shadow_stats()["shadow_count"] == 1
        assert get_shadow_stats()["enforced_count"] == 0


class TestMultipleServices:
    def test_each_service_independent_mode(self):
        for i in range(5):
            register(f"svc-{i}", f"http://svc-{i}:800{i}")

        # Promote only even ones
        for i in [0, 2, 4]:
            promote(f"svc-{i}")

        for i in range(5):
            expected = "enforced" if i in [0, 2, 4] else "shadow"
            assert get_caller_mode(f"svc-{i}") == expected, \
                f"svc-{i} expected {expected}, got {get_caller_mode(f'svc-{i}')}"

    def test_promoting_one_does_not_affect_others(self):
        register("svc-a", "http://svc-a")
        register("svc-b", "http://svc-b")

        promote("svc-a")
        # svc-b should still be shadow
        assert is_shadow("svc-b") is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
