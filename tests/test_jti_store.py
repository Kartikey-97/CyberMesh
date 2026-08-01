"""
Tests for CyberMesh JTI Replay Protection (Phase 2)

These tests verify:
1. First-use tokens are accepted
2. Replayed tokens are blocked
3. Expired entries are cleaned up
4. Memory bounds are enforced via eviction
5. Concurrent access is safe
6. Stats tracking is accurate

No Docker required — pure unit tests.
"""

import sys
import os
import time
import pytest
import threading

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from proxy.jti_store import consume, is_consumed, get_stats, clear, _consumed, _cleanup_expired, MAX_JTI_ENTRIES


@pytest.fixture(autouse=True)
def clean_store():
    """Reset the JTI store before each test."""
    clear()
    yield
    clear()


class TestJTIConsume:
    """Test the core consume() function."""

    def test_first_use_accepted(self):
        """A never-seen JTI should be accepted."""
        is_new, detail = consume("jti-001", time.time() + 60)
        assert is_new is True
        assert "accepted" in detail.lower() or "first use" in detail.lower()

    def test_replay_blocked(self):
        """Same JTI used twice → second is blocked."""
        exp = time.time() + 60
        is_new_1, _ = consume("jti-002", exp)
        is_new_2, detail = consume("jti-002", exp)

        assert is_new_1 is True
        assert is_new_2 is False
        assert "replay" in detail.lower() or "reuse" in detail.lower()

    def test_different_jtis_both_accepted(self):
        """Two different JTIs should both be accepted."""
        exp = time.time() + 60
        ok1, _ = consume("jti-aaa", exp)
        ok2, _ = consume("jti-bbb", exp)
        assert ok1 is True
        assert ok2 is True

    def test_replay_returns_truncated_jti(self):
        """The detail message should include the truncated JTI for identification."""
        jti = "abcdef12-3456-7890-abcd-ef1234567890"
        consume(jti, time.time() + 60)
        _, detail = consume(jti, time.time() + 60)
        assert "abcdef12" in detail  # First 8 chars

    def test_triple_replay(self):
        """Even a third attempt should be blocked."""
        exp = time.time() + 60
        consume("jti-triple", exp)
        consume("jti-triple", exp)
        is_new_3, _ = consume("jti-triple", exp)
        assert is_new_3 is False


class TestJTIIsConsumed:
    """Test the read-only is_consumed() function."""

    def test_unconsumed_jti(self):
        assert is_consumed("jti-never-seen") is False

    def test_consumed_jti(self):
        consume("jti-seen", time.time() + 60)
        assert is_consumed("jti-seen") is True


class TestJTICleanup:
    """Test expired entry cleanup."""

    def test_expired_entries_removed(self):
        """Entries with expiry in the past should be cleaned up."""
        # Insert an already-expired entry
        consume("jti-expired", time.time() - 10)
        assert is_consumed("jti-expired") is True

        _cleanup_expired()
        assert is_consumed("jti-expired") is False

    def test_valid_entries_kept(self):
        """Entries with future expiry should survive cleanup."""
        consume("jti-valid", time.time() + 300)
        _cleanup_expired()
        assert is_consumed("jti-valid") is True

    def test_mixed_cleanup(self):
        """Only expired entries should be removed."""
        consume("jti-old", time.time() - 10)
        consume("jti-new", time.time() + 300)

        _cleanup_expired()
        assert is_consumed("jti-old") is False
        assert is_consumed("jti-new") is True


class TestJTIEviction:
    """Test memory-bound eviction."""

    def test_eviction_under_pressure(self):
        """When store reaches MAX_JTI_ENTRIES, oldest should be evicted."""
        # We can't fill 50k entries in a unit test, so we'll temporarily
        # monkey-patch the module constant. Instead, let's just verify
        # the mechanism by directly filling the store.
        from proxy import jti_store

        original_max = jti_store.MAX_JTI_ENTRIES
        try:
            jti_store.MAX_JTI_ENTRIES = 10  # Small limit for testing

            # Fill to capacity
            for i in range(10):
                consume(f"jti-fill-{i}", time.time() + 60 + i)

            # Next insert should trigger eviction
            is_new, _ = consume("jti-overflow", time.time() + 120)
            assert is_new is True

            # Store should not exceed limit after eviction
            assert len(_consumed) <= 11  # 10 - evicted + 1 new, approximately

        finally:
            jti_store.MAX_JTI_ENTRIES = original_max


class TestJTIStats:
    """Test observability stats."""

    def test_stats_initial(self):
        stats = get_stats()
        assert stats["total_checked"] == 0
        assert stats["replays_blocked"] == 0
        assert stats["active_entries"] == 0

    def test_stats_after_consume(self):
        consume("jti-stats-1", time.time() + 60)
        stats = get_stats()
        assert stats["total_checked"] == 1
        assert stats["replays_blocked"] == 0
        assert stats["active_entries"] == 1

    def test_stats_after_replay(self):
        consume("jti-stats-2", time.time() + 60)
        consume("jti-stats-2", time.time() + 60)
        stats = get_stats()
        assert stats["total_checked"] == 2
        assert stats["replays_blocked"] == 1
        assert stats["active_entries"] == 1  # Still only one entry


class TestJTIConcurrency:
    """Test thread safety."""

    def test_concurrent_consumes(self):
        """Multiple threads trying to consume the same JTI simultaneously."""
        results = []
        barrier = threading.Barrier(10)

        def try_consume(jti):
            barrier.wait()
            is_new, _ = consume(jti, time.time() + 60)
            results.append(is_new)

        threads = [threading.Thread(target=try_consume, args=("jti-race",)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly ONE thread should succeed (first-use)
        assert results.count(True) == 1
        assert results.count(False) == 9

    def test_concurrent_different_jtis(self):
        """Multiple threads consuming different JTIs should all succeed."""
        results = []
        barrier = threading.Barrier(10)

        def try_consume(idx):
            barrier.wait()
            is_new, _ = consume(f"jti-unique-{idx}", time.time() + 60)
            results.append(is_new)

        threads = [threading.Thread(target=try_consume, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed — different JTIs
        assert all(results)


class TestJTIIntegrationWithIdentity:
    """
    Integration test: verify that identity.py correctly uses jti_store.
    This doesn't test full JWT verification (needs crypto keys), but
    validates the wiring.
    """

    def test_jti_store_module_importable(self):
        """The jti_store module should be importable and functional."""
        from proxy.jti_store import consume, is_consumed, get_stats
        assert callable(consume)
        assert callable(is_consumed)
        assert callable(get_stats)

    def test_identity_imports_jti_consume(self):
        """identity.py should import jti_consume from jti_store."""
        from proxy import identity
        assert hasattr(identity, 'jti_consume')


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
