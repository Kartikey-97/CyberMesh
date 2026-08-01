"""
Tests for CyberMesh Phase 8 and 9 — Policy Versioning and Persistence

Covers:
    - Serialization and deserialization of policy keys (4-tuples)
    - Snapshot creation and storage
    - Ring buffer eviction (MAX_VERSIONS)
    - Saving and loading to/from JSON
    - Rollback restoring previous state
"""

import os
import json
import tempfile
import pytest

from proxy.policy_engine import update_learned_policy, learned_policy
from proxy.policy_versioning import (
    _snapshots,
    save_snapshot,
    list_versions,
    get_version,
    rollback_policy,
    MAX_VERSIONS,
    _key_to_str,
    _str_to_key,
)
import proxy.policy_persistence as pp


@pytest.fixture(autouse=True)
def clean_state():
    """Reset state between tests."""
    _snapshots.clear()
    update_learned_policy({})
    # Use a temp file for testing
    fd, tmp_file = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    old_file = pp.POLICY_FILE
    pp.POLICY_FILE = tmp_file
    
    yield
    
    pp.POLICY_FILE = old_file
    if os.path.exists(tmp_file):
        os.remove(tmp_file)


class TestKeySerialisation:
    def test_key_serialisation_roundtrip(self):
        key = ("caller-svc", "target-svc", "POST", "/api/v1/users/{id}")
        s = _key_to_str(key)
        assert s == "caller-svc|target-svc|POST|/api/v1/users/{id}"
        assert _str_to_key(s) == key

    def test_invalid_key_string(self):
        with pytest.raises(ValueError):
            _str_to_key("not-enough-parts")


class TestSnapshotRingBuffer:
    def test_save_and_list_snapshots(self):
        policy1 = {("a", "b", "GET", "/path"): {"count": 1, "last_seen": 100.0}}
        ver1 = save_snapshot(policy1, "snap 1")
        
        policy2 = {("a", "b", "GET", "/path2"): {"count": 2, "last_seen": 101.0}}
        ver2 = save_snapshot(policy2, "snap 2")
        
        versions = list_versions()
        assert len(versions) == 2
        # list_versions returns newest first
        assert versions[0]["version"] == ver2
        assert versions[1]["version"] == ver1

    def test_ring_buffer_eviction(self):
        for i in range(MAX_VERSIONS + 5):
            save_snapshot({("c", "t", "GET", f"/{i}"): {"count": 1}}, f"snap {i}")
            
        assert len(_snapshots) == MAX_VERSIONS
        versions = list_versions()
        # The oldest ones (0 to 4) should be gone
        # Newest is MAX_VERSIONS + 4
        assert versions[0]["version"] == MAX_VERSIONS + 5
        assert versions[-1]["version"] == 6


class TestRollback:
    def test_rollback_returns_copy_of_snapshot(self):
        policy = {("a", "b", "GET", "/path"): {"count": 1, "last_seen": 100.0}}
        ver = save_snapshot(policy, "test")
        
        restored = rollback_policy(ver)
        assert restored is not None
        assert restored == policy
        
        # Mutating the restored policy shouldn't affect the snapshot
        restored[("a", "b", "GET", "/path")]["count"] = 999
        snap = get_version(ver)
        assert snap.policy[("a", "b", "GET", "/path")]["count"] == 1

    def test_rollback_invalid_version(self):
        assert rollback_policy(9999) is None


class TestPersistence:
    def test_save_and_load_state(self):
        policy = {("svc-a", "svc-b", "GET", "/hello"): {"count": 5, "last_seen": 123.0}}
        update_learned_policy(policy)
        save_snapshot(policy, "baseline")
        
        # Save to disk
        pp.save_state()
        
        assert os.path.exists(pp.POLICY_FILE)
        
        # Clear memory
        update_learned_policy({})
        _snapshots.clear()
        
        # Load from disk
        assert pp.load_state() is True
        
        # Verify active policy
        assert len(learned_policy) == 1
        assert learned_policy[("svc-a", "svc-b", "GET", "/hello")]["count"] == 5
        
        # Verify snapshots
        assert len(_snapshots) == 1
        assert _snapshots[0].label == "baseline"

    def test_load_nonexistent_file(self):
        # Temp file created by fixture, delete it to test nonexistent
        os.remove(pp.POLICY_FILE)
        assert pp.load_state() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
