"""
Tests for CyberMesh Phase 3 — Path-Aware Policy Engine

Covers:
    - path_template.py: templatize(), is_sensitive(), policy_key()
    - learning_mode.py: record(), generate_policy(), get_observations()
    - policy_engine.py: Tier 1/2/3 scoring, unknown pair detection,
                        known pair + novel endpoint, known pair + known route

No Docker required — pure unit tests.

Competition significance: These tests verify the core lateral movement
detection capability. A failing test_tier3_unknown_pair means the engine
would allow a compromised service to reach any target freely.
"""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# ─── Path Template Tests ───────────────────────────────────────────────────────

from proxy.path_template import templatize, is_sensitive, policy_key


class TestTemplatize:
    def test_numeric_id(self):
        assert templatize("/users/123") == "/users/{id}"

    def test_nested_numeric(self):
        assert templatize("/users/123/orders/456") == "/users/{id}/orders/{id}"

    def test_uuid(self):
        assert templatize("/users/550e8400-e29b-41d4-a716-446655440000") == "/users/{id}"

    def test_uuid_mid_path(self):
        assert templatize("/orgs/550e8400-e29b-41d4-a716-446655440000/members") == "/orgs/{id}/members"

    def test_objectid(self):
        assert templatize("/docs/507f1f77bcf86cd799439011") == "/docs/{id}"

    def test_no_id(self):
        assert templatize("/api/v2/health") == "/api/v2/health"

    def test_empty_path(self):
        assert templatize("") == "/"

    def test_root(self):
        assert templatize("/") == "/"

    def test_no_leading_slash(self):
        assert templatize("users/123") == "/users/{id}"

    def test_query_string_stripped(self):
        # Query string should not be included in template
        assert templatize("/users/123?format=json") == "/users/{id}"

    def test_preserves_non_id_segments(self):
        assert templatize("/api/users/123/orders") == "/api/users/{id}/orders"

    def test_long_numeric_id(self):
        assert templatize("/billing/9999999999") == "/billing/{id}"

    def test_version_segment_preserved(self):
        # /api/v2 should NOT be templatized — v2 has a letter prefix
        result = templatize("/api/v2/endpoint")
        assert result == "/api/v2/endpoint"

    def test_short_hex(self):
        # 8-char hex segment should be treated as ID
        assert templatize("/sessions/a3f5b2c1") == "/sessions/{id}"


class TestIsSensitive:
    def test_admin_path(self):
        assert is_sensitive("/admin/config") is True

    def test_delete_method(self):
        assert is_sensitive("/users/123", "DELETE") is True

    def test_config_path(self):
        assert is_sensitive("/api/config") is True

    def test_secret_path(self):
        assert is_sensitive("/api/secrets/db") is True

    def test_normal_get(self):
        assert is_sensitive("/users/123", "GET") is False

    def test_post_non_sensitive(self):
        assert is_sensitive("/orders", "POST") is False

    def test_shutdown_path(self):
        assert is_sensitive("/internal/shutdown") is True

    def test_case_insensitive(self):
        assert is_sensitive("/Admin/Config") is True


class TestPolicyKey:
    def test_normalizes_path(self):
        key = policy_key("svc-a", "svc-b", "GET", "/users/123")
        assert key == ("svc-a", "svc-b", "GET", "/users/{id}")

    def test_uppercases_method(self):
        key = policy_key("svc-a", "svc-b", "get", "/health")
        assert key == ("svc-a", "svc-b", "GET", "/health")

    def test_same_path_different_ids_same_key(self):
        key1 = policy_key("a", "b", "GET", "/users/1")
        key2 = policy_key("a", "b", "GET", "/users/999")
        assert key1 == key2


# ─── Learning Mode Tests ───────────────────────────────────────────────────────

from proxy.learning_mode import (
    record, generate_policy, get_observations, get_observation_count, start_learning
)


@pytest.fixture(autouse=True)
def reset_learning():
    start_learning()
    yield
    start_learning()  # cleanup


class TestLearningMode:
    def test_record_creates_entry(self):
        record("svc-a", "svc-b", "GET", "/users")
        obs = get_observations()
        assert len(obs) == 1

    def test_record_templatizes_path(self):
        record("svc-a", "svc-b", "GET", "/users/123")
        obs = get_observations()
        # Key should contain the template, not the raw ID
        key = list(obs.keys())[0]
        assert "{id}" in key
        assert "123" not in key

    def test_record_increments_count(self):
        record("svc-a", "svc-b", "GET", "/users/1")
        record("svc-a", "svc-b", "GET", "/users/2")  # same template
        obs = get_observations()
        assert len(obs) == 1
        count = list(obs.values())[0]["count"]
        assert count == 2

    def test_different_methods_different_keys(self):
        record("svc-a", "svc-b", "GET", "/users")
        record("svc-a", "svc-b", "POST", "/users")
        obs = get_observations()
        assert len(obs) == 2

    def test_generate_policy_structure(self):
        record("svc-a", "svc-b", "GET", "/health")
        policy = generate_policy()
        assert len(policy) == 1
        key = list(policy.keys())[0]
        assert key == ("svc-a", "svc-b", "GET", "/health")
        assert policy[key]["count"] == 1

    def test_start_learning_resets(self):
        record("svc-a", "svc-b", "GET", "/health")
        start_learning()
        assert get_observation_count() == 0

    def test_observation_has_timestamps(self):
        before = time.time()
        record("svc-a", "svc-b", "GET", "/health")
        after = time.time()
        obs = get_observations()
        v = list(obs.values())[0]
        assert before <= v["first_seen"] <= after
        assert before <= v["last_seen"] <= after


# ─── Policy Engine Tests ───────────────────────────────────────────────────────

from proxy.policy_engine import check, update_learned_policy, learned_policy


@pytest.fixture
def clean_policy():
    """Start with an empty policy."""
    update_learned_policy({})
    yield
    update_learned_policy({})


@pytest.fixture
def simple_policy():
    """A policy where svc-a → svc-b GET /health is known (3 observations)."""
    policy = {
        ("svc-a", "svc-b", "GET", "/health"): {
            "count": 3, "first_seen": time.time() - 100, "last_seen": time.time() - 5
        }
    }
    update_learned_policy(policy)
    yield
    update_learned_policy({})


@pytest.fixture
def rich_policy():
    """Policy with multiple routes for comprehensive tests."""
    now = time.time()
    policy = {
        ("svc-a", "svc-b", "GET", "/health"): {"count": 3, "first_seen": now - 100, "last_seen": now - 5},
        ("svc-a", "svc-b", "GET", "/users/{id}"): {"count": 12, "first_seen": now - 200, "last_seen": now - 1},
        ("svc-a", "svc-b", "POST", "/orders"): {"count": 5, "first_seen": now - 150, "last_seen": now - 10},
    }
    update_learned_policy(policy)
    yield
    update_learned_policy({})


class TestPolicyEngineLearningMode:
    def test_learning_mode_always_allows(self, clean_policy):
        allow, score, reasons, last_seen = check("any", "any", "GET", "/anything", "learning")
        assert allow is True
        assert score == 100.0

    def test_learning_mode_shows_template(self, clean_policy):
        allow, score, reasons, _ = check("a", "b", "GET", "/users/123", "learning")
        assert any("{id}" in r.detail for r in reasons)


class TestPolicyEngineTier1:
    """Tier 1: Exact match — route fully known."""

    def test_exact_match_allowed(self, simple_policy):
        allow, score, reasons, last_seen = check("svc-a", "svc-b", "GET", "/health", "enforce")
        assert allow is True
        assert score > 0

    def test_exact_match_score_reflects_count(self, simple_policy):
        # 3 observations → score 70
        _, score, _, _ = check("svc-a", "svc-b", "GET", "/health", "enforce")
        assert score == 70.0

    def test_high_count_gets_high_score(self, rich_policy):
        # 12 observations → score 100
        _, score, _, _ = check("svc-a", "svc-b", "GET", "/users/42", "enforce")
        assert score == 100.0  # 42 templatizes to {id}, matches /users/{id}

    def test_exact_match_returns_last_seen(self, simple_policy):
        _, _, _, last_seen = check("svc-a", "svc-b", "GET", "/health", "enforce")
        assert last_seen is not None
        assert isinstance(last_seen, float)

    def test_single_observation_score_55(self):
        policy = {
            ("svc-a", "svc-b", "GET", "/ping"): {"count": 1, "first_seen": time.time(), "last_seen": time.time()}
        }
        update_learned_policy(policy)
        _, score, _, _ = check("svc-a", "svc-b", "GET", "/ping", "enforce")
        assert score == 55.0
        update_learned_policy({})

    def test_path_template_collapses(self, rich_policy):
        # /users/999 should match /users/{id} in the policy
        allow, score, reasons, _ = check("svc-a", "svc-b", "GET", "/users/999", "enforce")
        assert allow is True
        assert score == 100.0


class TestPolicyEngineTier2:
    """Tier 2: Known pair, novel endpoint."""

    def test_novel_normal_endpoint(self, simple_policy):
        # svc-a → svc-b known, but POST /orders is new
        allow, score, reasons, last_seen = check("svc-a", "svc-b", "POST", "/orders", "enforce")
        assert allow is True  # Not blocked, just lower score
        assert score == 45.0  # Tier 2 normal
        assert last_seen is None
        assert any("WARN" in r.result or "novel" in r.detail.lower() for r in reasons)

    def test_novel_sensitive_endpoint(self, simple_policy):
        # svc-a → svc-b known, accessing /admin/config is novel+sensitive
        allow, score, reasons, _ = check("svc-a", "svc-b", "GET", "/admin/config", "enforce")
        assert allow is True  # Still forwarded (low score will drive STEP_UP)
        assert score == 15.0  # Tier 2 sensitive

    def test_novel_delete_is_sensitive(self, simple_policy):
        # DELETE is inherently sensitive regardless of path
        allow, score, _, _ = check("svc-a", "svc-b", "DELETE", "/users/1", "enforce")
        assert allow is True
        assert score == 15.0  # DELETE → sensitive

    def test_tier2_message_includes_labels(self, simple_policy):
        _, _, reasons, _ = check("svc-a", "svc-b", "GET", "/admin/secret", "enforce")
        reason_text = " ".join(r.detail for r in reasons)
        assert "SENSITIVE" in reason_text or "sensitive" in reason_text.lower()


class TestPolicyEngineTier3:
    """Tier 3: Unknown pair — lateral movement detection."""

    def test_unknown_pair_blocked(self, simple_policy):
        # svc-c has never been seen at all
        allow, score, reasons, _ = check("svc-c", "svc-b", "GET", "/health", "enforce")
        assert allow is False
        assert score == 0.0

    def test_unknown_pair_reason_mentions_lateral_movement(self, simple_policy):
        _, _, reasons, _ = check("svc-evil", "svc-b", "GET", "/admin", "enforce")
        reason_text = " ".join(r.detail for r in reasons).lower()
        assert "lateral" in reason_text or "unauthorized" in reason_text

    def test_empty_policy_all_unknown(self, clean_policy):
        allow, score, _, _ = check("svc-a", "svc-b", "GET", "/health", "enforce")
        assert allow is False
        assert score == 0.0

    def test_known_caller_unknown_target(self, simple_policy):
        # svc-a → svc-b known, but svc-a → svc-EVIL is Tier 3
        allow, score, _, _ = check("svc-a", "svc-evil", "GET", "/data", "enforce")
        assert allow is False
        assert score == 0.0

    def test_reversed_pair_unknown(self, simple_policy):
        # svc-b → svc-a is NOT the same as svc-a → svc-b
        allow, score, _, _ = check("svc-b", "svc-a", "GET", "/health", "enforce")
        assert allow is False
        assert score == 0.0


class TestPolicyEngineScoreThresholds:
    """Verify the obs count → score ladder."""

    @pytest.mark.parametrize("count,expected_score", [
        (1, 55.0),
        (2, 70.0),
        (4, 70.0),
        (5, 85.0),
        (9, 85.0),
        (10, 100.0),
        (50, 100.0),
    ])
    def test_obs_to_score(self, count, expected_score):
        policy = {
            ("a", "b", "GET", "/x"): {"count": count, "first_seen": time.time(), "last_seen": time.time()}
        }
        update_learned_policy(policy)
        _, score, _, _ = check("a", "b", "GET", "/x", "enforce")
        assert score == expected_score
        update_learned_policy({})


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
