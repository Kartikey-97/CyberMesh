"""
CyberMesh Proxy — Policy Persistence (Phase 9)

Handles saving and loading the active learned policy and the version
snapshots to/from disk (JSON). This ensures that if the proxy restarts,
it doesn't lose all the traffic patterns it learned, nor does it lose
the audit trail of previous policy versions.

Data format (policy.json):
{
    "active_policy": {
        "caller|target|METHOD|/path": {"count": 5, "last_seen": 1690000000.0},
        ...
    },
    "snapshots": [
        {
            "version": 1,
            "timestamp": 1680000000.0,
            "label": "auto-snapshot-v1",
            "rule_count": 10,
            "policy": { ... }
        },
        ...
    ]
}
"""

import json
import logging
import os
import threading
from typing import Dict, Any

from proxy.policy_engine import learned_policy, update_learned_policy
from proxy.policy_versioning import (
    serialise_policy,
    deserialise_policy,
    get_all_snapshots_for_persistence,
    load_snapshots_from_persistence,
)

logger = logging.getLogger("cybermesh-persistence")

POLICY_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "policy.json")
_save_lock = threading.Lock()


def ensure_data_dir():
    """Ensure the data directory exists."""
    os.makedirs(os.path.dirname(POLICY_FILE), exist_ok=True)


def save_state():
    """
    Save the current active policy and all snapshots to disk.
    Thread-safe.
    """
    with _save_lock:
        ensure_data_dir()
        
        # We must acquire the engine's lock indirectly by copying, but Python dicts
        # are generally thread-safe for shallow iteration. We'll build the serialized
        # active policy.
        serialized_active = serialise_policy(learned_policy)
        serialized_snapshots = get_all_snapshots_for_persistence()
        
        data = {
            "active_policy": serialized_active,
            "snapshots": serialized_snapshots,
        }
        
        # Write to temporary file then rename for atomic write
        tmp_file = f"{POLICY_FILE}.tmp"
        try:
            with open(tmp_file, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_file, POLICY_FILE)
            logger.info("Policy state saved to disk (%d rules, %d snapshots)", 
                        len(serialized_active), len(serialized_snapshots))
        except Exception as e:
            logger.error("Failed to save policy state: %s", e)


def load_state() -> bool:
    """
    Load the active policy and snapshots from disk.
    Called at startup.
    Returns True if loaded successfully, False if file doesn't exist or error.
    """
    with _save_lock:
        if not os.path.exists(POLICY_FILE):
            logger.info("No persisted policy found at %s. Starting fresh.", POLICY_FILE)
            return False
            
        try:
            with open(POLICY_FILE, "r") as f:
                data = json.load(f)
                
            active_raw = data.get("active_policy", {})
            snapshots_raw = data.get("snapshots", [])
            
            # Restore active policy
            restored_active = deserialise_policy(active_raw)
            update_learned_policy(restored_active)
            
            # Restore snapshots
            load_snapshots_from_persistence(snapshots_raw)
            
            logger.info("Policy state loaded from disk (%d rules, %d snapshots)", 
                        len(restored_active), len(snapshots_raw))
            return True
            
        except Exception as e:
            logger.error("Failed to load policy state: %s", e)
            return False
