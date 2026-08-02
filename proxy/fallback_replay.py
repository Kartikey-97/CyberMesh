"""Fallback replay — plays pre-recorded events for demo safety."""

import asyncio
import json
import logging
from proxy.event_stream import EventBroadcaster
from shared.event_schema import CyberMeshEvent

logger = logging.getLogger("cybermesh-replay")


async def replay_events(broadcaster: EventBroadcaster, fixture_path: str, stats: dict = None):
    """Load a JSON fixture file and replay events with realistic timing."""
    try:
        with open(fixture_path, "r") as f:
            events_data = json.load(f)

        logger.info("Replaying %d events from %s", len(events_data), fixture_path)

        for event_data in events_data:
            # Extract delay before creating the event
            delay_ms = event_data.pop("delay_ms", 1000)

            # Wait before sending this event
            await asyncio.sleep(delay_ms / 1000.0)

            # Create and broadcast the event
            # Filter out fields that aren't part of CyberMeshEvent
            valid_fields = {
                "event_type", "caller", "target", "path", "method",
                "decision", "trust_score", "identity_score", "behavior_score",
                "context_score", "band", "latency_ms", "reasons", "mode", "data",
            }
            filtered = {k: v for k, v in event_data.items() if k in valid_fields}

            event = CyberMeshEvent(**filtered)
            broadcaster.broadcast(event)
            
            if stats and event.event_type == "request_decision":
                stats["total_requests"] += 1
                if event.decision == "ALLOW":
                    stats["allowed"] += 1
                elif event.decision == "BLOCK":
                    stats["blocked"] += 1
                elif event.decision == "STEP_UP":
                    stats["step_ups"] += 1
                stats["total_latency_ms"] += (event.latency_ms or 0)

            logger.info("Replayed: %s (%s)", event.event_type, event.caller or "system")

        logger.info("Replay complete")

    except FileNotFoundError:
        logger.error("Fixture file not found: %s", fixture_path)
    except Exception as e:
        logger.error("Error replaying events: %s", e)
