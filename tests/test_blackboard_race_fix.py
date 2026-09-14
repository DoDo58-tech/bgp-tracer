"""Regression tests for the Blackboard race condition fix (2026-09-13).

Bug (before fix):
  ``Blackboard.write()`` checked ``existing = self._sections.get(...)``
  **outside** the lock, then acquired the lock to write. Under high
  concurrency two coroutines could both read ``existing=None``, both
  pass the write-once check, and the second would silently overwrite the
  first. The same race existed in ``update_section()``.

After fix:
  - The check and the write are both inside the same ``async with self._lock``.
  - The lock makes the check-then-act atomic so the first writer wins
    and subsequent writers are rejected.
  - Notifications happen outside the lock to avoid holding it across
    subscriber callbacks (which may themselves await).
  - ``_notify`` no longer swallows ``asyncio.CancelledError``.

The other test files in this directory use sync tests with asyncio.run(),
so we follow the same pattern to avoid adding a pytest-asyncio dependency.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_write_race_first_writer_wins():
    """Concurrent identical-fingerprint writes — first writer wins, no silent overwrite."""
    from agents.core import Blackboard

    async def go():
        bb = Blackboard()

        async def writer(idx):
            value = {
                "summary": {"routing_event_count": 401, "writer": idx},
                "anomaly_count": 401,
            }
            await bb.write("routing", "result", value, _writer=f"W{idx}")

        await asyncio.gather(*[writer(i) for i in range(50)])

        final = await bb.read("routing", "result")
        return final

    final = asyncio.run(go())
    assert final["anomaly_count"] == 401, f"anomaly_count corrupted: {final['anomaly_count']}"
    assert final["summary"]["routing_event_count"] == 401, (
        f"routing_event_count corrupted: {final['summary']['routing_event_count']}"
    )


def test_update_section_race_protects_critical_keys():
    """Same race for update_section() — concurrent updates must not corrupt the critical key."""
    from agents.core import Blackboard

    async def go():
        bb = Blackboard()

        async def updater(idx):
            await bb.update_section(
                "traffic",
                {
                    "result": {
                        "anomalies": [{"ts": f"2024-01-03T15:{idx:02d}:00", "z": 5.0}],
                        "anomaly_count": 1,
                    },
                    "non_critical_meta": f"writer_{idx}",
                },
                _writer=f"U{idx}",
            )

        await asyncio.gather(*[updater(i) for i in range(50)])

        return await bb.read_section("traffic")

    final = asyncio.run(go())
    # `traffic.result` is a critical key — only the first writer's payload wins.
    assert "anomalies" in final["result"], "critical key 'traffic.result' was overwritten"
    assert len(final["result"]["anomalies"]) == 1, (
        f"Critical key 'traffic.result' corrupted under concurrent updates: "
        f"got {len(final['result']['anomalies'])} anomalies (expected 1). "
        f"This means the write-once protection lost the race."
    )
    # `non_critical_meta` is not protected — any value may win.
    assert "non_critical_meta" in final


def test_notify_does_not_swallow_cancelled_error():
    """CancelledError must propagate out of _notify so shutdown/timeout works."""
    from agents.core import Blackboard

    async def go():
        bb = Blackboard()

        async def cancel_immediately(payload):
            raise asyncio.CancelledError("test cancel")

        bb.subscribe("traffic", cancel_immediately)
        try:
            await bb._notify("traffic", "anomaly_count", 1)
        except asyncio.CancelledError:
            return "propagated"
        return "swallowed"

    result = asyncio.run(go())
    assert result == "propagated", (
        f"CancelledError was silently swallowed by _notify (got {result!r}). "
        "This would defeat asyncio timeout/shutdown semantics."
    )


def test_notify_logs_subscriber_errors_instead_of_silent():
    """Non-cancellation subscriber exceptions are logged, not swallowed."""
    from agents.core import Blackboard

    async def go():
        bb = Blackboard()

        def bad_callback(payload):
            raise ValueError("subscriber is broken")

        bb.subscribe("traffic", bad_callback)
        # Must not raise — the fix logs and continues.
        await bb._notify("traffic", "anomaly_count", 1)
        return "ok"

    result = asyncio.run(go())
    assert result == "ok"


def test_write_race_high_concurrency():
    """Stress: 200 concurrent writers, all with fingerprint-equivalent data."""
    from agents.core import Blackboard

    async def go():
        bb = Blackboard()

        async def writer(idx):
            await bb.write(
                "routing",
                "result",
                {
                    "summary": {"routing_event_count": 401},
                    "_internal_writer_idx": idx,
                    "anomaly_count": 401,
                },
                _writer=f"W{idx}",
            )

        await asyncio.gather(*[writer(i) for i in range(200)])
        return await bb.read("routing", "result")

    final = asyncio.run(go())
    assert final["anomaly_count"] == 401, (
        f"anomaly_count corrupted under high concurrency: {final['anomaly_count']}"
    )
    assert final["summary"]["routing_event_count"] == 401, (
        f"routing_event_count corrupted under high concurrency: "
        f"{final['summary']['routing_event_count']}"
    )
