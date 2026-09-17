"""Tests for ``utils.tracing`` (round-22 observability add-on)."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_stage_records_elapsed_and_tokens():
    """A ``stage`` context must capture elapsed time and token counters."""
    from utils.tracing import metrics, stage

    metrics.reset()
    with stage("unit.test", event_asn="12479") as ctx:
        ctx.add_tokens(in_tok=100, out_tok=40)
        time.sleep(0.05)

    events = metrics.all()
    assert len(events) == 1, f"expected 1 event, got {len(events)}"
    evt = events[0]
    assert evt.name == "unit.test"
    assert evt.tokens_in == 100
    assert evt.tokens_out == 40
    assert 0.04 <= evt.elapsed_s <= 0.5
    assert evt.attrs.get("event_asn") == "12479"
    assert evt.error is None


def test_stage_captures_exception():
    """An exception inside ``stage`` must be recorded AND re-raised."""
    from utils.tracing import metrics, stage

    metrics.reset()
    raised = False
    try:
        with stage("unit.test.error"):
            raise ValueError("boom")
    except ValueError:
        raised = True

    assert raised, "stage did not re-raise"
    events = metrics.all()
    assert events and events[0].error and "boom" in events[0].error


def test_metrics_aggregate_by_stage_name():
    """Aggregated metrics must count + sum tokens per stage name."""
    from utils.tracing import metrics, stage

    metrics.reset()
    with stage("agg.x") as ctx:
        ctx.add_tokens(10, 5)
    with stage("agg.x") as ctx:
        ctx.add_tokens(20, 7)
    with stage("agg.y") as ctx:
        ctx.add_tokens(3, 1)

    snap = metrics.to_dict()
    assert snap["event_count"] == 3
    assert snap["tokens_in_total"] == 33
    assert snap["tokens_out_total"] == 13
    assert snap["by_stage"]["agg.x"]["count"] == 2
    assert snap["by_stage"]["agg.x"]["tokens_in"] == 30
    assert snap["by_stage"]["agg.y"]["count"] == 1
    assert snap["by_stage"]["agg.y"]["errors"] == 0


def test_metrics_save_round_trip(tmp_path):
    """Saving the metrics must produce a JSON file that round-trips."""
    from utils.tracing import metrics, stage

    metrics.reset()
    with stage("rt.x"):
        pass
    out = tmp_path / "metrics.json"
    metrics.save(out)
    data = json.loads(out.read_text())
    assert data["event_count"] == 1
    assert data["by_stage"]["rt.x"]["count"] == 1


def test_metrics_reset_clears_state():
    from utils.tracing import metrics, stage

    with stage("reset.x"):
        pass
    assert metrics.all()
    metrics.reset()
    assert metrics.all() == []
