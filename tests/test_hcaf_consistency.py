"""HCAF consistency tests against the 34-event ground-truth dataset.

Tests the HCAF verdict (routing_to_traffic / traffic_to_routing /
independent / unknown) against the human-reviewed labels in
``data_check/ground_truth_collection/human_review_report.csv``.

The CSV doesn't carry an explicit "direction" label (only a
"traffic_route_correlation" strength of {高, 中}), so we measure:

    1. **Detection coverage**: % of events where HCAF returns a known
       direction (not "unknown") vs ground-truth "verified=True".
    2. **Direction agreement** (proxy): among events that human reviewers
       marked as "高" correlation, what fraction of HCAF verdicts agree
       with the "expected" direction implied by event_type?
       - hijack / leak → routing→traffic expected
       - outage → traffic→routing expected (operational failure → routing change)

This is a coarse proxy — real ground-truth direction labels would need
a separate human study. The test is tagged ``slow`` because it iterates
over all 34 events and runs the full HCAF pipeline on synthetic
data for each.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from agents.causal_attribution import 因果归因引擎  # noqa: E402


pytestmark = pytest.mark.slow

_GT_PATH = _ROOT / "data_check" / "ground_truth_collection" / "human_review_report.csv"


# ─── Ground-truth loader ────────────────────────────────────────────────


def _load_ground_truth():
    """Return list of dicts from the ground-truth CSV."""
    with open(_GT_PATH) as f:
        return list(csv.DictReader(f))


# ─── Synthetic timelines ────────────────────────────────────────────────


def _synth_timeline(n: int = 120, base: float = 0.4, spike_at: int = 60,
                    spike_height: float = 0.7, spike_width: int = 10,
                    seed: int = 0):
    """Build a Cloudflare-style 5-min timeline with a single anomaly window."""
    from datetime import datetime, timedelta
    rng = np.random.default_rng(seed)
    series = np.full(n, base) + rng.normal(0, 0.05, size=n)
    series[spike_at:spike_at + spike_width] = spike_height + rng.normal(0, 0.05, size=spike_width)
    base_dt = datetime.fromisoformat("2024-01-01T00:00:00+00:00")
    return [
        {"timestamp": (base_dt + timedelta(minutes=5 * i)).isoformat(), "score": float(v)}
        for i, v in enumerate(series)
    ]


def _hcaf_run(event: dict) -> dict:
    """Run the full HCAF pipeline on a synthetic pair of timelines derived
    from the event's traffic_score / route_score."""
    try:
        traffic_score = float(event["traffic_score"])
    except (ValueError, KeyError):
        traffic_score = 0.6
    try:
        route_score = float(event["route_score"])
    except (ValueError, KeyError):
        route_score = 0.7

    # Build routing timeline with a spike at index 30.
    routing_tl = _synth_timeline(n=120, base=0.3, spike_at=30,
                                  spike_height=route_score, spike_width=5,
                                  seed=hash(event["event_id"]) & 0xFFFF)
    # Build traffic timeline with a spike at index 50 (delayed).
    traffic_tl = _synth_timeline(n=120, base=0.4, spike_at=50,
                                  spike_height=traffic_score, spike_width=5,
                                  seed=(hash(event["event_id"]) >> 16) & 0xFFFF)

    routing_ctx = {
        "origin_as": event.get("attacker_as", "AS65000"),
        "event_type": event.get("event_type", "unknown"),
        "affected_as_count": 3,
    }
    traffic_ctx = {
        "traffic_drop_ratio": 1.0 - traffic_score,
        "baseline": {"mean": 0.4},
        "affected_prefix": "10.0.0.0/24",
    }
    topo_ctx = {"adjacency": {}}  # empty → uses quick_cascade_estimate

    engine = 因果归因引擎()
    result = engine.分析(
        路由时间线=routing_tl,
        流量时间线=traffic_tl,
        路由上下文=routing_ctx,
        流量上下文=traffic_ctx,
        拓扑上下文=topo_ctx,
        目标AS=event.get("victim_as", "AS12479"),
    )
    return result


# ─── Tests ──────────────────────────────────────────────────────────────


def test_ground_truth_csv_loads():
    """Sanity: the CSV has 34 verified events."""
    rows = _load_ground_truth()
    assert len(rows) == 34, f"Expected 34 ground-truth events, got {len(rows)}"
    # All are flagged for inclusion.
    assert all(r["final_keep"] == "✅" for r in rows), "Not all rows are marked keep"


def test_hcaf_runs_on_all_events():
    """HCAF pipeline must produce a verdict for every ground-truth event
    (no exceptions, no infinite loops)."""
    rows = _load_ground_truth()
    for ev in rows:
        result = _hcaf_run(ev)
        # HCAF returns a dataclass; convert to dict.
        assert hasattr(result, "方向"), f"No 方向 field for {ev['event_id']}"
        assert hasattr(result, "强度"), f"No 强度 field for {ev['event_id']}"
        # 方向 must be one of the known values.
        # The implementation sometimes returns "routing -> traffic" (with
        # spaces and arrows) and sometimes "routing_to_traffic" depending
        # on which sub-method produced the verdict. Normalise.
        raw = result.方向
        norm = raw.replace(" ", "").replace("->", "_to_")
        valid_dirs = {"routing_to_traffic", "traffic_to_routing",
                      "independent", "unknown", "insufficient", "none"}
        assert norm in valid_dirs, (
            f"{ev['event_id']}: unexpected direction {raw!r} (normalised {norm!r})"
        )


def _norm_dir(d: str) -> str:
    """Normalise the direction string across implementations."""
    return d.replace(" ", "").replace("->", "_to_").replace("→", "_to_")


def test_hcaf_detection_coverage():
    """Coverage = % of events where HCAF gives a non-'unknown' verdict."""
    rows = _load_ground_truth()
    verdicts = [_hcaf_run(ev).方向 for ev in rows]
    known = sum(1 for v in verdicts if _norm_dir(v) not in {"unknown", "insufficient", "none"})
    coverage = known / len(rows)
    # Synthetic timelines are crude, so we just require HCAF to not
    # collapse to "unknown" on everything. Real-world coverage should
    # be much higher; this is a sanity floor.
    assert coverage >= 0.50, (
        f"HCAF coverage {coverage:.0%} below 50% floor — pipeline broken?\n"
        f"Verdicts: {Counter(verdicts)}"
    )


def test_hcaf_directions_distribute_across_event_types():
    """Across the 3 event types (hijack / leak / outage), HCAF should
    produce at least 2 distinct direction verdicts. If everything
    collapses to one direction, that's a sign of a degenerate pipeline."""
    rows = _load_ground_truth()
    by_type = defaultdict(list)
    for ev in rows:
        by_type[ev["event_type"]].append(_norm_dir(_hcaf_run(ev).方向))
    distinct_per_type = {k: len(set(v)) for k, v in by_type.items()}
    # At least one event type should produce ≥2 distinct verdicts.
    assert any(d >= 2 for d in distinct_per_type.values()), (
        f"All event types collapsed to single verdict: {distinct_per_type}\n"
        f"By type: {dict(by_type)}"
    )


def test_hcaf_high_correlation_events_match_direction_proxy():
    """Events marked '高' correlation by human reviewers: HCAF's verdict
    should agree with the proxy direction (hijack/leak → routing→traffic)
    more often than not. This is a coarse proxy because the GT doesn't
    carry explicit direction labels."""
    rows = _load_ground_truth()
    high_corr = [ev for ev in rows if ev.get("traffic_route_correlation") == "高"]
    # Need a minimum sample.
    if len(high_corr) < 5:
        pytest.skip(f"Only {len(high_corr)} high-correlation events — too few")

    correct = 0
    total = 0
    for ev in high_corr:
        if ev["event_type"] not in ("hijack", "leak", "outage"):
            continue
        verdict = _norm_dir(_hcaf_run(ev).方向)
        # Proxy: hijack/leak → expected routing→traffic; outage → traffic→routing
        expected = "routing_to_traffic" if ev["event_type"] in ("hijack", "leak") else "traffic_to_routing"
        total += 1
        if verdict == expected:
            correct += 1
    # Sanity floor: at least 25% agreement on synthetic timelines.
    # Real ground-truth direction labels would tighten this; until then
    # we just assert the pipeline is doing something useful.
    agreement = correct / total if total else 0
    assert agreement >= 0.25, (
        f"HCAF agreement with proxy direction only {agreement:.0%} "
        f"({correct}/{total}). GT labels: high-correlation events.\n"
        f"This suggests HCAF doesn't pick up routing→traffic causality even when "
        f"human reviewers mark high correlation."
    )


def test_hcaf_confidence_calibration_smoke():
    """Smoke: HCAF's 置信度 (confidence) field should be in [0, 1]."""
    rows = _load_ground_truth()
    for ev in rows:
        result = _hcaf_run(ev)
        c = getattr(result, "置信度", None)
        assert c is not None, f"No 置信度 for {ev['event_id']}"
        assert 0.0 <= c <= 1.0, f"{ev['event_id']}: confidence {c} out of [0,1]"


def test_hcaf_is_deterministic():
    """Re-running HCAF on the same event must give the same direction
    (no LLM in the loop, no random sampling)."""
    rows = _load_ground_truth()
    # Pick 3 events to re-run.
    sample = rows[:3]
    for ev in sample:
        r1 = _hcaf_run(ev)
        r2 = _hcaf_run(ev)
        assert r1.方向 == r2.方向, (
            f"Non-deterministic for {ev['event_id']}: {r1.方向} vs {r2.方向}"
        )
        # Strength is an Enum; compare by enum identity.
        assert r1.强度 == r2.强度, (
            f"Strength drift for {ev['event_id']}: {r1.强度} vs {r2.强度}"
        )


def test_hcaf_outputs_创新发现_list():
    """The 创新发现 list must contain all 4 methods (MSBD, CTPR, CIC, Granger)."""
    rows = _load_ground_truth()
    ev = rows[0]
    result = _hcaf_run(ev)
    findings = getattr(result, "创新发现列表", [])
    assert len(findings) == 4, f"Expected 4 findings, got {len(findings)}"
    method_names = {f.方法名 for f in findings}
    expected = {
        "多尺度因果断点检测",  # MSBD
        "因果传递路径重建",    # CTPR
        "反事实干预网络估计",  # CIC
        "Granger（baseline）",
    }
    assert method_names == expected, (
        f"Method set mismatch: {method_names}\nExpected: {expected}"
    )
