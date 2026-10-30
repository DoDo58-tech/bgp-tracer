"""Prototype: routing observation rate vs severity as the routing-side signal.

The production representation scores a routing bucket by the *severity* of
the events that landed in it.  For BGP that is the wrong quantity: a hijack
and a leak differ in *kind*, not in the magnitude of a per-event score, and
the severity field is usually absent.  What actually moves when the
control plane changes is the **observation rate** -- how many routing events
the collector sees per unit time.  An outage suppresses it, a hijack or a
leak amplifies it, and both are visible as a change in the rate.

This script measures, on every labelled event, whether the rate carries a
change that the severity-based series does not.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents._segmentation import detect_changes  # noqa: E402
from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
GRID = 300


def routing_events(cache: Path) -> list[dict]:
    d = json.loads(cache.read_text(encoding="utf-8"))
    rb = d.get("routing") or {}
    corr = d.get("correlation") or {}
    evs: list[dict] = []
    for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                "forge_hijacking", "route_leaks"):
        v = rb.get(key)
        if isinstance(v, list):
            evs += [e for e in v if isinstance(e, dict)]
    if not evs:
        evs = [e for e in (corr.get("routing_events") or []) if isinstance(e, dict)]
    return evs


def traffic_points(cache: Path) -> list[dict]:
    d = json.loads(cache.read_text(encoding="utf-8"))
    corr = d.get("correlation") or {}
    tb = d.get("traffic") or {}
    out = [e for e in (tb.get("anomalies") or []) if isinstance(e, dict)]
    if not out:
        out = [e for e in (corr.get("traffic_events_full") or []) if isinstance(e, dict)]
    if not out:
        out = [e for e in (corr.get("traffic_events") or []) if isinstance(e, dict)]
    return out


def series(points: list[dict], start, end, mode: str) -> list[float]:
    """Bucket the points on the event window and score each bucket."""
    n = max(1, int((end - start).total_seconds()) // GRID + 1)
    acc = [0.0] * n
    for p in points:
        ts = parse_timestamp(p.get("timestamp"))
        if ts is None:
            continue
        idx = int((ts - start).total_seconds()) // GRID
        if 0 <= idx < n:
            if mode == "rate":
                acc[idx] += 1.0
            else:
                sev = p.get("severity")
                acc[idx] += float(sev) if isinstance(sev, (int, float)) else 0.8
    if mode == "rate":
        return acc
    return [a if a > 0 else 1e-9 for a in acc]


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':38s} {'mode':8s} {'n':>4s} {'flat':>5s} "
          f"{'changes':>8s} {'t_onset':>8s}")
    for r in rows:
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=r["event_id"], allow_same_date=False)
        if not m:
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        start = parse_timestamp(d.get("start_time"))
        end = parse_timestamp(d.get("end_time"))
        if start is None or end is None or end <= start:
            continue
        revs = routing_events(m.path)
        tpts = traffic_points(m.path)
        if not revs or not tpts:
            continue
        for mode in ("severity", "rate"):
            s = series(revs, start, end, mode)
            if len(s) < 6:
                continue
            min_seg = max(2, int(round(0.10 * len(s))))
            det = detect_changes(np.array(s), min_seg, 1.0)
            flat = float(np.ptp(s)) < 1e-9
            print(f"{r['event_id'][:36]:38s} {mode:8s} {len(s):>4d} "
                  f"{str(flat):>5s} {str(det['changes']):>8s} "
                  f"{det['t_onset']:>8.2f}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
