"""The decisive experiment: a *paired* control-plane / data-plane test.

The earlier experiments failed for one reason, and the ground truth
shows what the right pairing is.  The ground truth records the
control-plane displacement **at the traffic trough**:

    ``trough=2025-04-01T06:45:00Z (control z=-2.21 drop=12.6%)``

That is the physical question a causal claim has to answer: *when the
data plane deviated, had the control plane already deviated, and by
how much?*  Asking for the control plane's own change point first and
then looking for a response after it is the wrong order -- the control
plane's rate series is sparse and its own baseline contains bursts,
so a change point read off it lands in the wrong place.

So the method is reorganised around the pairing:

1.  **Control-plane displacement, paired.**  On the detector's
    five-minute grid -- with the holes filled, because an omitted
    bucket is zero routing messages -- the channel's rate is compared
    with the baseline period's mean rate *in the window in which the
    data plane deviated*.  The displacement is a ratio, so it is the
    same statement for every AS.

2.  **Exclusivity.**  The displacement is compared with the
    displacement the *same* channel shows at *placebo* windows of the
    same length inside the baseline period.  The null comes from the
    instrument's own normal behaviour on the same quantity, measured
    before the incident.

3.  **Precedence.**  The control plane's onset is taken from the
    detector's own routing anomaly records -- which carry exact
    timestamps and cluster during the incident -- and the data plane's
    onset from the traffic detector's impact window.

4.  **Scope and congruence.**  The routing edge's prefixes have to
    intersect the entity the traffic series measures, and the two
    movements have to point the same way.

This script evaluates the pairing on the corpus and prints, for every
event, each veto's statistic.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.temporal import parse_timestamp  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"

GRID_SECONDS = 300

CHANNEL_FEATURES: Dict[str, Tuple[str, ...]] = {
    "volume": ("total_messages", "announcement_count"),
    "withdrawal": ("withdrawal_count",),
    "origin_change": ("num_ori_change", "origin_change_count"),
    "path_change": ("path_change_rate",),
}

#: The routing anomaly kinds, and what each of them means physically.
ROUTE_KINDS = (
    "origin_hijacked", "origin_hijacking", "forge_hijacked",
    "forge_hijacking", "route_leaks",
)


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def read_buckets(block: Any) -> Dict[datetime, Dict[str, Any]]:
    if not isinstance(block, dict):
        return {}
    out: Dict[datetime, Dict[str, Any]] = {}
    for raw, entry in block.items():
        if not isinstance(entry, dict):
            continue
        ts = parse_timestamp(raw)
        if ts is None:
            continue
        out[ts] = entry
    return out


def channel_value(entry: Dict[str, Any], channel: str) -> float:
    for key in CHANNEL_FEATURES[channel]:
        val = _num(entry.get(key))
        if val is not None:
            return val
    return 0.0


def build_grid(event: Dict[datetime, Dict[str, Any]],
               base: Dict[datetime, Dict[str, Any]],
               ) -> Dict[str, Any]:
    """The control plane on the detector's own grid, holes filled."""
    all_stamps = sorted(set(event) | set(base))
    if not all_stamps:
        return {"stamps": [], "cells": {}, "split": 0, "level": {}}

    origin = all_stamps[0]
    n_cells = int((all_stamps[-1] - origin).total_seconds()) // GRID_SECONDS + 1

    cells = {ch: [0.0] * n_cells for ch in CHANNEL_FEATURES}
    for src in (event, base):
        for ts, entry in src.items():
            idx = int((ts - origin).total_seconds()) // GRID_SECONDS
            if not (0 <= idx < n_cells):
                continue
            for ch in CHANNEL_FEATURES:
                val = channel_value(entry, ch)
                if val:
                    cells[ch][idx] = val

    stamps = [origin + timedelta(seconds=GRID_SECONDS * i)
              for i in range(n_cells)]

    if base:
        split = int((max(base) - origin).total_seconds()) // GRID_SECONDS + 1
    else:
        split = 0
    split = max(0, min(split, n_cells))

    level = {}
    for ch in CHANNEL_FEATURES:
        seg = np.asarray(cells[ch][:split] if split > 0 else cells[ch],
                         dtype=float)
        level[ch] = float(seg.mean()) if seg.size else 0.0

    return {"stamps": stamps, "cells": cells, "split": split, "level": level}


def cells_in_window(control: Dict[str, Any], start: Optional[datetime],
                    end: Optional[datetime]) -> List[int]:
    stamps = control["stamps"]
    if start is None or end is None or not stamps:
        return []
    lo = max(0, int((start - stamps[0]).total_seconds()) // GRID_SECONDS)
    hi = min(len(stamps) - 1,
             int((end - stamps[0]).total_seconds()) // GRID_SECONDS)
    if hi < lo:
        return []
    return list(range(lo, hi + 1))


def paired_displacement(control: Dict[str, Any], channel: str,
                        idxs: Sequence[int]) -> Optional[float]:
    """The channel's rate in the paired window, as a multiple of normal."""
    level = control["level"].get(channel, 0.0)
    if level <= 0 or not idxs:
        return None
    cells = control["cells"][channel]
    observed = float(np.mean([cells[i] for i in idxs]))
    return observed / level


def placebo_displacements(control: Dict[str, Any], channel: str,
                          width: int) -> List[float]:
    """The displacement at placebo windows of the same length.

    The placebos are windows of the baseline period, so they measure
    the same channel, with the same instrument, over the same number
    of cells, in a period that is known to be normal.
    """
    level = control["level"].get(channel, 0.0)
    if level <= 0:
        return []
    cells = control["cells"][channel]
    split = control["split"]
    end = split if split > 0 else len(cells)
    if end - width < 1:
        return []
    out = []
    for start in range(0, end - width + 1):
        observed = float(np.mean(cells[start:start + width]))
        out.append(abs(observed / level - 1.0))
    return out


def routing_onset(cache: Dict[str, Any]) -> Optional[datetime]:
    """The earliest routing anomaly the detector recorded."""
    rb = cache.get("routing") or {}
    best: Optional[datetime] = None
    for key in ROUTE_KINDS:
        block = rb.get(key)
        if not isinstance(block, list):
            continue
        for e in block:
            if not isinstance(e, dict):
                continue
            ts = parse_timestamp(e.get("timestamp") or e.get("first_seen"))
            if ts is None:
                continue
            if best is None or ts < best:
                best = ts
    return best


def traffic_impact(cache: Dict[str, Any]) -> Tuple[Optional[datetime],
                                                   Optional[datetime]]:
    """The data plane's impact window, from the traffic detector."""
    tb = cache.get("traffic") or {}
    for key in ("expanded_windows", "consecutive_anomaly_windows"):
        wins = tb.get(key)
        if isinstance(wins, list) and wins:
            start = parse_timestamp(wins[0].get("start"))
            end = parse_timestamp(wins[0].get("end"))
            if start is not None:
                return start, end
    period = tb.get("original_outage_period")
    if isinstance(period, dict):
        return (parse_timestamp(period.get("start_time")),
                parse_timestamp(period.get("end_time")))
    return None, None


def traffic_trough(cache: Dict[str, Any]) -> Optional[datetime]:
    """The moment the traffic metric was at its lowest."""
    corr = cache.get("correlation") or {}
    tb = cache.get("traffic") or {}
    raw = None
    for source in (corr.get("traffic_events_full"), tb.get("anomalies")):
        if isinstance(source, list) and source:
            raw = source
            break
    if raw is None:
        return None
    best = None
    for e in raw:
        if not isinstance(e, dict):
            continue
        ts = parse_timestamp(e.get("timestamp") or e.get("time"))
        if ts is None:
            continue
        val = _num(e.get("current_value"))
        if val is None:
            val = _num(e.get("value"))
        if val is None:
            continue
        if best is None or val < best[1]:
            best = (ts, val)
    return best[0] if best else None


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':30s} {'cp_on':>8s} {'tf_on':>8s} {'lag':>7s} | "
          f"{'channel':13s} {'disp':>7s} {'null':>7s} {'ratio':>7s} | "
          f"{'gt_cdrop':>9s} {'gt_tdrop':>9s}")
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"{eid[:28]:30s} NO CACHE")
            continue
        cache = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (cache.get("routing") or {}).get("outage_analysis") or {}
        control = build_grid(read_buckets(oa.get("timeseries_event")),
                             read_buckets(oa.get("timeseries_baseline")))

        tf_start, tf_end = traffic_impact(cache)
        cp_on = routing_onset(cache)
        lag = ((tf_start - cp_on).total_seconds() / 60.0
               if tf_start and cp_on else None)
        idxs = cells_in_window(control, tf_start, tf_end)
        width = max(1, len(idxs))

        best = None
        for channel in CHANNEL_FEATURES:
            disp = paired_displacement(control, channel, idxs)
            if disp is None:
                continue
            nulls = placebo_displacements(control, channel, width)
            null = max(nulls) if nulls else 0.0
            ratio = abs(disp - 1.0) / null if null > 1e-9 else float("inf")
            if best is None or ratio > best[2]:
                best = (channel, disp, ratio, null)

        print(f"{eid[:28]:30s} "
              f"{cp_on.strftime('%H:%M') if cp_on else '--':>8s} "
              f"{tf_start.strftime('%H:%M') if tf_start else '--':>8s} "
              f"{'' if lag is None else f'{lag:+6.0f}':>7s} | "
              f"{(best[0] if best else '--'):13s} "
              f"{(f'{best[1]:.2f}' if best else '--'):>7s} "
              f"{(f'{best[3]:.2f}' if best else '--'):>7s} "
              f"{(f'{best[2]:.1f}' if best else '--'):>7s} | "
              f"{r.get('control_pct_drop', ''):>9s} "
              f"{r.get('traffic_pct_drop', ''):>9s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
