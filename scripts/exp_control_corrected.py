"""The corrected control-plane construction, and the pairing experiment.

The earlier version of this experiment had two defects, both visible
in its own output:

*   The null was the **median of the non-zero baseline cells**, but the
    statistic was a **rolling mean over twelve cells**.  A channel that
    emits messages in one cell out of twelve has a non-zero-cell median
    of one message and a rolling mean of one twelfth of a message, so
    the two were never on the same scale and the departure was read at
    the wrong place.  The null has to be the *mean per cell* of the
    baseline period -- zeros included -- because a rolling mean over
    ``w`` cells has expectation ``w`` times that.

*   The control plane was read over the detector's *event* window only.
    But the traffic impact very often starts **before** the announced
    window does: Telia Finland's traffic collapsed at 06:45 while the
    routing window opens at 08:00.  The control-plane movement is
    therefore in the detector's *baseline* period, which the estimator
    would otherwise use only as a null.  The baseline is real routing
    evidence and is read as part of the series.

This script puts the corrected control plane against several readings
of the traffic response and prints the pairing, so the choice of
response definition is made on the evidence and not by assumption.
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

#: Each channel is read from the feature that actually carries it.  A
#: ratio and a count are not interchangeable, so they are not mixed.
CHANNEL_FEATURES: Dict[str, Tuple[str, ...]] = {
    "volume": ("total_messages", "announcement_count"),
    "origin_change": ("num_ori_change", "origin_change_count"),
    "path_change": ("path_change_rate",),
}


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
    """The control plane on one uniform grid with the holes filled.

    An omitted bucket means *zero* routing messages, not a missing
    measurement, so the grid is filled with zeros and the count in a
    cell is the rate over that cell.
    """
    stamps_all = sorted(set(event) | set(base))
    if not stamps_all:
        return {"stamps": [], "cells": {}, "split": 0, "level": {},
                "scale": {}}

    origin = stamps_all[0]
    n_cells = int((stamps_all[-1] - origin).total_seconds()) // GRID_SECONDS + 1

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
        base_end = max(base)
        split = int((base_end - origin).total_seconds()) // GRID_SECONDS + 1
    else:
        split = 0
    split = max(0, min(split, n_cells))

    level: Dict[str, float] = {}
    scale: Dict[str, float] = {}
    for ch in CHANNEL_FEATURES:
        seg = np.asarray(cells[ch][:split] if split > 0 else cells[ch],
                         dtype=float)
        # The expected number of messages in a *typical* cell of the
        # baseline period.  Zeros are part of the typical cell: a
        # channel that emits in one cell out of five emits zero in the
        # other four.
        level[ch] = float(seg.mean()) if seg.size else 0.0
        # The dispersion of the baseline's own rolling sums, which is
        # the yardstick the departure is measured against.
        if seg.size >= 4:
            roll = np.convolve(seg, np.ones(4) / 4.0, mode="valid")
            med = float(np.median(roll))
            mad = float(np.median(np.abs(roll - med)))
            scale[ch] = 1.4826 * mad
        else:
            scale[ch] = 0.0

    return {"stamps": stamps, "cells": cells, "split": split,
            "level": level, "scale": scale}


def control_onset(control: Dict[str, Any], channel: str, width: int,
                  k: float, persist: int) -> Optional[int]:
    """The first sustained departure of the control plane from normal.

    The statistic is a rolling sum over ``width`` cells; its null is
    ``width`` times the baseline's mean per cell, and its scale is the
    baseline's own rolling-sum dispersion.
    """
    cells = control["cells"].get(channel) or []
    level = control["level"].get(channel, 0.0)
    scale = control["scale"].get(channel, 0.0)
    n = len(cells)
    if n < max(width, persist) or level <= 0:
        return None

    roll = np.convolve(np.asarray(cells, dtype=float),
                       np.ones(width), mode="full")[:n]
    expected = width * level
    # The threshold on the rolling sum: the baseline's own dispersion,
    # widened so a channel whose baseline is perfectly flat still has a
    # usable floor.
    floor = max(k * width * scale, 0.25 * expected, 1e-9)

    for i in range(n):
        if abs(roll[i] - expected) <= floor:
            continue
        tail = roll[i:i + persist]
        if len(tail) < persist:
            break
        if all(abs(v - expected) > floor for v in tail):
            return i
    return None


def traffic_points(cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every traffic observation the detector recorded, with its fields."""
    corr = cache.get("correlation") or {}
    tb = cache.get("traffic") or {}
    raw = None
    for source in (corr.get("traffic_events_full"), tb.get("anomalies"),
                   corr.get("traffic_events")):
        if isinstance(source, list) and source:
            raw = source
            break
    if raw is None:
        return []
    out = []
    seen = set()
    for e in raw:
        if not isinstance(e, dict):
            continue
        ts = parse_timestamp(e.get("timestamp") or e.get("time"))
        if ts is None or ts in seen:
            continue
        seen.add(ts)
        out.append({
            "ts": ts,
            "z": abs(float(e.get("z_score") or 0.0)),
            "value": _num(e.get("current_value")) if _num(e.get("current_value"))
            is not None else _num(e.get("value")),
            "method": str(e.get("method") or ""),
            "severity": str(e.get("severity") or ""),
        })
    out.sort(key=lambda p: p["ts"])
    return out


def response_candidates(cache: Dict[str, Any],
                        points: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Several readings of "when the data plane answered"."""
    tb = cache.get("traffic") or {}
    out: Dict[str, Any] = {}

    if points:
        out["first_anomaly"] = points[0]["ts"]
        # The trough: the observation at which the metric was furthest
        # from its normal level.
        trough = None
        for p in points:
            v = p["value"]
            if v is None:
                continue
            if trough is None or v < trough[1]:
                trough = (p["ts"], v)
        if trough:
            out["trough"] = trough[0]
        # The first sustained-outage anomaly, which the detector marks
        # when the metric actually collapsed rather than merely moved.
        sustained = [p["ts"] for p in points
                     if p["method"] == "sustained_outage"]
        if sustained:
            out["sustained"] = sustained[0]

    for key in ("consecutive_anomaly_windows", "expanded_windows"):
        wins = tb.get(key)
        if isinstance(wins, list) and wins:
            ts = parse_timestamp(wins[0].get("start"))
            if ts is not None:
                out[f"{key}_start"] = ts
                break
    return out


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':30s} {'cp_onset':>10s} {'ch':13s} | "
          f"{'first':>8s} {'trough':>8s} {'sust':>8s} {'win':>8s} | "
          f"{'lag_trough':>10s}")
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
        points = traffic_points(cache)
        cand = response_candidates(cache, points)

        best = None
        for channel in CHANNEL_FEATURES:
            at = control_onset(control, channel, width=6, k=3.0, persist=3)
            if at is None:
                continue
            stamp = control["stamps"][at]
            if best is None or stamp < best[1]:
                best = (channel, stamp)
        if best is None:
            print(f"{eid[:28]:30s} {'--':>10s} {'--':13s} | "
                  f"{'':8s} {'':8s} {'':8s} {'':8s} |")
            continue
        channel, cp_stamp = best

        def fmt(key: str) -> str:
            ts = cand.get(key)
            return ts.strftime("%H:%M") if ts else "-"

        lag = None
        if cand.get("trough"):
            lag = (cand["trough"] - cp_stamp).total_seconds() / 60.0
        print(f"{eid[:28]:30s} {cp_stamp.strftime('%m-%d %H:%M'):>10s} "
              f"{channel:13s} | {fmt('first_anomaly'):>8s} "
              f"{fmt('trough'):>8s} {fmt('sustained'):>8s} "
              f"{fmt('consecutive_anomaly_windows_start'):>8s} | "
              f"{'' if lag is None else f'{lag:+8.0f}m':>10s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
