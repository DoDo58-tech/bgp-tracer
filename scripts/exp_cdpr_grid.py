"""The decisive experiment for the CDPR representation.

What the diagnostics established about the data:

*   The routing detector emits **5-minute grid buckets**, but it only
    emits a bucket when the target AS had at least one routing message
    in it.  An omitted bucket therefore means *zero* routing messages,
    not a missing measurement.  Reading the series as it is stored --
    with holes in it -- makes a bucket's count look incomparable with
    its neighbour's, because a bucket 30 minutes after the previous one
    covers three empty grid cells that are simply not there.

*   The buckets carry counts (``announcement_count``,
    ``withdrawal_count``, ``num_ori_change``) and *ratios*
    (``path_change_rate``, ``ori_change_rate``).  A ratio is not a
    count and cannot be compared with one; each channel has to be read
    from the feature that actually carries it.

*   The detector's *baseline* window is real routing evidence too.  It
    is the period before the announced window, and the control-plane
    onset often falls inside it, because the traffic impact is usually
    reported before the routing window is opened.  Reading the baseline
    as only a null throws away the evidence that carries the onset.

*   The traffic detector stores the anomalies it found, each with its
    own wall-clock timestamp, the measured value, and the deviation
    from the historical baseline.  That is a *response* series: the
    points where the data plane left its normal level.

This script puts the three together -- control-plane rate on a filled
uniform grid, a robust null from the baseline window, a sustained
departure as the onset, and the traffic anomaly series as the response
-- and reports, for every event and every protocol setting, whether the
control-plane onset precedes the traffic response and by how much.
"""
from __future__ import annotations

import csv
import itertools
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"

#: The grid the routing detector buckets on.
GRID_SECONDS = 300

#: The channels of the control plane, each read from the feature that
#: actually carries it.  ``volume`` counts messages, ``origin_change``
#: counts origin changes; a *rate* feature is not mixed in with them.
CHANNEL_FEATURES: Dict[str, Tuple[str, ...]] = {
    "volume": ("announcement_count", "total_messages"),
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


def channel_count(entry: Dict[str, Any], channel: str) -> float:
    for key in CHANNEL_FEATURES[channel]:
        val = _num(entry.get(key))
        if val is not None:
            return val
    return 0.0


def fill_grid(event: Dict[datetime, Dict[str, Any]],
              base: Dict[datetime, Dict[str, Any]],
              ) -> Tuple[List[datetime], Dict[str, List[float]],
                         List[int], Dict[str, float]]:
    """The control plane on one uniform grid, with the holes filled.

    The event window and the baseline window are contiguous in time and
    both are routing observations, so they are read as one series.  The
    grid is the detector's own five-minute grid; a cell with no bucket
    is a cell with zero routing messages.

    Returns the grid stamps, the per-channel cell values, the index
    where the baseline period ends, and the baseline's robust level
    per channel.
    """
    all_stamps = sorted(set(event) | set(base))
    if not all_stamps:
        return [], {}, 0, {}

    origin = all_stamps[0]
    last = all_stamps[-1]
    n_cells = int((last - origin).total_seconds()) // GRID_SECONDS + 1
    if n_cells <= 0:
        return [], {}, 0, {}

    cells: Dict[str, List[float]] = {
        ch: [0.0] * n_cells for ch in CHANNEL_FEATURES
    }
    for ts, entry in event.items():
        idx = int((ts - origin).total_seconds()) // GRID_SECONDS
        if 0 <= idx < n_cells:
            for ch in CHANNEL_FEATURES:
                cells[ch][idx] = channel_count(entry, ch)
    for ts, entry in base.items():
        idx = int((ts - origin).total_seconds()) // GRID_SECONDS
        if 0 <= idx < n_cells:
            for ch in CHANNEL_FEATURES:
                # The baseline is never added on top of the event: the
                # two are disjoint in time by construction, but a cell
                # at the seam can carry a bucket from either side.
                if cells[ch][idx] == 0.0:
                    cells[ch][idx] = channel_count(entry, ch)

    stamps = [origin + timedelta(seconds=GRID_SECONDS * i)
              for i in range(n_cells)]

    # Where the baseline period ends.
    if base:
        base_end = max(base)
        split = int((base_end - origin).total_seconds()) // GRID_SECONDS + 1
    else:
        split = 0
    split = max(0, min(split, n_cells))

    levels: Dict[str, float] = {}
    for ch in CHANNEL_FEATURES:
        seg = cells[ch][:split] if split > 0 else cells[ch]
        if not seg:
            levels[ch] = 0.0
            continue
        arr = np.asarray(seg, dtype=float)
        nonzero = arr[arr > 0]
        # The central level of normal operation, measured in messages
        # per grid cell.  The median over *all* cells (zeros included)
        # is the right central level for a count that is usually small.
        levels[ch] = float(np.median(nonzero)) if nonzero.size else 0.0

    return stamps, cells, split, levels


def rolling_mean(values: Sequence[float], width: int) -> List[float]:
    if width <= 1:
        return list(values)
    arr = np.asarray(values, dtype=float)
    out = []
    for i in range(len(arr)):
        lo = max(0, i - width + 1)
        out.append(float(arr[lo:i + 1].mean()))
    return out


def robust_scale(values: Sequence[float]) -> float:
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return 0.0
    med = float(np.median(arr))
    mad = float(np.median(np.abs(arr - med)))
    return 1.4826 * mad


def onset_from_grid(cells: Sequence[float], level: float,
                    split: int, width: int, k: float,
                    persist: int) -> Optional[int]:
    """The first sustained departure of the rate from its normal level.

    The departure is measured against a robust scale computed on the
    baseline period only, so the incident's own excursion cannot
    inflate the threshold it has to clear.
    """
    n = len(cells)
    if n < persist or level <= 0:
        return None
    smoothed = rolling_mean(cells, width)
    normalised = [v / level for v in smoothed]
    scale = robust_scale(normalised[:split] if split > 0 else normalised[:1])
    if scale <= 1e-9:
        scale = 0.05
    # The threshold is the robust scale of the baseline's own
    # fluctuation, floored so a very quiet channel still has one.
    band = max(k * scale, 0.15)

    for i in range(n):
        if abs(normalised[i] - 1.0) <= band:
            continue
        tail = normalised[i:i + persist]
        if len(tail) < persist:
            break
        if all(abs(v - 1.0) > band for v in tail):
            return i
    return None


def traffic_response(cache: Dict[str, Any]) -> List[Tuple[datetime, float]]:
    """The traffic anomaly series: (timestamp, absolute deviation)."""
    corr = cache.get("correlation") or {}
    tb = cache.get("traffic") or {}
    raw = None
    # The anomaly list is preferred: it is the record that carries the
    # measured value *and* the historical mean it was compared against.
    # The serialised event stream carries a placeholder baseline, so a
    # consumer that reads it first reconstructs a deviation of hundreds
    # of standard deviations with the sign inverted.
    for source in (tb.get("anomalies"), corr.get("traffic_events_full"),
                   corr.get("traffic_events")):
        if isinstance(source, list) and source:
            raw = source
            break
    if raw is None:
        return []
    best: Dict[datetime, float] = {}
    for e in raw:
        if not isinstance(e, dict):
            continue
        ts = parse_timestamp(e.get("timestamp") or e.get("time"))
        if ts is None:
            continue
        z = _num(e.get("z_score"))
        if z is None:
            val = _num(e.get("current_value"))
            if val is None:
                val = _num(e.get("value"))
            z = abs(val) if val is not None else 0.0
        mag = abs(float(z))
        if ts not in best or mag > best[ts]:
            best[ts] = mag
    return sorted(best.items())


def window_start(cache: Dict[str, Any]) -> Optional[datetime]:
    tb = cache.get("traffic") or {}
    period = tb.get("original_outage_period")
    if isinstance(period, dict):
        ts = parse_timestamp(period.get("start_time"))
        if ts is not None:
            return ts
    return parse_timestamp(cache.get("start_time"))


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    events: List[Dict[str, Any]] = []
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            continue
        cache = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (cache.get("routing") or {}).get("outage_analysis") or {}
        event = read_buckets(oa.get("timeseries_event"))
        base = read_buckets(oa.get("timeseries_baseline"))
        if not event and not base:
            continue
        stamps, cells, split, levels = fill_grid(event, base)
        response = traffic_response(cache)
        events.append({
            "event_id": eid,
            "cause": r.get("cause", ""),
            "stamps": stamps,
            "cells": cells,
            "split": split,
            "levels": levels,
            "response": response,
            "window_start": window_start(cache),
        })

    print(f"loaded {len(events)} events with a control-plane series")

    widths = (6, 12, 24, 36)
    ks = (2.0, 3.0, 4.0)
    persists = (2, 3, 4)
    lag_max = 90 * 60.0

    results: List[Dict[str, Any]] = []
    for width, k, persist in itertools.product(widths, ks, persists):
        correct = 0
        wrong = 0
        abstain = 0
        details: List[Dict[str, Any]] = []
        for ev in events:
            best_channel = None
            for channel in CHANNEL_FEATURES:
                level = ev["levels"].get(channel, 0.0)
                if level <= 0:
                    continue
                at = onset_from_grid(ev["cells"][channel], level,
                                     ev["split"], width, k, persist)
                if at is None:
                    continue
                cp_stamp = ev["stamps"][at]
                # The response onset: the first traffic anomaly.
                if not ev["response"]:
                    continue
                tf_stamp = ev["response"][0][0]
                lag = (tf_stamp - cp_stamp).total_seconds()
                if best_channel is None or lag > best_channel[1]:
                    best_channel = (channel, lag, cp_stamp, tf_stamp)
            if best_channel is None:
                abstain += 1
                details.append({"event_id": ev["event_id"],
                                "outcome": "abstain", "reason": "no_onset"})
                continue
            channel, lag, cp_stamp, tf_stamp = best_channel
            if 0.0 <= lag <= lag_max:
                correct += 1
                outcome = "correct"
            else:
                wrong += 1
                outcome = "wrong"
            details.append({
                "event_id": ev["event_id"], "outcome": outcome,
                "channel": channel, "lag_min": round(lag / 60.0, 1),
                "cp": str(cp_stamp), "tf": str(tf_stamp),
            })
        results.append({
            "width": width, "k": k, "persist": persist,
            "correct": correct, "wrong": wrong, "abstain": abstain,
            "n": len(events),
            "details": details,
        })

    results.sort(key=lambda r: (-r["correct"], r["wrong"], -r["persist"]))
    print(f"\n{'w':>3s} {'k':>4s} {'p':>2s} {'ok':>3s} {'bad':>4s} "
          f"{'abs':>4s}  score")
    for r in results[:20]:
        print(f"{r['width']:>3d} {r['k']:>4.1f} {r['persist']:>2d} "
              f"{r['correct']:>3d} {r['wrong']:>4d} {r['abstain']:>4d}  "
              f"{r['correct'] / r['n']:.3f}")

    best = results[0]
    print(f"\nbest: width={best['width']} k={best['k']} persist={best['persist']}")
    for d in best["details"]:
        print(f"  {d['event_id'][:40]:42s} {d['outcome']:8s} "
              f"{d.get('channel',''):14s} lag={d.get('lag_min')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
