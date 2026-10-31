"""The final method: a paired difference-in-differences on the control plane.

Everything the earlier experiments established, in one place.

**What the data actually is.**  The routing detector buckets the
target AS's *involvement* in routing messages on a five-minute grid;
the ground-truth verifier buckets the target's *own announcements* on
the same grid and compares them with the **same clock slots on the
previous days**.  The same-clock comparison is the only one that
works: a network announces more at 14:30 than at 03:00 whatever
happened, so a 45-minute incident measured against a 24-hour average
measures the time of day.  The rates are per **wall-clock slot**, not
per observed bucket, because a bucket with no announcement is a slot in
which the network was quiet.

**The causal question, and why the old framing fails.**  The question
is not "did A move, then did B move".  It is "**when the data plane
deviated, had the control plane already deviated, and did it deviate
more than it does on an ordinary day at the same hour**".  That is a
*paired* question, and answering it needs a *counterfactual*: what
the control plane would have done at that hour if nothing had happened.
The counterfactual is the same clock slots on the previous days.

**Why the counterfactual is the control arm.**  A global traffic
series moves for reasons that have nothing to do with the victim.  The
ground truth records exactly this: ``control_z_min`` is the *global*
series' z-score at the victim's trough, and the dataset admits an event
only when the victim's drop exceeds the global one by a margin.  A
causal claim about one AS has to be made against the same background,
or it is really a claim about the internet.

**The four vetoes, restated for this design.**

V1 *Precedence*   the control plane must have deviated **at or before**
    the data plane's trough, within a physical propagation bound.
V2 *Exclusivity*  the control plane's deviation must exceed what the
    same channel shows at **placebo windows** of the same length in the
    same-clock baseline.  The null is the instrument's own behaviour on
    the same quantity at the same hour on ordinary days.
V3 *Scope*        the routing edge and the measured series must be
    about the same entity.
V4 *Congruence*   the two movements must point the same way, and the
    routing edge's kind must be physically compatible with the
    direction claimed.

This script evaluates the design's statistics on the corpus.
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

#: Each channel is read from the feature that carries it.  A ratio and a
#: count are different quantities and are never mixed.
CHANNEL_FEATURES: Dict[str, Tuple[str, ...]] = {
    "volume": ("total_messages", "announcement_count"),
    "withdrawal": ("withdrawal_count",),
    "origin_change": ("num_ori_change", "origin_change_count"),
    "path_change": ("path_change_rate",),
}


def num(value: Any) -> Optional[float]:
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
        val = num(entry.get(key))
        if val is not None:
            return val
    return 0.0


def same_clock_baseline(buckets: Dict[datetime, Dict[str, Any]],
                        channel: str, window_start: datetime,
                        window_end: datetime,
                        days: int = 4) -> Dict[str, float]:
    """The channel's mean rate in the *same clock slots* on earlier days.

    The baseline is keyed by the clock position (``HH:MM``) of the
    slot, and each key holds the average over the previous days.  This
    is the counterfactual the causal question needs: what this channel
    does at this hour on an ordinary day.
    """
    slots: Dict[str, List[float]] = {}
    moment = window_start.replace(second=0, microsecond=0)
    step = timedelta(seconds=GRID_SECONDS)
    slot_keys: List[str] = []
    while moment <= window_end:
        slot_keys.append(moment.strftime("%H:%M"))
        moment += step

    by_slot: Dict[str, List[float]] = {k: [] for k in slot_keys}
    for ts, entry in buckets.items():
        delta = (window_start.date() - ts.date()).days
        if delta <= 0:
            continue
        if delta > days:
            continue
        key = ts.strftime("%H:%M")
        if key in by_slot:
            by_slot[key].append(channel_value(entry, channel))

    out: Dict[str, float] = {}
    for key in slot_keys:
        values = by_slot.get(key) or []
        out[key] = float(np.mean(values)) if values else 0.0
    return out


def grid_rate(buckets: Dict[datetime, Dict[str, Any]], channel: str,
              start: datetime, end: datetime) -> Tuple[List[str], List[float]]:
    """The channel's rate per wall-clock slot in the window.

    A slot with no bucket is a slot with zero messages, and the rate
    is per slot -- not per observed bucket -- because the whole point
    is to see a collapse.
    """
    slot_values: Dict[str, float] = {}
    for ts, entry in buckets.items():
        if not (start <= ts <= end):
            continue
        slot_values[ts.strftime("%H:%M")] = channel_value(entry, channel)

    slots: List[str] = []
    rates: List[float] = []
    moment = start.replace(second=0, microsecond=0)
    step = timedelta(seconds=GRID_SECONDS)
    while moment <= end:
        key = moment.strftime("%H:%M")
        slots.append(key)
        rates.append(slot_values.get(key, 0.0))
        moment += step
    return slots, rates


def traffic_measure(cache: Dict[str, Any]) -> Dict[str, Any]:
    """The data plane's measurement: its trough and the deviation there.

    The traffic detector stored, for every anomaly, the measured value
    *and* the historical mean and standard deviation it compared it
    against.  That comparison is already a same-clock comparison, so
    the deviation is available without re-fetching anything.
    """
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
        return {}

    best_z = None
    trough = None
    for e in raw:
        if not isinstance(e, dict):
            continue
        ts = parse_timestamp(e.get("timestamp") or e.get("time"))
        if ts is None:
            continue
        z = num(e.get("z_score"))
        if z is not None and (best_z is None or z < best_z[0]):
            best_z = (float(z), ts)
        val = num(e.get("current_value"))
        if val is None:
            val = num(e.get("value"))
        if val is not None and (trough is None or val < trough[0]):
            trough = (float(val), ts)

    out: Dict[str, Any] = {}
    if best_z:
        out["z_min"] = best_z[0]
        out["z_time"] = best_z[1]
    if trough:
        out["trough_value"] = trough[0]
        out["trough_time"] = trough[1]
    return out


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':28s} {'ch':13s} {'disp':>6s} {'null':>6s} {'excl':>6s} | "
          f"{'cp_trough':>9s} {'tf_trough':>9s} {'lag_m':>7s} | "
          f"{'gt_cz':>7s} {'gt_cdrop':>8s}")
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"{eid[:26]:28s} NO CACHE")
            continue
        cache = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (cache.get("routing") or {}).get("outage_analysis") or {}
        event_b = read_buckets(oa.get("timeseries_event"))
        base_b = read_buckets(oa.get("timeseries_baseline"))
        if not event_b:
            print(f"{eid[:26]:28s} NO CONTROL SERIES")
            continue

        measure = traffic_measure(cache)
        tf_trough = measure.get("trough_time")
        if tf_trough is None:
            print(f"{eid[:26]:28s} NO TRAFFIC MEASURE")
            continue

        # The paired window: the data plane's impact, measured on the
        # control plane's grid.
        win_start = tf_trough - timedelta(minutes=30)
        win_end = tf_trough + timedelta(minutes=30)

        rows_out = []
        for channel in CHANNEL_FEATURES:
            slots, rates = grid_rate(event_b, channel, win_start, win_end)
            if not slots:
                continue
            observed = float(np.mean(rates))
            baseline = same_clock_baseline(
                base_b, channel, win_start, win_end)
            base_vals = [baseline.get(k, 0.0) for k in slots]
            expected = float(np.mean(base_vals)) if base_vals else 0.0
            if expected <= 0:
                continue
            disp = observed / expected

            # The placebo null: the same channel's displacement at
            # placebo windows of the same length inside the baseline.
            nulls: List[float] = []
            if base_b:
                stamps = sorted(base_b)
                for i in range(0, max(1, len(stamps) - len(slots) + 1)):
                    p_start = stamps[i]
                    p_end = p_start + timedelta(
                        seconds=GRID_SECONDS * (len(slots) - 1))
                    p_slots, p_rates = grid_rate(base_b, channel,
                                                 p_start, p_end)
                    if len(p_rates) != len(rates):
                        continue
                    p_base = same_clock_baseline(
                        base_b, channel, p_start, p_end)
                    p_expected = float(np.mean(
                        [p_base.get(k, 0.0) for k in p_slots])) \
                        if p_slots else 0.0
                    if p_expected <= 0:
                        continue
                    nulls.append(abs(float(np.mean(p_rates)) / p_expected - 1.0))
            null = max(nulls) if nulls else 0.0
            excl = abs(disp - 1.0) / null if null > 1e-9 else float("inf")
            rows_out.append((channel, disp, null, excl))

        if not rows_out:
            print(f"{eid[:26]:28s} NO CHANNEL WITH BASELINE")
            continue
        channel, disp, null, excl = max(rows_out, key=lambda t: t[3])

        # The control plane's own deviation at the data plane's trough.
        cp_stamps = sorted(event_b)
        cp_at = None
        for ts in cp_stamps:
            if abs((ts - tf_trough).total_seconds()) <= GRID_SECONDS:
                cp_at = ts
                break
        lag = ((tf_trough - cp_at).total_seconds() / 60.0
               if cp_at else None)

        print(f"{eid[:26]:28s} {channel:13s} {disp:6.2f} {null:6.2f} "
              f"{excl:6.1f} | "
              f"{cp_at.strftime('%H:%M') if cp_at else '--':>9s} "
              f"{tf_trough.strftime('%H:%M'):>9s} "
              f"{'' if lag is None else f'{lag:+6.0f}':>7s} | "
              f"{r.get('control_z_min', ''):>7s} "
              f"{r.get('control_pct_drop', ''):>8s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
