"""The decisive experiment for the CDPR representation.

Three findings from the diagnostics drive this script.

1.  **The control-plane buckets are chunk measurements, not rates.**
    The detector emits one bucket per parquet chunk; the bucket's stamp
    is the chunk's start and the bucket's count is the number of
    routing messages the chunk carried.  Chunks have unequal durations
    (5 minutes to 35 minutes in the corpus), so the *count* is not
    comparable across buckets.  A count of 26 over five minutes is
    three times the rate of a count of 26 over thirty minutes.

2.  **The "baseline" window is evidence, not only a null.**
    The quick path runs the routing detector over the window the
    *traffic* stage asked for.  When the traffic impact starts before
    that window does -- which is the normal case, because the traffic
    provider reports the impact at the trough and the routing window
    is opened at the announced start -- the control-plane onset falls
    inside the detector's *baseline* period.  The baseline is therefore
    read as part of the control-plane series, and only its robust
    central level is used as the null.

3.  **The traffic response is a level shift of the measured value.**
    The detector's ``z_score`` is standardised against a mean that the
    cache carries as a placeholder, so a large ``z`` can sit on a
    perfectly normal observation.  The level shift of the measured
    value series is the physical quantity: the impact is the traffic
    metric leaving the level it occupied before the incident.

This script puts all three together and reports, for every event, the
control-plane onset, the response onset, and the lag between them.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"

CHANNELS = {
    "volume": ("announcement_count", "total_messages"),
    "origin_change": ("num_ori_change", "ori_change_rate"),
    "path_change": ("num_path_change", "path_change_rate"),
}


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def read_buckets(block: Any) -> List[Tuple[datetime, Dict[str, Any]]]:
    if not isinstance(block, dict):
        return []
    out = []
    for raw, entry in block.items():
        if not isinstance(entry, dict):
            continue
        ts = parse_timestamp(raw)
        if ts is None:
            continue
        out.append((ts, entry))
    out.sort(key=lambda p: p[0])
    return out


def channel_value(entry: Dict[str, Any], channel: str) -> float:
    for key in CHANNELS[channel]:
        val = _num(entry.get(key))
        if val is not None:
            return val
    return 0.0


def build_control(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """The control plane as a union series of chunk rates.

    The event window and the baseline window are contiguous in time and
    both are real routing observations, so they are read as one series.
    Each bucket's *rate* is its count divided by the wall-clock span it
    covers, which makes buckets of unequal duration comparable.
    """
    event = read_buckets(analysis.get("timeseries_event"))
    base = read_buckets(analysis.get("timeseries_baseline"))
    merged: List[Tuple[datetime, Dict[str, Any]]] = []
    seen = set()
    for ts, entry in event + base:
        if ts in seen:
            continue
        seen.add(ts)
        merged.append((ts, entry))
    merged.sort(key=lambda p: p[0])

    default_span = 300.0
    spans: List[float] = []
    for i, (ts, _) in enumerate(merged):
        if i + 1 < len(merged):
            span = (merged[i + 1][0] - ts).total_seconds()
        else:
            span = default_span
        spans.append(span if span > 0 else default_span)

    rates: Dict[str, List[float]] = {}
    for channel in CHANNELS:
        rates[channel] = [
            channel_value(entry, channel) / (span / 60.0)
            for (_, entry), span in zip(merged, spans)
        ]

    # The null: the robust central rate of the detector's own baseline
    # period.  A median is used because the baseline period can contain
    # the incident itself.
    levels: Dict[str, float] = {}
    for channel in CHANNELS:
        vals = [channel_value(entry, channel) / (span / 60.0)
                for (_, entry), span in zip(base, spans[len(base):] or spans)]
        # ``spans`` was computed on the merged series; recompute on base.
        vals = []
        for i, (_, entry) in enumerate(base):
            if i + 1 < len(base):
                span = (base[i + 1][0] - base[i][0]).total_seconds()
            else:
                span = default_span
            if span <= 0:
                span = default_span
            vals.append(channel_value(entry, channel) / (span / 60.0))
        positives = [v for v in vals if v > 0]
        levels[channel] = float(np.median(positives)) if positives else 0.0

    return {
        "stamps": [ts for ts, _ in merged],
        "rates": rates,
        "levels": levels,
        "n": len(merged),
        "n_base": len(base),
        "n_event": len(event),
    }


def sustained_onset(values: List[float], level: float, tol: float,
                    persist: int) -> Optional[int]:
    n = len(values)
    for i in range(n):
        if abs(values[i] - level) <= tol:
            continue
        tail = values[i:i + persist]
        if len(tail) < persist:
            break
        if all(abs(v - level) > tol for v in tail):
            return i
    return None


def detect_control_onset(control: Dict[str, Any], channel: str,
                          width: int = 3, tol_frac: float = 0.6,
                          persist: int = 2) -> Optional[int]:
    """The first sustained departure of the channel's rate from normal."""
    rates = control["rates"][channel]
    level = control["levels"][channel]
    if level <= 0 or not rates:
        return None
    factor = [r / level for r in rates]
    if width > 1:
        smoothed = [float(np.mean(factor[max(0, i - width + 1):i + 1]))
                    for i in range(len(factor))]
    else:
        smoothed = factor
    return sustained_onset(smoothed, 1.0, tol_frac, persist)


def build_traffic(cache: Dict[str, Any]) -> List[Tuple[datetime, float]]:
    """The traffic side as a de-duplicated level series."""
    corr = cache.get("correlation") or {}
    tb = cache.get("traffic") or {}
    raw = None
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
        val = _num(e.get("current_value"))
        if val is None:
            val = _num(e.get("value"))
        if val is None:
            continue
        if ts not in best:
            best[ts] = val
    return sorted(best.items())


def detect_response_onset(series: List[Tuple[datetime, float]],
                          lead: int = 3, persist: int = 2
                          ) -> Tuple[Optional[int], float]:
    """The first sustained level shift of the traffic metric."""
    n = len(series)
    if n < 4:
        return None, 0.0
    values = [v for _, v in series]
    h = max(2, min(lead, n // 3))
    leading = values[:h]
    level = float(np.median(leading))
    mad = float(np.median(np.abs(np.array(leading) - level)))
    band = max(mad * 3.0, abs(level) * 0.20, 1e-12)
    for i in range(h, n):
        if abs(values[i] - level) <= band:
            continue
        tail = values[i:i + persist]
        if len(tail) < persist:
            break
        if all(abs(v - level) > band for v in tail):
            return i, abs(level - values[i]) / max(abs(level), 1e-12)
    return None, 0.0


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':32s} {'ch':14s} {'cp_onset':>10s} {'tf_onset':>10s} "
          f"{'lag_min':>8s} {'drop':>6s}  cp_windows")
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"{eid[:30]:32s} NO CACHE")
            continue
        cache = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (cache.get("routing") or {}).get("outage_analysis") or {}
        control = build_control(oa)
        traffic = build_traffic(cache)
        tau_r, drop = detect_response_onset(traffic)
        tf_stamp = traffic[tau_r][0] if tau_r is not None else None

        printed = False
        for channel in CHANNELS:
            tau_c = detect_control_onset(control, channel)
            cp_stamp = control["stamps"][tau_c] if tau_c is not None else None
            lag = ((tf_stamp - cp_stamp).total_seconds() / 60.0
                   if tf_stamp and cp_stamp else None)
            if not printed:
                printed = True
                print(f"{eid[:30]:32s} "
                      f"n_cp={control['n']:4d}(e{control['n_event']}/b{control['n_base']}) "
                      f"n_tf={len(traffic):3d} "
                      f"cp=[{control['stamps'][0] if control['stamps'] else None}"
                      f"..{control['stamps'][-1] if control['stamps'] else None}] "
                      f"tf=[{traffic[0][0] if traffic else None}"
                      f"..{traffic[-1][0] if traffic else None}]")
            print(f"{'':32s} {channel:14s} "
                  f"{str(cp_stamp):>10s} {str(tf_stamp):>10s} "
                  f"{'' if lag is None else f'{lag:+8.0f}':>8s} "
                  f"{drop:6.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
