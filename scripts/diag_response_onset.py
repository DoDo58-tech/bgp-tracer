"""Locate the traffic response onset on the measured value series.

The data-plane response is a *level shift* of the measured traffic
metric: the incident is the metric leaving the level it occupied before.
The detector's ``z_score`` is not used for the onset -- the cache's
z-scores are standardised against a placeholder mean and therefore
place a large z on a perfectly ordinary observation -- but the measured
value is used as it was recorded, on its own timestamps.

This prints the de-duplicated value series and the onset that a
sustained-level-shift rule finds, next to the trough the ground truth
recorded, so the two can be compared directly.
"""
from __future__ import annotations

import csv
import json
import re
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

_TROUGH_RE = re.compile(r"trough=([0-9T:\-]+Z?)")


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def traffic_series(cache: Dict[str, Any]) -> List[Tuple[datetime, float]]:
    """The measured traffic metric, one value per distinct timestamp."""
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
        val = _num(e.get("current_value"))
        if val is None:
            val = _num(e.get("value"))
        if val is None:
            continue
        # A zero placeholder and a real measurement can share a stamp;
        # the real one is kept.
        if ts not in best or abs(val) > abs(best[ts]):
            best[ts] = val
    return sorted(best.items())


def onset(series: List[Tuple[datetime, float]], lead: int = 3,
          persist: int = 2, rel: float = 0.25) -> Optional[int]:
    n = len(series)
    if n < 4:
        return None
    values = [v for _, v in series]
    h = max(2, min(lead, n // 3))
    head = np.asarray(values[:h], dtype=float)
    level = float(np.median(head))
    mad = float(np.median(np.abs(head - level)))
    band = max(mad * 3.0, abs(level) * rel, 1e-12)
    for i in range(h, n):
        if abs(values[i] - level) <= band:
            continue
        tail = values[i:i + persist]
        if len(tail) < persist:
            break
        if all(abs(v - level) > band for v in tail):
            return i
    return None


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"\n### {eid}: NO CACHE")
            continue
        cache = json.loads(m.path.read_text(encoding="utf-8"))
        series = traffic_series(cache)
        gt_start = parse_timestamp(r.get("start_utc"))
        note = r.get("traffic_note", "")
        tm = _TROUGH_RE.search(note or "")
        gt_trough = parse_timestamp(tm.group(1)) if tm else None

        print(f"\n### {eid}")
        print(f"    gt_start={gt_start}  gt_trough={gt_trough}  n={len(series)}")
        if not series:
            print("    NO TRAFFIC SERIES")
            continue
        vals = [v for _, v in series]
        print(f"    values: {['%.4g' % v for v in vals]}")
        for lead in (2, 3, 4):
            for persist in (1, 2, 3):
                at = onset(series, lead, persist)
                if at is None:
                    continue
                stamp = series[at][0]
                d_gt = ((stamp - gt_start).total_seconds() / 60.0
                        if gt_start else None)
                d_tr = ((stamp - gt_trough).total_seconds() / 60.0
                        if gt_trough else None)
                print(f"    onset lead={lead} persist={persist}: {stamp} "
                      f"(vs gt_start {d_gt:+.0f}m, vs gt_trough {d_tr:+.0f}m)"
                      if d_gt is not None and d_tr is not None else
                      f"    onset lead={lead} persist={persist}: {stamp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
