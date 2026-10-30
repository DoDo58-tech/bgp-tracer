"""Locate an incident with a sustained-deviation rule.

The corpus records the incident window for every event, which is a
ground truth for localisation.  The control-plane rate is measured in
buckets that the parquet cache truncates at chunk boundaries, so a single
bucket is a partial measurement and a *rolling sum* over several buckets
is the clean one.  On that smoothed, baseline-normalised rate, the
incident is a **sustained deviation from one**, and its onset is the
first bucket at which the deviation starts and stays.

This script compares onset rules on that series and reports the
localisation error against the recorded incident time.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"


def read_buckets(entries: dict) -> List[Tuple[datetime, dict]]:
    out = []
    for stamp, entry in entries.items():
        ts = parse_timestamp(stamp)
        if ts is None or not isinstance(entry, dict):
            continue
        out.append((ts, entry))
    out.sort(key=lambda item: item[0])
    return out


def rolling_sum(values: List[float], width: int) -> List[float]:
    if width <= 1:
        return list(values)
    arr = np.asarray(values, dtype=float)
    return [float(arr[max(0, i - width + 1):i + 1].sum()) for i in range(len(arr))]


def sustained_onset(values: List[float], level: float, tol: float,
                    persist: int) -> Optional[int]:
    """The first index at which the series leaves ``level`` and stays out.

    ``persist`` is the number of consecutive observations the deviation
    has to hold, which is what separates an incident from a truncated
    bucket.
    """
    n = len(values)
    for i in range(n):
        if abs(values[i] - level) <= tol:
            continue
        window = values[i:i + persist]
        if len(window) < persist:
            break
        if all(abs(v - level) > tol for v in window):
            return i
    return None


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    widths = (1, 2, 3, 6, 12)
    persists = (2, 3, 5)
    print(f"{'event':34s} {'truth':>6s} " +
          " ".join(f"w{w}p{p}" for w in widths for p in persists))
    for r in rows:
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=r["event_id"], allow_same_date=False)
        if not m:
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (d.get("routing") or {}).get("outage_analysis") or {}
        tse = read_buckets(oa.get("timeseries_event") or {})
        tsb = read_buckets(oa.get("timeseries_baseline") or {})
        if not tse or not tsb:
            continue
        truth = parse_timestamp(r.get("start_utc"))
        if truth is None:
            continue
        base_counts = [float(e.get("total_messages") or 0) for _, e in tsb]
        positives = [c for c in base_counts if c > 0]
        base_level = float(np.median(positives)) if positives else 0.0
        counts = [float(e.get("total_messages") or 0) for _, e in tse]
        stamps = [s for s, _ in tse]
        out = []
        for width in widths:
            sm = rolling_sum(counts, width)
            # Normalise the rolling sum by the baseline's rolling sum at
            # the same width, so the normalised series reads one when the
            # control plane is normal.
            base_sm = rolling_sum(base_counts, width)
            bp = [c for c in base_sm if c > 0]
            level = float(np.median(bp)) if bp else 0.0
            norm = [v / level if level > 0 else 0.0 for v in sm]
            for persist in persists:
                # A tolerance of a quarter of the normal rate.
                tol = 0.25
                at = sustained_onset(norm, 1.0, tol, persist)
                if at is None:
                    out.append("   --  ")
                else:
                    delta = (stamps[at] - truth).total_seconds() / 60.0
                    out.append(f"{delta:+6.0f}m")
        print(f"{r['event_id'][:32]:34s} {truth.strftime('%H:%M'):>6s} " +
              " ".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
