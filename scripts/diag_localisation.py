"""Can the estimator localise an incident whose time is known?

The corpus records, for every event, the window in which the incident
occurred.  That is a ground truth for *localisation* even when the
causal direction is not the question: a method that cannot find the
control-plane change near the known incident time cannot be trusted to
order that change against a data-plane response.

This script measures, for several smoothing widths, the distance between
the control-plane change point the estimator would pick and the incident
time the corpus records.  The smoothing width matters because the
detector's buckets are cut at parquet-chunk boundaries, so a single
bucket is a truncated measurement of the control-plane rate and a
wider bucket is a cleaner one.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"


def read_buckets(entries: dict) -> List[Tuple[datetime, dict]]:
    out = []
    for stamp, entry in entries.items():
        ts = parse_timestamp(stamp)
        if ts is None or not isinstance(entry, dict):
            continue
        out.append((ts, entry))
    out.sort(key=lambda item: item[0])
    return out


def smooth(values: List[float], width: int) -> List[float]:
    """The rolling sum over ``width`` consecutive buckets."""
    if width <= 1:
        return list(values)
    out = []
    arr = np.asarray(values, dtype=float)
    for i in range(len(arr)):
        lo = max(0, i - width + 1)
        out.append(float(arr[lo:i + 1].sum()))
    return out


def best_change(values: List[float], min_seg: int) -> Optional[int]:
    """The anchor of the largest relative jump."""
    arr = np.asarray(values, dtype=float)
    n = len(arr)
    if n < 2 * min_seg + 1:
        return None
    best, at = None, -1
    for anchor in range(min_seg, n - min_seg + 1):
        m1 = float(arr[:anchor].mean())
        m2 = float(arr[anchor:].mean())
        scale = max(abs(m1), abs(m2), 1e-9)
        rel = abs(m2 - m1) / scale
        if best is None or rel > best:
            best, at = rel, anchor
    return at


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    print(f"{'event':36s} {'truth':>8s} " + " ".join(f"w={w:<2d}" for w in (1, 2, 3, 6, 12)))
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
        base_level = float(np.median([c for c in base_counts if c > 0])) if any(c > 0 for c in base_counts) else 0.0
        counts = [float(e.get("total_messages") or 0) for _, e in tse]
        stamps = [s for s, _ in tse]
        out = []
        for width in (1, 2, 3, 6, 12):
            sm = smooth(counts, width)
            norm = [v / base_level if base_level > 0 else v for v in sm]
            min_seg = max(2, int(round(0.15 * len(norm))))
            at = best_change(norm, min_seg)
            if at is None:
                out.append("   --  ")
                continue
            delta = (stamps[at] - truth).total_seconds() / 60.0
            out.append(f"{delta:+7.0f}m")
        print(f"{r['event_id'][:34]:36s} {truth.strftime('%H:%M'):>8s} " + " ".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
