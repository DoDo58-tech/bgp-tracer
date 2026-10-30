"""Diagnose the control-plane series shape and the right grid width.

The control-plane rate is read from the detector's per-bucket feature
series.  Two questions decide how the estimator may use it:

* the detector's buckets are *irregular* -- some slots are missing -- so
  a bucket index does not mean a fixed wall-clock interval;
* the raw counts alternate sharply between neighbouring buckets, so a
  fine grid measures file-granularity noise rather than the incident.

This script prints the raw entries and, for several grid widths, the
lag-1 autocorrelation of the rate and the ratio of its change magnitude
to its baseline change magnitude.  A grid width where the noise has
averaged out and the incident still stands out is the width the estimator
should use.
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

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"


def buckets_on_grid(entries: dict, grid_seconds: int) -> list[float]:
    """Aggregate the detector's buckets onto a uniform grid."""
    items = []
    for stamp, entry in entries.items():
        ts = parse_timestamp(stamp)
        if ts is None or not isinstance(entry, dict):
            continue
        count = entry.get("announcement_count")
        if not isinstance(count, (int, float)):
            count = entry.get("total_messages")
        if not isinstance(count, (int, float)):
            continue
        items.append((ts, float(count)))
    if not items:
        return []
    items.sort()
    origin = items[0][0]
    n = int((items[-1][0] - origin).total_seconds()) // grid_seconds + 1
    sums = [0.0] * n
    counts = [0] * n
    for ts, val in items:
        idx = int((ts - origin).total_seconds()) // grid_seconds
        if 0 <= idx < n:
            sums[idx] += val
            counts[idx] += 1
    return [sums[i] for i in range(n)]


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    for r in rows:
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=r["event_id"], allow_same_date=False)
        if not m:
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (d.get("routing") or {}).get("outage_analysis") or {}
        tse = oa.get("timeseries_event") or {}
        tsb = oa.get("timeseries_baseline") or {}
        if not tse:
            continue

        print(f"=== {r['event_id'][:44]}")
        # Irregularity of the detector's own buckets.
        stamps = sorted(parse_timestamp(k) for k in tse if parse_timestamp(k))
        gaps = Counter(
            int((stamps[i + 1] - stamps[i]).total_seconds())
            for i in range(len(stamps) - 1))
        print(f"    detector buckets={len(stamps)} gap histogram={dict(sorted(gaps.items())[:8])}")

        raw = sorted(tse.items())
        print(f"    first 8 raw: {[(k, v.get('announcement_count')) for k, v in raw[:8]]}")

        for grid in (300, 600, 900, 1800):
            ev = buckets_on_grid(tse, grid)
            base = buckets_on_grid(tsb, grid)
            if len(ev) < 6 or len(base) < 6:
                continue
            ev_arr = np.asarray(ev)
            base_arr = np.asarray(base)
            # Lag-1 autocorrelation of the rate: near +-1 means the
            # series is dominated by bucket-to-bucket noise.
            if ev_arr.std() > 0 and len(ev_arr) > 2:
                ac = float(np.corrcoef(ev_arr[:-1], ev_arr[1:])[0, 1])
            else:
                ac = float("nan")
            # How big is the worst change in the event window relative
            # to the worst change in the baseline window?
            def max_rel_jump(a):
                best = 0.0
                for i in range(1, len(a)):
                    scale = max(abs(a[i - 1]), abs(a[i]), 1e-9)
                    best = max(best, abs(a[i] - a[i - 1]) / scale)
                return best
            ev_jump, base_jump = max_rel_jump(ev_arr), max_rel_jump(base_arr)
            ratio = ev_jump / base_jump if base_jump > 0 else float("inf")
            print(f"    grid={grid:4d}s n_ev={len(ev):3d} n_base={len(base):3d} "
                  f"lag1_ac={ac:6.2f} ev_jump={ev_jump:6.2f} "
                  f"base_jump={base_jump:6.2f} ratio={ratio:6.2f}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
