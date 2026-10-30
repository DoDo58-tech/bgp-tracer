"""Prototype: does the control-plane observation rate carry the signal?

For every labelled event the script builds the control-plane series from
the detector's own feature buckets and reports, per channel:

* whether the channel is flat over the event window;
* whether the event window's displacement at its own best anchor exceeds
  what the *baseline* window shows at its best anchor -- that is, whether
  the incident moved the control plane more than ordinary variation does.

A channel that never moves is useless.  A channel that moves in the event
window no more than in the baseline is noise.  Only a channel that clears
the baseline is evidence.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents._segmentation import detect_changes  # noqa: E402
from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.control_plane import (  # noqa: E402
    CONTROL_PLANE_CHANNELS,
    build_control_plane_series,
)

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"


def best_displacement(values: list[float], min_seg: int) -> tuple[float, int]:
    """The largest |post - pre| displacement and where it sits."""
    n = len(values)
    if n < 2 * min_seg + 1:
        return 0.0, -1
    arr = np.asarray(values, dtype=float)
    best, at = 0.0, -1
    for anchor in range(min_seg, n - min_seg + 1):
        pre = arr[max(0, anchor - min_seg):anchor]
        post = arr[anchor:anchor + min_seg]
        if len(pre) == 0 or len(post) == 0:
            continue
        d = abs(float(post.mean()) - float(pre.mean()))
        if d > best:
            best, at = d, anchor
    return best, at


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
        start = parse_timestamp(d.get("start_time"))
        end = parse_timestamp(d.get("end_time"))
        series = build_control_plane_series(oa, window_start=start, window_end=end)
        if series.n_buckets < 6:
            continue
        print(f"=== {r['event_id'][:44]}  cause={r.get('cause')}")
        print(f"    buckets={series.n_buckets} baseline={len(series.baseline_stamps)}")
        for ch in CONTROL_PLANE_CHANNELS:
            ev = series.channel(ch)
            base = series.baseline_channel(ch)
            if not ev:
                print(f"    {ch:14s} (absent)")
                continue
            min_seg = max(2, int(round(0.15 * len(ev))))
            d_ev, at = best_displacement(ev, min_seg)
            det = detect_changes(np.asarray(ev), min_seg, 1.0)
            if len(base) >= 6:
                bseg = max(2, int(round(0.15 * len(base))))
                d_base, _ = best_displacement(base, bseg)
            else:
                d_base = float("nan")
            ratio = d_ev / d_base if d_base and d_base == d_base else float("nan")
            print(f"    {ch:14s} flat={float(np.ptp(ev)) < 1e-9!s:5s} "
                  f"changes={str(det['changes']):12s} "
                  f"disp_ev={d_ev:12.3f} disp_base={d_base:12.3f} ratio={ratio:8.2f}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
