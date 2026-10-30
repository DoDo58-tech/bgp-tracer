"""Which control-plane statistic separates the event window from the baseline?

The detector's per-bucket counts are truncated at parquet-chunk
boundaries, so a single bucket's count is not a clean measurement of the
control-plane rate for that interval: the chunk that ends mid-bucket
contributes only part of it.  The *sum* over a window is unaffected,
because every message is counted exactly once.

So the statistic to compare is a windowed aggregate, not a per-bucket
value.  This script computes, for several window widths, the ratio of the
event window's aggregate to the baseline window's aggregate, and also
the same ratio computed on the raw per-bucket values, so the two can be
compared directly.

A statistic that separates the event from the baseline on the *right*
events -- outages and leaks and hijacks -- and does not separate it on
the events where the control plane is not what broke, is the statistic
the estimator should use.
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

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"


def read(entries: dict) -> list[tuple]:
    out = []
    for stamp, entry in entries.items():
        ts = parse_timestamp(stamp)
        if ts is None or not isinstance(entry, dict):
            continue
        out.append((ts, entry))
    out.sort(key=lambda item: item[0])
    return out


def channel_value(entry: dict, channel: str) -> float:
    if channel == "volume":
        v = entry.get("total_messages")
        return float(v) if isinstance(v, (int, float)) else 0.0
    if channel == "origin_change":
        v = entry.get("num_ori_change")
        return float(v) if isinstance(v, (int, float)) else 0.0
    if channel == "path_change":
        v = entry.get("num_longer")
        v2 = entry.get("num_shorter")
        a = float(v) if isinstance(v, (int, float)) else 0.0
        b = float(v2) if isinstance(v2, (int, float)) else 0.0
        return a + b
    if channel == "flapping":
        v = entry.get("flapping_prefix_count")
        return float(v) if isinstance(v, (int, float)) else 0.0
    return 0.0


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    channels = ("volume", "origin_change", "path_change", "flapping")
    for r in rows:
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=r["event_id"], allow_same_date=False)
        if not m:
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (d.get("routing") or {}).get("outage_analysis") or {}
        tse = read(oa.get("timeseries_event") or {})
        tsb = read(oa.get("timeseries_baseline") or {})
        if not tse or not tsb:
            continue
        print(f"=== {r['event_id'][:42]} cause={r.get('cause')}")
        for ch in channels:
            ev = np.array([channel_value(e, ch) for _, e in tse])
            base = np.array([channel_value(e, ch) for _, e in tsb])
            if ev.sum() <= 0 and base.sum() <= 0:
                continue
            # Per-hour rate: the windows cover different spans.
            ev_span = (tse[-1][0] - tse[0][0]).total_seconds() / 3600.0 or 1.0
            base_span = (tsb[-1][0] - tsb[0][0]).total_seconds() / 3600.0 or 1.0
            ev_rate = ev.sum() / ev_span
            base_rate = base.sum() / base_span
            ratio = ev_rate / base_rate if base_rate > 0 else float("inf")
            # Robust: median of per-bucket values (ignores the truncated ones).
            ev_med = float(np.median(ev))
            base_med = float(np.median(base))
            med_ratio = ev_med / base_med if base_med > 0 else float("inf")
            # Trimmed mean (drop the extreme 25% at each end): rejects the
            # chunk-boundary truncation.
            ev_tr = float(np.mean(np.sort(ev)[len(ev) // 4: len(ev) - len(ev) // 4])) if len(ev) >= 4 else float(np.mean(ev))
            base_tr = float(np.mean(np.sort(base)[len(base) // 4: len(base) - len(base) // 4])) if len(base) >= 4 else float(np.mean(base))
            tr_ratio = ev_tr / base_tr if base_tr > 0 else float("inf")
            print(f"    {ch:14s} rate_ratio={ratio:9.2f}  med_ratio={med_ratio:9.2f}  trim_ratio={tr_ratio:9.2f}"
                  f"   (ev_s={ev.sum():.0f} base_s={base.sum():.0f})")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
