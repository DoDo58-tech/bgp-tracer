"""Diagnose the clock relationship between the traffic series, the control
plane and the ground truth.

Three clocks meet in one attribution and they are not the same clock:

* the ground truth's ``start_utc`` / ``traffic_note`` trough time,
* the traffic provider's observation timestamps, and
* the routing detector's bucket timestamps.

The attribution compares the last two, so their offset has to be
*measured*, not assumed.  This script prints, for each event, the
traffic series' own trough (the minimum of the measured value), the
ground truth's recorded trough, and the offset between them, next to
the control plane's bucket range.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"

_TROUGH_RE = re.compile(r"trough=([0-9T:\-]+Z?)")


def truth_trough(note: str) -> Optional[str]:
    m = _TROUGH_RE.search(note or "")
    return m.group(1) if m else None


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    for r in rows:
        eid = r["event_id"]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"{eid[:34]:36s} NO CACHE")
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        corr = d.get("correlation") or {}
        rb = d.get("routing") or {}
        tb = d.get("traffic") or {}
        oa = rb.get("outage_analysis") or {}

        tf = [e for e in (corr.get("traffic_events_full") or [])
              if isinstance(e, dict)]
        # Collapse duplicate timestamps: a zero-z placeholder and a real
        # measurement share a stamp.
        best: dict = {}
        for e in tf:
            ts = parse_timestamp(e.get("timestamp"))
            if ts is None:
                continue
            val = e.get("value")
            z = e.get("z_score")
            score = (abs(float(z)) if isinstance(z, (int, float)) else 0.0,
                     -float(val) if isinstance(val, (int, float)) else 0.0)
            if ts not in best or score > best[ts][0]:
                best[ts] = (score, e)

        stamps = sorted(best)
        trough = None
        if stamps:
            vals = [(best[t][1].get("value"), t) for t in stamps]
            trough = min(vals, key=lambda p: (p[0] is None, p[0]))[1]

        tt = truth_trough(r.get("traffic_note", ""))
        tt_ts = parse_timestamp(tt) if tt else None
        off = ((trough - tt_ts).total_seconds() / 60.0
               if trough and tt_ts else None)

        tse = oa.get("timeseries_event") or {}
        ks = sorted(tse.keys())
        print(f"{eid[:34]:36s} gt_start={r.get('start_utc')}  "
              f"trough_gt={tt}  trough_tf={trough}  "
              f"offset_min={off if off is None else round(off)}")
        print(f"{'':36s} tf_range={stamps[0] if stamps else None}..{stamps[-1] if stamps else None} "
              f"n={len(stamps)}  cp_range={ks[0] if ks else None}..{ks[-1] if ks else None}")
        if tb:
            print(f"{'':36s} traffic_block keys={sorted(tb.keys())[:10]}")
            for key in ("analysis_period", "start_time", "end_time",
                        "window", "hour_offset", "data_start", "data_end"):
                if tb.get(key) is not None:
                    print(f"{'':38s}{key}={tb.get(key)}")
        if corr.get("summary"):
            print(f"{'':38s}corr.summary={json.dumps(corr['summary'])[:120]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
