"""Inspect the traffic-side observation semantics.

The traffic detector records, per observation, the measured ``value``, the
historical ``mean``, a ``pct_change`` and a ``z_score``.  The attribution
needs a response magnitude that is (a) signed the right way -- a *drop*
is the response, a rise is not -- and (b) comparable across events, so a
raw byte counter cannot be used directly.

This script prints the relation between the recorded fields so the
magnitude the estimator reads is the one the detector actually measured.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK = ROOT / "results/quick"
GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"


def main() -> int:
    rows = list(csv.DictReader(open(GT, encoding="utf-8")))
    for r in rows:
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=r["event_id"], allow_same_date=False)
        if not m:
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        corr = d.get("correlation") or {}
        tf = [e for e in (corr.get("traffic_events_full") or []) if isinstance(e, dict)]
        if not tf:
            continue
        print(f"=== {r['event_id'][:44]}  n={len(tf)}")
        ts = [parse_timestamp(e.get("timestamp")) for e in tf]
        ts = [t for t in ts if t]
        if len(ts) > 1:
            gaps = sorted(
                int((ts[i + 1] - ts[i]).total_seconds())
                for i in range(len(ts) - 1))
            from collections import Counter
            print(f"    gap histogram: {dict(Counter(gaps).most_common(6))}")
        for e in tf[:4]:
            print(f"    ts={e.get('timestamp')} value={e.get('value')} "
                  f"mean={e.get('mean')} pct_change={e.get('pct_change')} "
                  f"z={e.get('z_score')} sev={e.get('severity')} dir={e.get('direction')}")
        # Does z agree with (value - mean)?
        agree = 0
        total = 0
        for e in tf:
            v, mean, z = e.get("value"), e.get("mean"), e.get("z_score")
            if not all(isinstance(x, (int, float)) for x in (v, mean, z)):
                continue
            total += 1
            if (v - mean) * z > 0:
                agree += 1
        print(f"    z agrees in sign with (value-mean): {agree}/{total}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
