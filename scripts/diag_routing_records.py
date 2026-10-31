"""What the routing detector's own event records say, and when.

The rate series turned out to be a fragile way to locate the control-
plane onset: the detector's buckets are sparse, and a sustained
departure can be read off at the wrong place.  The detector also emits
*event records* -- one per routing anomaly it recognised -- and each
record carries the wall-clock time at which the anomaly was seen.

Those records are the control plane's own testimony about *when* it
moved, and they are what a causal method should read rather than a
re-derived change point.  This prints, for every event, the routing
records' types, their time range, and how that range relates to the
traffic impact.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"


def _events(raw: Any) -> List[dict]:
    if isinstance(raw, list):
        return [e for e in raw if isinstance(e, dict)]
    return []


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
        corr = cache.get("correlation") or {}
        rb = cache.get("routing") or {}

        records: List[dict] = []
        sources = []
        for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                    "forge_hijacking", "route_leaks"):
            block = _events(rb.get(key))
            if block:
                sources.append(f"{key}={len(block)}")
            records.extend(block)
        if not records:
            block = _events(corr.get("routing_events_full"))
            if block:
                sources.append(f"corr.routing_events_full={len(block)}")
            records.extend(block)
        if not records:
            block = _events(corr.get("routing_events"))
            if block:
                sources.append(f"corr.routing_events={len(block)}")
            records.extend(block)

        types = Counter(str(e.get("event_type") or e.get("type") or "?")
                        for e in records)
        stamps = []
        for e in records:
            ts = parse_timestamp(e.get("timestamp") or e.get("first_seen")
                                 or e.get("time"))
            if ts is not None:
                stamps.append(ts)
        stamps.sort()

        tb = cache.get("traffic") or {}
        traffic = _events(corr.get("traffic_events_full")) or _events(tb.get("anomalies"))
        tstamps = []
        for e in traffic:
            ts = parse_timestamp(e.get("timestamp") or e.get("time"))
            if ts is not None:
                tstamps.append(ts)
        tstamps.sort()

        # The detector's own view of when the impact was.
        impact = None
        for key in ("consecutive_anomaly_windows", "expanded_windows"):
            wins = tb.get(key)
            if isinstance(wins, list) and wins:
                impact = parse_timestamp(wins[0].get("start"))
                break

        print(f"\n### {eid}  ({r.get('cause')}/{r.get('subtype')})")
        print(f"    sources: {', '.join(sources) or 'NONE'}   "
              f"types={dict(types)}")
        if stamps:
            print(f"    routing records: n={len(stamps)} "
                  f"range={stamps[0]} .. {stamps[-1]}")
            # A histogram of the records' density over 30-minute bins
            # shows whether the records cluster (an incident) or are
            # spread (background noise).
            bins: Counter = Counter()
            for ts in stamps:
                minute = ts.minute // 30 * 30
                bins[ts.replace(minute=minute, second=0)] += 1
            top = bins.most_common(6)
            print(f"    densest 30-min bins: "
                  f"{[(str(k), v) for k, v in top]}")
        else:
            print("    routing records: NO TIMESTAMPS")
        if tstamps:
            print(f"    traffic anomalies: n={len(tstamps)} "
                  f"range={tstamps[0]} .. {tstamps[-1]}")
        else:
            print("    traffic anomalies: NONE")
        print(f"    detector impact start={impact}   "
              f"gt_start={r.get('start_utc')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
