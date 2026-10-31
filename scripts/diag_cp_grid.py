"""Inspect the control-plane bucket grid in detail.

The detector's ``timeseries_event`` and ``timeseries_baseline`` are the
routing side of the attribution, so their time grid decides whether an
onset can be located at all.  This prints, for a few representative
events, the stamps, the gaps between them, and the count carried by
each bucket, so the grid's real shape is visible rather than assumed.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

GT = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"

SAMPLES = [
    "outage_telia_finland_2025_04_01",
    "outage_44244_20250622_x17",
    "outage_syria_maula_hiaa_2025_01_23",
    "leak_cox_communications_2025_05_01",
]


def dump(label: str, series: dict) -> None:
    items = []
    for raw_stamp, entry in series.items():
        ts = parse_timestamp(raw_stamp)
        if ts is None or not isinstance(entry, dict):
            continue
        items.append((ts, entry))
    items.sort(key=lambda p: p[0])
    print(f"  --- {label}: {len(items)} buckets")
    if not items:
        return
    gaps = Counter(
        int((items[i + 1][0] - items[i][0]).total_seconds())
        for i in range(len(items) - 1))
    print(f"      gap histogram: {dict(sorted(gaps.items()))}")
    for ts, entry in items[:14]:
        print(f"      {ts}  ann={entry.get('announcement_count')} "
              f"wd={entry.get('withdrawal_count')} "
              f"tot={entry.get('total_messages')} "
              f"ori={entry.get('num_ori_change')} "
              f"path={entry.get('num_path_change')}")
    if len(items) > 14:
        print(f"      ... ({len(items) - 20} more)")
        for ts, entry in items[-6:]:
            print(f"      {ts}  ann={entry.get('announcement_count')} "
                  f"wd={entry.get('withdrawal_count')} "
                  f"tot={entry.get('total_messages')} "
                  f"ori={entry.get('num_ori_change')} "
                  f"path={entry.get('num_path_change')}")


def main() -> int:
    rows = {r["event_id"]: r for r in
            csv.DictReader(open(GT, encoding="utf-8"))}
    for eid in SAMPLES:
        r = rows[eid]
        asn = r.get("victim_as") or r.get("target_as")
        m = resolve_cache(asn, r.get("start_utc"), r.get("end_utc"), QUICK,
                          event_id=eid, allow_same_date=False)
        if not m:
            print(f"\n### {eid}: NO CACHE")
            continue
        d = json.loads(m.path.read_text(encoding="utf-8"))
        oa = (d.get("routing") or {}).get("outage_analysis") or {}
        print(f"\n### {eid}")
        print(f"    gt=[{r['start_utc']} .. {r['end_utc']}]  "
              f"cache=[{d.get('start_time')} .. {d.get('end_time')}]")
        dump("event", oa.get("timeseries_event") or {})
        dump("baseline", oa.get("timeseries_baseline") or {})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
