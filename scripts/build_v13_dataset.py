#!/usr/bin/env python3
"""Step 4: Build final_balanced_dataset_v13.csv.

Composition:
- All 16 v12 events (kept)
- Top 6 verified hijacks from v13 verified pool (round-robin from different dates)
- Top 5 verified leaks from v13 verified pool (round-robin from different dates)

Total: 27 events. Class balance: 6 outage, 10 leak, 10 hijack, 1 roa_misconfig.

Output:
  - data_check/ground_truth_collection/final_balanced_dataset_v13.csv
  - data_check/ground_truth_collection/v13_rejected_events.csv (the 155 not-picked)
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from collections import defaultdict
import pandas as pd

ROOT = Path("/data/bgp_tracer")
GT_DIR = ROOT / "data_check/ground_truth_collection"
V12_CSV = GT_DIR / "final_balanced_dataset_v12.csv"
V13_VERIFIED = Path("/tmp/v13_verified.jsonl")
V13_REJECTED_EXTRA = Path("/tmp/v13_rejected_extra.jsonl")
OUT_KEPT = GT_DIR / "final_balanced_dataset_v13.csv"
OUT_REJ = GT_DIR / "v13_rejected_events.csv"


def main():
    # Read v12 as base
    with open(V12_CSV) as f:
        v12_rows = list(csv.DictReader(f))
        v12_fields = list(v12_rows[0].keys()) if v12_rows else []

    # Read v13 verified
    with open(V13_VERIFIED) as f:
        v13_verified = [json.loads(l) for l in f]

    # Read v13 rejected
    with open(V13_REJECTED_EXTRA) as f:
        v13_rejected = [json.loads(l) for l in f]

    # v12 eids set
    v12_eids = set(r['event_id'] for r in v12_rows)

    # Pick top events from v13_verified, deduplicating by date for diversity
    # Group by date, sort by quality, pick one per date
    def pick_diverse(events, n_target):
        by_date = defaultdict(list)
        for e in events:
            by_date[e['date']].append(e)
        # within each date, sort by quality desc
        picked = []
        dates_seen = set()
        # round-robin across dates, picking highest quality
        while len(picked) < n_target and any(by_date.values()):
            for d in sorted(by_date.keys()):
                if not by_date[d]:
                    continue
                if len(picked) >= n_target:
                    break
                if d not in dates_seen:
                    e = by_date[d].pop(0)
                    picked.append(e)
                    dates_seen.add(d)
        return picked

    # Quality score (recompute to be safe)
    for e in v13_verified:
        cv = e.get('traffic', {}).get('cv', 1.0) or 1.0
        lag = e.get('traffic', {}).get('lag24', 0.0) or 0.0
        prefix_count = e.get('rrc00', {}).get('prefix_count', 0) or 0
        origin_a = e.get('rrc00', {}).get('origin_a', 0) or 0
        q = (1.0 - min(cv, 1.0)) * 0.3 + min(max(lag, 0), 1.0) * 0.3 + min(prefix_count / 100, 1.0) * 0.2 + min(origin_a / 1000, 1.0) * 0.2
        e['_q'] = q
    v13_verified.sort(key=lambda x: x['_q'], reverse=True)

    # By class
    hijacks = [v for v in v13_verified if v['cause_label'] == 'origin_hijack_victim']
    leaks = [v for v in v13_verified if v['cause_label'] == 'route_leak']

    # Pick diverse events: 6 hijack + 5 leak (to balance with v12)
    picked_hijacks = pick_diverse(hijacks, 6)
    picked_leaks = pick_diverse(leaks, 5)

    # Build v13 rows from v12 + picked
    out_rows = list(v12_rows)
    for ev in picked_hijacks + picked_leaks:
        out_rows.append({
            'tier': 'B',
            'event_id': ev['event_id'],
            'name': ev['date'] + ' ' + ev['cause_label'].replace('_', ' '),
            'date': ev['date'],
            'start_time_utc': ev.get('start_time') or f"{ev['date']}T00:00:00Z",
            'end_time_utc': ev.get('end_time') or f"{ev['date']}T23:59:59Z",
            'duration_hours': '24',
            'victim_as': ev.get('victim_as', ''),
            'attacker_as': ev.get('attacker_as', ''),
            'leak_as': ev.get('leak_as', ''),
            'event_type': 'verified_bgpstream_cf_radar',
            'ground_truth_cause_label': ev['cause_label'],
            'ground_truth_root_cause_subtype': '',
            'ground_truth_confidence': 'verified',
            'traffic_pct_deviation_source': 'cf_radar',
            'traffic_pct_deviation_pct': '0',
            'routing_evidence_source': 'rrc00_parquet',
            'routing_origin_count': str(ev.get('rrc00', {}).get('origin_a', 0)),
            'routing_withdrawal_count': str(ev.get('rrc00', {}).get('withdraws', 0)),
            'ground_truth_source': ev.get('source', ''),
            'source_url': 'https://bgpstream.com',
            'project_detector_runnable': 'True',
            'project_cache_path': ev.get('traffic_csv', ''),
            'runnable_reason': f"v13 verified: RRC00 prefix_count={ev.get('rrc00',{}).get('prefix_count',0)} origin_a={ev.get('rrc00',{}).get('origin_a',0)} path_a={ev.get('rrc00',{}).get('path_a',0)}",
            'rrc00_covered': 'True',
            'derived_from': '',
            'notes': f"v13: prefix={ev.get('prefix','')} traffic_cv={ev.get('traffic',{}).get('cv',0):.3f} lag24={ev.get('traffic',{}).get('lag24',0):.3f}",
            'v11_traffic_regularity_source': 'cf_radar_api',
            'v11_rrc00_origin_announces': str(ev.get('rrc00', {}).get('origin_a', 0)),
            'v11_rrc00_path_announces': str(ev.get('rrc00', {}).get('path_a', 0)),
            'v11_rrc00_verified': 'True',
            'v11_kept': 'True',
            'v11_rejection_reason': '',
        })

    # v13 rejected: combine v12_rejected (14) + v13_rejected_extra (155) - picked
    picked_eids = set(v['event_id'] for v in picked_hijacks + picked_leaks)
    v13_rej_pool = list(v13_rejected)
    with open(GT_DIR / "v12_rejected_events.csv") as f:
        v12_rej_rows = list(csv.DictReader(f))
    # Convert v13_rejected_extra to row format
    v13_rej_rows = []
    for r in v13_rejected:
        v13_rej_rows.append({
            'event_id': r['eid'],
            'date': '',
            'ground_truth_cause_label': r.get('cause', ''),
            'v11_rejection_reason': r.get('reason', ''),
        })
    # Merge v12 rejected + v13 rejected extra
    all_rej = list(v12_rej_rows) + v13_rej_rows

    # Write
    with open(OUT_KEPT, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=v12_fields)
        w.writeheader()
        for r in out_rows:
            w.writerow({k: r.get(k, '') for k in v12_fields})

    with open(OUT_REJ, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=v12_fields)
        w.writeheader()
        for r in all_rej:
            w.writerow({k: r.get(k, '') for k in v12_fields})

    # Class distribution
    from collections import Counter
    print(f"v13 kept: {len(out_rows)}")
    print(f"  v12 inherited: {len(v12_rows)}")
    print(f"  v13 added hijack: {len(picked_hijacks)}")
    print(f"  v13 added leak: {len(picked_leaks)}")
    print()
    print("Class distribution:")
    c = Counter(r['ground_truth_cause_label'] for r in out_rows)
    for k, v in c.most_common():
        print(f"  {k}: {v}")
    print()
    print(f"v13 rejected: {len(all_rej)}")


if __name__ == '__main__':
    main()