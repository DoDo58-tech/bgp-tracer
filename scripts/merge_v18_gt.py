#!/usr/bin/env python3
"""
Final merge: routing summary + traffic stats + audit notes into v18 groundtruth.
"""
import json
import csv
from pathlib import Path

V18_CSV = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'
SUMMARY = 'data/groundtruth_v18/summary.json'
OUT_CSV = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'


def main():
    with open(SUMMARY) as f:
        routing = {r['event_id']: r for r in json.load(f)}

    with open(V18_CSV) as f:
        rows = list(csv.DictReader(f))

    for r in rows:
        eid = r['event_id']
        s = routing.get(eid)
        if not s or 'error' in s:
            r['routing_total_A_v18'] = ''
            r['routing_peak_A_v18'] = ''
            r['routing_n_buckets_v18'] = ''
            r['routing_victim_total_A_v18'] = ''
            r['routing_victim_peak_A_v18'] = ''
            r['routing_v18_status'] = 'no_routing_data'
            continue
        t = s['totals']
        r['routing_total_A_v18'] = t['announcement_count']
        r['routing_peak_A_v18'] = s['peak_announce_per_5m']
        r['routing_n_buckets_v18'] = s['n_buckets']
        v_as = s.get('victim_as')
        if v_as and str(v_as) in s['by_target']:
            r['routing_victim_total_A_v18'] = s['by_target'][str(v_as)]['total_announce']
            r['routing_victim_peak_A_v18'] = s['by_target'][str(v_as)]['peak_announce_per_5m']
        else:
            r['routing_victim_total_A_v18'] = ''
            r['routing_victim_peak_A_v18'] = ''
        r['routing_v18_status'] = 'ok'

    # Preserve original column order
    with open(V18_CSV) as f:
        orig = list(csv.DictReader(f).fieldnames or [])
    new_cols = [
        'routing_total_A_v18', 'routing_peak_A_v18', 'routing_n_buckets_v18',
        'routing_victim_total_A_v18', 'routing_victim_peak_A_v18', 'routing_v18_status',
    ]
    fieldnames = orig + [c for c in new_cols if c not in orig]

    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f'Written: {OUT_CSV} ({len(rows)} rows)')


if __name__ == '__main__':
    main()
