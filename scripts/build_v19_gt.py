#!/usr/bin/env python3
"""
Build v19 final groundtruth: 40 events (20 outage / 10 hijack / 10 leak).
Select best evidence-rich events from v18 + new candidates.
"""
import json
import csv
from pathlib import Path

V18_CSV = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'
CAND_FILE = 'data/groundtruth_v19/candidate_metadata.jsonl'
OUT_CSV = 'data_check/ground_truth_collection/final_balanced_v19_40.csv'


def load_v18():
    with open(V18_CSV) as f:
        return list(csv.DictReader(f))


def load_cands():
    cands = []
    with open(CAND_FILE) as f:
        for l in f:
            l = l.strip()
            if l:
                cands.append(json.loads(l))
    return cands


def main():
    v18 = load_v18()
    cands = load_cands()
    v18_ids = {e['event_id'] for e in v18}

    # Convert v18 to common format
    rows = []
    for e in v18:
        cause = e['ground_truth_cause_label']
        subtype = e['ground_truth_root_cause_subtype']
        rt_peak = int(e.get('routing_victim_peak_A_v18') or 0)
        tr_z = e.get('traffic_z_min_v18', '')
        rows.append({
            'event_id': e['event_id'],
            'name': e['name'],
            'date': e['date'],
            'start_utc': e['start_time_utc'],
            'end_utc': e['end_time_utc'],
            'victim_as': e['victim_as'],
            'attacker_as': e.get('attacker_as', ''),
            'leak_as': e.get('leak_as', ''),
            'cause': cause,
            'subtype': subtype,
            'routing_peak_A': rt_peak,
            'routing_status': e.get('routing_v18_status', ''),
            'traffic_z_min': tr_z,
            'traffic_pct_drop': e.get('traffic_pct_drop_v18', ''),
            'source': e.get('ground_truth_source', ''),
            'source_url': e.get('source_url', ''),
            'evidence_tier': e.get('evidence_tier', ''),
            'origin': 'v18',
        })

    # Add new candidates (skip those already in v18)
    for c in cands:
        if c['event_id'] in v18_ids:
            continue
        rows.append({
            'event_id': c['event_id'],
            'name': c.get('name', c['event_id']),
            'date': c['date'],
            'start_utc': c['start_utc'],
            'end_utc': c['end_utc'],
            'victim_as': c['victim_as'],
            'attacker_as': c.get('attacker_as', ''),
            'leak_as': c.get('leak_as', ''),
            'cause': c['cause'],
            'subtype': c['subtype'],
            'routing_peak_A': c.get('routing_peak_A', 0),
            'routing_status': c.get('routing_status', 'ok'),
            'traffic_z_min': str(c.get('traffic_z_min', '')),
            'traffic_pct_drop': str(c.get('traffic_pct_drop', '')),
            'source': c.get('source', ''),
            'source_url': c.get('source_url', ''),
            'evidence_tier': c.get('evidence_tier', ''),
            'origin': 'v19_new',
        })

    # Now select: 20 outage / 10 hijack / 10 leak
    from collections import defaultdict
    by_cause = defaultdict(list)
    for r in rows:
        by_cause[r['cause']].append(r)

    # Sort by routing_peak_A desc (strongest signal first)
    for cause in by_cause:
        by_cause[cause].sort(key=lambda x: -x['routing_peak_A'])

    selected = []
    selected.extend(by_cause['outage'][:20])
    selected.extend(by_cause['route_leak'][:10])
    selected.extend(by_cause['origin_hijack_victim'][:10])

    print(f'Selection by cause:')
    for cause, lst in by_cause.items():
        print(f'  {cause}: {len(lst)} available, {min(20 if cause=="outage" else 10, len(lst))} selected')
    print(f'Total selected: {len(selected)}')

    # Write CSV
    fieldnames = ['event_id', 'name', 'date', 'start_utc', 'end_utc',
                  'victim_as', 'attacker_as', 'leak_as', 'cause', 'subtype',
                  'routing_peak_A', 'routing_status', 'traffic_z_min', 'traffic_pct_drop',
                  'source', 'source_url', 'evidence_tier', 'origin']
    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(selected)
    print(f'Written: {OUT_CSV} ({len(selected)} rows)')


if __name__ == '__main__':
    main()
