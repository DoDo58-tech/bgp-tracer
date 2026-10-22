#!/usr/bin/env python3
"""
Generate quick caches for v19 events that don't have one.
Run sequentially in background to avoid server overload.
"""
import os
import sys
import subprocess
import csv
import json
import time
from pathlib import Path

GT = 'data_check/ground_truth_collection/final_balanced_v19_40.csv'
QUICK_DIR = Path('results/quick')
QUICK_DIR.mkdir(parents=True, exist_ok=True)


def already_has_cache(event_id, asn, date):
    date_compact = date.replace('-', '')
    patterns = [
        f"quick_{asn}_{date_compact}*.json",
        f"quick_{event_id}*.json",
    ]
    for p in patterns:
        matches = list(QUICK_DIR.glob(p))
        if matches:
            return matches[0]
    return None


def main():
    events = list(csv.DictReader(open(GT)))
    pending = []
    for e in events:
        asn = e['victim_as'].replace('AS', '')
        eid = e['event_id']
        date = e['date']
        if already_has_cache(eid, asn, date):
            print(f'  {eid:<55} AS{asn} {date}  has cache')
            continue
        # If attacker_as or leak_as exists, also try that AS
        candidates = [asn]
        for f in ('attacker_as', 'leak_as'):
            v = e.get(f, '').replace('AS', '').strip()
            if v and v != asn and v not in candidates:
                candidates.append(v)
        pending.append((eid, asn, date, e['start_utc'], e['end_utc'], candidates))

    print(f'\nNeed to generate {len(pending)} caches')
    # Print commands
    for eid, asn, date, s, en, cands in pending:
        # Use primary AS first
        asn_to_use = cands[0]
        start = s.replace(' ', 'T')
        end = en.replace(' ', 'T')
        print(f'  python3 chief_agent.py --asn {asn_to_use} --start "{start}" --end "{end}" --mode quick --json-summary > logs/cachegen_{eid}.log 2>&1')
    return pending


if __name__ == '__main__':
    p = main()
    # Save list
    with open('logs/v19_pending_caches.jsonl', 'w') as f:
        for x in p:
            f.write(json.dumps(x) + '\n')
