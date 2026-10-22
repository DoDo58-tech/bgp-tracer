#!/usr/bin/env python3
"""Build a curated ground truth from v19 events, filtering for:
  - clear evidence
  - balanced across 3 classes
  - no 'opportunistic during outage' or 'RPKI takeover' subtypes (too ambiguous)
  - no 'misorigination by tier1' (often mis-attributed)
"""
import csv
import json
from collections import Counter
from pathlib import Path

GT = Path('data_check/ground_truth_collection/final_balanced_v19_40.csv')
OUT = Path('data_check/ground_truth_collection/final_clean_v20.csv')

events = list(csv.DictReader(open(GT)))

# Subtypes that are inherently ambiguous — the routing-side signal
# cannot be cleanly attributed to the right class without ground truth.
AMBIGUOUS = {
    'origin_asn_hijack_opportunistic_during_outage',
    'rpki_credential_takeover_misorigin',
    'origin_asn_hijack_misconfig',  # RPKI tampering ambiguous
    'misorigination_by_tier1',  # Often looks like outage at receiver
}

# Filter
filtered = [e for e in events if e.get('subtype') not in AMBIGUOUS]
print(f'After filtering: {len(filtered)} events')

# Class distribution
c = Counter(e['cause'] for e in filtered)
print(f'  Distribution: {dict(c)}')

# Balanced subset
by_cause = {'outage': [], 'route_leak': [], 'origin_hijack_victim': []}
for e in filtered:
    by_cause[e['cause']].append(e)


def score_event(e):
    s = 0
    if e.get('evidence_tier') == 'A':
        s += 10
    if int(e['date'][:4]) >= 2024:
        s += 5
    if int(e['date'][:4]) >= 2025:
        s += 3
    # Reward having traffic data (recent events have CF Radar data)
    try:
        asn = e['victim_as'].replace('AS', '')
        from datetime import datetime
        d = datetime.strptime(e['date'], '%Y-%m-%d')
        # Heuristic: 2018-2019 events often lack CF Radar data
        if d.year < 2020:
            s -= 2
    except Exception:
        pass
    return s


balanced = []
for cause, evts in by_cause.items():
    evts_sorted = sorted(evts, key=lambda e: -score_event(e))
    n = min(8, len(evts_sorted))
    balanced.extend(evts_sorted[:n])
    print(f'  {cause}: took {n} of {len(evts_sorted)}')

balanced = sorted(balanced, key=lambda e: e['date'])
print(f'\nFinal clean v20: {len(balanced)} events')
c2 = Counter(e['cause'] for e in balanced)
print(f'  Distribution: {dict(c2)}')

cols = list(balanced[0].keys())
with open(OUT, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for e in balanced:
        w.writerow(e)
print(f'Wrote: {OUT}')
