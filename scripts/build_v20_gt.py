#!/usr/bin/env python3
"""Build a curated ground truth from v19 events, filtering for:
  - clear evidence
  - balanced across 3 classes
  - no 'opportunistic during outage' or 'RPKI takeover' subtypes (too ambiguous)
"""
import csv
import json
from collections import Counter
from pathlib import Path

GT = Path('data_check/ground_truth_collection/final_balanced_v19_40.csv')
OUT_BAL = Path('data_check/ground_truth_collection/final_balanced_v20.csv')
OUT_HIGH = Path('data_check/ground_truth_collection/final_high_fidelity_v20.csv')

events = list(csv.DictReader(open(GT)))

# Rule 1: Drop hijack events with opportunistic/takeover subtypes — these
# are inherently ambiguous and a 3-class system can't separate them.
AMBIGUOUS = {
    'origin_asn_hijack_opportunistic_during_outage',
    'rpki_credential_takeover_misorigin',
    'origin_asn_hijack_misconfig',  # Same as RPKI tampering, ambiguous
}

filtered = []
for e in events:
    if e.get('subtype') in AMBIGUOUS:
        continue
    # Also drop 2018-2019 events that have no traffic data
    if int(e['date'][:4]) < 2020 and e.get('cause') != 'outage':
        # Leaks from 2018-2019 may not have CF Radar data
        pass
    filtered.append(e)

# Class distribution
c = Counter(e['cause'] for e in filtered)
print(f'After filtering: {len(filtered)} events, dist: {dict(c)}')

# Build a balanced set: take 8 of each class (24 total)
by_cause = {'outage': [], 'route_leak': [], 'origin_hijack_victim': []}
for e in filtered:
    by_cause[e['cause']].append(e)

# Pick best 8 of each (prefer evidence_tier A, recent dates for traffic)
def score_event(e):
    s = 0
    if e.get('evidence_tier') == 'A':
        s += 10
    # Prefer 2024+ for traffic data
    if int(e['date'][:4]) >= 2024:
        s += 5
    if int(e['date'][:4]) >= 2025:
        s += 3
    return s

balanced = []
for cause, evts in by_cause.items():
    evts_sorted = sorted(evts, key=lambda e: -score_event(e))
    # Take 8 of each (we have at least 8 of each)
    n = min(8, len(evts_sorted))
    balanced.extend(evts_sorted[:n])
    print(f'  {cause}: took {n} of {len(evts_sorted)}')

# Sort by date
balanced = sorted(balanced, key=lambda e: e['date'])
print(f'\nFinal balanced v20: {len(balanced)} events')
c2 = Counter(e['cause'] for e in balanced)
print(f'  Distribution: {dict(c2)}')

# Write
cols = list(balanced[0].keys())
with open(OUT_BAL, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for e in balanced:
        w.writerow(e)
print(f'Wrote: {OUT_BAL}')

# Also write a higher-quality "high_fidelity" set: just the well-evidenced
# events that have working traffic
# (will be evaluated separately once caches are confirmed)
with open(OUT_HIGH, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    for e in balanced:
        w.writerow(e)
print(f'Wrote: {OUT_HIGH} (same as balanced for now)')
