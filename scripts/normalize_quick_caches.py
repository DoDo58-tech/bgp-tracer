#!/usr/bin/env python3
"""Normalize all quick-cache timestamps to naive ISO format.

Walks all event arrays in correlation: timeline, routing_events, traffic_events,
routing_events_full, traffic_events_full.
"""
import json
import re
from pathlib import Path

QUICK_DIR = Path("/data/bgp_tracer/results/quick")
KEYS = ['timeline', 'routing_events', 'traffic_events', 'routing_events_full', 'traffic_events_full']
n_changed_files = 0
n_changed_ts = 0
for f in sorted(QUICK_DIR.glob("quick_*.json")):
    with open(f) as fp:
        d = json.load(fp)
    changed = False
    for k in KEYS:
        arr = d.get('correlation', {}).get(k, [])
        for e in arr:
            ts = e.get('timestamp', '')
            if isinstance(ts, str):
                new_ts = re.sub(r'\s*[+-]\d{2}:?\d{2}$', '', ts)
                new_ts = new_ts.replace('Z', '').strip()
                if new_ts != ts:
                    e['timestamp'] = new_ts
                    changed = True
                    n_changed_ts += 1
    if changed:
        with open(f, 'w') as fp:
            json.dump(d, fp, indent=2, default=str)
        n_changed_files += 1
print(f"Updated {n_changed_files} cache files ({n_changed_ts} timestamps)")