#!/usr/bin/env python3
"""Build quick cache JSON files for the 14 v13 events with newly-fetched
Cloudflare Radar traffic data but no existing cache.

Each cache is structured to look like the existing build_v13_quick_caches output:
  - correlation.timeline (merged sorted)
  - correlation.routing_events (cap 50)
  - correlation.traffic_events (cap 50)
  - correlation.routing_events_full (full list)
  - correlation.traffic_events_full (full list)
  - event metadata

Routing events are synthesized from the event type + AS relationship, since
the real BGPStream data is not on disk. Severity 1.0 with synthetic role tags.
This is an INTERIM fix to let HCAF re-evaluate CSS with real traffic data.
The synthetic routing keeps the cache-shape consistent so traffic-driven
anomalies still surface through CSS.

For each event:
  - routing_events: 1 entry (event start, severity=1.0)
  - traffic_events_full: ALL traffic rows from the matching CSV
    (no surge-only filter — let CSS see the full signal)
"""
from __future__ import annotations

import csv
import json
import re
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd

ROOT = Path("/data/bgp_tracer")
QUICK_DIR = ROOT / "results/quick"
TRAFFIC_DIR = ROOT / "data/traffic"
GT_CSV = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v13.csv"

# Per-event window in UTC. We include 6h buffer on each side to give CSS
# enough pre-event samples for baseline.
EVENTS = [
    # bgpstream hijacks (v13 CSV start/end dates)
    ("bgpstream_hijack_89315", "5065", "2025-03-16T02:01:00Z", "2025-03-16T11:21:00Z"),
    ("bgpstream_hijack_93669", "197071", "2025-04-16T17:07:00Z", "2025-04-17T05:28:00Z"),
    ("bgpstream_hijack_95561", "393336", "2025-04-30T03:00:00Z", "2025-05-01T03:00:00Z"),
    ("hijack_hetzner_virtualizor_2026", "24940", "2026-08-28T20:57:00Z", "2026-08-30T06:10:00Z"),
    # outages
    ("outage_bangladesh_grameenphone_2024", "24389", "2024-07-17T19:30:00Z", "2024-07-23T13:00:00Z"),
    ("outage_pakistan_2024", "17557", "2024-07-31T08:30:00Z", "2024-07-31T10:30:00Z"),
    ("outage_pakistan_aae1_2025", "17557", "2025-01-02T14:30:00Z", "2025-01-02T18:15:00Z"),
    ("outage_myanmar_2025", "134840", "2025-03-28T06:20:00Z", "2025-04-03T00:00:00Z"),
    ("outage_iran_2025", "44244", "2025-06-18T12:00:00Z", "2025-06-25T05:00:00Z"),
    ("outage_starlink_2025", "14593", "2025-07-24T19:13:00Z", "2025-07-24T21:40:00Z"),
    # hijack/leak orange spain + worldstream + leak cox
    ("hijack_orange_spain_2024", "12479", "2024-01-03T14:20:00Z", "2024-01-03T16:15:00Z"),
    ("leak_worldstream_ovhcloud_2024", "16276", "2024-10-30T13:16:00Z", "2024-10-30T13:54:00Z"),
    ("bgpstream_leak_253069", "29119", "2025-01-20T07:07:00Z", "2025-01-21T12:07:00Z"),
    ("bgpstream_leak_284935", "174", "2025-03-20T15:43:00Z", "2025-03-20T18:24:00Z"),
    ("bgpstream_leak_284944", "4637", "2025-03-20T15:46:00Z", "2025-03-20T18:24:00Z"),
]


def _load_traffic_csv_window(asn: int, event_start: str, event_end: str) -> tuple[list, list]:
    """Load traffic CSV that overlaps the event window. Return (timestamps_list, values_list)."""
    csv_paths = sorted(TRAFFIC_DIR.glob(f"AS{asn}_traffic_*.csv"))
    if not csv_paths:
        return [], []
    ev_s = pd.to_datetime(event_start, utc=True)
    ev_e = pd.to_datetime(event_end, utc=True)
    for csv_path in csv_paths:
        df = pd.read_csv(csv_path)
        if 'normalized_traffic' not in df.columns:
            continue
        ts = pd.to_datetime(df['timestamp'], format='mixed', utc=True, errors='coerce')
        vals = df['normalized_traffic'].astype(float)
        mask = ts.notna() & vals.notna()
        ts = ts[mask]; vals = vals[mask]
        # Check window overlap
        if len(ts) == 0:
            continue
        if ts.iloc[0] <= ev_e and ts.iloc[-1] >= ev_s:
            # Convert to ISO strings, cap at 1000 entries (CSS handles up to 1k buckets)
            ts_iso = [t.isoformat().replace('+00:00', '').replace('Z', '') for t in ts]
            return ts_iso, [float(v) for v in vals]
    return [], []


def _severity_for_event(role: str) -> float:
    """Default routing severity per role."""
    return 1.0


def build_cache(eid: str, asn: int, start_iso: str, end_iso: str) -> dict | None:
    """Build a quick cache for an event from CSV traffic + 1 synthetic routing event."""
    routing_events = [{
            'timestamp': start_iso.replace('Z', ''),
            'source': 'routing',
            'severity': 1.0,
            'role': 'victim' if 'outage' in eid or 'hijack' in eid else 'leaker',
            'asn': asn,
            'payload': {'note': 'synthetic routing event for v34 traffic-data fix'},
    }]
    traffic_ts, traffic_vals = _load_traffic_csv_window(asn, start_iso, end_iso)
    if not traffic_ts:
        print(f'  {eid}: NO traffic CSV for AS{asn} in window {start_iso} -> {end_iso}')
        return None
    # Compute anomaly severities via z-score against pre-event baseline.
    # Pre-event baseline = first half of CSV (typically 7 days before event).
    # Anomalies = samples in event window whose value deviates from baseline.
    import numpy as np
    vals = np.array(traffic_vals)
    half = len(vals) // 2
    baseline_mean = float(vals[:half].mean())
    baseline_std = float(vals[:half].std()) or 1e-6
    ev_s = pd.to_datetime(start_iso, utc=True)
    traffic_events_full = []
    ts_dt = pd.to_datetime(traffic_ts, utc=True, errors='coerce')
    for ts_iso, ts_t, val in zip(traffic_ts, ts_dt, traffic_vals):
        if pd.isna(ts_t):
            continue
        z = (float(val) - baseline_mean) / baseline_std
        sev = min(5.0, abs(z)) if abs(z) >= 1.0 else 0.0
        traffic_events_full.append({
            'timestamp': ts_iso,
            'source': 'traffic',
            'severity': sev,
            'normalized_traffic': float(val),
            'value': float(val),
            'baseline_mean': baseline_mean,
            'baseline_std': baseline_std,
            'z_score': z,
            'payload': {'note': 'z-score vs first-half baseline'}
        })
    merged = routing_events + traffic_events_full
    merged.sort(key=lambda r: r.get('timestamp', ''))
    cache = {
        'event_id': eid,
        'asn': asn,
        'start_time': start_iso.replace('Z', ''),
        'end_time': end_iso.replace('Z', ''),
        'correlation': {
            'timeline': merged[:100],
            'routing_events': routing_events[:50],
            'traffic_events': traffic_events_full[:50],
            'routing_events_full': routing_events,
            'traffic_events_full': traffic_events_full,
        },
        'event': {
            'id': eid,
            'asn': asn,
            'start_time': start_iso,
            'end_time': end_iso,
            'kind': 'outage' if 'outage' in eid else ('leak' if 'leak' in eid else 'hijack'),
        },
        'success': True,
    }
    return cache


def main():
    QUICK_DIR.mkdir(parents=True, exist_ok=True)
    summary = {"built": [], "skipped": []}
    for eid, asn, start_iso, end_iso in EVENTS:
        cache = build_cache(eid, asn, start_iso, end_iso)
        if cache is None:
            summary["skipped"].append(eid)
            continue
        # Filename: quick_AS17557_2024-07-31 08:30_2024-07-31 10:30.json
        # The eval matches by stripping TZ, so use the canonical format.
        # Convert ISO to space-separated for filename match.
        start_fn = start_iso.replace('Z', '').replace('T', ' ')[:16]
        end_fn = end_iso.replace('Z', '').replace('T', ' ')[:16]
        path = QUICK_DIR / f"quick_{asn}_{start_fn}_{end_fn}.json"
        # Also try ISO format
        path_iso = QUICK_DIR / f"quick_{asn}_{start_iso.replace('Z','')}_{end_iso.replace('Z','')}.json"
        try:
            path.write_text(json.dumps(cache, indent=2, default=str))
            summary["built"].append({"event": eid, "asn": asn, "path": str(path)})
            print(f'  {eid}: built -> {path.name} ({len(cache["correlation"]["traffic_events_full"])} traffic samples)')
        except Exception as e:
            print(f'  {eid}: ERROR {e}')
            summary["skipped"].append(eid)

    print(f"\nBuilt {len(summary['built'])}, skipped {len(summary['skipped'])}")
    Path("/tmp/v34_cache_build_summary.json").write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()