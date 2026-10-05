#!/usr/bin/env python3
"""Rebuild v13 quick caches with bidirectional traffic anomaly detection.

Key fix: the original build_v13_quick_caches.py only detected traffic SURGES
(> mean + 3σ). All 17 real-data v13 events show traffic DROPS (below baseline),
so traffic_events_full was empty for every event.

This script:
  1. For each event with a quick cache, reads the traffic CSV
  2. Detects both surges (> mean+3σ) AND drops (< mean-3σ) in the event window
  3. Uses a rolling baseline window that excludes the event window itself
     (avoids contamination from the drop itself)
  4. Rebuilds traffic_events_full with proper z-score severity
  5. Overwrites the cache with corrected traffic data

The routing events remain unchanged (they were correct).
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
import numpy as np

ROOT = Path("/data/bgp_tracer")
QUICK_DIR = ROOT / "results/quick"
TRAFFIC_DIR = ROOT / "data/traffic"
V13_CSV = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v13.csv"


def strip_tz(ts_val) -> str:
    """Convert a pandas Timestamp to a naive ISO string."""
    if pd.isna(ts_val):
        return ""
    t = ts_val
    if hasattr(t, 'tzinfo') and t.tzinfo is not None:
        t = t.tz_localize(None)
    s = t.isoformat()
    # Remove timezone suffix if present
    s = s.replace('+00:00', '').replace('Z', '')
    return s


def _load_traffic_csv(asn: str, event_start: str, event_end: str):
    """Load traffic CSV for a given AS and parse into (timestamps, values)."""
    csv_paths = sorted(TRAFFIC_DIR.glob(f"AS{asn}_traffic_*.csv"))
    if not csv_paths:
        return None, None
    csv_path = csv_paths[-1]
    df = pd.read_csv(csv_path)

    # Determine value column
    if 'normalized_traffic' in df.columns:
        val_col = 'normalized_traffic'
    elif 'value' in df.columns:
        val_col = 'value'
    else:
        cols = [c for c in df.columns if c != 'timestamp']
        val_col = cols[0] if cols else None
    if val_col is None:
        return None, None

    ts = pd.to_datetime(df['timestamp'], format='mixed', utc=True, errors='coerce')
    vals = df[val_col].astype(float)

    # Remove NaT rows
    mask = ts.notna() & vals.notna()
    return ts[mask], vals[mask]


def compute_traffic_anomalies(asn: str, event_start: str, event_end: str,
                               severity_sigma: float = 3.0) -> list[dict]:
    """Detect traffic anomalies in the event window vs a pre-event baseline.

    Algorithm:
      - Pre-event baseline window: [event_start - 7 days, event_start)
      - Event window: [event_start, event_end]
      - Baseline mean = mean(pre-event window)
      - Threshold: < (mean - sigma * std) = drop, > (mean + sigma * std) = surge
      - Severity: |value - baseline_mean| / baseline_std (capped at 5.0)

    Returns list of traffic event dicts with timestamp, source, severity, value, baseline.
    """
    ts, vals = _load_traffic_csv(asn, event_start, event_end)
    if ts is None:
        return []

    try:
        ev_start = pd.to_datetime(event_start, utc=True)
        ev_end = pd.to_datetime(event_end, utc=True)
        pre_start = ev_start - timedelta(days=7)
    except Exception:
        return []

    # Build baseline mask (pre-event window only)
    pre_mask = (ts >= pre_start) & (ts < ev_start)
    if pre_mask.sum() < 5:
        # Not enough pre-event data — fall back to first half of entire series
        n = len(vals)
        pre_mask = pd.Series([False] * n, index=vals.index)
        pre_half = vals.iloc[:n // 2]
        if len(pre_half) >= 5:
            pre_mask.iloc[:n // 2] = True

    pre_vals = vals[pre_mask]
    if len(pre_vals) < 3:
        return []

    baseline_mean = float(pre_vals.mean())
    baseline_std = float(pre_vals.std())
    if baseline_std <= 0:
        baseline_std = 1.0

    upper_thresh = baseline_mean + severity_sigma * baseline_std
    lower_thresh = baseline_mean - severity_sigma * baseline_std

    # Event window
    ev_mask = (ts >= ev_start) & (ts <= ev_end)
    ev_ts = ts[ev_mask]
    ev_vals = vals[ev_mask]

    events = []
    for t, v in zip(ev_ts, ev_vals):
        v = float(v)
        if v > upper_thresh:
            sev = min((v - upper_thresh) / baseline_std, 5.0)
            events.append({
                'timestamp': strip_tz(t),
                'source': 'traffic',
                'severity': float(sev),
                'value': v,
                'baseline': baseline_mean,
                'direction': 'surge',
            })
        elif v < lower_thresh:
            sev = min((lower_thresh - v) / baseline_std, 5.0)
            events.append({
                'timestamp': strip_tz(t),
                'source': 'traffic',
                'severity': float(sev),
                'value': v,
                'baseline': baseline_mean,
                'direction': 'drop',
            })

    return events


def rebuild_cache_for_row(row: dict) -> bool:
    """Rebuild a single quick cache with corrected traffic anomalies.

    Returns True if cache was rebuilt, False if skipped.
    """
    eid = row['event_id']
    event_type = row.get('ground_truth_cause_label', '')

    # Determine which ASN to use for traffic
    traffic_asn = None
    if event_type in ('route_leak',):
        # For leaks, traffic is measured at the leaker AS
        leaker = row.get('leak_as', '').replace('AS', '').strip()
        if leaker:
            traffic_asn = leaker
    elif event_type in ('origin_hijack_victim', 'roa_misconfig', 'outage'):
        victim = row.get('victim_as', '').replace('AS', '').strip()
        if victim:
            traffic_asn = victim

    if not traffic_asn:
        print(f"  SKIP {eid}: no traffic ASN found")
        return False

    # Find the quick cache file
    asn = traffic_asn
    start = row.get('start_time_utc', '').replace('T', 'T')[:16]
    end = row.get('end_time_utc', '').replace('T', 'T')[:16]

    # Try multiple filename patterns
    candidates = list(QUICK_DIR.glob(f"quick_{asn}_*.json"))
    cache_path = None
    for c in candidates:
        stem = c.stem.replace(f"quick_{asn}_", "")
        if start[:10] in stem:
            cache_path = c
            break

    if cache_path is None:
        print(f"  SKIP {eid}: no cache found for ASN={asn}")
        return False

    # Load existing cache
    with open(cache_path) as f:
        cache = json.load(f)

    # Compute traffic anomalies
    event_start = row.get('start_time_utc', '')
    event_end = row.get('end_time_utc', '')
    traffic_events = compute_traffic_anomalies(traffic_asn, event_start, event_end)

    print(f"  {eid}: {len(traffic_events)} traffic events ({traffic_asn})")

    # Rebuild the correlation section
    routing_events_full = cache.get('correlation', {}).get('routing_events_full', [])
    routing_events = routing_events_full[:50]
    traffic_events_full = traffic_events
    traffic_events_cap = traffic_events_full[:50]

    # Rebuild merged timeline
    merged = list(routing_events_full) + list(traffic_events_full)
    for ev in merged:
        tsv = ev.get('timestamp', '')
        if isinstance(tsv, str):
            ev['timestamp'] = tsv.replace('+00:00', '').replace('Z', '')
    merged.sort(key=lambda x: x.get('timestamp', ''))

    cache['correlation'] = {
        'timeline': merged,
        'routing_events': routing_events,
        'traffic_events': traffic_events_cap,
        'routing_events_full': routing_events_full,
        'traffic_events_full': traffic_events_full,
    }

    # Write back
    with open(cache_path, 'w') as f:
        json.dump(cache, f, indent=2, default=str)

    return True


def main():
    print("=== Rebuilding v13 quick caches with bidirectional traffic anomaly detection ===\n")
    rows = list(csv.DictReader(open(V13_CSV)))

    # Only rebuild non-synthetic (real-data) caches
    synthetic_eids = {
        'bgpstream_hijack_89315', 'bgpstream_hijack_93669', 'bgpstream_hijack_95561',
        'hijack_hetzner_virtualizor_2026',
        'bgpstream_leak_253069', 'bgpstream_leak_284935', 'bgpstream_leak_284944',
        'leak_cox_communications_2025',
    }

    n_rebuilt = 0
    n_skipped = 0
    for r in rows:
        eid = r['event_id']
        if eid in synthetic_eids:
            print(f"SKIP {eid}: synthetic (no real cache)")
            n_skipped += 1
            continue

        print(f"Processing {eid}...")
        ok = rebuild_cache_for_row(r)
        if ok:
            n_rebuilt += 1
        else:
            n_skipped += 1

    print(f"\nDone: {n_rebuilt} rebuilt, {n_skipped} skipped")


if __name__ == '__main__':
    main()
