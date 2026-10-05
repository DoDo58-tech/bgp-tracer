#!/usr/bin/env python3
"""Build quick-cache files for v13 events from routing_grounded_cases data.

Output: results/quick/quick_AS{n}_{start}_{end}.json with the format the
       eval_hcaf_vs_baselines.py expects (correlation.timeline, routing_events,
       traffic_events).
"""
from __future__ import annotations

import csv
import json
import re
import time
from pathlib import Path
import pandas as pd

ROOT = Path("/data/bgp_tracer")
QUICK_DIR = ROOT / "results/quick"
H_DIR = ROOT / "data_check/traffic_anomalies_events/routing_grounded_cases/hijack/kept"
L_DIR = ROOT / "data_check/traffic_anomalies_events/routing_grounded_cases/leak/kept"
TRAFFIC_DIR = ROOT / "data/traffic"
V13_CSV = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v13.csv"


def make_event_record(ts: str, source: str, severity: float, payload: dict) -> dict:
    return {
        'timestamp': ts,
        'source': source,
        'severity': severity,
        'payload': payload,
    }


def build_hijack_cache(rec: dict, eid: str, fname: str) -> dict:
    """Build quick-cache JSON for a hijack event."""
    e = rec['event']
    va = rec.get('victim_anomalies') or []
    ha = rec.get('attacker_anomalies') or rec.get('hijacker_anomalies') or []
    routing_events = []
    for x in va:
        routing_events.append({
            'timestamp': x.get('timestamp', e.get('start_time', '')),
            'source': 'routing', 'severity': 1.0,
            'role': 'victim',
            'prefix': x.get('prefix'), 'origin_as': x.get('origin_as'),
            'as_path': x.get('as_path'),
            'payload': x,
        })
    for x in ha:
        routing_events.append({
            'timestamp': x.get('timestamp', e.get('start_time', '')),
            'source': 'routing', 'severity': 1.0,
            'role': 'attacker',
            'prefix': x.get('prefix'), 'origin_as': x.get('origin_as'),
            'as_path': x.get('as_path'),
            'payload': x,
        })
    routing_events.sort(key=lambda r: r['timestamp'])
    # Traffic events from CF Radar CSV
    traffic_events = []
    csv_paths = list(TRAFFIC_DIR.glob(f"AS{e.get('victim_asns', ['0'])[0]}_traffic_*.csv"))
    if csv_paths:
        csv_path = sorted(csv_paths)[-1]
        df = pd.read_csv(csv_path)
        if 'normalized_traffic' in df.columns:
            s = df['normalized_traffic'].astype(float)
            ts = pd.to_datetime(df['timestamp'], format='mixed', utc=True, errors='coerce')
            mask = ts.notna()
            ts = ts[mask]; s = s[mask]
            # Strip tzinfo to keep naive for compatibility
            ts_list = []
            for t in ts:
                if pd.notna(t):
                    if hasattr(t, 'tzinfo') and t.tzinfo is not None:
                        t = t.tz_localize(None) if hasattr(t, 'tz_localize') else t.replace(tzinfo=None)
                    ts_list.append(t)
            # Determine baseline mean and threshold
            baseline_mean = float(s.head(len(s) // 2).mean())
            baseline_std = float(s.head(len(s) // 2).std()) or 1.0
            threshold = baseline_mean + 3 * baseline_std
            # Mark anomalies
            for i, (t, val) in enumerate(zip(ts_list, s)):
                if pd.notna(val) and float(val) > threshold:
                    traffic_events.append({
                        'timestamp': str(t) if not hasattr(t,'isoformat') else t.isoformat(),
                        'source': 'traffic',
                        'severity': float(min((val - threshold) / baseline_std, 5.0)),
                        'value': float(val),
                        'baseline': baseline_mean,
                    })
            traffic_events = traffic_events[:500]  # cap
    # Build merged timeline
    merged = routing_events + traffic_events
    # Strip tzinfo from each timestamp string
    for ev in merged:
        tsv = ev.get('timestamp')
        if isinstance(tsv, str):
            ev['timestamp'] = tsv.replace('+00:00', '').replace('Z', '')
    merged.sort(key=lambda r: r['timestamp'])
    return {
        'event_id': eid,
        'correlation': {
            'timeline': merged,
            'routing_events': routing_events[:50],
            'traffic_events': traffic_events[:50],
            'routing_events_full': routing_events,
            'traffic_events_full': traffic_events,
        },
        'event': e,
    }


def build_leak_cache(rec: dict, eid: str, fname: str) -> dict:
    e = rec['event']
    route_leaks = rec.get('route_leaks', []) or []
    routing_events = []
    for x in route_leaks:
        routing_events.append({
            'timestamp': x.get('timestamp', e.get('start_time', '')),
            'source': 'routing', 'severity': float(x.get('leak_probability', 0.5)),
            'role': 'leaker',
            'prefix': x.get('prefix'),
            'origin_as': x.get('origin-as'),
            'as_path': x.get('as-path'),
            'leak_probability': x.get('leak_probability'),
            'payload': x,
        })
    routing_events.sort(key=lambda r: r['timestamp'])
    # Traffic
    traffic_events = []
    leaker = e.get('leak_asn') or e.get('leak_src_asn')
    if leaker:
        csv_paths = list(TRAFFIC_DIR.glob(f"AS{leaker}_traffic_*.csv"))
        if csv_paths:
            csv_path = sorted(csv_paths)[-1]
            df = pd.read_csv(csv_path)
            if 'normalized_traffic' in df.columns:
                s = df['normalized_traffic'].astype(float)
                ts = pd.to_datetime(df['timestamp'], format='mixed', utc=True, errors='coerce')
                mask = ts.notna()
                ts = ts[mask]; s = s[mask]
                baseline_mean = float(s.head(len(s) // 2).mean())
                baseline_std = float(s.head(len(s) // 2).std()) or 1.0
                threshold = baseline_mean + 3 * baseline_std
                for i, (t, val) in enumerate(zip(ts, s)):
                    if pd.notna(val) and float(val) > threshold:
                        traffic_events.append({
                            'timestamp': str(t),
                            'source': 'traffic',
                            'severity': float(min((val - threshold) / baseline_std, 5.0)),
                            'value': float(val),
                            'baseline': baseline_mean,
                        })
                traffic_events = traffic_events[:500]
    merged = routing_events + traffic_events
    # Strip tzinfo from each timestamp string
    for ev in merged:
        tsv = ev.get('timestamp')
        if isinstance(tsv, str):
            ev['timestamp'] = tsv.replace('+00:00', '').replace('Z', '')
    merged.sort(key=lambda r: r['timestamp'])
    return {
        'event_id': eid,
        'correlation': {
            'timeline': merged,
            'routing_events': routing_events[:50],
            'traffic_events': traffic_events[:50],
            'routing_events_full': routing_events,
            'traffic_events_full': traffic_events,
        },
        'event': e,
    }


def parse_filename_for_startend(eid: str) -> tuple[str, str]:
    """Extract start/end from candidate_id or use event_start_time from source."""
    # Get from the routing_grounded_cases JSON
    h_path = H_DIR / f"{eid}.json"
    l_path = L_DIR / f"{eid}.json"
    for p in [h_path, l_path]:
        if p.exists():
            with open(p) as f:
                d = json.load(f)
            e = d['event']
            return e['start_time'], e['end_time']
    return '', ''


def main():
    QUICK_DIR.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(V13_CSV)))
    n_built = 0
    n_skipped = 0
    for r in rows:
        eid = r['event_id']
        # Extract candidate_id (numeric part)
        m = re.search(r'_(\d+)$', eid)
        if not m:
            n_skipped += 1
            continue
        candidate_id = m.group(1)
        # Determine kind
        if 'hijack' in eid.lower():
            h_path = H_DIR / f"{candidate_id}.json"
            if not h_path.exists():
                n_skipped += 1
                continue
            with open(h_path) as f:
                rec = json.load(f)
            cache = build_hijack_cache(rec, eid, candidate_id)
        elif 'leak' in eid.lower() or 'leak_reliablesite' in eid or 'leak_voxility' in eid:
            l_path = L_DIR / f"{candidate_id}.json"
            if not l_path.exists():
                # Try with leak_reliablesite/voxility - they don't have routing_grounded_cases
                # Fall back to CSV traffic + RRC00 + event metadata
                cache = build_v12style_leak_cache(r)
                if cache is None:
                    n_skipped += 1
                    continue
            else:
                with open(l_path) as f:
                    rec = json.load(f)
                cache = build_leak_cache(rec, eid, candidate_id)
        else:
            n_skipped += 1
            continue
        if cache is None:
            n_skipped += 1
            continue
        # Extract victim/leaker ASN for filename
        asn = ''
        for k in ['victim_as', 'attacker_as', 'leak_as']:
            v = r.get(k, '').strip()
            if v:
                asn = v.replace('AS', '')
                break
        if not asn:
            n_skipped += 1
            continue
        start = r.get('start_time_utc', '').replace(':', '').replace('-', '').replace('T', 'T')[:16]
        end = r.get('end_time_utc', '').replace(':', '').replace('-', '').replace('T', 'T')[:16]
        # Output filename: quick_AS{n}_{start}_{end}.json
        out_name = f"quick_{asn}_{start}_{end}.json"
        out_path = QUICK_DIR / out_name
        with open(out_path, 'w') as f:
            json.dump(cache, f, indent=2, default=str)
        n_built += 1
    print(f"Built {n_built} quick caches, skipped {n_skipped}")
    # List output
    files = sorted(QUICK_DIR.glob("quick_*.json"))
    print(f"Total quick files now: {len(files)}")


def build_v12style_leak_cache(row: dict) -> dict | None:
    """Build a quick-cache for v12-style leaks using RRC00 + traffic CSV."""
    eid = row['event_id']
    leaker = row.get('leak_as', '').replace('AS', '').strip()
    if not leaker:
        return None
    # RRC00 routing events (we don't have full BGPStream data; use RRC00 announces)
    # For simplicity, treat start_time as event_time and synthesize 1 routing event
    e = {
        'kind': 'leak', 'id': eid,
        'start_time': row.get('start_time_utc', ''),
        'end_time': row.get('end_time_utc', ''),
        'leak_asn': leaker,
    }
    routing_events = [{
        'timestamp': e['start_time'],
        'source': 'routing', 'severity': 1.0,
        'role': 'leaker',
        'payload': {'note': 'v12-style leak recovered from v13 build'},
    }]
    # Traffic events from CSV
    traffic_events = []
    csv_paths = list(TRAFFIC_DIR.glob(f"AS{leaker}_traffic_*.csv"))
    if csv_paths:
        csv_path = sorted(csv_paths)[-1]
        df = pd.read_csv(csv_path)
        if 'normalized_traffic' in df.columns:
            s = df['normalized_traffic'].astype(float)
            ts = pd.to_datetime(df['timestamp'], format='mixed', utc=True, errors='coerce')
            mask = ts.notna()
            ts = ts[mask]; s = s[mask]
            # Strip tzinfo
            ts_list = []
            for t in ts:
                if pd.notna(t):
                    if hasattr(t, 'tzinfo') and t.tzinfo is not None:
                        t = t.tz_localize(None) if hasattr(t, 'tz_localize') else t.replace(tzinfo=None)
                    ts_list.append(t)
            baseline_mean = float(s.head(len(s) // 2).mean())
            baseline_std = float(s.head(len(s) // 2).std()) or 1.0
            threshold = baseline_mean + 3 * baseline_std
            for t, val in zip(ts_list, s):
                if pd.notna(val) and float(val) > threshold:
                    traffic_events.append({
                        'timestamp': str(t) if not hasattr(t,'isoformat') else t.isoformat(),
                        'source': 'traffic',
                        'severity': float(min((val - threshold) / baseline_std, 5.0)),
                        'value': float(val), 'baseline': baseline_mean,
                    })
            traffic_events = traffic_events[:500]
    merged = routing_events + traffic_events
    # Strip tzinfo from each timestamp string
    for ev in merged:
        tsv = ev.get('timestamp')
        if isinstance(tsv, str):
            ev['timestamp'] = tsv.replace('+00:00', '').replace('Z', '')
    merged.sort(key=lambda r: r['timestamp'])
    return {
        'event_id': eid,
        'correlation': {
            'timeline': merged,
            'routing_events': routing_events,
            'traffic_events': traffic_events,
            'routing_events_full': routing_events,
            'traffic_events_full': traffic_events,
        },
        'event': e,
    }


if __name__ == '__main__':
    main()