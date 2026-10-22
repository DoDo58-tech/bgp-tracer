#!/usr/bin/env python3
"""
Per-event traffic analysis: compute min/max z-score and pct drop vs baseline.
Output: enriched CSV with traffic stats per event.
"""
import os
import sys
import json
import csv
import time
import glob
import polars as pl
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

TRAFFIC_DIR = Path('data/traffic')
GT_CSV = 'data_check/ground_truth_collection/final_balanced_dataset_v17_30.csv'
OUT_CSV = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'
OUT_DIR = Path('data/groundtruth_v18')


def find_traffic_file(asn, date):
    """Find traffic file for AS+date. Pick the one whose [start,end] range covers date."""
    pattern = str(TRAFFIC_DIR / f'AS{asn}_traffic_*T*_to_*T*.csv')
    files = glob.glob(pattern)
    target = datetime.fromisoformat(date + 'T00:00:00')
    candidates = []
    for f in files:
        base = os.path.basename(f)
        # AS14593_traffic_2025-07-21T00:00:00Z_to_2025-07-28T00:00:00Z.csv
        try:
            parts = base.replace('.csv', '').split('_to_')
            start_str = parts[0].split('_traffic_')[1]
            end_str = parts[1]
            s = datetime.fromisoformat(start_str.rstrip('Z'))
            e = datetime.fromisoformat(end_str.rstrip('Z'))
            if s <= target + timedelta(days=1) and e >= target:
                candidates.append((f, s, e))
        except Exception:
            continue
    if not candidates:
        return None
    # Prefer the one with shortest range (most specific)
    candidates.sort(key=lambda x: (x[2] - x[1]))
    return candidates[0][0]


def analyze_event_traffic(asn, start_utc, end_utc):
    """Return dict with traffic stats in window + baseline."""
    # Parse AS
    asn_num = int(asn.replace('AS', ''))
    start_date = start_utc.split(' ')[0]
    f = find_traffic_file(asn_num, start_date)
    if not f:
        return {'error': f'no traffic file for {asn} near {start_date}'}

    df = pl.read_csv(f, try_parse_dates=True)
    # df has columns timestamp, value - normalize to naive UTC
    if df['timestamp'].dtype == pl.Utf8:
        df = df.with_columns(pl.col('timestamp').str.to_datetime('%Y-%m-%dT%H:%M:%S', strict=False))
    # Drop timezone if any
    if hasattr(df['timestamp'].dtype, 'time_zone') and df['timestamp'].dtype.time_zone is not None:
        df = df.with_columns(pl.col('timestamp').dt.replace_time_zone(None))
    # Filter to window
    s = datetime.fromisoformat(start_utc.replace(' ', 'T').replace('Z', ''))
    e = datetime.fromisoformat(end_utc.replace(' ', 'T').replace('Z', ''))
    df_w = df.filter((pl.col('timestamp') >= s) & (pl.col('timestamp') <= e))
    if len(df_w) == 0:
        return {'error': 'no data in window'}

    # Convert to numpy
    vals = df_w['value'].to_numpy().astype(float)
    times = df_w['timestamp'].to_list()

    # Compute baseline: same 7 days prior to start
    baseline_start = s - timedelta(days=7)
    baseline_end = s
    df_b = df.filter((pl.col('timestamp') >= baseline_start) & (pl.col('timestamp') < baseline_end))
    if len(df_b) < 5:
        # Try 3 days
        baseline_start = s - timedelta(days=3)
        df_b = df.filter((pl.col('timestamp') >= baseline_start) & (pl.col('timestamp') < baseline_end))
    baseline_vals = df_b['value'].to_numpy().astype(float) if len(df_b) else np.array([])

    bmean = float(np.mean(baseline_vals)) if len(baseline_vals) else 0.0
    bstd = float(np.std(baseline_vals)) if len(baseline_vals) else 1.0

    wmin = float(np.min(vals))
    wmax = float(np.max(vals))
    wmean = float(np.mean(vals))

    z_min = (wmin - bmean) / bstd if bstd > 0 else 0.0
    pct_drop = (bmean - wmin) / bmean * 100 if bmean > 0 else 0.0
    pct_max = (wmax - bmean) / bmean * 100 if bmean > 0 else 0.0

    return {
        'n_points_window': int(len(vals)),
        'n_points_baseline': int(len(baseline_vals)),
        'window_min': wmin,
        'window_max': wmax,
        'window_mean': wmean,
        'baseline_mean': bmean,
        'baseline_std': bstd,
        'z_min': z_min,
        'pct_drop_vs_baseline': pct_drop,
        'pct_max_vs_baseline': pct_max,
        'window_start_actual': str(times[0]),
        'window_end_actual': str(times[-1]),
    }


def main():
    with open(GT_CSV) as f:
        events = list(csv.DictReader(f))
    print(f'Processing {len(events)} events...\n')

    new_rows = []
    for i, e in enumerate(events, 1):
        eid = e['event_id']
        victim = e.get('victim_as', '')
        start_utc = e['start_time_utc']
        end_utc = e['end_time_utc']
        t0 = time.time()
        if not victim:
            new_rows.append({**e, 'traffic_z_min_v18': '', 'traffic_pct_drop_v18': '', 'traffic_status_v18': 'no_victim_as'})
            continue
        try:
            stats = analyze_event_traffic(victim, start_utc, end_utc)
        except Exception as ex:
            new_rows.append({**e, 'traffic_z_min_v18': '', 'traffic_pct_drop_v18': '', 'traffic_status_v18': f'error: {ex}'})
            print(f'[{i:2d}] {eid} ERROR: {ex}')
            continue
        if 'error' in stats:
            new_rows.append({**e, 'traffic_z_min_v18': '', 'traffic_pct_drop_v18': '', 'traffic_status_v18': stats['error']})
            print(f'[{i:2d}] {eid} {stats["error"]}')
            continue
        new_rows.append({**e,
            'traffic_z_min_v18': f"{stats['z_min']:.2f}",
            'traffic_pct_drop_v18': f"{stats['pct_drop_vs_baseline']:.1f}",
            'traffic_window_min_v18': f"{stats['window_min']:.4f}",
            'traffic_baseline_mean_v18': f"{stats['baseline_mean']:.4f}",
            'traffic_baseline_n_v18': stats['n_points_baseline'],
            'traffic_window_n_v18': stats['n_points_window'],
            'traffic_status_v18': 'ok',
        })
        print(f'[{i:2d}] {eid:<55} z_min={stats["z_min"]:+.2f} drop={stats["pct_drop_vs_baseline"]:5.1f}% bmean={stats["baseline_mean"]:.3f} ({time.time()-t0:.1f}s)')

    # Write - union of all keys
    if new_rows:
        keys = set()
        for r in new_rows:
            keys.update(r.keys())
        keys = list(keys)
        # Preserve original order: start with original GT keys
        with open(GT_CSV) as f:
            orig_keys = list(csv.DictReader(f).fieldnames or [])
        for k in keys:
            if k not in orig_keys:
                orig_keys.append(k)
        with open(OUT_CSV, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=orig_keys)
            w.writeheader()
            w.writerows(new_rows)
        print(f'\nWritten to {OUT_CSV}')


if __name__ == '__main__':
    main()
