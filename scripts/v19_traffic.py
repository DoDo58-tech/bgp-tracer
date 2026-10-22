#!/usr/bin/env python3
"""
For v19 candidates, find traffic data (if any) and compute z_min, drop%.
Also save traffic time series parquet if available.
"""
import os
import sys
import csv
import json
import glob
import polars as pl
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

CAND_FILE = 'data/groundtruth_v19/candidate_metadata.jsonl'
TRAFFIC_DIR = Path('data/traffic')
OUT_DIR = Path('data/groundtruth_v19')


def find_traffic_file(asn, date):
    pattern = str(TRAFFIC_DIR / f'AS{asn}_traffic_*T*_to_*T*.csv')
    files = glob.glob(pattern)
    target = datetime.fromisoformat(date + 'T00:00:00')
    candidates = []
    for f in files:
        base = os.path.basename(f)
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
    candidates.sort(key=lambda x: (x[2] - x[1]))
    return candidates[0][0]


def analyze_traffic(asn, start_utc, end_utc):
    asn_num = int(asn.replace('AS', ''))
    start_date = start_utc.split(' ')[0]
    f = find_traffic_file(asn_num, start_date)
    if not f:
        return {'error': 'no_traffic_file'}
    df = pl.read_csv(f, try_parse_dates=True)
    if df['timestamp'].dtype == pl.Utf8:
        df = df.with_columns(pl.col('timestamp').str.to_datetime('%Y-%m-%dT%H:%M:%S', strict=False))
    if hasattr(df['timestamp'].dtype, 'time_zone') and df['timestamp'].dtype.time_zone is not None:
        df = df.with_columns(pl.col('timestamp').dt.replace_time_zone(None))
    s = datetime.fromisoformat(start_utc.replace(' ', 'T').replace('Z', ''))
    e = datetime.fromisoformat(end_utc.replace(' ', 'T').replace('Z', ''))
    df_w = df.filter((pl.col('timestamp') >= s) & (pl.col('timestamp') <= e))
    if len(df_w) == 0:
        return {'error': 'no_data_in_window'}
    # Tag window
    df = df.with_columns(
        ((pl.col('timestamp') >= s) & (pl.col('timestamp') <= e)).alias('in_event_window')
    )
    # Save full TS parquet
    out_ts = OUT_DIR / f'{Path(f).stem.split("_traffic_")[0].lower()}_{start_date.replace("-", "")}_traffic_ts.parquet'
    # Use a clean name based on asn
    out_ts = OUT_DIR / f'AS{asn_num}_{start_date.replace("-", "")}_traffic_ts.parquet'
    df.write_parquet(out_ts)
    # Compute stats
    vals = df_w['value'].to_numpy().astype(float)
    baseline_start = s - timedelta(days=7)
    baseline_end = s
    df_b = df.filter((pl.col('timestamp') >= baseline_start) & (pl.col('timestamp') < baseline_end))
    if len(df_b) < 5:
        baseline_start = s - timedelta(days=3)
        df_b = df.filter((pl.col('timestamp') >= baseline_start) & (pl.col('timestamp') < baseline_end))
    bv = df_b['value'].to_numpy().astype(float) if len(df_b) else np.array([])
    bm = float(np.mean(bv)) if len(bv) else 0
    bs = float(np.std(bv)) if len(bv) else 1
    wmin = float(np.min(vals))
    z_min = (wmin - bm) / bs if bs > 0 else 0
    drop = (bm - wmin) / bm * 100 if bm > 0 else 0
    return {
        'traffic_file': f,
        'n_window': int(len(vals)),
        'n_baseline': int(len(bv)),
        'window_min': wmin,
        'baseline_mean': bm,
        'z_min': z_min,
        'pct_drop': drop,
    }


def main():
    with open(CAND_FILE) as f:
        cands = [json.loads(l) for l in f if l.strip()]
    print(f'Processing {len(cands)} candidates for traffic...')
    enriched = []
    for c in cands:
        eid = c['event_id']
        asn = c['victim_as']
        s = c['start_utc']
        e = c['end_utc']
        try:
            stats = analyze_traffic(asn, s, e)
        except Exception as ex:
            stats = {'error': str(ex)}
        if 'error' in stats:
            c['traffic_z_min'] = ''
            c['traffic_pct_drop'] = ''
            c['traffic_status'] = stats['error']
            print(f'  {eid:<55} {asn} {stats["error"]}')
        else:
            c['traffic_z_min'] = round(stats['z_min'], 2)
            c['traffic_pct_drop'] = round(stats['pct_drop'], 1)
            c['traffic_status'] = 'ok'
            c['traffic_window_n'] = stats['n_window']
            c['traffic_baseline_n'] = stats['n_baseline']
            print(f'  {eid:<55} {asn} z={stats["z_min"]:+.2f} drop={stats["pct_drop"]:5.1f}%')
        enriched.append(c)

    with open(CAND_FILE, 'w') as f:
        for c in enriched:
            f.write(json.dumps(c) + '\n')
    print(f'\nUpdated {CAND_FILE}')


if __name__ == '__main__':
    main()
