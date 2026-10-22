#!/usr/bin/env python3
"""
Save per-event traffic time series parquet (window + baseline).
"""
import os
import sys
import csv
import glob
import polars as pl
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

TRAFFIC_DIR = Path('data/traffic')
GT_CSV = 'data_check/ground_truth_collection/final_balanced_v18_30.csv'
OUT_DIR = Path('data/groundtruth_v18')
OUT_DIR.mkdir(parents=True, exist_ok=True)


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


def main():
    with open(GT_CSV) as f:
        events = list(csv.DictReader(f))

    saved = 0
    for e in events:
        eid = e['event_id']
        victim = e.get('victim_as', '')
        if not victim:
            continue
        asn = int(victim.replace('AS', ''))
        start_utc = e['start_time_utc']
        end_utc = e['end_time_utc']
        start_date = start_utc.split(' ')[0]
        f = find_traffic_file(asn, start_date)
        if not f:
            continue
        df = pl.read_csv(f, try_parse_dates=True)
        if df['timestamp'].dtype == pl.Utf8:
            df = df.with_columns(pl.col('timestamp').str.to_datetime('%Y-%m-%dT%H:%M:%S', strict=False))
        if hasattr(df['timestamp'].dtype, 'time_zone') and df['timestamp'].dtype.time_zone is not None:
            df = df.with_columns(pl.col('timestamp').dt.replace_time_zone(None))
        # Tag window
        s = datetime.fromisoformat(start_utc.replace(' ', 'T').replace('Z', ''))
        en = datetime.fromisoformat(end_utc.replace(' ', 'T').replace('Z', ''))
        df = df.with_columns(
            ((pl.col('timestamp') >= s) & (pl.col('timestamp') <= en)).alias('in_event_window')
        )
        out = OUT_DIR / f'{eid}_traffic_timeseries.parquet'
        df.write_parquet(out)
        saved += 1
    print(f'Saved {saved} traffic time series parquets to {OUT_DIR}')


if __name__ == '__main__':
    main()
