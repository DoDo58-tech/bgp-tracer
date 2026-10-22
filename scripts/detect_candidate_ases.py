#!/usr/bin/env python3
"""
For each event_features file, find the AS with biggest routing surge
in the window by scanning parquet data.
"""
import os
import sys
import polars as pl
import re
import csv
import json
import glob
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

FEAT_DIR = Path('data/event_features/timeseries_csv')
PARQ_DIR = Path('data/updates_rrc00/parquet')
OUT_FILE = 'data/groundtruth_v18/candidate_as_detection.json'


def parse_event_time(ts_str):
    """Parse timestamp like '2025-01-05 13:45:00' to datetime."""
    return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')


def find_top_as(date_str, hour_window=2):
    """Find top 5 origin ASes in parquet for the given date+hour window."""
    date_compact = date_str.replace('-', '')
    # Use 5-min buckets - take first hour of date
    files = sorted(PARQ_DIR.glob(f'updates.{date_compact}.*.parquet'))
    if not files:
        return None
    # Just process first 12 files (1 hour)
    files = files[:24] if len(files) >= 24 else files
    parts = []
    for f in files:
        try:
            df = pl.read_parquet(f, columns=['as_path', 'announce'])
        except:
            continue
        if len(df) == 0:
            continue
        parts.append(df)
        del df
    if not parts:
        return None
    df = pl.concat(parts)
    df = df.with_columns(
        pl.col('as_path').fill_null('').str.split(' ').list.last()
         .cast(pl.Int64, strict=False).alias('origin_as')
    )
    df = df.filter(pl.col('origin_as').is_not_null())
    # Just count origin AS
    counts = df.group_by('origin_as').agg(pl.len().alias('n')).sort('n', descending=True).head(20)
    return [(int(r['origin_as']), int(r['n'])) for r in counts.iter_rows(named=True)]


def find_top_as_in_window(date_str, start_hhmm, end_hhmm):
    """Find top 5 origin ASes in a specific time window."""
    date_compact = date_str.replace('-', '')
    files = sorted(PARQ_DIR.glob(f'updates.{date_compact}.*.parquet'))
    if not files:
        return None
    # Filter files in window
    in_window = []
    for f in files:
        name = f.stem  # updates.YYYYMMDD.HHMM
        parts = name.split('.')
        if len(parts) >= 3:
            hhmm = parts[2]
            if start_hhmm <= hhmm <= end_hhmm:
                in_window.append(f)
    if not in_window:
        return None
    parts = []
    for f in in_window:
        try:
            df = pl.read_parquet(f, columns=['as_path', 'announce'])
        except:
            continue
        if len(df) == 0:
            continue
        parts.append(df)
    if not parts:
        return None
    df = pl.concat(parts)
    df = df.with_columns(
        pl.col('as_path').fill_null('').str.split(' ').list.last()
         .cast(pl.Int64, strict=False).alias('origin_as')
    )
    df = df.filter(pl.col('origin_as').is_not_null())
    counts = df.group_by('origin_as').agg(pl.len().alias('n')).sort('n', descending=True).head(10)
    return [(int(r['origin_as']), int(r['n'])) for r in counts.iter_rows(named=True)]


def detect_event_window(feat_csv):
    """From features CSV, detect the spike window (5min buckets with high announce count)."""
    df = pl.read_csv(feat_csv)
    if len(df) == 0:
        return None, None, None
    # Find max announce bucket
    max_idx = df['announcement_count'].arg_max()
    max_ts = df['timestamp'][max_idx]
    max_val = df['announcement_count'][max_idx]
    # baseline = mean of first 24 buckets
    baseline = df.head(min(24, len(df)))['announcement_count'].mean()
    if baseline == 0:
        baseline = 1
    spike = max_val / baseline
    # Find sustained spike: contiguous buckets where announce > 5x baseline
    threshold = max(baseline * 3, 50)
    spike_buckets = df.filter(pl.col('announcement_count') > threshold)
    if len(spike_buckets) == 0:
        return None, None, None
    start = spike_buckets['timestamp'].min()
    end = spike_buckets['timestamp'].max()
    return start, end, (max_val, baseline, spike)


def main():
    files = sorted(FEAT_DIR.glob('*.csv'))
    results = {}
    for f in files:
        name = f.stem.replace('_timeseries', '')
        try:
            start, end, stats = detect_event_window(f)
        except Exception as e:
            print(f'{name}: error {e}')
            continue
        if start is None:
            print(f'{name}: no spike detected')
            continue
        # Parse start date
        if isinstance(start, str):
            start_dt = parse_event_time(start)
        else:
            start_dt = start
    date_str = start_dt.strftime('%Y-%m-%d')
    # Find top AS in window - expand to ±6h
    s_hhmm = (start_dt - timedelta(hours=6)).strftime('%H%M')
    e_hhmm = (start_dt + timedelta(hours=6)).strftime('%H%M')
    top_as = find_top_as_in_window(date_str, s_hhmm, e_hhmm)
    if not top_as:
        # Try full day
        top_as = find_top_as_in_window(date_str, '0000', '2355')
        results[name] = {
            'date': date_str,
            'window_start': start_dt.isoformat(),
            'max_val': stats[0],
            'baseline': stats[1],
            'spike_ratio': round(stats[2], 1),
            'top_as_in_window': top_as[:5] if top_as else [],
        }
        print(f'{name}: date={date_str} start={start} spike={stats[2]:.0f}x (max={stats[0]} base={stats[1]:.0f}) top_as={top_as[:3] if top_as else "?"}')

    with open(OUT_FILE, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f'\nSaved to {OUT_FILE}')


if __name__ == '__main__':
    main()
