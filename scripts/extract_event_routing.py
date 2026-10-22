#!/usr/bin/env python3
"""
Per-event routing feature extractor using parquet files.
- One event at a time (low memory)
- Saves per-event parquet + summary JSON
"""
import os
import sys
import json
import gc
import csv
import time
import polars as pl
import re
from pathlib import Path
from datetime import datetime, timedelta

PARQ_DIR = Path('data/updates_rrc00/parquet')
OUT_DIR = Path('data/groundtruth_v18')
OUT_DIR.mkdir(parents=True, exist_ok=True)

GT_CSV = 'data_check/ground_truth_collection/final_balanced_dataset_v17_30.csv'


def _parse_as(s):
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if not s or s == 'AS0':
        return None
    if s.upper().startswith('AS'):
        s = s[2:]
    try:
        return int(s)
    except ValueError:
        return None


def _bucket(ts_col):
    return ts_col.dt.truncate('5m').alias('bucket')


def extract_event(event):
    """Extract routing features for one event in its window."""
    date = event['date']
    start_utc = event['start_time_utc']
    end_utc = event['end_time_utc']
    victim_as = _parse_as(event.get('victim_as'))
    attacker_as = _parse_as(event.get('attacker_as'))
    leak_as = _parse_as(event.get('leak_as'))

    targets = [x for x in (victim_as, attacker_as, leak_as) if x is not None]
    if not targets:
        return None

    # 1) determine window extended ±1h for baseline
    try:
        start_dt = datetime.fromisoformat(start_utc.replace('Z', '+00:00')).replace(tzinfo=None)
        end_dt = datetime.fromisoformat(end_utc.replace('Z', '+00:00')).replace(tzinfo=None)
    except Exception as e:
        print(f'  ! bad timestamps for {event["event_id"]}: {e}')
        return None
    if end_dt <= start_dt:
        return None

    # 2) load parquet files covering window
    # Window may span multiple days. Determine date list.
    days = []
    cur = start_dt.date()
    end_day = end_dt.date()
    while cur <= end_day:
        days.append(cur.strftime('%Y%m%d'))
        cur = cur + timedelta(days=1)
    files = []
    for d in days:
        files.extend(sorted(PARQ_DIR.glob(f'updates.{d}.*.parquet')))
    if not files:
        for d in days:
            files.extend(sorted(PARQ_DIR.glob(f'updates.{d[:4]}-{d[4:6]}-{d[6:8]}.*.parquet')))
    if not files:
        print(f'  ! no parquets for {date}')
        return None

    # 3) Read relevant columns only
    target_set = list(targets)
    parts = []
    for f in files:
        try:
            df = pl.read_parquet(f, columns=['type', 'announce', 'prefix', 'as_path', 'origin', 'timestamp', 'ts'])
        except Exception:
            continue
        # Build ts: prefer ts (datetime), fall back to timestamp (str)
        if df['ts'].null_count() == len(df) or df['ts'].dtype == pl.Utf8:
            # Build from string
            df = df.with_columns(
                pl.col('timestamp').str.to_datetime('%Y-%m-%d %H:%M:%S', strict=False).alias('ts')
            )
        # Filter to window first
        df = df.filter((pl.col('ts') >= start_dt) & (pl.col('ts') <= end_dt))
        if len(df) == 0:
            continue
        # origin AS = last token in as_path
        df = df.with_columns(
            pl.col('as_path').fill_null('').str.split(' ').list.last()
             .cast(pl.Int64, strict=False).alias('origin_as')
        )
        # For outages: also include if any of the target ASes appear in as_path
        # Build "in_path" filter using regex on as_path string
        pat = '|'.join(rf'\b{t}\b' for t in target_set)
        df = df.filter(pl.col('origin_as').is_in(target_set) | pl.col('as_path').str.contains(pat))
        if len(df) == 0:
            continue
        # 5-min bucket
        df = df.with_columns(pl.col('ts').dt.truncate('5m').alias('bucket'))
        parts.append(df)
        del df
    if not parts:
        return None
    df = pl.concat(parts)
    del parts
    gc.collect()
    # 8) aggregate per bucket
    df = df.with_columns(pl.col('prefix').alias('prefix_str'))
    g = df.group_by('bucket').agg([
        (pl.col('announce') == 'A').sum().alias('announcement_count'),
        (pl.col('announce') == 'W').sum().alias('withdrawal_count'),
        pl.col('prefix_str').n_unique().alias('unique_prefix_count'),
        pl.col('origin_as').n_unique().alias('unique_origin_count'),
        pl.len().alias('total_updates'),
    ]).sort('bucket')

    # 9) per-victim / per-attacker counts
    by_target = {}
    for tgt in target_set:
        sub = df.filter(pl.col('origin_as') == tgt).group_by('bucket').agg([
            (pl.col('announce') == 'A').sum().alias('A'),
            (pl.col('announce') == 'W').sum().alias('W'),
            pl.col('prefix_str').n_unique().alias('unique_prefix'),
        ]).sort('bucket')
        by_target[str(tgt)] = {
            'total_announce': int(sub['A'].sum()),
            'total_withdraw': int(sub['W'].sum()),
            'peak_announce_per_5m': int(sub['A'].max()) if len(sub) else 0,
            'peak_withdraw_per_5m': int(sub['W'].max()) if len(sub) else 0,
            'n_active_buckets': int((sub['A'] + sub['W'] > 0).sum()),
        }

    summary = {
        'event_id': event['event_id'],
        'date': date,
        'name': event['name'],
        'ground_truth_cause': event['ground_truth_cause_label'],
        'ground_truth_subtype': event['ground_truth_root_cause_subtype'],
        'victim_as': victim_as,
        'attacker_as': attacker_as,
        'leak_as': leak_as,
        'window_start_utc': start_utc,
        'window_end_utc': end_utc,
        'window_start_naive': start_dt.isoformat(),
        'window_end_naive': end_dt.isoformat(),
        'n_buckets': int(len(g)),
        'totals': {
            'announcement_count': int(g['announcement_count'].sum()),
            'withdrawal_count': int(g['withdrawal_count'].sum()),
            'unique_prefix_count': int(g['unique_prefix_count'].max()),
            'unique_origin_count': int(g['unique_origin_count'].max()),
        },
        'peak_announce_per_5m': int(g['announcement_count'].max()) if len(g) else 0,
        'peak_withdraw_per_5m': int(g['withdrawal_count'].max()) if len(g) else 0,
        'by_target': by_target,
    }
    return summary, g


def main():
    with open(GT_CSV) as f:
        events = list(csv.DictReader(f))
    print(f'Processing {len(events)} events...\n')

    results = []
    for i, e in enumerate(events, 1):
        t0 = time.time()
        eid = e['event_id']
        try:
            r = extract_event(e)
        except Exception as ex:
            print(f'[{i:2d}] {eid:<55} ERROR: {ex}')
            results.append({'event_id': eid, 'error': str(ex)})
            continue
        if r is None:
            print(f'[{i:2d}] {eid:<55} no data')
            results.append({'event_id': eid, 'error': 'no data'})
            continue
        summary, df = r
        # Save per-event features
        out_parq = OUT_DIR / f'{eid}_routing_features.parquet'
        df.write_parquet(out_parq)
        # Append to results
        results.append(summary)
        print(f'[{i:2d}] {eid:<55} A={summary["totals"]["announcement_count"]:>5} W={summary["totals"]["withdrawal_count"]:>5} peakA={summary["peak_announce_per_5m"]:>3} peakW={summary["peak_withdraw_per_5m"]:>3} ({time.time()-t0:.1f}s)')

        # Free memory
        del df
        gc.collect()

    # Save summary
    with open(OUT_DIR / 'summary.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f'\nSummary saved to {OUT_DIR / "summary.json"}')


if __name__ == '__main__':
    main()
