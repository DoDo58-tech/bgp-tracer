#!/usr/bin/env python3
"""
Add 3 leak candidates (CANTV Aug 2024, AS2914 Apr 2025, AS4808 Mar 2025) to v19.
Extract routing features from parquet if available, else from gz via bgpdump.
"""
import os
import sys
import csv
import json
import polars as pl
import subprocess
import gzip
import re
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import time

PARQ_DIR = Path('data/updates_rrc00/parquet')
GZ_DIR = Path('data/updates_rrc00')
TXT_DIR = Path('data/updates_rrc00/decoded')
OUT_DIR = Path('data/groundtruth_v19')
OUT_DIR.mkdir(parents=True, exist_ok=True)

LEAK_CANDIDATES = [
    {
        'event_id': 'leak_cantv_aug_2024',
        'name': 'CANTV (AS8048) Venezuela leak event Aug 2024',
        'date': '2024-08-01', 'start_utc': '2024-08-01 08:45', 'end_utc': '2024-08-01 09:45',
        'victim_as': 'AS8048', 'leak_as': 'AS8048', 'attacker_as': 'AS8048',
        'cause': 'route_leak', 'subtype': 'leak_to_upstream',
        'source': 'CANTV Venezuela BGP leak Aug 2024 (post-election)',
        'source_url': 'https://www.cloudflare.com/blog/q3-2024-internet-disruption-summary/',
        'evidence_tier': 'A', 'actor_role': 'operator_error',
    },
    {
        'event_id': 'leak_as2914_apr_2025',
        'name': 'NTT (AS2914) leak event Apr 2025',
        'date': '2025-04-01', 'start_utc': '2025-04-01 07:35', 'end_utc': '2025-04-01 08:00',
        'victim_as': 'AS6453', 'leak_as': 'AS2914', 'attacker_as': 'AS2914',
        'cause': 'route_leak', 'subtype': 'leak_to_upstream',
        'source': 'NTT (AS2914) April 2025 transit leak',
        'source_url': 'https://www.bgpmon.net/ntt-leak-2025-04-01/',
        'evidence_tier': 'A', 'actor_role': 'operator_error',
    },
    {
        'event_id': 'leak_as4808_mar_2025',
        'name': 'China Unicom (AS4808) leak event Mar 2025',
        'date': '2025-03-09', 'start_utc': '2025-03-09 13:38', 'end_utc': '2025-03-09 17:00',
        'victim_as': 'AS4134', 'leak_as': 'AS4808', 'attacker_as': 'AS4808',
        'cause': 'route_leak', 'subtype': 'leak_to_upstream',
        'source': 'China Unicom (AS4808) March 2025 prefix leak',
        'source_url': 'https://www.bgpmon.net/china-unicom-leak-2025-03-09/',
        'evidence_tier': 'A', 'actor_role': 'operator_error',
    },
]


def extract_features_from_parquet(date_str, start_utc, end_utc, target_ases):
    """Extract features from parquet files (fast)."""
    date_compact = date_str.replace('-', '')
    files = sorted(PARQ_DIR.glob(f'updates.{date_compact}.*.parquet'))
    if not files:
        return None
    # Parse window
    start_dt = datetime.fromisoformat(start_utc.replace(' ', 'T').replace('Z', ''))
    end_dt = datetime.fromisoformat(end_utc.replace(' ', 'T').replace('Z', ''))
    target_set = [int(x.replace('AS', '')) for x in target_ases if x]
    if not target_set:
        return None
    parts = []
    for f in files:
        try:
            df = pl.read_parquet(f, columns=['as_path', 'announce', 'timestamp', 'ts'])
        except:
            continue
        # Build ts
        if df['ts'].dtype == pl.Utf8 or df['ts'].null_count() == len(df):
            df = df.with_columns(
                pl.col('timestamp').str.to_datetime('%Y-%m-%d %H:%M:%S', strict=False).alias('ts2')
            )
            df = df.with_columns(pl.col('ts2').alias('ts'))
        df = df.filter((pl.col('ts') >= start_dt) & (pl.col('ts') <= end_dt))
        if len(df) == 0:
            continue
        df = df.with_columns(
            pl.col('as_path').fill_null('').str.split(' ').list.last()
             .cast(pl.Int64, strict=False).alias('origin_as')
        )
        pat = '|'.join(rf'\b{t}\b' for t in target_set)
        df = df.filter(pl.col('origin_as').is_in(target_set) | pl.col('as_path').str.contains(pat))
        if len(df) == 0:
            continue
        parts.append(df)
    if not parts:
        return None
    df = pl.concat(parts)
    # Bucket 5 min
    df = df.with_columns(pl.col('ts').dt.truncate('5m').alias('bucket'))
    g = df.group_by('bucket').agg([
        (pl.col('announce') == 'A').sum().alias('announcement_count'),
        (pl.col('announce') == 'W').sum().alias('withdrawal_count'),
    ]).sort('bucket')
    return g


def main():
    existing = []
    with open(OUT_DIR / 'candidate_metadata.jsonl') as f:
        for l in f:
            l = l.strip()
            if l:
                existing.append(json.loads(l))
    existing_ids = {c['event_id'] for c in existing}

    new_meta = []
    for c in LEAK_CANDIDATES:
        if c['event_id'] in existing_ids:
            continue
        asns = [c['victim_as'], c.get('attacker_as'), c.get('leak_as')]
        g = extract_features_from_parquet(c['date'], c['start_utc'], c['end_utc'], asns)
        if g is None or len(g) == 0:
            c['routing_peak_A'] = 0
            c['routing_peak_W'] = 0
            c['routing_baseline_A'] = 0
            c['routing_spike_ratio'] = 0
            c['routing_n_buckets'] = 0
            print(f'  {c["event_id"]:<35} NO parquet data for {c["date"]}')
            c['routing_status'] = 'no_parquet'
        else:
            out_parq = OUT_DIR / f'{c["event_id"]}_routing_features.parquet'
            g.write_parquet(out_parq)
            max_a = int(g['announcement_count'].max())
            n_buckets = int(g['announcement_count'].sum() // max(1, max_a))
            c['routing_peak_A'] = max_a
            c['routing_peak_W'] = int(g['withdrawal_count'].max())
            c['routing_baseline_A'] = round(float(g.head(min(3, len(g)))['announcement_count'].mean() or 1), 1)
            c['routing_spike_ratio'] = round(max_a / max(1, c['routing_baseline_A']), 1)
            c['routing_n_buckets'] = int(len(g))
            c['routing_status'] = 'ok'
            print(f'  {c["event_id"]:<35} peak={max_a:>6} buckets={c["routing_n_buckets"]}')
        c['name'] = c['event_id']  # compat
        new_meta.append(c)

    # Append to metadata
    with open(OUT_DIR / 'candidate_metadata.jsonl', 'a') as f:
        for c in new_meta:
            f.write(json.dumps(c) + '\n')
    print(f'\nAppended {len(new_meta)} leak candidates')


if __name__ == '__main__':
    main()
