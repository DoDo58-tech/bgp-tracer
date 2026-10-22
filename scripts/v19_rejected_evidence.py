#!/usr/bin/env python3
"""
Extract routing features and traffic evidence for the 5 v17 rejected events.
Saves them to data/groundtruth_v19/rejected/ for transparency.
"""
import os
import sys
import json
import csv
import polars as pl
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
import glob

PARQ_DIR = Path('data/updates_rrc00/parquet')
GZ_DIR = Path('data/updates_rrc00')
TXT_DIR = Path('data/updates_rrc00/decoded')
OUT_DIR = Path('data/groundtruth_v19/rejected')
OUT_DIR.mkdir(parents=True, exist_ok=True)

REJ_CSV = 'data_check/ground_truth_collection/final_balanced_dataset_v17_rejected.csv'


def _parse_as(s):
    if not s:
        return None
    s = s.strip()
    if not s or s == 'AS0':
        return None
    if s.upper().startswith('AS'):
        s = s[2:]
    try:
        return int(s)
    except:
        return None


def extract_from_parquet(date_str, start_utc, end_utc, target_ases):
    date_compact = date_str.replace('-', '')
    files = sorted(PARQ_DIR.glob(f'updates.{date_compact}.*.parquet'))
    if not files:
        return None
    start_dt = datetime.fromisoformat(start_utc.replace(' ', 'T').replace('Z', ''))
    end_dt = datetime.fromisoformat(end_utc.replace(' ', 'T').replace('Z', ''))
    target_set = [t for t in target_ases if t is not None]
    if not target_set:
        return None
    parts = []
    for f in files:
        try:
            df = pl.read_parquet(f, columns=['as_path', 'announce', 'timestamp', 'ts', 'prefix'])
        except:
            continue
        if df['ts'].dtype == pl.Utf8 or df['ts'].null_count() == len(df):
            df = df.with_columns(
                pl.col('timestamp').str.to_datetime('%Y-%m-%d %H:%M:%S', strict=False).alias('ts')
            )
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
    df = df.with_columns(pl.col('ts').dt.truncate('5m').alias('bucket'))
    g = df.group_by('bucket').agg([
        (pl.col('announce') == 'A').sum().alias('announcement_count'),
        (pl.col('announce') == 'W').sum().alias('withdrawal_count'),
        pl.col('prefix').n_unique().alias('unique_prefix_count'),
    ]).sort('bucket')
    return g


def main():
    rej = list(csv.DictReader(open(REJ_CSV)))
    print(f'Processing {len(rej)} rejected events...')
    results = []
    for e in rej:
        eid = e['event_id']
        date = e['date']
        s = e['start_time_utc']
        en = e['end_time_utc']
        targets = [_parse_as(e.get(k)) for k in ('victim_as', 'attacker_as', 'leak_as')]
        g = extract_from_parquet(date, s, en, targets)
        rec = {
            'event_id': eid,
            'cause': e['ground_truth_cause_label'],
            'rejection_reason': e.get('rejection_reason', ''),
            'public_source': e.get('ground_truth_source', ''),
            'source_url': e.get('source_url', ''),
            'routing_status': 'no_data',
            'routing_total_A': 0,
            'routing_peak_A': 0,
        }
        if g is not None and len(g) > 0:
            out = OUT_DIR / f'{eid}_routing_features.parquet'
            g.write_parquet(out)
            rec['routing_status'] = 'ok'
            rec['routing_total_A'] = int(g['announcement_count'].sum())
            rec['routing_peak_A'] = int(g['announcement_count'].max())
            rec['routing_parquet'] = str(out)
        results.append(rec)
        print(f'  {eid:<35} {rec["routing_status"]:<10} peak={rec["routing_peak_A"]} reason={rec["rejection_reason"][:50]}')

    with open(OUT_DIR / 'rejected_with_evidence.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nSaved to {OUT_DIR}/rejected_with_evidence.json')


if __name__ == '__main__':
    main()
