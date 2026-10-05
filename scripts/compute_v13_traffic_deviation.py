#!/usr/bin/env python3
"""Compute traffic_pct_deviation for v13 events using cached CSVs.

For each v13 event, compute the actual deviation % around the event window
and update the v13 CSV.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from datetime import datetime, timedelta
import re
import pandas as pd
import numpy as np

ROOT = Path("/data/bgp_tracer")
GT_DIR = ROOT / "data_check/ground_truth_collection"
V13_CSV = GT_DIR / "final_balanced_dataset_v13.csv"
OUT_V13 = GT_DIR / "final_balanced_dataset_v13.csv"


def compute_deviation_from_csv(csv_path: Path, event_date: str) -> dict:
    """Compute traffic deviation around event_date from CF Radar CSV."""
    try:
        df = pd.read_csv(csv_path)
        if df.empty:
            return {'pct': None, 'cv': None, 'lag24': None, 'reason': 'empty'}
        # numeric column
        traffic_col = None
        for c in df.columns:
            if df[c].dtype in ['float64', 'int64'] and c.lower() != 'timestamp':
                traffic_col = c
                break
        if traffic_col is None:
            for c in df.columns[1:]:
                if df[c].dtype in ['float64', 'int64']:
                    traffic_col = c
                    break
        if traffic_col is None:
            return {'pct': None, 'reason': 'no_column'}
        s = df[traffic_col].astype(float)
        # Parse timestamps
        ts = pd.to_datetime(df['timestamp'], format='mixed', utc=True, errors='coerce')
        if ts.isna().any():
            # Skip rows with bad timestamps
            mask = ts.notna()
            ts = ts[mask]
            s = s[mask]
        event_dt = pd.to_datetime(event_date, utc=True)
        # Window: ±3 hours around event (assume event mid-day)
        # Better: use full day window
        event_day_start = event_dt.normalize()
        event_day_end = event_day_start + pd.Timedelta(days=1)
        # event window mask
        mask_event = (ts >= event_day_start) & (ts < event_day_end)
        mask_baseline = (ts < event_day_start) | (ts >= event_day_end + pd.Timedelta(days=1))
        if mask_event.sum() < 5:
            # event window has too few samples; use ±2h around mid-day
            mid_day = event_day_start + pd.Timedelta(hours=12)
            mask_event = (ts >= mid_day - pd.Timedelta(hours=3)) & (ts < mid_day + pd.Timedelta(hours=3))
            mask_baseline = ~mask_event
        if mask_event.sum() < 5:
            return {'pct': None, 'reason': 'event_window_too_small'}
        # Compute deviation
        event_mean = float(s[mask_event].mean())
        baseline_mean = float(s[mask_baseline].mean())
        if baseline_mean == 0:
            return {'pct': None, 'reason': 'baseline_zero'}
        pct = ((event_mean - baseline_mean) / baseline_mean) * 100.0
        # Full series regularity
        s_clean = (s - s.mean())
        n = len(s_clean)
        cv = float(s.std() / s.mean()) if s.mean() > 0 else float('inf')
        lag24 = 0.0
        for lag in [96, 288, 48, 24]:
            if n > lag * 2:
                a = s_clean.iloc[:n-lag].values
                b = s_clean.iloc[lag:].values
                denom = float((s_clean**2).sum())
                if denom > 0:
                    lag24 = float((a * b).sum() / denom)
                    break
        return {'pct': round(pct, 2), 'cv': round(cv, 3), 'lag24': round(lag24, 3), 'n_samples': n}
    except Exception as e:
        return {'pct': None, 'reason': f'err:{e}'}


def main():
    rows = list(csv.DictReader(open(V13_CSV)))
    fields = list(rows[0].keys())
    updated = 0
    for r in rows:
        eid = r['event_id']
        cache_path = r.get('project_cache_path', '')
        if 'v13' not in eid or not cache_path:
            continue
        p = Path(cache_path)
        if not p.exists():
            print(f"WARN: missing cache for {eid}: {cache_path}")
            continue
        result = compute_deviation_from_csv(p, r['date'])
        if result.get('pct') is not None:
            r['traffic_pct_deviation_pct'] = str(result['pct'])
            r['notes'] = f"v13: prefix={r.get('victim_as','')}/{r.get('attacker_as','')}/{r.get('leak_as','')} | deviation={result['pct']}% (cv={result.get('cv')}, lag24={result.get('lag24')}, n={result.get('n_samples')})"
            updated += 1
            print(f"  {eid:35s} {r['date']} deviation={result['pct']:+.2f}%  cv={result.get('cv')} lag24={result.get('lag24')}")
        else:
            print(f"  {eid:35s} {r['date']} NO DEV ({result.get('reason')})")

    # Write
    with open(OUT_V13, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, '') for k in fields})
    print(f"\nUpdated {updated} v13 events with traffic deviation.")


if __name__ == '__main__':
    main()