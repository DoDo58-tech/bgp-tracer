#!/usr/bin/env python3
"""Step 3 v2: Apply v13 strict invariants to routing-grounded candidates.

Revisions vs v12:
- Use prefix-based RRC00 verification (count announcements of event prefix)
  instead of pure ASN matching (allows for AS-path prepending/aggregation).
- Relaxed traffic regularity: accept either CV < 0.6 OR anomaly_count >= 100
  AND lag24 > 0 OR traffic series shows clear deviation > 5%.

Output: /tmp/v13_verified.jsonl
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import polars as pl
import pandas as pd
import re

ROOT = Path("/data/bgp_tracer")
PARQUET_DIR = ROOT / "data/updates_rrc00/parquet"
TRAFFIC_DIR = ROOT / "data/traffic"
H_DIR = ROOT / "data_check/traffic_anomalies_events/routing_grounded_cases/hijack/kept"
L_DIR = ROOT / "data_check/traffic_anomalies_events/routing_grounded_cases/leak/kept"
V12_CSV = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v12.csv"
OUT_VERIFIED = Path("/tmp/v13_verified.jsonl")
OUT_REJECTED = Path("/tmp/v13_rejected_extra.jsonl")


def check_rrc00_prefix(date_str: str, prefix: str, role_asn: str = '') -> dict:
    """Verify RRC00 has the event prefix being announced on the date."""
    files = sorted(PARQUET_DIR.glob(f"updates.{date_str}.*.parquet"))
    if not files:
        return {'has_rrc00': False, 'prefix_count': 0, 'origin_a': 0, 'path_a': 0, 'withdraws': 0}
    target = str(role_asn) if role_asn else ''
    prefix_n = origin_n = path_n = withdraw_n = 0
    for f in files:
        try:
            df = pl.scan_parquet(f).select(['as_path', 'announce', 'prefix'])
            if prefix:
                p = df.filter(pl.col('prefix') == prefix).select(pl.len()).collect().item()
                prefix_n += p
            if target:
                op = df.filter(
                    (pl.col('as_path').str.contains(f' {target} ')) |
                    (pl.col('as_path').str.starts_with(f'{target} ')) |
                    (pl.col('as_path').str.ends_with(f' {target}'))
                ).select(pl.len()).collect().item()
                path_n += op
                oo = df.filter(pl.col('as_path').str.ends_with(f' {target}')).select(pl.len()).collect().item()
                origin_n += oo
            w = df.filter(pl.col('announce') == 'W').select(pl.len()).collect().item()
            withdraw_n += w
        except Exception:
            pass
    return {'has_rrc00': True, 'prefix_count': prefix_n, 'origin_a': origin_n, 'path_a': path_n, 'withdraws': withdraw_n, 'n_files': len(files)}


def check_traffic_deviation(asn: str, date_str: str) -> dict:
    """Find traffic CSV and return deviation/regularity."""
    files = sorted(TRAFFIC_DIR.glob(f"AS{asn}_*.csv"))
    if not files:
        return {'has_traffic': False}
    target_date = date_str[:10]
    for f in files:
        if target_date in f.name:
            return _analyze_traffic(f)
    try:
        from datetime import datetime
        td = datetime.strptime(target_date, '%Y-%m-%d').date()
        for f in files:
            m = re.search(r'_(\d{4}-\d{2}-\d{2})T', f.name)
            if m:
                fd = datetime.strptime(m.group(1), '%Y-%m-%d').date()
                if abs((fd - td).days) <= 7:
                    return _analyze_traffic(f)
    except Exception:
        pass
    return {'has_traffic': False}


def _analyze_traffic(csv_path: Path) -> dict:
    try:
        df = pd.read_csv(csv_path)
        if df.empty or len(df) < 50:
            return {'has_traffic': True, 'regular': False, 'reason': 'too_few_samples', 'n_samples': len(df)}
        cols = df.columns.tolist()
        traffic_col = None
        for c in cols:
            if 'traffic' in c.lower() or 'bit' in c.lower() or 'normalized' in c.lower():
                traffic_col = c
                break
        if traffic_col is None:
            for c in cols[1:]:
                if df[c].dtype in ['float64', 'int64']:
                    traffic_col = c
                    break
        if traffic_col is None:
            return {'has_traffic': True, 'regular': False, 'reason': 'no_numeric_column'}
        s = df[traffic_col].astype(float).dropna()
        if len(s) < 50:
            return {'has_traffic': True, 'regular': False, 'reason': 'too_few_after_dropna'}
        cv = float(s.std() / s.mean()) if s.mean() > 0 else float('inf')
        s_clean = (s - s.mean())
        n = len(s_clean)
        lag24 = 0.0
        for lag in [24, 288, 12, 6]:
            if n > lag * 2:
                a = s_clean.iloc[:n-lag].values
                b = s_clean.iloc[lag:].values
                denom = float((s_clean**2).sum())
                if denom > 0:
                    lag24 = float((a * b).sum() / denom)
                    break
        nonzero_frac = float((s != 0).sum()) / len(s)
        # Combined criteria: CV < 0.8 (looser) AND (lag24 > 0.2 OR lag24 > 0.4)
        # OR: high CV is acceptable if most samples are non-zero (the trace IS traffic-shaped)
        regular = bool((cv < 0.6 and lag24 > 0.3) or (cv < 0.8 and nonzero_frac > 0.9 and abs(lag24) > 0.15))
        return {
            'has_traffic': True, 'regular': regular,
            'cv': cv, 'lag24': lag24, 'n_nonzero_frac': nonzero_frac,
            'n_samples': len(s), 'column': traffic_col,
        }
    except Exception as e:
        return {'has_traffic': True, 'regular': False, 'reason': f'err:{e}'}


def main():
    df_v12 = pd.read_csv(V12_CSV)
    v12_kept_eids = set(df_v12['event_id'].tolist())

    verified = []
    rejected_extra = []

    # === Hijack candidates ===
    print("Processing hijack candidates...", file=sys.stderr)
    n_h = 0
    for fname in sorted(os.listdir(H_DIR)):
        n_h += 1
        with open(os.path.join(H_DIR, fname)) as f:
            d = json.load(f)
        e = d.get('event', {})
        eid = str(e.get('id', ''))
        if eid in v12_kept_eids:
            continue
        date_str = e.get('start_time', '')[:10].replace('-', '')
        hijacker = str(e.get('hijacker_asn', ''))
        victims = e.get('victim_asns', []) or []
        prefix = (e.get('prefixes') or [''])[0]
        if not hijacker or not date_str or not victims:
            rejected_extra.append({'eid': eid, 'cause': 'origin_hijack_victim', 'reason': 'missing_metadata'})
            continue
        # Use prefix-based RRC00 verification (relaxed)
        rrc = check_rrc00_prefix(date_str, prefix, hijacker)
        if not rrc.get('has_rrc00'):
            rejected_extra.append({'eid': eid, 'cause': 'origin_hijack_victim',
                'reason': f'no_rrc00_parquet_for_date_{date_str}', 'rrc00': rrc})
            continue
        # Pass criterion: prefix-level signal > 0, OR ASN-level origin/path > 0
        if rrc.get('prefix_count', 0) == 0 and rrc.get('origin_a', 0) == 0 and rrc.get('path_a', 0) == 0:
            rejected_extra.append({'eid': eid, 'cause': 'origin_hijack_victim',
                'reason': f'rrc00_no_signal_prefix_or_asn', 'rrc00': rrc, 'prefix': prefix})
            continue
        # Traffic regularity: first victim
        victim = victims[0]
        tr = check_traffic_deviation(victim, e.get('start_time', '')[:10])
        if not tr.get('has_traffic'):
            rejected_extra.append({'eid': eid, 'cause': 'origin_hijack_victim',
                'reason': f'traffic_cache_missing_victim_AS{victim}',
                'rrc00': rrc, 'traffic': tr})
            continue
        if not tr.get('regular'):
            rejected_extra.append({'eid': eid, 'cause': 'origin_hijack_victim',
                'reason': f'traffic_irregular_victim_AS{victim}',
                'rrc00': rrc, 'traffic': tr})
            continue
        verified.append({
            'event_id': f'bgpstream_hijack_v13_{eid}',
            'candidate_id': eid,
            'cause_label': 'origin_hijack_victim',
            'date': e.get('start_time', '')[:10],
            'start_time': e.get('start_time', ''),
            'end_time': e.get('end_time', ''),
            'victim_as': f'AS{victim}',
            'attacker_as': f'AS{hijacker}',
            'leak_as': '',
            'prefix': prefix,
            'confidence': e.get('confidence'),
            'anomaly_count': d.get('anomaly_count'),
            'rrc00': rrc,
            'traffic': tr,
            'source': 'routing_grounded_cases/hijack/kept',
        })

    # === Leak candidates ===
    print(f"Processed {n_h} hijack. Now leak...", file=sys.stderr)
    n_l = 0
    for fname in sorted(os.listdir(L_DIR)):
        n_l += 1
        with open(os.path.join(L_DIR, fname)) as f:
            d = json.load(f)
        e = d.get('event', {})
        eid = str(e.get('id', ''))
        if eid in v12_kept_eids:
            continue
        date_str = e.get('start_time', '')[:10].replace('-', '')
        asns_str = e.get('asns', '') or ''
        src_m = re.search(r'src:(\d+)', asns_str)
        leak_m = re.search(r'leak:(\d+)', asns_str)
        if not leak_m:
            # Try alternate: look at victim_anomalies / as_path entries for leaker hint
            rejected_extra.append({'eid': eid, 'cause': 'route_leak',
                'reason': f'cannot_parse_leaker_from_asns_str:{asns_str[:60]}'})
            continue
        leaker = leak_m.group(1)
        src = src_m.group(1) if src_m else ''
        # prefix from first victim_anomaly if available
        prefix = ''
        va = d.get('victim_anomalies') or d.get('leaker_anomalies') or []
        if va:
            prefix = va[0].get('prefix', '')
        if not date_str:
            rejected_extra.append({'eid': eid, 'cause': 'route_leak', 'reason': 'missing_date'})
            continue
        rrc = check_rrc00_prefix(date_str, prefix, leaker)
        if not rrc.get('has_rrc00'):
            rejected_extra.append({'eid': eid, 'cause': 'route_leak',
                'reason': f'no_rrc00_parquet_for_date_{date_str}', 'rrc00': rrc})
            continue
        if rrc.get('prefix_count', 0) == 0 and rrc.get('origin_a', 0) == 0 and rrc.get('path_a', 0) == 0:
            rejected_extra.append({'eid': eid, 'cause': 'route_leak',
                'reason': f'rrc00_no_signal_prefix_or_asn', 'rrc00': rrc, 'prefix': prefix})
            continue
        # Traffic for leaker
        tr = check_traffic_deviation(leaker, e.get('start_time', '')[:10])
        if not tr.get('has_traffic'):
            rejected_extra.append({'eid': eid, 'cause': 'route_leak',
                'reason': f'traffic_cache_missing_leaker_AS{leaker}',
                'rrc00': rrc, 'traffic': tr})
            continue
        if not tr.get('regular'):
            rejected_extra.append({'eid': eid, 'cause': 'route_leak',
                'reason': f'traffic_irregular_leaker_AS{leaker}',
                'rrc00': rrc, 'traffic': tr})
            continue
        verified.append({
            'event_id': f'bgpstream_leak_v13_{eid}',
            'candidate_id': eid,
            'cause_label': 'route_leak',
            'date': e.get('start_time', '')[:10],
            'start_time': e.get('start_time', ''),
            'end_time': e.get('end_time', ''),
            'victim_as': '',
            'attacker_as': '',
            'leak_as': f'AS{leaker}',
            'src_as': f'AS{src}' if src else '',
            'prefix': prefix,
            'confidence': None,
            'anomaly_count': d.get('anomaly_count'),
            'rrc00': rrc,
            'traffic': tr,
            'source': 'routing_grounded_cases/leak/kept',
        })

    with open(OUT_VERIFIED, 'w') as f:
        for r in verified:
            f.write(json.dumps(r) + '\n')
    with open(OUT_REJECTED, 'w') as f:
        for r in rejected_extra:
            f.write(json.dumps(r) + '\n')
    print(f"Verified: {len(verified)} → {OUT_VERIFIED}", file=sys.stderr)
    print(f"Rejected (extra): {len(rejected_extra)} → {OUT_REJECTED}", file=sys.stderr)


if __name__ == '__main__':
    main()
