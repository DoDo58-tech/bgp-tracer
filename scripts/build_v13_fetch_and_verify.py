#!/usr/bin/env python3
"""Step 3 v3: Fetch CF Radar HTTP timeseries for candidate ASNs on event date.

Uses Cloudflare Radar API with dateStart/dateEnd syntax (NOT the 30-day sliding
window the chief_agent uses). Caches results to data/traffic/AS{asn}_*.csv.

Then re-runs strict invariant checks: prefix-level RRC00 + traffic regularity.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta
import polars as pl
import pandas as pd
import re
import requests

ROOT = Path("/data/bgp_tracer")
PARQUET_DIR = ROOT / "data/updates_rrc00/parquet"
TRAFFIC_DIR = ROOT / "data/traffic"
H_DIR = ROOT / "data_check/traffic_anomalies_events/routing_grounded_cases/hijack/kept"
L_DIR = ROOT / "data_check/traffic_anomalies_events/routing_grounded_cases/leak/kept"
V12_CSV = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v12.csv"
OUT_VERIFIED = Path("/tmp/v13_verified.jsonl")
OUT_REJECTED = Path("/tmp/v13_rejected_extra.jsonl")

# CF Radar config
token = open(ROOT / ".env").read().split("CLOUDFLARE_API_TOKEN=")[1].split("\n")[0].strip()
CF_URL = "https://api.cloudflare.com/client/v4/radar/http/timeseries"
HEADERS = {"Authorization": f"Bearer {token}"}


def fetch_cf_traffic(asn: str, start_iso: str, end_iso: str) -> dict:
    """Fetch CF Radar HTTP timeseries for ASN between two timestamps."""
    params = {
        "format": "json",
        "aggInterval": "15m",
        "dateStart": start_iso,
        "dateEnd": end_iso,
        "asn": int(asn),
        "name": "http_requests",
    }
    try:
        r = requests.get(CF_URL, params=params, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            return {'fetched': False, 'reason': f'http_{r.status_code}: {r.json().get("errors", "")[:200] if r.status_code != 200 else ""}'}
        data = r.json()
        if 'errors' in data and data['errors']:
            return {'fetched': False, 'reason': f'api_error: {data["errors"][0].get("message","?")[:200]}'}
        hr = data.get('result', {}).get('http_requests', {})
        if not hr or 'timestamps' not in hr or not hr.get('values'):
            return {'fetched': False, 'reason': 'empty_result'}
        ts = hr['timestamps']
        vals = hr['values']
        return {'fetched': True, 'timestamps': ts, 'values': vals, 'n_samples': len(ts)}
    except Exception as e:
        return {'fetched': False, 'reason': f'exception:{e}'}


def cache_traffic(asn: str, start_date: str, end_date: str, traffic: dict) -> Path | None:
    """Save traffic to CSV in TRAFFIC_DIR."""
    if not traffic.get('fetched'):
        return None
    ts = traffic['timestamps']
    vals = traffic['values']
    csv_path = TRAFFIC_DIR / f"AS{asn}_traffic_{start_date}T00:00:00Z_to_{end_date}T00:00:00Z.csv"
    df = pd.DataFrame({'timestamp': ts, 'normalized_traffic': vals})
    df.to_csv(csv_path, index=False)
    return csv_path


def check_rrc00_prefix(date_str: str, prefix: str, role_asn: str = '') -> dict:
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


def check_regularity_from_csv(csv_path: Path) -> dict:
    try:
        df = pd.read_csv(csv_path)
        if df.empty or len(df) < 50:
            return {'regular': False, 'reason': 'too_few_samples', 'n_samples': len(df)}
        # find numeric column
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
            return {'regular': False, 'reason': 'no_numeric_column'}
        s = df[traffic_col].astype(float).dropna()
        if len(s) < 50:
            return {'regular': False, 'reason': 'too_few_after_dropna'}
        cv = float(s.std() / s.mean()) if s.mean() > 0 else float('inf')
        s_clean = (s - s.mean())
        n = len(s_clean)
        lag24 = 0.0
        # 15-min buckets, so lag24 = 24*4 = 96 (6 hours), lag96=24h
        for lag in [96, 288, 48, 24, 12]:
            if n > lag * 2:
                a = s_clean.iloc[:n-lag].values
                b = s_clean.iloc[lag:].values
                denom = float((s_clean**2).sum())
                if denom > 0:
                    lag24 = float((a * b).sum() / denom)
                    break
        nonzero_frac = float((s != 0).sum()) / len(s)
        # Combined criteria
        regular = bool((cv < 0.6 and lag24 > 0.3) or (cv < 0.8 and nonzero_frac > 0.9 and abs(lag24) > 0.15))
        return {
            'regular': regular, 'cv': cv, 'lag24': lag24,
            'n_nonzero_frac': nonzero_frac, 'n_samples': len(s), 'column': traffic_col,
        }
    except Exception as e:
        return {'regular': False, 'reason': f'err:{e}'}


def main():
    df_v12 = pd.read_csv(V12_CSV)
    v12_kept_eids = set(df_v12['event_id'].tolist())

    # Step A: Collect all candidates with role ASNs
    candidates = []  # list of (eid, kind, role_asn, date, prefix, source_json)
    for fname in sorted(os.listdir(H_DIR)):
        with open(os.path.join(H_DIR, fname)) as f:
            d = json.load(f)
        e = d.get('event', {})
        eid = str(e.get('id', ''))
        if eid in v12_kept_eids:
            continue
        hijacker = str(e.get('hijacker_asn', ''))
        victims = e.get('victim_asns', []) or []
        prefix = (e.get('prefixes') or [''])[0]
        if not hijacker or not victims or not prefix:
            continue
        date_str = e.get('start_time', '')[:10]
        candidates.append({
            'kind': 'origin_hijack_victim', 'eid': eid, 'fname': fname,
            'role_asn_for_traffic': victims[0],
            'role_asn_for_rrc00': hijacker,
            'date': date_str, 'prefix': prefix,
            'source': 'hijack'
        })
    for fname in sorted(os.listdir(L_DIR)):
        with open(os.path.join(L_DIR, fname)) as f:
            d = json.load(f)
        e = d.get('event', {})
        eid = str(e.get('id', ''))
        if eid in v12_kept_eids:
            continue
        # Leaks use 'leak_src_asn' / 'leak_asn' / 'leak_dst_asn' fields
        leaker = str(e.get('leak_asn', '') or e.get('leak_src_asn', ''))
        src = str(e.get('leak_src_asn', ''))
        dst = str(e.get('leak_dst_asn', ''))
        if not leaker:
            rejected_extra.append({'eid': eid, 'cause': 'route_leak',
                'reason': 'missing_leaker_asn'})
            continue
        prefix = ''
        va = d.get('route_leaks') or d.get('victim_anomalies') or d.get('leaker_anomalies') or []
        if va:
            prefix = va[0].get('prefix', '')
        date_str = e.get('start_time', '')[:10]
        candidates.append({
            'kind': 'route_leak', 'eid': eid, 'fname': fname,
            'role_asn_for_traffic': leaker,
            'role_asn_for_rrc00': leaker,
            'date': date_str, 'prefix': prefix,
            'source': 'leak'
        })

    print(f"Total candidates to fetch/process: {len(candidates)}", file=sys.stderr)

    # Step B: Fetch CF Radar traffic for each candidate's traffic-role ASN
    # Use 7-day window centered on event date for baseline + event window
    fetched = 0
    cached = 0
    for i, c in enumerate(candidates):
        asn = c['role_asn_for_traffic']
        date_str = c['date']
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%d')
        except Exception:
            continue
        # Cache key: use existing if present
        existing = sorted(TRAFFIC_DIR.glob(f"AS{asn}_*.csv"))
        if existing:
            # Check if any contains the event date or ±7 days
            for f in existing:
                m = re.search(r'_(\d{4}-\d{2}-\d{2})T', f.name)
                if m:
                    fd = datetime.strptime(m.group(1), '%Y-%m-%d').date()
                    if abs((fd - dt.date()).days) <= 14:
                        c['traffic_csv'] = str(f)
                        cached += 1
                        break
            if 'traffic_csv' in c:
                continue
        # Fetch 7-day window from CF Radar
        start = dt - timedelta(days=3)
        end = dt + timedelta(days=4)
        start_iso = start.strftime("%Y-%m-%dT00:00:00Z")
        end_iso = end.strftime("%Y-%m-%dT00:00:00Z")
        result = fetch_cf_traffic(asn, start_iso, end_iso)
        if result.get('fetched'):
            csv_path = cache_traffic(asn, start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d'), result)
            if csv_path:
                c['traffic_csv'] = str(csv_path)
                fetched += 1
        else:
            c['traffic_fetch_error'] = result.get('reason', 'unknown')
        # Rate limit: ~1 req per 1.5s to be safe
        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(candidates)}] fetched={fetched} cached={cached}", file=sys.stderr)
        time.sleep(0.6)

    print(f"Done fetching. fetched={fetched} cached={cached}", file=sys.stderr)

    # Step C: Apply strict invariants
    verified = []
    rejected_extra = []
    for c in candidates:
        date_str = c['date'].replace('-', '')
        # RRC00 check
        rrc = check_rrc00_prefix(date_str, c['prefix'], c['role_asn_for_rrc00'])
        if not rrc.get('has_rrc00'):
            rejected_extra.append({'eid': c['eid'], 'cause': c['kind'],
                'reason': f'no_rrc00_parquet_for_date_{date_str}', 'rrc00': rrc})
            continue
        if rrc.get('prefix_count', 0) == 0 and rrc.get('origin_a', 0) == 0 and rrc.get('path_a', 0) == 0:
            rejected_extra.append({'eid': c['eid'], 'cause': c['kind'],
                'reason': 'rrc00_no_signal_prefix_or_asn', 'rrc00': rrc, 'prefix': c['prefix']})
            continue
        # Traffic check
        csv_path = c.get('traffic_csv')
        if not csv_path:
            rejected_extra.append({'eid': c['eid'], 'cause': c['kind'],
                'reason': f'traffic_fetch_failed_{c.get("traffic_fetch_error","?")}',
                'rrc00': rrc})
            continue
        tr = check_regularity_from_csv(Path(csv_path))
        if not tr.get('regular'):
            rejected_extra.append({'eid': c['eid'], 'cause': c['kind'],
                'reason': f'traffic_irregular', 'rrc00': rrc, 'traffic': tr})
            continue
        verified.append({
            'event_id': f"bgpstream_{'hijack' if c['kind']=='origin_hijack_victim' else 'leak'}_v13_{c['eid']}",
            'candidate_id': c['eid'],
            'cause_label': c['kind'],
            'date': c['date'],
            'start_time': '',
            'end_time': '',
            'victim_as': f"AS{c['role_asn_for_traffic']}" if c['kind']=='origin_hijack_victim' else '',
            'attacker_as': f"AS{c['role_asn_for_rrc00']}" if c['kind']=='origin_hijack_victim' else '',
            'leak_as': f"AS{c['role_asn_for_traffic']}" if c['kind']=='route_leak' else '',
            'prefix': c['prefix'],
            'rrc00': rrc,
            'traffic': tr,
            'traffic_csv': csv_path,
            'source': f"routing_grounded_cases/{c['source']}/kept",
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