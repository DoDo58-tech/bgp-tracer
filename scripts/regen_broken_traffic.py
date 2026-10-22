#!/usr/bin/env python3
"""Regenerate caches for v19 events that have broken traffic detector.

User requirement: time spans should not be too long, truncate to 6h.
Skip-detector is forbidden; all detectors must run.
"""
import csv
import json
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

GT = Path('data_check/ground_truth_collection/final_balanced_v19_40.csv')
QUICK_DIR = Path('results/quick')
LOG_DIR = Path('logs')
QUICK_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
MAX_HOURS = 6


def parse_time(s):
    s = s.replace('Z', '').strip()
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def truncate(start, end, max_h=6):
    if end - start <= timedelta(hours=max_h):
        return start, end
    return end - timedelta(hours=max_h), end


def traffic_works(cache_path):
    try:
        d = json.load(open(cache_path))
        t = d.get('traffic', {})
        return bool(t.get('success')) and t.get('anomaly_count') is not None
    except Exception:
        return False


def find_cache(asn, start_dt, end_dt):
    """Find ANY cache for this AS in date range. Prefer working ones."""
    date_compact_start = start_dt.strftime('%Y%m%d')
    date_compact_end = end_dt.strftime('%Y%m%d')
    candidates = list(QUICK_DIR.glob(f"quick_{asn}_*.json"))
    # Pass 1: same date AND traffic works
    for c in candidates:
        s = str(c)
        if date_compact_start in s.replace('-', '') or date_compact_end in s.replace('-', ''):
            if traffic_works(c):
                return c
    # Pass 2: same date (any)
    for c in candidates:
        s = str(c)
        if date_compact_start in s.replace('-', '') or date_compact_end in s.replace('-', ''):
            return c
    return None


def gen_cache(asn, start, end, eid, attempt=1):
    """Generate one quick cache, truncated to 6h."""
    start_str = start.strftime('%Y-%m-%dT%H:%M')
    end_str = end.strftime('%Y-%m-%dT%H:%M')
    log_file = LOG_DIR / f"regen_{eid}.log"
    cmd = ['python3', 'chief_agent.py', '--asn', asn, '--start', start_str,
           '--end', end_str, '--mode', 'quick', '--json-summary']
    print(f'  [{attempt}] {eid} AS{asn} {start_str} -> {end_str}')
    try:
        with open(log_file, 'w') as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=300)
        # Even on fatal returncode, cache may be there
        cache = find_cache(asn, start, end)
        if cache and traffic_works(cache):
            print(f'  OK ({cache.name})')
            return True
        print(f'  FAIL (rc={proc.returncode})')
        return False
    except subprocess.TimeoutExpired:
        print(f'  TIMEOUT')
        return False
    except Exception as e:
        print(f'  ERR: {e}')
        return False


def main():
    events = list(csv.DictReader(open(GT)))
    pending = []
    for e in events:
        eid = e['event_id']
        asn = e['victim_as'].replace('AS', '')
        if not asn:
            continue
        start = parse_time(e.get('start_utc', ''))
        end = parse_time(e.get('end_utc', ''))
        if not start or not end:
            continue
        start, end = truncate(start, end, MAX_HOURS)
        cache = find_cache(asn, start, end)
        if cache and traffic_works(cache):
            print(f'  [skip] {eid}: traffic OK')
            continue
        pending.append((eid, asn, start, end))

    print(f'\nNeed to regenerate {len(pending)} caches')
    ok = fail = 0
    for eid, asn, start, end in pending:
        if gen_cache(asn, start, end, eid):
            ok += 1
        else:
            fail += 1
        time.sleep(3)
    print(f'\nDone: {ok} ok, {fail} failed')


if __name__ == '__main__':
    main()
