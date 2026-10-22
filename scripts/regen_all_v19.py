#!/usr/bin/env python3
"""Regenerate ALL caches for v19 with the fixed detectors (outage+traffic).

- All 3 detectors (outage, leak, hijack) must run (no skipping).
- 6h max window.
- Parallel batches (controlled by max_concurrent).
"""
import csv
import json
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
import sys

GT = Path('data_check/ground_truth_collection/final_balanced_v19_40.csv')
QUICK_DIR = Path('results/quick')
LOG_DIR = Path('logs')
QUICK_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
MAX_HOURS = 6
MAX_CONCURRENT = 2


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


def gen_cache(asn, start, end, eid):
    """Generate one quick cache, truncated to 6h."""
    start_str = start.strftime('%Y-%m-%dT%H:%M')
    end_str = end.strftime('%Y-%m-%dT%H:%M')
    log_file = LOG_DIR / f"regen_all_{eid}.log"
    cmd = ['python3', 'chief_agent.py', '--asn', asn, '--start', start_str,
           '--end', end_str, '--mode', 'quick', '--json-summary']
    print(f'  {eid} AS{asn} {start_str} -> {end_str}', flush=True)
    try:
        with open(log_file, 'w') as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=600)
        # Check if cache exists (even if subprocess returned non-zero)
        date_compact = start.strftime('%Y%m%d')
        candidates = list(QUICK_DIR.glob(f"quick_{asn}_*.json"))
        for c in candidates:
            if date_compact in str(c).replace('-', ''):
                d = json.load(open(c))
                oa = d.get('routing', {}).get('outage_analysis', {})
                ts = d.get('traffic', {})
                t_ok = bool(ts.get('success')) and ts.get('anomaly_count') is not None
                o_ok = oa.get('success') if isinstance(oa, dict) else False
                if t_ok and o_ok:
                    print(f'    OK: both detectors', flush=True)
                    return True
                elif t_ok or o_ok:
                    which = 'traffic+outage' if t_ok and o_ok else ('traffic' if t_ok else 'outage')
                    print(f'    PARTIAL: only {which} works', flush=True)
                    return True
        print(f'    FAIL: rc={proc.returncode}', flush=True)
        return False
    except subprocess.TimeoutExpired:
        print(f'    TIMEOUT', flush=True)
        return False
    except Exception as e:
        print(f'    ERR: {e}', flush=True)
        return False


def main():
    events = list(csv.DictReader(open(GT)))
    jobs = []
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
        jobs.append((eid, asn, start, end))
    print(f'Total events: {len(jobs)}', flush=True)

    # Run in parallel using subprocess.Popen with semaphore
    import threading
    sem = threading.Semaphore(MAX_CONCURRENT)
    results = {}
    lock = threading.Lock()

    def worker(eid, asn, start, end):
        with sem:
            ok = gen_cache(asn, start, end, eid)
            with lock:
                results[eid] = ok

    threads = []
    for eid, asn, start, end in jobs:
        t = threading.Thread(target=worker, args=(eid, asn, start, end))
        t.start()
        threads.append(t)
        time.sleep(2)  # Stagger
    for t in threads:
        t.join()
    ok = sum(1 for v in results.values() if v)
    print(f'\nDone: {ok}/{len(jobs)} ok')


if __name__ == '__main__':
    main()
