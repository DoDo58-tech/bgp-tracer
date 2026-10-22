#!/usr/bin/env python3
"""Generate remaining v19 quick caches with 6h max time window.

User's instruction: ground-truth time spans should not be too long, truncate to 6h.
"""
import csv
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

GT = Path('data_check/ground_truth_collection/final_balanced_v19_40.csv')
QUICK_DIR = Path('results/quick')
LOG_DIR = Path('logs')
QUICK_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

MAX_WINDOW_HOURS = 6


def parse_event_time(s):
    """Parse event time string to datetime."""
    s = s.replace('Z', '').strip()
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def truncate_window(start, end, max_hours=6):
    """Truncate window to max_hours if longer, keeping the END (most important part)."""
    delta = end - start
    if delta <= timedelta(hours=max_hours):
        return start, end
    new_start = end - timedelta(hours=max_hours)
    return new_start, end


def has_cache(asn, start_dt, end_dt):
    """Check if any cache covers this AS in this window."""
    date_compact = start_dt.strftime('%Y%m%d')
    candidates = list(QUICK_DIR.glob(f"quick_{asn}_*.json"))
    for c in candidates:
        # Try to extract dates from filename
        m = re.findall(r'(20\d{2})-?(\d{2})-?(\d{2})', c.name)
        if not m:
            continue
        # First match should be the start date
        for y, mo, d in m:
            try:
                file_date = datetime(int(y), int(mo), int(d))
                if start_dt.date() <= file_date.date() <= end_dt.date():
                    return True
            except ValueError:
                continue
    return False


def gen_cache(asn, start_dt, end_dt, eid):
    """Generate one quick cache. Returns True if successful."""
    start_str = start_dt.strftime('%Y-%m-%dT%H:%M')
    end_str = end_dt.strftime('%Y-%m-%dT%H:%M')
    log_file = LOG_DIR / f"cachegen_{eid}.log"
    cmd = [
        'python3', 'chief_agent.py',
        '--asn', asn,
        '--start', start_str,
        '--end', end_str,
        '--mode', 'quick',
        '--json-summary',
    ]
    print(f'  [start] {eid} AS{asn} {start_str} -> {end_str}')
    try:
        with open(log_file, 'w') as f:
            proc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=300)
        if proc.returncode == 0:
            print(f'  [ok]    {eid}')
            return True
        else:
            # Check if cache file was actually created (fatal on shutdown is ok)
            cache = list(QUICK_DIR.glob(f"quick_{asn}_{start_dt.strftime('%Y-%m-%d')}*.json"))
            if cache:
                print(f'  [ok-soft] {eid} (cache written despite shutdown)')
                return True
            print(f'  [fail]  {eid} rc={proc.returncode}')
            return False
    except subprocess.TimeoutExpired:
        print(f'  [timeout] {eid}')
        return False
    except Exception as e:
        print(f'  [error] {eid}: {e}')
        return False


def main():
    events = list(csv.DictReader(open(GT)))
    pending = []
    for e in events:
        eid = e['event_id']
        asn = e.get('victim_as', '').replace('AS', '').strip()
        if not asn:
            continue
        start = parse_event_time(e.get('start_utc', ''))
        end = parse_event_time(e.get('end_utc', ''))
        if not start or not end:
            print(f'  [skip] {eid}: cannot parse time')
            continue
        # Truncate to 6h max
        start, end = truncate_window(start, end, MAX_WINDOW_HOURS)
        if has_cache(asn, start, end):
            print(f'  [skip] {eid} AS{asn} {start.date()}: has cache')
            continue
        pending.append((eid, asn, start, end))

    print(f'\n>>> Need to generate {len(pending)} caches')
    ok = 0
    fail = 0
    for eid, asn, start, end in pending:
        if gen_cache(asn, start, end, eid):
            ok += 1
        else:
            fail += 1
        time.sleep(2)  # Cool down
    print(f'\nDone: {ok} ok, {fail} failed')


if __name__ == '__main__':
    main()
