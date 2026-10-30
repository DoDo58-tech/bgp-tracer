#!/usr/bin/env python3
"""Move caches written by a superseded detector build out of the corpus.

The origin-hijack and route-leak detectors were corrected after some
caches had already been written.  A cache carries the detector's own
verdict, so a cache written before a detector fix reports the pre-fix
verdict; keeping it in the corpus mixes two different measurements into
one evaluation.

This script takes the set of cache files whose mtime is older than a
cut-off and moves them into a quarantine directory, so the corpus
contains only caches produced by the current detector build.  Nothing is
deleted: the quarantined files stay on disk for inspection.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

QUICK_DIR = ROOT / "results" / "quick"
QUARANTINE = QUICK_DIR / "stale"


def parse_cutoff(value):
    if not value:
        return None
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def cache_mtime(path):
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", default="",
                        help="ISO timestamp; caches older than this are quarantined")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cutoff = parse_cutoff(args.before)
    if cutoff is None:
        print("error: --before is required", file=sys.stderr)
        return 2

    QUARANTINE.mkdir(parents=True, exist_ok=True)
    moved = 0
    kept = 0
    for path in sorted(QUICK_DIR.glob("quick_*.json")):
        if cache_mtime(path) >= cutoff:
            kept += 1
            continue
        if args.dry_run:
            print(f"would quarantine {path.name}")
        else:
            shutil.move(str(path), str(QUARANTINE / path.name))
        moved += 1
    print(f"quarantined={moved} kept={kept} cutoff={cutoff.isoformat()}")
    print(f"quarantine dir: {QUARANTINE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
