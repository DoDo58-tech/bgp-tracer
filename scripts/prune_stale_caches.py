#!/usr/bin/env python3
"""Remove stale duplicate quick caches, keeping the newest per window.

The same (ASN, start, end) window can be encoded by two files when the
filename separator differs ("_" vs "T").  The stale twin was produced by an
older detector build: it has an empty hijack channel and a leak count
pinned at the detector's truncation cap, so it carries less information
than the newer file for the same window.

Only files that are an *exact duplicate window* of a newer file are
removed.  Files with a unique window are never touched, and the removed
file is copied to `results/quick/stale/` first so the deletion is
reversible.

Writes results/eval/cache_prune_report.json.
"""

from __future__ import annotations

import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import candidates, parse_window_from_stem  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
STALE_DIR = QUICK_DIR / "stale"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cache_prune_report.json"


def main() -> int:
    dry_run = "--apply" not in sys.argv

    groups: dict[tuple, list[Path]] = defaultdict(list)
    for path in candidates(QUICK_DIR):
        window = parse_window_from_stem(path.stem)
        if window is None:
            continue
        asn = str(path.stem.split("_")[1]) if "_" in path.stem else ""
        groups[(asn, window[0], window[1])].append(path)

    removed = []
    for key, paths in groups.items():
        if len(paths) < 2:
            continue
        ordered = sorted(paths, key=lambda p: p.stat().st_mtime)
        newest = ordered[-1]
        for path in ordered[:-1]:
            record = {
                "asn": key[0],
                "start": key[1].isoformat(),
                "end": key[2].isoformat(),
                "removed": path.name,
                "kept": newest.name,
                "removed_mtime": path.stat().st_mtime,
                "kept_mtime": newest.stat().st_mtime,
            }
            if not dry_run:
                STALE_DIR.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), str(STALE_DIR / path.name))
            removed.append(record)

    payload = {
        "mode": "dry_run" if dry_run else "applied",
        "n_removed": len(removed),
        "removed": removed,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    print(f"{'would remove' if dry_run else 'removed'}: {len(removed)} duplicate-window caches")
    for record in removed[:10]:
        print(f"  {record['removed']}  ->  keep {record['kept']}")
    if len(removed) > 10:
        print(f"  ... and {len(removed) - 10} more")
    print(f"wrote {OUT_PATH}")
    if dry_run:
        print("\nre-run with --apply to perform the move")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
