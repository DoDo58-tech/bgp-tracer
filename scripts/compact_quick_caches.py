"""Compact the quick caches already on disk.

Caches written before the compaction was introduced keep one record per
announcement, which makes them hundreds of megabytes, slow to load and prone
to being OOM-killed.  The compaction itself is lossless for scoring, so it
can be applied to the existing files instead of re-running the detectors --
which would take hours and re-fetch data.

The rewrite is atomic: the compacted payload is written to a temporary file
and then moved over the original, so an interrupted run never leaves a
half-written cache behind.

Usage:
    python3 scripts/compact_quick_caches.py [--dry-run] [--min-mb 20]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_compaction import compact_cache_payload  # noqa: E402
from utils.helpers import make_json_safe  # noqa: E402

QUICK_DIR = ROOT / "results" / "quick"


def compact_file(path: Path, dry_run: bool = False) -> tuple[bool, int, int]:
    """Compact one cache.  Returns (changed, bytes_before, bytes_after)."""
    before = path.stat().st_size
    if before == 0:
        return False, before, before

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"  skip {path.name}: unreadable ({exc})")
        return False, before, before

    routing, correlation = compact_cache_payload(
        data.get("routing"), data.get("correlation"))
    if routing is data.get("routing") and correlation is data.get("correlation"):
        return False, before, before

    data["routing"] = routing
    data["correlation"] = correlation

    payload = json.dumps(make_json_safe(data), ensure_ascii=False, default=str)
    after = len(payload.encode("utf-8"))
    if after >= before:
        return False, before, before

    if dry_run:
        print(f"  would compact {path.name}: {before/1e6:.1f} MB -> {after/1e6:.1f} MB")
        return True, before, after

    tmp = path.with_suffix(path.suffix + ".compact.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(payload)
    os.replace(tmp, path)
    print(f"  compacted {path.name}: {before/1e6:.1f} MB -> {after/1e6:.1f} MB "
          f"({before/max(after,1):.0f}x)")
    return True, before, after


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--min-mb", type=float, default=5.0,
                    help="only consider caches at least this large")
    ap.add_argument("--dir", default=str(QUICK_DIR))
    args = ap.parse_args()

    directory = Path(args.dir)
    threshold = args.min_mb * 1e6
    candidates = [p for p in sorted(directory.glob("quick_*.json"))
                  if p.stat().st_size >= threshold]
    print(f"candidates: {len(candidates)} (>= {args.min_mb} MB)")

    changed = 0
    saved = 0
    for path in candidates:
        ok, before, after = compact_file(path, dry_run=args.dry_run)
        if ok:
            changed += 1
            saved += before - after

    verb = "would free" if args.dry_run else "freed"
    print(f"\n{changed} cache(s) {verb} {saved/1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
