#!/usr/bin/env python3
"""Audit the quick-cache corpus for hygiene problems.

Two classes of problem are reported:

1. *Duplicate windows.*  The same (ASN, start, end) window is encoded by
   more than one file because the filename separator differs ("_" vs "T").
   The resolution rule keeps the newest file, but a stale file with the same
   window is still a trap for any code that globs instead of resolving.

2. *Degraded caches.*  A cache whose detector channels are empty while a
   sibling cache for the same window has measurements is a measurement that
   lost data.  A cache is flagged when every routing channel
   (hijack / leak / outage) is silent but a sibling for the same window is
   not.

3. *Saturated leak channels.*  A cache whose leak count sits exactly on the
   detector's truncation cap carries no count information; the distinct
   leaking routes in the itemised list are the real measurement.

Writes results/eval/cache_hygiene_audit.json.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import candidates, parse_window_from_stem  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cache_hygiene_audit.json"
LEAK_CAP = 5000


def channels(cache: dict) -> dict:
    routing = cache.get("routing") or {}
    return {
        "hijack": len(routing.get("origin_hijacked") or [])
        + len(routing.get("origin_hijacking") or [])
        + len(routing.get("forge_hijacked") or [])
        + len(routing.get("forge_hijacking") or []),
        "leak": len(routing.get("route_leaks") or []),
        "outage": bool(routing.get("outage_suspected")),
    }


def has_measurement(ch: dict) -> bool:
    return ch["hijack"] > 0 or ch["leak"] > 0 or ch["outage"]


def main() -> int:
    groups: dict[tuple, list[tuple[Path, dict]]] = defaultdict(list)
    unparsed = 0

    for path in candidates(QUICK_DIR):
        window = parse_window_from_stem(path.stem)
        if window is None:
            unparsed += 1
            continue
        try:
            cache = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        asn = str(cache.get("asn") or "").strip()
        key = (asn, window[0].isoformat(), window[1].isoformat())
        groups[key].append((path, cache))

    duplicate_windows = []
    degraded_caches = []
    saturated_leaks = []
    empty_caches = []
    n_files = 0

    for key, entries in groups.items():
        n_files += len(entries)
        if len(entries) > 1:
            entries_sorted = sorted(entries, key=lambda t: t[0].stat().st_mtime)
            newest = entries_sorted[-1]
            for path, cache in entries_sorted[:-1]:
                ch = channels(cache)
                newer_ch = channels(newest[1])
                stale_has = has_measurement(ch)
                newer_has = has_measurement(newer_ch)
                duplicate_windows.append({
                    "asn": key[0],
                    "start": key[1],
                    "end": key[2],
                    "stale_file": path.name,
                    "kept_file": newest[0].name,
                    "stale_channels": ch,
                    "kept_channels": newer_ch,
                    "stale_is_degraded": stale_has and not newer_has,
                })
                if stale_has and not newer_has:
                    degraded_caches.append(path.name)
            newest_ch = channels(newest[1])
            if newest_ch["leak"] >= LEAK_CAP:
                saturated_leaks.append(newest[0].name)

        # single-file windows
        if len(entries) == 1:
            path, cache = entries[0]
            ch = channels(cache)
            if not has_measurement(ch):
                empty_caches.append(path.name)
            elif ch["leak"] >= LEAK_CAP:
                saturated_leaks.append(path.name)

    payload = {
        "n_files": n_files,
        "n_windows": len(groups),
        "n_unparsed_filenames": unparsed,
        "n_duplicate_windows": len(duplicate_windows),
        "duplicate_windows": duplicate_windows,
        "n_degraded_caches": len(degraded_caches),
        "degraded_caches": degraded_caches,
        "n_saturated_leak_caches": len(saturated_leaks),
        "saturated_leak_caches": saturated_leaks,
        "n_empty_caches": len(empty_caches),
        "empty_caches": empty_caches,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    print(f"cache files scanned      : {n_files}")
    print(f"distinct windows         : {len(groups)}")
    print(f"duplicate windows        : {len(duplicate_windows)}")
    print(f"  of which stale-degraded: {len(degraded_caches)}")
    print(f"leak channel saturated   : {len(saturated_leaks)}")
    print(f"no routing channel at all: {len(empty_caches)}")
    print(f"wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
