#!/usr/bin/env python3
"""Rebuild leak field for a corrupt quick cache by re-running
analyze_leak_surface against RRC00 and patching the cache in place.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from detectors.leak.leak_detector import analyze_leak_surface  # noqa


def fix_cache(path: Path) -> int:
    with path.open() as f:
        c = json.load(f)
    rt = c.get("routing")
    if not isinstance(rt, dict):
        # Build a routing dict
        c["routing"] = rt = {"route_leaks": [], "origin_hijacked": [], "origin_hijacking": []}
    leaks = rt.get("route_leaks", [])
    asn = c.get("asn") or path.stem.split("_")[1]
    asn = str(asn)
    if asn.startswith("AS"):
        asn = asn[2:]
    s = c.get("start_time", "") or ""
    e = c.get("end_time", "") or ""
    s = s.replace("T", " ").rstrip("Z")
    e = e.replace("T", " ").rstrip("Z")
    print(f"  {path.name}: re-running for AS{asn} {s} -> {e}")
    try:
        result = analyze_leak_surface(asn, s, e, max_leaks=5000)
    except Exception as exc:
        print(f"    ERROR: {exc}")
        return 0
    new_leaks = result.get("route_leaks", []) or []
    if not new_leaks:
        print(f"    no leaks found")
        return 0
    rt["route_leaks"] = [str(x) for x in new_leaks]
    with path.open("w") as f:
        json.dump(c, f, indent=2, default=str)
    print(f"    patched with {len(new_leaks)} leaks")
    return len(new_leaks)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("caches", nargs="+", type=Path)
    args = p.parse_args()
    total = 0
    for path in args.caches:
        if not path.exists():
            print(f"  {path}: not found")
            continue
        total += fix_cache(path)
    print(f"Total leaks patched: {total}")


if __name__ == "__main__":
    main()
