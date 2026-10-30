#!/usr/bin/env python3
"""Test a candidate discriminator for the origin-hijack detector.

The detector currently flags an announcement as `origin_hijacked` when the
announced prefix is *contained in* a block the target owns.  For a
transit provider that rule fires on every customer announcement of a
more-specific prefix inside the provider's allocation, which is ordinary
BGP, not hijacking.

Candidate rule tested here:

  A parent-covered announcement is a hijack only when the target AS does
  not appear in the AS path of the announcement.  When the target is
  present in the path immediately before the origin AS, the origin is a
  customer of the target announcing its own more-specific prefix, which
  is legitimate origination.

The script reports, per cached event, how many alerts each rule would
keep, and it prints a sample so the kept alerts can be eyeballed.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

QUICK_DIR = ROOT / "results" / "quick"


def strip_as(value):
    s = str(value or "").strip()
    return s[2:] if s.upper().startswith("AS") else s


def path_of(alert):
    raw = alert.get("as_path") or alert.get("as-path") or ""
    if isinstance(raw, (list, tuple)):
        return [strip_as(a) for a in raw]
    return [strip_as(a) for a in str(raw).replace("|", " ").split() if a.strip()]


def target_in_path(alert, target):
    return target in path_of(alert)


def customer_announcement(alert, target):
    """The target is the AS immediately before the origin AS."""
    path = path_of(alert)
    origin = strip_as(alert.get("origin_as") or alert.get("hijacker_as"))
    if len(path) >= 2 and origin and path[-1] == origin:
        return path[-2] == target
    return False


def main():
    print(f"{'cache':46s} {'alerts':>8s} {'no-target':>10s} {'cust-ann':>9s} {'kept':>7s}")
    for path in sorted(QUICK_DIR.glob("quick_*.json")):
        try:
            cache = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        routing = cache.get("routing") or {}
        target = strip_as(routing.get("asn") or cache.get("asn"))
        alerts = routing.get("origin_hijacked") or []
        if not alerts or not target:
            continue
        no_target = sum(1 for a in alerts if not target_in_path(a, target))
        cust = sum(1 for a in alerts if customer_announcement(a, target))
        kept = sum(1 for a in alerts if not customer_announcement(a, target))
        print(f"{path.name[:46]:46s} {len(alerts):8d} {no_target:10d} {cust:9d} {kept:7d}")


if __name__ == "__main__":
    main()
