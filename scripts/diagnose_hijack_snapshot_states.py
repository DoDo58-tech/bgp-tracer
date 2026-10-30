#!/usr/bin/env python3
"""Diagnose how origin-hijack alerts break down by snapshot coverage.

For every cached `origin_hijacked` / `origin_hijacking` alert the script
re-derives the snapshot state of the announced prefix and reports which
combination produces the alert.  The goal is to separate the three
situations that the detector currently collapses into one:

  exact-owned      the snapshot records the target as the origin of the
                   exact prefix the attacker announced
  exact-foreign    the snapshot records a *different* origin for the
                   exact prefix -- a genuine conflict
  parent-only      the snapshot does not cover the exact prefix; the
                   target only owns a covering parent block

Only the second is a hijack of the target's own space.  The third is the
normal case of a downstream customer announcing a more-specific prefix
inside the target's allocation, and the detector was flagging it.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = ROOT / "results" / "quick"
PREFIX2AS_DIR = ROOT / "data" / "prefix2as"

SNAPSHOT_DATE = {
    "quick_812_2022-07-08": "20220708",
    "quick_12479_2024-01-03": "20240103",
    "quick_1299_2025-05-20": "20250520",
    "quick_16509_2020-04-01": "20200401",
    "quick_13335_2022-02-01": "20220201",
}


def load_snapshot(stamp):
    for path in sorted(PREFIX2AS_DIR.glob(f"*{stamp}*.parsed.json")):
        return json.loads(path.read_text())
    return {}


def strip_as(value):
    s = str(value or "").strip()
    return s[2:] if s.upper().startswith("AS") else s


def classify(alert, snapshot, target_as):
    prefix = alert.get("prefix")
    origin = strip_as(alert.get("origin_as") or alert.get("hijacker_as"))
    owners = snapshot.get(prefix)
    if owners is None:
        return "unknown-prefix", origin
    owners = [strip_as(o) for o in (owners if isinstance(owners, (list, set, tuple)) else [owners])]
    if target_as in owners:
        return "exact-owned", origin
    if origin in owners:
        return "exact-other-owner", origin
    return "exact-foreign", origin


def main():
    for stem, stamp in SNAPSHOT_DATE.items():
        matches = sorted(QUICK_DIR.glob(f"{stem}*.json"))
        if not matches:
            continue
        snapshot = load_snapshot(stamp)
        if not snapshot:
            print(f"== {stem}: no snapshot for {stamp}")
            continue
        cache = json.loads(matches[0].read_text())
        routing = cache.get("routing") or {}
        target = strip_as(routing.get("asn") or cache.get("asn"))
        for key in ("origin_hijacked", "origin_hijacking"):
            alerts = routing.get(key) or []
            if not alerts:
                continue
            counter = Counter()
            for alert in alerts:
                state, _ = classify(alert, snapshot, target)
                counter[state] += 1
            print(f"== {stem} AS{target} {key}: {len(alerts)} records")
            for state, n in counter.most_common():
                print(f"     {state:20s} {n}")


if __name__ == "__main__":
    main()
