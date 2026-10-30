#!/usr/bin/env python3
"""Evaluate candidate origin-hijack rules against cached detector output.

The detector resolves each announced prefix against the RouteViews
prefix2as snapshot.  Three snapshot states exist, and the current code
collapses them:

  exact-owned     the snapshot names the target as an origin of the exact
                  prefix  -> the target's space is in play
  exact-other     the snapshot names a different origin for the exact
                  prefix  -> the exact prefix is NOT the target's
  unknown         the snapshot does not cover the exact prefix at all

For the two "hijacked" / "hijacking" verdicts the current code falls back
to parent-block coverage whenever the exact prefix is unknown or owned by
someone else, which is what produces the mass false positives: a provider
announcing a customer's more-specific prefix, or an AS unrelated to the
target announcing a prefix that merely falls inside the target's block.

Candidate rules evaluated here:

  R0  current behaviour (parent fallback everywhere)
  R1  exact-prefix only: a hijack needs the exact prefix to name the
      target (victim) or another origin (attacker)
  R2  exact-prefix only, plus: when the exact prefix is unknown, the
      announcement is a hijack only if the target is absent from the AS
      path (an unrelated AS is originating inside the target's block)

The script prints, per cache, how many alerts each rule keeps so the
trade-off between recall on true hijacks and precision on transit noise
is visible.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

QUICK_DIR = ROOT / "results" / "quick"
PREFIX2AS_DIR = ROOT / "data" / "prefix2as"

SNAPSHOT_FOR_CACHE = {
    "quick_812_2022-07-08": "20220708",
    "quick_12479_2024-01-03": "20240103",
    "quick_1299_2025-05-20": "20250520",
    "quick_16509_2020-04-01": "20200401",
    "quick_16509_2018-04-24": "20180424",
    "quick_13335_2022-02-01": "20220201",
    "quick_17557_2024-07-31": "20240731",
    "quick_18001_2025-02-09": "20250209",
    "quick_20940_2023-09-18": "20230918",
    "quick_27947_2023-06-06": "20230606",
    "quick_9498_2024-01-25": "20240125",
    "quick_22773_2025-05-01": "20250501",
    "quick_12389_2025-01-14": "20250114",
    "quick_1221_2020-09-29": "20200929",
    "quick_131621_2019-05-08": "20190508",
}


def strip_as(value):
    s = str(value or "").strip()
    return s[2:] if s.upper().startswith("AS") else s


def path_of(alert):
    raw = alert.get("as_path") or alert.get("as-path") or ""
    if isinstance(raw, (list, tuple)):
        return [strip_as(a) for a in raw]
    return [strip_as(a) for a in str(raw).replace("|", " ").split() if a.strip()]


def load_snapshot(stamp):
    for path in sorted(PREFIX2AS_DIR.glob(f"*{stamp}*.parsed.json")):
        return json.loads(path.read_text())
    return {}


def exact_owners(snapshot, prefix):
    owners = snapshot.get(prefix)
    if owners is None:
        return None
    if isinstance(owners, (list, set, tuple)):
        return [strip_as(o) for o in owners]
    return [strip_as(owners)]


def main():
    print(f"{'cache':44s} {'side':6s} {'alerts':>8s} {'R0':>8s} {'R1':>8s} {'R2':>8s}")
    totals = Counter()
    for path in sorted(QUICK_DIR.glob("quick_*.json")):
        if path.name.startswith("quick_annotation"):
            continue
        stem = path.name[:28]
        stamp = None
        for key, value in SNAPSHOT_FOR_CACHE.items():
            if path.name.startswith(key):
                stamp = value
                break
        if stamp is None:
            continue
        snapshot = load_snapshot(stamp)
        if not snapshot:
            continue
        try:
            cache = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        routing = cache.get("routing") or {}
        target = strip_as(routing.get("asn") or cache.get("asn"))
        if not target:
            continue
        for side, key in (("victim", "origin_hijacked"), ("attacker", "origin_hijacking")):
            alerts = routing.get(key) or []
            if not alerts:
                continue
            r0 = r1 = r2 = 0
            for alert in alerts:
                prefix = alert.get("prefix")
                origin = strip_as(alert.get("origin_as") or alert.get("hijacker_as"))
                owners = exact_owners(snapshot, prefix)
                target_in_path = target in path_of(alert)
                r0 += 1
                if owners is None:
                    if side == "victim":
                        if not target_in_path:
                            r2 += 1
                    else:
                        r2 += 0
                    continue
                if target in owners:
                    if side == "victim":
                        if origin != target:
                            r1 += 1
                            r2 += 1
                    else:
                        r1 += 0
                    continue
                if side == "attacker":
                    if origin == target:
                        r1 += 1
                        r2 += 1
                else:
                    r1 += 0
            totals["alerts"] += len(alerts)
            totals["r0"] += r0
            totals["r1"] += r1
            totals["r2"] += r2
            print(f"{path.name[:44]:44s} {side:6s} {len(alerts):8d} {r0:8d} {r1:8d} {r2:8d}")
    print()
    print(f"TOTAL alerts={totals['alerts']}  R0={totals['r0']}  R1={totals['r1']}  R2={totals['r2']}")


if __name__ == "__main__":
    main()
