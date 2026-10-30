#!/usr/bin/env python3
"""Simulate corrected origin-hijack classification on cached alerts.

The shipped detector resolves an announced prefix against the RouteViews
prefix2as snapshot and falls back to parent-block coverage whenever the
exact prefix is not covered by the snapshot or is covered by someone
else.  That fallback is what turns ordinary transit traffic into hijack
alerts.

This script re-classifies every cached alert with the corrected rule and
reports, per cache, how many alerts survive:

  exact_owned_target   snapshot names the target as an origin of the exact
                       prefix -> the target's own space is in play
  exact_owned_other    snapshot names a different origin for the exact
                       prefix -> the target is not the legitimate origin
                       and the prefix is not the target's space
  unknown              snapshot does not cover the exact prefix

Corrected verdicts:

  victim   (origin_hijacked)  fires when the snapshot names the target as
                              an origin of the exact prefix and the
                              observed origin differs, OR when the exact
                              prefix is unknown, its covering parent is
                              target-owned, and the target does not appear
                              in the announcement's AS path (an unrelated
                              AS originating inside the target's block)
  attacker (origin_hijacking) fires when the snapshot names a different
                              origin for the exact prefix and the target
                              announced it

The `target in path` exclusion is the substantive correction: when the
target is in the AS path immediately before the origin AS, the origin is a
customer of the target announcing a more-specific prefix inside the
target's allocation, which is ordinary origination, not hijacking.
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


def strip_as(value):
    s = str(value or "").strip()
    return s[2:] if s.upper().startswith("AS") else s


def path_of(alert):
    raw = alert.get("as_path") or alert.get("as-path") or ""
    if isinstance(raw, (list, tuple)):
        return [strip_as(a) for a in raw]
    return [strip_as(a) for a in str(raw).replace("|", " ").split() if a.strip()]


def load_snapshot_for(path):
    """Find the prefix2as snapshot whose name matches the cache's date."""
    import re
    match = re.search(r"(20\d{2})-(\d{2})-(\d{2})", path.name)
    if not match:
        return {}
    stamp = "".join(match.groups())
    for candidate in sorted(PREFIX2AS_DIR.glob(f"*{stamp}*.parsed.json")):
        return json.loads(candidate.read_text())
    return {}


def owners_of(snapshot, prefix):
    owners = snapshot.get(prefix)
    if owners is None:
        return None
    if isinstance(owners, (list, set, tuple)):
        return [strip_as(o) for o in owners]
    return [strip_as(owners)]


def covering_parent(snapshot, prefix):
    """Longest snapshot prefix covering `prefix` (proper parent only)."""
    try:
        import ipaddress
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None, None
    best = None
    for plen in range(net.prefixlen - 1, -1, -1):
        parent = net.supernet(new_prefix=plen)
        owners = owners_of(snapshot, str(parent))
        if owners is not None:
            return str(parent), owners
    return None, None


def classify(alert, snapshot, target):
    prefix = alert.get("prefix")
    origin = strip_as(alert.get("origin_as") or alert.get("hijacker_as"))
    path = path_of(alert)
    target_in_path = target in path

    owners = owners_of(snapshot, prefix)
    if owners is not None:
        if target in owners:
            return "victim_exact" if origin != target else "none_exact_self"
        if origin == target:
            return "attacker_exact"
        return "none_exact_other"

    parent, parent_owners = covering_parent(snapshot, prefix)
    if parent_owners is None:
        return "none_no_parent"
    if target in parent_owners:
        if origin == target:
            return "none_parent_self"
        if target_in_path:
            return "none_parent_customer"
        return "victim_parent"
    if origin == target:
        return "attacker_parent"
    return "none_parent_other"


def main():
    print(f"{'cache':44s} {'side':9s} {'alerts':>8s} {'keep':>8s}  breakdown")
    totals = Counter()
    for path in sorted(QUICK_DIR.glob("quick_*.json")):
        if path.name.startswith("quick_annotation"):
            continue
        try:
            cache = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        routing = cache.get("routing") or {}
        target = strip_as(routing.get("asn") or cache.get("asn"))
        if not target:
            continue
        snapshot = load_snapshot_for(path)
        if not snapshot:
            continue
        for side, key in (("victim", "origin_hijacked"), ("attacker", "origin_hijacking")):
            alerts = routing.get(key) or []
            if not alerts:
                continue
            counter = Counter()
            for alert in alerts:
                counter[classify(alert, snapshot, target)] += 1
            keep = counter["victim_exact"] + counter["victim_parent"] \
                + counter["attacker_exact"] + counter["attacker_parent"]
            totals["alerts"] += len(alerts)
            totals["keep"] += keep
            for state, n in counter.items():
                totals[state] += n
            breakdown = " ".join(f"{k}={v}" for k, v in counter.most_common())
            print(f"{path.name[:44]:44s} {side:9s} {len(alerts):8d} {keep:8d}  {breakdown}")
    print()
    print(f"TOTAL alerts={totals['alerts']}  keep={totals['keep']}")
    for state, n in totals.most_common():
        print(f"    {state:24s} {n}")


if __name__ == "__main__":
    main()
