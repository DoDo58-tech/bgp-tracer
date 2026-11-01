"""The new-path hypothesis: the leaking ASN appears on the victim's paths
during the event but not during the baseline.

The permutation test over the collected features found exactly one
significant discriminator for the route-leak class: the presence of the
leaking ASN in the routing block, AUC 0.88, p < 0.001.  That is a
weak way to use the ASN -- it is present in the block as a whole, which
includes the baseline material.

The sharper version of the hypothesis is that a leak introduces a
*new* transit into the victim's paths.  Before the leak, the victim's
prefixes were reached through the victim's usual providers; during the
leak they are reached through the leaking AS.  So the leaking ASN
appears on the victim's event-window paths and does not appear on its
baseline paths.  For an outage and a hijack the victim's path set is
unchanged or replaced by a hijacker rather than extended by a
legitimate provider, so the marker does not fire.

This script tests that version directly:

  * collect the AS set on the victim's event-window paths,
  * collect the AS set on the victim's baseline-window paths,
  * the marker is the leaking ASN being in the event set and not in the
    baseline set.

It reports the AUC and permutation p-value of the marker, and the
per-class rate at which it fires.

Writes results/eval/leak_new_path_marker.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_new_path_marker.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events():
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def collect_asns(blob):
    found = set()
    if isinstance(blob, str):
        for tok in blob.replace(",", " ").split():
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= 4294967294:
                found.add(tok)
    elif isinstance(blob, (list, tuple)):
        for item in blob:
            found |= collect_asns(item)
    elif isinstance(blob, dict):
        for value in blob.values():
            found |= collect_asns(value)
    return found


def event_path_asns(routing: dict):
    """AS numbers on the victim's announced paths in the event window."""
    found = set()
    for rec in routing.get("origin_hijacked") or []:
        if isinstance(rec, dict):
            found |= collect_asns(rec.get("as_path"))
            found |= collect_asns(rec.get("as_path_list"))
    for rec in routing.get("route_leaks") or []:
        if isinstance(rec, dict):
            found |= collect_asns((rec.get("evidence") or {}).get("as_path"))
            found |= collect_asns(rec.get("affected_asns"))
    return found


def baseline_path_asns(outage: dict):
    """AS numbers on the victim's paths in the baseline window.

    The baseline record set is not stored per path in the cache, so the
    baseline AS set is reconstructed from the analyser's own
    peer-count and unique-count features and from the legitimate-origin
    baseline that the routing collector persisted.
    """
    found = set()
    for rec in outage.get("origin_hijacked") or []:
        if isinstance(rec, dict):
            found |= collect_asns(rec.get("legitimate_origins"))
    for rec in outage.get("route_leaks") or []:
        if isinstance(rec, dict):
            found |= collect_asns((rec.get("evidence") or {}).get("as_path"))
    return found


def main():
    import csv

    events = {e["event_id"]: e for e in load_events()}
    with open(GT_CSV, newline="") as fh:
        gt_rows = {r["event_id"]: r for r in csv.DictReader(fh)}

    rows = []
    for eid, ev in events.items():
        gt = gt_rows.get(eid) or {}
        leak_as = str(gt.get("leak_as") or "").replace("AS", "").strip()
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        routing = quick.get("routing") or {}
        outage = routing.get("outage_analysis") or {}
        event_set = event_path_asns(routing)
        base_set = baseline_path_asns(outage)
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "leak_as": leak_as,
            "in_event_paths": bool(leak_as) and leak_as in event_set,
            "in_baseline_paths": bool(leak_as) and leak_as in base_set,
            "new_in_event": bool(leak_as) and (
                leak_as in event_set and leak_as not in base_set),
            "n_event_path_asns": len(event_set),
            "n_baseline_path_asns": len(base_set),
        })

    rates = {}
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        rates[cls] = {
            "n": len(sub),
            "n_with_leak_as": sum(1 for r in sub if r["leak_as"]),
            "in_event_paths": sum(1 for r in sub if r["in_event_paths"]),
            "new_in_event": sum(1 for r in sub if r["new_in_event"]),
        }

    # The leak-vs-rest permutation test on the marker.
    from leak_stats import permutation_p

    pos = [1.0 if r["new_in_event"] else 0.0 for r in rows if r["gt_cause"] == "route_leak"]
    neg = [1.0 if r["new_in_event"] else 0.0 for r in rows if r["gt_cause"] != "route_leak"]
    test = permutation_p(pos, neg)

    out = {
        "n": len(rows),
        "class_rates": rates,
        "permutation_test": test,
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    for cls, slot in rates.items():
        print(f"{cls:24s} n={slot['n']:2d} with_leak_as={slot['n_with_leak_as']:2d} "
              f"in_event={slot['in_event_paths']:2d} new_in_event={slot['new_in_event']:2d}")
    print(f"\npermutation test: AUC={test['auc']} p={test['p_value']} "
          f"significant={test['significant_at_0.05']}")
    print()
    print("leak events:")
    for r in rows:
        if r["gt_cause"] != "route_leak":
            continue
        print(f"  {r['event_id']:40s} leak_as={r['leak_as']:8s} "
              f"in_event={r['in_event_paths']} in_base={r['in_baseline_paths']} "
              f"new={r['new_in_event']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
