"""Does the victim's own ASN appear in the announced path?

A route leak and an origin hijack produce the same detector output:
an announcement of the victim's prefix with an origin that is not the
victim.  They differ in *why*.

  * In a leak the victim originated the announcement and handed it to a
    peer it should not have.  The announcement still carries the
    victim's ASN in its AS path, because the victim's routers put
    their own ASN on it.  The path seen by a peer therefore contains
    the victim.
  * In a hijack the victim's ASN originated nothing.  The hijacker's
    announcement carries the hijacker's ASN and no trace of the victim.

So the discriminator is whether the victim's ASN appears inside the
AS path of the very records the hijack detector reported.  This script
measures that rate per class, and the permutation test of it.

Writes results/eval/victim_in_path.json.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "victim_in_path.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")
SEED = 20240117


def load_events():
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def path_asns(record: dict):
    raw = str(record.get("as_path") or "")
    return [hop for hop in raw.split() if hop.strip().isdigit()]


def analyse(routing: dict, victim: str):
    records = routing.get("origin_hijacked") or []
    victim_d = str(victim).replace("AS", "").strip()
    total = 0
    contains = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        hops = path_asns(rec)
        if not hops:
            continue
        total += 1
        if victim_d in hops:
            contains += 1
    return {
        "n_records_with_path": total,
        "n_path_containing_victim": contains,
        "fraction": round(contains / total, 4) if total else None,
    }


def permutation_p(positives, negatives, seed=SEED, trials=5000):
    from leak_identifiability_verdict import auc

    if not positives or not negatives:
        return {"auc": 0.5, "p_value": 1.0, "significant_at_0.05": False}
    observed = auc(positives, negatives)
    pool = list(positives) + list(negatives)
    n_pos = len(positives)
    rng = random.Random(seed)
    count = 0
    for _ in range(trials):
        rng.shuffle(pool)
        a = auc(pool[:n_pos], pool[n_pos:])
        if abs(a - 0.5) >= abs(observed - 0.5):
            count += 1
    return {
        "auc": round(observed, 4),
        "p_value": round(count / trials, 4),
        "significant_at_0.05": (count / trials) < 0.05,
    }


def main():
    events = {e["event_id"]: e for e in load_events()}
    rows = []
    for eid, ev in events.items():
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        routing = quick.get("routing") or {}
        victim = str(
            routing.get("target_asn") or routing.get("asn") or ev["asn"]
        ).replace("AS", "").strip()
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            **analyse(routing, victim),
        })

    print(f"{'event':42s} {'gt':22s} {'recs':>7s} {'in_path':>8s} {'frac':>7s}")
    for r in sorted(rows, key=lambda x: (x["gt_cause"], x["event_id"])):
        frac = r["fraction"]
        frac_s = f"{frac:.3f}" if frac is not None else "-"
        print(f"{r['event_id']:42s} {r['gt_cause']:22s} "
              f"{r['n_records_with_path']:>7d} "
              f"{r['n_path_containing_victim']:>8d} {frac_s:>7s}")

    print()
    pos = []
    neg = []
    for r in rows:
        if r["fraction"] is None:
            continue
        if r["gt_cause"] == "route_leak":
            pos.append(r["fraction"])
        else:
            neg.append(r["fraction"])
    test = permutation_p(pos, neg)
    print(f"leak vs rest: AUC={test['auc']} p={test['p_value']} "
          f"significant={test['significant_at_0.05']}")

    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        fracs = sorted(r["fraction"] for r in sub if r["fraction"] is not None)
        print(f"{cls:24s} n={len(sub):2d} median={fracs[len(fracs)//2] if fracs else None} "
              f"min={fracs[0] if fracs else None} max={fracs[-1] if fracs else None}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(
        {"rows": rows, "permutation_test": test}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
