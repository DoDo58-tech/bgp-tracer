"""Separate a leak from a hijack using the detector's own record semantics.

The hijack detector emits an ``origin_hijacked`` record when the target
network legitimately owns a prefix and *someone else* announced it.
That is the shared precondition of a leak and a hijack, and the
detector cannot distinguish them, because from the victim's side the
two look alike: the victim's prefix is being exported by a network that
is not the victim's own upstream.

What separates them is *who* exports it and *how*:

* a **hijack** is the attacker originating the prefix, so the
  announcement's AS path does not contain the victim at all -- the
  attacker's route replaces the victim's;
* a **leak** is a peer re-exporting the route it legitimately learned,
  so the victim's ASN is still in the path.

This script measures that distinction on the detector's own records,
which is the population the cause rule already reads.  It reports, per
event, how many cross-origin announcements keep the victim in the path
and how many drop it, and it checks whether the ground-truth actor
appears among the origins that keep the victim in the path.

Writes results/eval/hijack_vs_leak_path.json.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "hijack_vs_leak_path.json"


def load_gt() -> list[dict]:
    out = []
    for r in csv.DictReader(GT_CSV.open()):
        out.append(
            {
                "event_id": r["event_id"],
                "asn": str(r.get("victim_as") or "").replace("AS", "").strip(),
                "start": (r.get("start_utc") or "").strip(),
                "end": (r.get("end_utc") or "").strip(),
                "gt_cause": (r.get("cause") or "").strip(),
                "gt_leak_as": (r.get("leak_as") or "").replace("AS", "").strip(),
                "gt_attacker_as": (r.get("attacker_as") or "").replace("AS", "").strip(),
            }
        )
    return out


def path_tokens(record: dict) -> list[str]:
    raw = record.get("as_path") or record.get("as-path") or ""
    return [t for t in str(raw).replace("|", " ").split() if t]


def analyze(path: Path, ev: dict) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    victim = ev["asn"]

    keep = 0            # victim still in the path -> re-export -> leak shape
    drop = 0            # victim absent -> origination -> hijack shape
    keep_origins: Counter = Counter()
    drop_origins: Counter = Counter()
    keep_prefixes: set = set()
    drop_prefixes: set = set()

    for rec in routing.get("origin_hijacked") or []:
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin_as") or "").replace("AS", "").strip()
        if not origin or origin == victim:
            continue
        legit = {str(x).replace("AS", "").strip() for x in (rec.get("legitimate_origins") or [])}
        if victim not in legit:
            continue
        pfx = str(rec.get("prefix") or "")
        tokens = path_tokens(rec)
        if victim in tokens:
            keep += 1
            keep_origins[origin] += 1
            if pfx:
                keep_prefixes.add(pfx)
        else:
            drop += 1
            drop_origins[origin] += 1
            if pfx:
                drop_prefixes.add(pfx)

    actor = ev["gt_leak_as"] or ev["gt_attacker_as"]
    total = keep + drop
    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "victim": victim,
        "gt_actor": actor,
        "n_cross_origin": total,
        "n_keep_victim_in_path": keep,
        "n_drop_victim_absent": drop,
        "keep_share": round(keep / total, 4) if total else None,
        "n_keep_prefixes": len(keep_prefixes),
        "n_drop_prefixes": len(drop_prefixes),
        "keep_origins": keep_origins.most_common(8),
        "drop_origins": drop_origins.most_common(8),
        "actor_in_keep": bool(actor and keep_origins.get(actor)),
        "actor_in_drop": bool(actor and drop_origins.get(actor)),
        "actor_keep_count": keep_origins.get(actor, 0) if actor else 0,
        "actor_drop_count": drop_origins.get(actor, 0) if actor else 0,
    }


def main() -> int:
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        rows.append(analyze(match.path, ev))

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))

    print(f"{'event_id':42s} {'gt':>8s} {'cross':>7s} {'keep':>7s} {'drop':>7s} "
          f"{'keepSh':>7s} {'actor':>8s} {'aKeep':>7s} {'aDrop':>7s}")
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        print(f"\n===== {cause} (n={len(grp)}) =====")
        for r in sorted(grp, key=lambda x: x["event_id"]):
            print(
                f"{r['event_id'][:42]:42s} {r['gt_cause'][:8]:>8s} "
                f"{r['n_cross_origin']:>7d} {r['n_keep_victim_in_path']:>7d} "
                f"{r['n_drop_victim_absent']:>7d} {str(r['keep_share']):>7s} "
                f"{str(r['gt_actor'] or '-'):>8s} {r['actor_keep_count']:>7d} "
                f"{r['actor_drop_count']:>7d}"
            )

    print()
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [r for r in rows if r["gt_cause"] == cause]
        if not grp:
            continue
        shares = sorted(
            r["keep_share"] for r in grp if isinstance(r["keep_share"], (int, float))
        )
        keeps = sorted(r["n_keep_victim_in_path"] for r in grp)
        sh = f"{shares[len(shares)//2]:.3f}" if shares else "n/a"
        print(f"{cause:22s} n={len(grp):2d} keep_share median={sh:>7} "
              f"keep_count median={keeps[len(keeps)//2]:>6d} "
              f"max={keeps[-1]:>6d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
