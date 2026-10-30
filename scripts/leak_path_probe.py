"""Probe the raw routing records for a leak signature.

A route leak and an origin hijack are both "the victim's prefixes are
announced by someone else", but their AS paths differ:

* leak -- the leaker re-exports a route it legitimately learned, so
  the victim's ASN is still in the AS path and the origin is a third
  party;
* hijack -- the attacker originates the prefix, so the victim's ASN is
  absent from the path.

This script walks every hijack-detector record of every event (both
the ``origin_hijacked`` and ``origin_hijacking`` lists) and reports how
often the victim is still present in the path of a cross-origin
announcement.  It then checks whether the ground-truth leaking ASN is
the origin of any of them.
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


def path_set(rec: dict) -> set[str]:
    raw = rec.get("as_path") or rec.get("as-path") or ""
    if isinstance(raw, list):
        return {str(x).replace("AS", "").strip() for x in raw}
    return {t.replace("AS", "").strip() for t in str(raw).replace("|", " ").split() if t.strip()}


def probe(path: Path, ev: dict) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    victim = ev["asn"]
    actor = ev["gt_leak_as"] or ev["gt_attacker_as"]

    stats = {
        "acked": 0, "acking": 0,
        "cross_acked": 0, "cross_acking": 0,
        "cross_acked_victim_in_path": 0, "cross_acking_victim_in_path": 0,
        "actor_origin_acked": 0, "actor_origin_acking": 0,
        "actor_origin_victim_in_path_acked": 0, "actor_origin_victim_in_path_acking": 0,
        "actor_in_path_acked": 0, "actor_in_path_acking": 0,
    }
    actor_origins = Counter()

    for key, tag in (("origin_hijacked", "acked"), ("origin_hijacking", "acking")):
        for rec in routing.get(key) or []:
            if not isinstance(rec, dict):
                continue
            stats[tag] += 1
            origin = str(rec.get("origin_as") or "").replace("AS", "").strip()
            legit = {str(x).replace("AS", "").strip() for x in (rec.get("legitimate_origins") or [])}
            tokens = path_set(rec)
            if actor and origin == actor:
                stats[f"actor_origin_{tag}"] += 1
                actor_origins[origin] += 1
                if victim in tokens:
                    stats[f"actor_origin_victim_in_path_{tag}"] += 1
            if actor and actor in tokens:
                stats[f"actor_in_path_{tag}"] += 1
            if not origin or origin == victim:
                continue
            if victim not in legit and origin not in legit:
                continue
            stats[f"cross_{tag}"] += 1
            if victim in tokens:
                stats[f"cross_{tag}_victim_in_path"] += 1

    return {
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
        "victim": victim,
        "actor": actor,
        **stats,
        "actor_origin_examples": actor_origins.most_common(3),
    }


def main() -> None:
    rows = []
    for ev in load_gt():
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        rows.append(probe(match.path, ev))

    out = PROJECT_ROOT / "results" / "eval" / "leak_path_probe.json"
    out.write_text(json.dumps(rows, indent=1))

    hdr = (f"{'event_id':42s} {'gt':>8s} {'victim':>7s} {'actor':>7s} "
           f"{'cAck':>7s} {'cAckVP':>7s} {'cIng':>7s} {'cIngVP':>7s} "
           f"{'aOrigA':>7s} {'aOrigI':>7s} {'aVP_A':>6s} {'aVP_I':>6s}")
    print(hdr)
    for r in sorted(rows, key=lambda x: (x["gt_cause"], x["event_id"])):
        print(
            f"{r['event_id'][:42]:42s} {r['gt_cause'][:8]:>8s} {r['victim']:>7s} "
            f"{str(r['actor'] or '-'):>7s} {r['cross_acked']:>7d} "
            f"{r['cross_acked_victim_in_path']:>7d} {r['cross_acking']:>7d} "
            f"{r['cross_acking_victim_in_path']:>7d} "
            f"{r['actor_origin_acked']:>7d} {r['actor_origin_acking']:>7d} "
            f"{r['actor_origin_victim_in_path_acked']:>6d} "
            f"{r['actor_origin_victim_in_path_acking']:>6d}"
        )


if __name__ == "__main__":
    main()
