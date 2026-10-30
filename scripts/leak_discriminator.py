"""A leak discriminator built from the leaking ASN's presence in the path.

The analysis in ``leak_asn_recoverability.py`` established two facts
about the corpus:

  * the ground truth names the leaking ASN for every route-leak event,
    and for no other class;
  * that ASN appears in the routing block for 8 of the 10 leak events,
    and for 0 of the 17 outage events and 1 of the 12 hijack events.

So the leaking ASN is a *class marker* even though it is not known a
priori: the question a classifier must answer is not "is ASN X
leaking?" but "is the ASN whose appearance in the path is anomalous
the one that is leaking?".

This script tests whether that question has a usable answer.  For each
event it finds the set of AS numbers that appear in the victim's path
but are not the victim and not one of the victim's legitimate origins,
and then asks whether the ground truth's leaking ASN is among them.  It
reports:

  * the recall of the marker set (does the leak ASN appear at all),
  * the precision of the *rule* built on it (when the marker set is
    non-empty, predict leak; otherwise not),
  * the events the rule still gets wrong.

Writes results/eval/leak_discriminator.json.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "leak_discriminator.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def load_gt_rows() -> dict:
    with open(GT_CSV, newline="") as fh:
        return {r["event_id"]: r for r in csv.DictReader(fh)}


def collect_asns(blob) -> set:
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


def path_foreign_asns(routing: dict, victim: str) -> set:
    """AS numbers seen on the victim's paths that are neither the victim
    nor one of the victim's legitimate origins."""
    victim_d = str(victim).replace("AS", "").strip()
    legitimate = {victim_d}
    for rec in routing.get("origin_hijacked") or []:
        if not isinstance(rec, dict):
            continue
        for x in (rec.get("legitimate_origins") or []):
            legitimate.add(str(x).replace("AS", "").strip())

    foreign = set()
    for rec in routing.get("origin_hijacked") or []:
        if isinstance(rec, dict):
            foreign |= collect_asns(rec.get("as_path"))
            foreign |= collect_asns(rec.get("as_path_list"))
    for rec in routing.get("route_leaks") or []:
        foreign |= collect_asns(rec)
    return {a for a in foreign if a and a not in legitimate}


def main() -> int:
    events = {e["event_id"]: e for e in load_events()}
    gt_rows = load_gt_rows()

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
        victim = str(
            routing.get("target_asn") or routing.get("asn") or ev["asn"]
        ).replace("AS", "").strip()
        foreign = path_foreign_asns(routing, victim)
        rows.append({
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "leak_as": leak_as,
            "n_foreign": len(foreign),
            "leak_as_is_foreign": bool(leak_as) and leak_as in foreign,
            "foreign_sample": sorted(foreign)[:12],
        })

    leak_rows = [r for r in rows if r["gt_cause"] == "route_leak"]
    other_rows = [r for r in rows if r["gt_cause"] != "route_leak"]

    recall = sum(1 for r in leak_rows if r["leak_as_is_foreign"])
    false_marker = sum(
        1 for r in other_rows if r["leak_as"] and r["leak_as_is_foreign"]
    )

    # The rule the marker supports: an event is a leak when the victim's
    # paths carry a foreign AS that is not the victim's own transit and
    # the leak detector reported the victim's prefix on that path.
    def predict_leak(routing: dict, victim: str, leak_records: int) -> bool:
        foreign = path_foreign_asns(routing, victim)
        if not foreign:
            return False
        return leak_records > 0

    hits = 0
    errors = []
    for r in rows:
        ev = events[r["event_id"]]
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=r["event_id"], allow_same_date=False,
        )
        quick = json.loads(match.path.read_text())
        routing = quick.get("routing") or {}
        victim = str(
            routing.get("target_asn") or routing.get("asn") or ev["asn"]
        ).replace("AS", "").strip()
        pred_leak = predict_leak(
            routing, victim, len(routing.get("route_leaks") or []))
        actual_leak = r["gt_cause"] == "route_leak"
        if pred_leak == actual_leak:
            hits += 1
        else:
            errors.append({
                "event_id": r["event_id"],
                "gt": r["gt_cause"],
                "pred_leak": pred_leak,
                "n_foreign": r["n_foreign"],
            })

    out = {
        "n": len(rows),
        "leak_marker_recall": recall,
        "leak_n": len(leak_rows),
        "false_marker_outside_leak": false_marker,
        "rule_accuracy": round(hits / len(rows), 4),
        "rule_correct": hits,
        "errors": errors,
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"leak marker recall (leak ASN present among foreign path ASNs): "
          f"{recall}/{len(leak_rows)}")
    print(f"false marker outside leak class: {false_marker}")
    print(f"rule 'foreign path AS present and leak records present': "
          f"{hits}/{len(rows)}")
    print("errors:")
    for e in errors:
        print(f"  {e['event_id']:42s} gt={e['gt']:20s} "
              f"pred_leak={e['pred_leak']} n_foreign={e['n_foreign']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
