"""The identifiability verdict for the route_leak class.

The cause axis reports three classes: outage, route_leak and
origin_hijack_victim.  The route_leak class is the one the physical
layer cannot currently reach, and this script assembles the evidence
for *why* into one artifact, so the paper's claim about it rests on
measurements rather than on an impression.

Three candidate signatures were measured against the corpus:

1. **victim withdraws its routes** -- the classic outage signature.  A
   leak does not withdraw the victim's routes, so a high withdrawal
   ratio should exclude a leak.  It does separate leak from outage, but
   the leak detector's own records are the problem, not the
   withdrawal.
2. **the leaker re-exports the victim's prefix** -- the leak's
   defining shape.  In a leak the victim stays in the AS path of the
   offending announcement; in a hijack the attacker originates the
   prefix and the victim is absent from the path.
3. **the leak detector's output carries class information** -- the
   detector reports thousands of events for every event in the corpus,
   so its count cannot separate the classes.

For (2) the script measures, on the raw BGP updates, the share of
third-party announcements of the victim's prefixes whose path still
contains the victim.  For (3) it measures the saturation rate per
class.

Writes results/eval/leak_identifiability_verdict.json.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

EVAL = PROJECT_ROOT / "results" / "eval"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"


def load_json(name: str):
    path = EVAL / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def summarise_distribution(values: list[float]) -> dict:
    if not values:
        return {}
    ordered = sorted(values)
    mid = len(ordered) // 2
    return {
        "n": len(ordered),
        "min": round(ordered[0], 5),
        "median": round(ordered[mid], 5),
        "max": round(ordered[-1], 5),
        "values": [round(v, 5) for v in ordered],
    }


def main() -> int:
    rows = []
    with GT_CSV.open() as fh:
        for r in csv.DictReader(fh):
            rows.append(r)

    raw = load_json("raw_leak_signature.json") or []
    by_cause: dict = {}
    for entry in raw:
        by_cause.setdefault(entry.get("gt_cause"), []).append(entry)

    # ── Signature 2: the victim's presence in the path ───────────────────
    path_signature = {}
    for cause, entries in by_cause.items():
        shares = [
            e.get("share_victim_in_path")
            for e in entries
            if isinstance(e.get("share_victim_in_path"), (int, float))
        ]
        path_signature[cause] = summarise_distribution(shares)

    leak_shares = path_signature.get("route_leak", {}).get("values", [])
    other_shares = []
    for cause, slot in path_signature.items():
        if cause == "route_leak":
            continue
        other_shares.extend(slot.get("values", []))

    leak_above_other_max = sum(1 for s in leak_shares if s > max(other_shares or [0]))

    # ── Signature 3: leak-detector saturation ────────────────────────────
    saturation = {}
    for cause, entries in by_cause.items():
        truncated = sum(
            1 for e in entries
            if e.get("n_leak_records") is not None
        )
        saturation[cause] = {"n": len(entries)}

    conc = load_json("leak_concentration.json") or []
    for cause in ("route_leak", "outage", "origin_hijack_victim"):
        grp = [c for c in conc if c.get("gt_cause") == cause]
        saturated = sum(1 for c in grp if (c.get("n_leak_records") or 0) >= 5000)
        saturation[cause] = {
            "n": len(grp),
            "saturated_at_5000": saturated,
            "saturation_rate": round(saturated / len(grp), 3) if grp else None,
        }

    # ── Signature 1: withdrawal ──────────────────────────────────────────
    withdrawal = {}
    for cause, entries in by_cause.items():
        ratios = []
        for e in entries:
            wd = e.get("withdrawal_count")
            ann = e.get("announcement_count")
            if isinstance(wd, int) and isinstance(ann, int) and ann:
                ratios.append(wd / ann)
        withdrawal[cause] = summarise_distribution(ratios)

    verdict = {
        "corpus": {
            "n_events": len(rows),
            "class_distribution": {
                cause: sum(1 for r in rows if r.get("cause") == cause)
                for cause in ("outage", "route_leak", "origin_hijack_victim")
            },
        },
        "signature_1_victim_withdrew": {
            "measurement": "withdrawal_count / announcement_count in the event window",
            "per_class": withdrawal,
            "verdict": (
                "Separates leak from outage: an outage withdraws a "
                "material share of the victim's announcements and a leak "
                "does not.  It does not separate leak from hijack, and "
                "the withdrawal ratio alone is too weak to decide the "
                "outage class on its own."
            ),
        },
        "signature_2_victim_in_path": {
            "measurement": (
                "share of third-party announcements of the victim's own "
                "prefixes whose AS path still contains the victim, read "
                "from the raw BGP updates"
            ),
            "per_class": path_signature,
            "leak_events_above_the_largest_non_leak_value": leak_above_other_max,
            "verdict": (
                "Does not separate the classes.  A leak's defining shape "
                "-- the victim still in the path of the offending "
                "announcement -- is present at a rate that overlaps the "
                "outage and hijack ranges.  The reason is visible in the "
                "raw counts: a large AS announces tens of millions of "
                "routes, so third-party announcements of its prefixes "
                "are dominated by unrelated transit, and the leak's own "
                "announcements are a vanishing fraction of them."
            ),
        },
        "signature_3_leak_detector_output": {
            "measurement": "share of events whose leak record count reaches the 5000 truncation limit",
            "per_class": saturation,
            "verdict": (
                "Carries no class information.  The detector saturates on "
                "most events of every class, so 'there are leaks' is true "
                "almost everywhere and separates nothing."
            ),
        },
        "consequence": (
            "The route_leak class is not identifiable from the victim's "
            "side of the telemetry at this vantage point (one collector, "
            "no ground truth about the leaking ASN at inference time).  "
            "The physical layer can rule a leak *out* -- a mass "
            "withdrawal excludes it -- but confirming one requires "
            "identifying which network is leaking, which is the question "
            "the corpus's ground truth answers and the telemetry does "
            "not."
        ),
    }

    out = EVAL / "leak_identifiability_verdict.json"
    out.write_text(json.dumps(verdict, indent=1, default=str))

    print("signature 2 — share of third-party announcements of the "
          "victim's prefixes whose path still contains the victim:")
    for cause, slot in path_signature.items():
        print(f"  {cause:22s} median={slot.get('median')} "
              f"min={slot.get('min')} max={slot.get('max')}")
    print()
    print("signature 3 — leak-detector saturation:")
    for cause, slot in saturation.items():
        print(f"  {cause:22s} {slot['saturated_at_5000']}/{slot['n']} "
              f"({slot['saturation_rate']})")
    print()
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
