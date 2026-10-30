"""Per-feature discriminability report with cross-origin hijack accounting.

The production cause rule reads a small set of physical features.  This
script measures each feature's *actual* discriminative power against the
ground truth, and additionally measures a signal the rule does not
currently read: whether the hijack detector's records implicate a
*cross origin* (an origin that is neither the victim nor one of the
victim's legitimate origins), which is what an origin hijack looks
like, versus a detector artefact where the expected-origin baseline is
missing and every announcement is flagged.

Writes results/eval/cause_feature_report.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_feature_report.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_rows() -> list[dict]:
    path = PROJECT_ROOT / "results" / "eval" / "cause_feature_table.json"
    return json.loads(path.read_text())["rows"]


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def cross_origin_stats(ev: dict, routing: dict) -> dict:
    """How many hijack records implicate a cross origin?

    A record is *cross-origin* when its ``origin_as`` is neither the
    victim nor one of the victim's legitimate origins.  Those are the
    records that constitute an origin hijack claim.  Records that name
    the victim itself are detector artefacts: the expected-origin
    baseline was not built, so the victim's own announcements are
    flagged as hijacks.
    """
    victim = str(
        routing.get("target_asn") or routing.get("asn") or ev.get("asn") or ""
    ).replace("AS", "").strip()
    records = routing.get("origin_hijacked") or []
    cross = 0
    self_flag = 0
    other = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin_as") or "")
        legitimate = {str(x).replace("AS", "") for x in (rec.get("legitimate_origins") or [])}
        if origin and origin == victim:
            self_flag += 1
        elif victim in legitimate or (origin and origin in legitimate):
            cross += 1
        else:
            other += 1
    return {
        "hijack_records": len(records),
        "cross_origin": cross,
        "self_flagged": self_flag,
        "other_origin": other,
    }


def main() -> int:
    events = {e["event_id"]: e for e in load_events()}
    rows = load_rows()

    for row in rows:
        ev = events.get(row["event_id"])
        if not ev:
            continue
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=ev["event_id"], allow_same_date=False,
        )
        if match is None:
            row["hijack_detail"] = {}
            continue
        quick = json.loads(match.path.read_text())
        row["hijack_detail"] = cross_origin_stats(ev, quick.get("routing") or {})

    def bucket(row, name):
        if name == "cross_origin":
            return 1 if row.get("hijack_detail", {}).get("cross_origin", 0) > 0 else 0
        if name == "self_flagged":
            return 1 if row.get("hijack_detail", {}).get("self_flagged", 0) > 0 else 0
        if name == "no_baseline_expected_origin":
            return 1 if (
                row.get("hijack_detail", {}).get("hijack_records", 0) > 0
                and row.get("hijack_detail", {}).get("cross_origin", 0) == 0
            ) else 0
        return 1 if row.get(name) else 0

    features = [
        "victim_withdrew", "victim_withdrew_hard", "has_origin_hijack",
        "has_forge_hijack", "traffic_available", "traffic_signal",
        "cross_origin", "self_flagged", "no_baseline_expected_origin",
        "baseline_missing",
    ]

    report = {}
    for feat in features:
        per_class = {}
        for cls in CLASSES:
            sub = [r for r in rows if r["gt_cause"] == cls]
            hit = sum(1 for r in sub if bucket(r, feat))
            per_class[cls] = {"n": len(sub), "present": hit,
                              "rate": round(hit / len(sub), 3) if sub else None}
        # A feature is informative for a class when its rate differs
        # sharply from the corpus-wide rate for the other classes.
        report[feat] = per_class

    # Numeric separability: median withdrawal ratio and traffic drop.
    numeric = {}
    for cls in CLASSES:
        sub = [r for r in rows if r["gt_cause"] == cls]
        ratios = sorted(float(r["withdrawal_ratio"]) for r in sub)
        drops = sorted(float(r["traffic_drop_pct"]) for r in sub)
        numeric[cls] = {
            "n": len(sub),
            "withdrawal_ratio_median": round(ratios[len(ratios) // 2], 5) if ratios else None,
            "withdrawal_ratio_max": round(ratios[-1], 5) if ratios else None,
            "traffic_drop_median": round(drops[len(drops) // 2], 2) if drops else None,
            "traffic_drop_max": round(drops[-1], 2) if drops else None,
            "n_drop_ge_50": sum(1 for d in drops if d >= 50),
            "n_traffic_unavailable": sum(1 for r in sub if not r["traffic_available"]),
        }

    out = {"features": report, "numeric": numeric, "rows": rows}
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'feature':32s} {'outage':>16s} {'route_leak':>16s} {'hijack':>16s}")
    for feat, per in report.items():
        cells = []
        for cls in CLASSES:
            slot = per[cls]
            cells.append(f"{slot['present']:3d}/{slot['n']:<3d}({slot['rate']})")
        print(f"{feat:32s} {cells[0]:>16s} {cells[1]:>16s} {cells[2]:>16s}")
    print()
    for cls, slot in numeric.items():
        print(cls, json.dumps(slot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
