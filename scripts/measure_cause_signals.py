"""Measure which physical signals actually separate the GT cause classes.

Nothing in the cause decision tree should be asserted from intuition.
This script computes, for every resolvable event in the ground-truth
corpus, the candidate signals and reports each one's class separation
(lift = P(signal | class) / P(signal)), so a threshold can be chosen
from measurement rather than guessed.

The signals come from the *physical* layers only — BGP message counts,
path structure, and traffic reachability.  No LLM is involved, so the
result is an honest description of what the telemetry can and cannot
tell apart.

Usage::

    python3 scripts/measure_cause_signals.py
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def signals_for(quick: dict) -> dict:
    tr = quick.get("traffic") or {}
    rr = quick.get("routing") or {}
    out = rr.get("outage_analysis") or {}
    feats = out.get("event_features") or {}
    indicators = set(out.get("indicators") or [])

    announcements = int(feats.get("announcement_count") or 0)
    withdrawals = int(feats.get("withdrawal_count") or 0)
    ratio = (withdrawals / announcements) if announcements else 0.0

    hijacked = rr.get("origin_hijacked") or (rr.get("hijack") or {}).get("origin_hijacked") or []
    hijacking = rr.get("origin_hijacking") or (rr.get("hijack") or {}).get("origin_hijacking") or []

    drop = tr.get("peak_trough_drop_pct")
    drop = float(drop) if isinstance(drop, (int, float)) else 0.0
    opa = int(tr.get("outage_period_anomaly_count") or 0)

    return {
        "traffic_available": bool(tr.get("data_available", tr.get("success", False))),
        "traffic_anomaly_count": int(tr.get("anomaly_count") or 0),
        "traffic_drop_pct": drop,
        "outage_period_anomalies": opa,
        "announcement_count": announcements,
        "withdrawal_count": withdrawals,
        "withdrawal_ratio": ratio,
        "announcement_drop_indicator": "announcement_drop" in indicators,
        "prefix_disappearance_indicator": "prefix_disappearance" in indicators,
        "outage_suspected": bool(out.get("is_outage_suspected")),
        "origin_hijacked_count": len(hijacked),
        "origin_hijacking_count": len(hijacking),
        "has_hijack": bool(hijacked or hijacking),
        "leak_count": int(rr.get("leak_count") or 0),
        "leak_truncated": bool(rr.get("leak_results_truncated")),
    }


def lift_table(rows: list[dict], key: str, threshold) -> dict:
    """For each class, P(signal>=threshold | class) and the lift vs. all."""
    out = {}
    for cls in CLASSES:
        subset = [r for r in rows if r["gt"] == cls]
        if not subset:
            continue
        hits = sum(1 for r in subset if r["sig"][key] >= threshold)
        out[cls] = {
            "n": len(subset),
            "hits": hits,
            "p": round(hits / len(subset), 3),
        }
    total = len(rows)
    base = sum(1 for r in rows if r["sig"][key] >= threshold) / total if total else 0.0
    for cls, v in out.items():
        v["lift"] = round(v["p"] / base, 2) if base else None
        v["base_p"] = round(base, 3)
    return out


def main() -> int:
    with open(GT_CSV, newline="") as fh:
        gt_rows = list(csv.DictReader(fh))

    rows = []
    for r in gt_rows:
        asn = str(r.get("victim_as", "")).replace("AS", "").strip()
        m = resolve_cache(
            asn, r["start_utc"], r["end_utc"], QUICK_DIR,
            event_id=r["event_id"], allow_same_date=False,
        )
        if m is None:
            continue
        try:
            quick = json.loads(m.path.read_text())
        except ValueError:
            continue
        rows.append({
            "event_id": r["event_id"],
            "gt": r["cause"],
            "sig": signals_for(quick),
        })

    print(f"resolvable events: {len(rows)} / {len(gt_rows)}")
    by_class = defaultdict(int)
    for r in rows:
        by_class[r["gt"]] += 1
    print("per class:", dict(by_class))
    print()

    probes = [
        ("traffic_available", 1),
        ("traffic_drop_pct", 50.0),
        ("outage_period_anomalies", 2),
        ("withdrawal_ratio", 0.01),
        ("withdrawal_count", 1),
        ("announcement_drop_indicator", 1),
        ("prefix_disappearance_indicator", 1),
        ("outage_suspected", 1),
        ("has_hijack", 1),
        ("origin_hijacked_count", 1),
        ("origin_hijacking_count", 1),
        ("leak_count", 1),
    ]

    print("=" * 96)
    print(f"{'signal':34s} {'thr':>6s}  " + "  ".join(f"{c[:18]:>26s}" for c in CLASSES))
    print("=" * 96)
    for key, thr in probes:
        tbl = lift_table(rows, key, thr)
        cells = []
        for c in CLASSES:
            v = tbl.get(c)
            if not v:
                cells.append(f"{'-':>26s}")
            else:
                cells.append(f"p={v['p']:<5.3f} lift={str(v['lift']):>5s}".rjust(26))
        print(f"{key:34s} {thr:>6}  " + "  ".join(cells))
    print()

    # ── Combined discriminators ────────────────────────────────────────────
    print("=" * 96)
    print("COMBINED RULES — accuracy over the resolvable corpus")
    print("=" * 96)

    def evaluate(fn, name):
        correct = 0
        confusion = defaultdict(int)
        for r in rows:
            pred = fn(r["sig"])
            confusion[(r["gt"], pred)] += 1
            if pred == r["gt"]:
                correct += 1
        per = {}
        for cls in CLASSES:
            c = sum(v for (g, p), v in confusion.items() if g == cls and p == cls)
            n = sum(v for (g, p), v in confusion.items() if g == cls)
            per[cls] = {"n": n, "correct": c, "acc": round(c / n, 3) if n else None}
        print(f"  {name:52s} acc={correct}/{len(rows)}={round(correct/len(rows),3)}  {per}")

    def rule_a(s):
        # withdrawal is the outage signature; hijack needs an explicit
        # hijack event and no withdrawal; everything else is a leak.
        if s["withdrawal_ratio"] >= 0.01:
            return "outage"
        if s["has_hijack"]:
            return "origin_hijack_victim"
        return "route_leak"

    def rule_b(s):
        if s["outage_period_anomalies"] >= 2 and s["withdrawal_ratio"] >= 0.005:
            return "outage"
        if s["has_hijack"] and s["withdrawal_ratio"] < 0.005:
            return "origin_hijack_victim"
        if not s["traffic_available"] and s["leak_count"] > 0:
            return "route_leak"
        return "route_leak"

    def rule_c(s):
        # outage: victim withdrew a material share of its announcements
        if s["withdrawal_count"] > 0 and s["withdrawal_ratio"] >= 0.01:
            return "outage"
        # hijack: the victim's prefixes were re-originated by someone else
        if s["origin_hijacked_count"] > 0 and s["withdrawal_ratio"] < 0.01:
            return "origin_hijack_victim"
        return "route_leak"

    evaluate(rule_a, "A: withdrawal>=1% -> outage; else hijack?; else leak")
    evaluate(rule_b, "B: outage needs both period-anomalies and withdrawal")
    evaluate(rule_c, "C: withdrawal->outage; origin_hijacked->hijack; else leak")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
