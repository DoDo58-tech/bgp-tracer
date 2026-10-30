"""Compare cause-rule variants with a calibration / held-out split.

Tuning a decision threshold on the same events you then report accuracy
on is the standard way to make an evaluation dishonest: the threshold
becomes a fitted parameter of the answer rather than a fixed part of the
system.  This harness therefore splits the corpus in two:

* **calibration** events decide the threshold;
* **held-out** events are scored once, with the threshold frozen.

Every number printed for the held-out half is an out-of-sample number.
The split is by event, deterministic, and reported so it can be checked.

Run:
    python3 scripts/eval_cause_rules.py
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

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"

CAUSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list:
    """Load the corpus, keeping only events that are scoreable.

    Two events in the corpus share an (ASN, window) pair but carry
    different cause labels.  A single cache cannot answer two different
    questions about the same measurement, so those groups are reported
    separately and excluded from scoring rather than silently counting
    one of the two labels as a hit.
    """
    rows = list(csv.DictReader(GT_CSV.open()))
    out = []
    conflicted: list = []
    by_window: dict = {}
    for row in rows:
        asn = str(row["victim_as"]).upper().replace("AS", "").strip()
        if not asn.isdigit():
            continue
        by_window.setdefault((asn, row["start_utc"], row["end_utc"]), []).append(row)
    for (asn, start, end), group in by_window.items():
        causes = {r["cause"].strip() for r in group}
        if len(causes) > 1:
            conflicted.append({
                "asn": asn, "window": f"{start} -> {end}",
                "labels": sorted(causes),
                "event_ids": [r["event_id"] for r in group],
            })
            continue
        row = group[0]
        match = resolve_cache(
            asn, row["start_utc"], row["end_utc"], QUICK_DIR,
            event_id=row["event_id"], allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        out.append({
            "event_id": row["event_id"],
            "cause": row["cause"].strip(),
            "asn": asn,
            "quick": quick,
        })
    out.sort(key=lambda e: e["event_id"])
    return out, conflicted


def split_calibration(events: list, fraction: float = 0.5) -> tuple:
    """Deterministic interleaved split, stratified by cause.

    Interleaving rather than slicing keeps the cause mix of both halves
    the same, so a half that happens to contain no leaks cannot flatter
    or damn a rule.
    """
    by_cause: dict[str, list] = {}
    for ev in events:
        by_cause.setdefault(ev["cause"], []).append(ev)
    calibration: list = []
    heldout: list = []
    for cause in sorted(by_cause):
        group = sorted(by_cause[cause], key=lambda e: e["event_id"])
        for idx, ev in enumerate(group):
            (calibration if idx % 2 == 0 else heldout).append(ev)
    return calibration, heldout


def features(ev: dict) -> dict:
    quick = ev["quick"]
    routing = quick.get("routing") or {}
    traffic = quick.get("traffic") or {}
    outage = routing.get("outage_analysis") or {}
    ef = outage.get("event_features") or {}
    announcements = int(ef.get("announcement_count") or 0)
    withdrawals = int(ef.get("withdrawal_count") or 0)
    drop = traffic.get("peak_trough_drop_pct")
    return {
        "announcements": announcements,
        "withdrawals": withdrawals,
        "ratio": (withdrawals / announcements) if announcements else 0.0,
        "outage_suspected": bool(outage.get("is_outage_suspected")),
        "indicators": set(outage.get("indicators") or []),
        "hijack": bool(
            routing.get("origin_hijacked") or routing.get("forge_hijacked")
        ),
        "traffic_available": bool(
            traffic.get("data_available", traffic.get("success", False))
        ),
        "traffic_signal": bool(
            traffic.get("traffic_signal_present")
            or int(traffic.get("anomaly_count") or 0) > 0
        ),
        "drop_pct": float(drop) if isinstance(drop, (int, float)) else 0.0,
        "outage_period": int(traffic.get("outage_period_anomaly_count") or 0),
    }


def predict(ev: dict, f: dict, ratio_threshold: float) -> str:
    """The rule under test, with one tunable parameter."""
    traffic_collapsed = f["traffic_signal"] and f["drop_pct"] >= 50.0
    victim_withdrew = f["ratio"] >= ratio_threshold

    if f["hijack"] and not victim_withdrew:
        return "origin_hijack_victim"
    if traffic_collapsed:
        if f["outage_period"] >= 2:
            return "outage"
        if victim_withdrew and f["outage_period"] > 0:
            return "outage"
        return "origin_hijack_victim"
    if f["traffic_signal"]:
        if f["outage_suspected"] and victim_withdrew:
            return "outage"
        return "origin_hijack_victim"
    if f["traffic_available"]:
        if victim_withdrew:
            return "outage"
        return "no_clear_anomaly"
    if f["outage_suspected"]:
        return "outage"
    return "no_clear_anomaly"


def score(events: list, ratio_threshold: float) -> dict:
    per = {c: [0, 0] for c in CAUSES}
    correct = 0
    for ev in events:
        f = features(ev)
        pred = predict(ev, f, ratio_threshold)
        hit = pred == ev["cause"]
        correct += hit
        bucket = per.setdefault(ev["cause"], [0, 0])
        bucket[1] += 1
        bucket[0] += hit
    return {
        "n": len(events),
        "correct": correct,
        "accuracy": correct / len(events) if events else 0.0,
        "per_cause": {k: v for k, v in per.items() if v[1]},
    }


def main() -> int:
    events, conflicted = load_events()
    calibration, heldout = split_calibration(events)
    print(f"scoreable events: {len(events)} "
          f"(calibration {len(calibration)}, held-out {len(heldout)})")
    if conflicted:
        print(f"\nexcluded {len(conflicted)} label-conflicting window(s):")
        for c in conflicted:
            print(f"  AS{c['asn']} {c['window']} labels={c['labels']} "
                  f"events={c['event_ids']}")

    # Fit the threshold on the calibration half only.
    candidates = [0.0, 0.001, 0.002, 0.005, 0.01, 0.02, 0.03, 0.05,
                  0.08, 0.10, 0.15, 0.20, 0.30]
    best_threshold = 0.0
    best_acc = -1.0
    print("\nthreshold sweep on the CALIBRATION half:")
    for threshold in candidates:
        result = score(calibration, threshold)
        flag = ""
        if result["accuracy"] > best_acc:
            best_acc = result["accuracy"]
            best_threshold = threshold
            flag = "  <- best"
        print(f"  {threshold:6.3f}  acc={result['accuracy']:.4f} "
              f"({result['correct']}/{result['n']}){flag}")

    print(f"\nchosen threshold (from calibration only): {best_threshold}")
    print(f"calibration accuracy : {score(calibration, best_threshold)['accuracy']:.4f}")
    held = score(heldout, best_threshold)
    print(f"held-out accuracy    : {held['accuracy']:.4f} "
          f"({held['correct']}/{held['n']})")
    print("\nheld-out per cause:")
    for cause, (hit, total) in held["per_cause"].items():
        print(f"  {cause:24s} {hit}/{total}")
    print("\nheld-out event ids:")
    for ev in sorted(heldout, key=lambda e: e["event_id"]):
        f = features(ev)
        pred = predict(ev, f, best_threshold)
        mark = "ok " if pred == ev["cause"] else "MISS"
        print(f"  {mark} {ev['event_id'][:36]:36s} gt={ev['cause']:22s} "
              f"pred={pred:22s} ratio={f['ratio']:.4f} "
              f"outage_period={f['outage_period']} hijack={f['hijack']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
