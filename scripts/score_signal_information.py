#!/usr/bin/env python3
"""Measure how much cause information the detector output actually carries.

This is an information-content audit, not a classifier fit.  For every
detector signal the script reports how well it separates the corpus's
cause classes, using the *prior* over classes as the baseline:

    lift = P(signal | class) / P(signal | corpus)

A signal whose lift is ~1.0 for every class carries no cause
information, no matter how plausible it looks.  This is what tells us
whether the agent can possibly beat a deterministic rule on cause, or
whether the honest ceiling is set by the data.

Usage:
    python scripts/score_signal_information.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "signal_information.json"


def load_events() -> list[dict]:
    rows = list(csv.DictReader(GT_CSV.open()))
    out = []
    for r in rows:
        asn = str(r.get("victim_as") or "").replace("AS", "").strip()
        match = resolve_cache(
            asn, (r.get("start_utc") or "").strip(), (r.get("end_utc") or "").strip(),
            QUICK_DIR, event_id=r["event_id"], allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        traffic = quick.get("traffic") or {}
        routing = quick.get("routing") or {}
        outage = routing.get("outage_analysis") or {}
        out.append(
            {
                "event_id": r["event_id"],
                "cause": (r.get("cause") or "").strip(),
                "traffic_available": bool(traffic.get("success")),
                "traffic_anomalies": int(traffic.get("anomaly_count") or 0),
                "traffic_drop_pct": float(
                    traffic.get("peak_trough_drop_pct") or 0.0
                ),
                "outage_period_anomalies": int(
                    traffic.get("outage_period_anomaly_count") or 0
                ),
                "leak_count": int(routing.get("leak_count") or 0),
                "leak_count_total": int(routing.get("leak_count_total") or 0),
                "leak_truncated": bool(routing.get("leak_results_truncated")),
                "leak_skipped": bool(routing.get("leak_analysis_skipped")),
                "routing_outage_suspected": bool(outage.get("is_outage_suspected")),
                "routing_outage_score": float(outage.get("outage_score") or 0.0),
                "hijack_events": len(routing.get("origin_hijacked") or []) + len(
                    routing.get("forge_hijacked") or []
                ),
            }
        )
    return out


SIGNALS = (
    "traffic_available",
    "traffic_signal",
    "traffic_drop_ge_50",
    "leak_count_positive",
    "leak_truncated",
    "routing_outage_suspected",
    "routing_outage_score_positive",
    "hijack_events_positive",
    "outage_period_anomalies_ge_2",
)


def signal_value(rec: dict, signal: str) -> bool:
    if signal == "traffic_available":
        return rec["traffic_available"]
    if signal == "traffic_signal":
        return rec["traffic_anomalies"] > 0
    if signal == "traffic_drop_ge_50":
        return rec["traffic_drop_pct"] >= 50.0
    if signal == "leak_count_positive":
        return rec["leak_count"] > 0
    if signal == "leak_truncated":
        return rec["leak_truncated"]
    if signal == "routing_outage_suspected":
        return rec["routing_outage_suspected"]
    if signal == "routing_outage_score_positive":
        return rec["routing_outage_score"] > 0.0
    if signal == "hijack_events_positive":
        return rec["hijack_events"] > 0
    if signal == "outage_period_anomalies_ge_2":
        return rec["outage_period_anomalies"] >= 2
    raise KeyError(signal)


def main() -> int:
    events = load_events()
    classes = sorted({e["cause"] for e in events})
    n = len(events)
    priors = {c: sum(1 for e in events if e["cause"] == c) / n for c in classes}

    report = {}
    for signal in SIGNALS:
        base = sum(1 for e in events if signal_value(e, signal)) / n
        rows = {}
        for c in classes:
            sub = [e for e in events if e["cause"] == c]
            hits = sum(1 for e in sub if signal_value(e, signal))
            p = hits / len(sub) if sub else 0.0
            rows[c] = {
                "n": len(sub),
                "hits": hits,
                "p_signal_given_class": round(p, 4),
                "lift": round(p / base, 4) if base else None,
            }
        report[signal] = {"corpus_rate": round(base, 4), "by_class": rows}

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(
        {"n": n, "priors": priors, "signals": report, "events": events},
        indent=1,
    ))

    print(f"n = {n}, class priors: "
          f"{ {c: round(p, 3) for c, p in priors.items()} }\n")
    for signal, st in report.items():
        lifts = {c: v["lift"] for c, v in st["by_class"].items()}
        vals = [v for v in lifts.values() if v is not None]
        spread = (max(vals) - min(vals)) if vals else 0.0
        flag = "INFORMATIVE" if spread >= 0.30 else ("weak" if spread >= 0.10 else "no info")
        print(f"{signal:34s} rate={st['corpus_rate']:.2f}  lift={lifts}  -> {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
