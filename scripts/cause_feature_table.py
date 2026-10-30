"""Physical-feature table for the 39-event corpus.

Dumps, for every event, the physical features the cause rule reads, plus
the ground-truth label and the two competing predictions (deterministic
rule vs agent pipeline).  The table is the input to the arbitration
analysis: it is what decides whether a signal is *physically* separable
from the label or only separable by the agent's prose.

Writes results/eval/cause_feature_table.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from detectors.evidence_chain_builder import (  # noqa: E402
    EvidenceChainBuilder,
    TRAFFIC_DROP_THRESHOLD_PCT,
    OUTAGE_PERIOD_ANOMALY_MIN,
    WITHDRAWAL_RATIO_OUTAGE,
)

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_feature_table.json"


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def predictions() -> dict:
    out = {}
    for name, key in (("gt_agent_full", "agent"), ("gt_rule_only", "rule")):
        path = PROJECT_ROOT / "results" / "eval" / f"{name}.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        for rec in data.get("records", []):
            out.setdefault(rec["event_id"], {})[key] = rec
    return out


def main() -> int:
    builder = EvidenceChainBuilder()
    preds = predictions()
    rows = []

    for ev in load_events():
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=ev["event_id"], allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        traffic = quick.get("traffic") or {}
        routing = quick.get("routing") or {}

        outage = routing.get("outage_analysis") or {}
        features = outage.get("event_features") or {}
        withdrawals = int(features.get("withdrawal_count") or 0)
        announcements = int(features.get("announcement_count") or 0)
        ratio = builder.withdrawal_ratio(outage)

        traffic_available = bool(
            traffic.get("data_available", traffic.get("success", False))
        )
        anomalies = int(traffic.get("anomaly_count") or 0)
        signal = bool(traffic.get("traffic_signal_present") or anomalies > 0)
        drop = traffic.get("peak_trough_drop_pct")
        drop = float(drop) if isinstance(drop, (int, float)) else 0.0
        opa = int(traffic.get("outage_period_anomaly_count") or 0)

        hijack_section = routing.get("hijack") or {}
        has_origin_hijack = bool(
            routing.get("origin_hijacked") or routing.get("origin_hijacking")
            or hijack_section.get("origin_hijacked")
            or hijack_section.get("origin_hijacking")
        )
        has_forge_hijack = bool(
            routing.get("forge_hijacked") or routing.get("forge_hijacking")
            or hijack_section.get("forge_hijacked")
            or hijack_section.get("forge_hijacking")
        )
        leak_count = int(routing.get("leak_count") or 0)
        leak_truncated = bool(routing.get("leak_results_truncated"))
        leak_skipped = bool(routing.get("leak_analysis_skipped"))
        evidenced_leaks = builder.count_evidenced_leaks(
            routing, routing.get("target_asn") or routing.get("asn")
        )
        victim_withdrew = (
            ratio >= WITHDRAWAL_RATIO_OUTAGE and withdrawals >= 100
        )
        victim_withdrew_hard = (
            ratio >= WITHDRAWAL_RATIO_OUTAGE and withdrawals >= 1000
        )

        rule_cause = builder.cause_from_evidence(traffic, routing, "")
        physical = builder.hard_physical_signature(traffic, routing)

        p = preds.get(ev["event_id"], {})
        agent_rec = p.get("agent") or {}
        rule_rec = p.get("rule") or {}

        rows.append({
            "event_id": ev["event_id"],
            "asn": ev["asn"],
            "gt_cause": ev["gt_cause"],
            "agent_cause": agent_rec.get("cause"),
            "rule_cause": rule_rec.get("cause") or rule_cause,
            "agent_overrode_rule": agent_rec.get("agent_overrode_rule"),
            "agent_confidence": agent_rec.get("agent_confidence"),
            "has_origin_hijack": has_origin_hijack,
            "has_forge_hijack": has_forge_hijack,
            "victim_withdrew": victim_withdrew,
            "victim_withdrew_hard": victim_withdrew_hard,
            "withdrawal_ratio": round(ratio, 5),
            "withdrawal_count": withdrawals,
            "announcement_count": announcements,
            "traffic_available": traffic_available,
            "traffic_signal": signal,
            "traffic_drop_pct": round(drop, 2),
            "outage_period_anomalies": opa,
            "leak_count": leak_count,
            "leak_truncated": leak_truncated,
            "leak_skipped": leak_skipped,
            "evidenced_leaks": evidenced_leaks,
            "physical_veto": physical,
            "baseline_weeks": traffic.get("baseline_weeks_available"),
            "rule_from_evidence": rule_cause,
        })

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps({"rows": rows}, indent=1, default=str))
    print(f"wrote {len(rows)} rows to {OUT_PATH}")

    from collections import Counter
    print("gt distribution:", Counter(r["gt_cause"] for r in rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
