"""Extract the agent's free-text cause proposal for every evaluation event.

The committed cause in an evaluation artefact is the output of the
arbitration, not the agent's own opinion.  Scoring the committed cause
as the agent arm would fold the gate into the agent and make the gate
untestable, so the proposal has to be read from the reasoning agent's
classification record.

This script runs the agent once over every event of both corpora and
writes the proposal, the physical quantities the arbitration reads, and
the committed cause into one artefact.  Both corpora are then scored
by the same code from the same file.

Writes results/eval/agent_proposals.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402

EVAL = PROJECT_ROOT / "results" / "eval"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = EVAL / "agent_proposals.json"
HELDOUT_PATH = EVAL / "heldout_events.json"


def normalize_cause(raw: str) -> str:
    text = str(raw or "").strip().lower().replace("-", " ")
    if not text:
        return ""
    rules = (
        ("origin hijack", "origin_hijack_victim"),
        ("path forgery", "origin_hijack_victim"),
        ("roa misconfig", "roa_misconfig"),
        ("route leak", "route_leak"),
        ("leak", "route_leak"),
        ("outage", "outage"),
        ("traffic only", "traffic_anomaly_only"),
        ("no clear anomaly", "no_clear_anomaly"),
    )
    for needle, label in rules:
        if needle in text:
            return label
    return ""


def physical_quantities(cache_path: Path) -> dict:
    quick = json.loads(cache_path.read_text())
    traffic = quick.get("traffic") or {}
    routing = quick.get("routing") or {}
    builder = EvidenceChainBuilder()

    veto = builder.hard_physical_signature(traffic, routing)
    from_evidence = builder.cause_from_evidence(traffic, routing, "")
    outage = routing.get("outage_analysis") or {}
    features = outage.get("event_features") or {}
    withdrawals = int(features.get("withdrawal_count") or 0)
    announcements = int(features.get("announcement_count") or 0)
    ratio = (withdrawals / announcements) if announcements > 0 else 0.0

    return {
        "veto": veto,
        "from_evidence": from_evidence,
        "rule_cause": veto or from_evidence,
        "cross_origin": builder.count_cross_origin_records(routing),
        "traffic_available": bool(
            traffic.get("data_available", traffic.get("success", False))
        ),
        "withdrew_hard": ratio >= 0.01 and withdrawals >= 1000,
        "withdrawal_ratio": round(ratio, 4),
        "withdrawal_count": withdrawals,
        "announcement_count": announcements,
    }


def agent_run(cache_path: Path) -> dict:
    from chief_agent import analyze_deep_from_quick

    quick = json.loads(cache_path.read_text())
    res = analyze_deep_from_quick(
        quick_result=quick, analysis_mode="traffic_first"
    )
    reasoning = res.get("reasoning_result") or {}
    classification = reasoning.get("llm_classification") or {}
    if not isinstance(classification, dict) or classification.get("source") != "llm":
        classification = {}
    raw = classification.get("cause") or classification.get("incident_type") or ""
    ec = res.get("evidence_chain") or {}
    arbitration = ec.get("arbitration") or {}
    return {
        "proposal": normalize_cause(raw),
        "proposal_raw": str(raw or ""),
        "committed": normalize_cause(
            ec.get("cause") or (res.get("chief_expert_analysis") or {}).get("cause") or ""
        ),
        "agent_confidence": arbitration.get("agent_confidence"),
    }


def development_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def heldout_events() -> list[dict]:
    return json.loads(HELDOUT_PATH.read_text())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--corpus", choices=("development", "heldout", "both"),
                    default="both")
    args = ap.parse_args()

    out: dict = {"development": [], "heldout": []}

    if args.corpus in ("development", "both"):
        for ev in development_events():
            match = resolve_cache(
                ev["asn"], ev["start"], ev["end"], QUICK_DIR,
                event_id=ev["event_id"], allow_same_date=False,
            )
            if match is None:
                continue
            row = {
                "event_id": ev["event_id"],
                "gt_cause": ev["gt_cause"],
                "asn": ev["asn"],
                "cache": str(match.path),
            }
            row.update(physical_quantities(match.path))
            row.update(agent_run(match.path))
            out["development"].append(row)
            print(f"  dev {row['event_id']:44s} prop={row['proposal'] or '-':22s} "
                  f"gt={row['gt_cause']}", flush=True)

    if args.corpus in ("heldout", "both"):
        for ev in heldout_events():
            match = resolve_cache(
                ev["asn"], ev["start"], ev["end"], QUICK_DIR,
                event_id=ev["event_id"], allow_same_date=True,
            )
            if match is None:
                continue
            row = {
                "event_id": ev["event_id"],
                "gt_cause": ev["gt_cause"],
                "asn": ev["asn"],
                "cache": str(match.path),
            }
            row.update(physical_quantities(match.path))
            row.update(agent_run(match.path))
            out["heldout"].append(row)
            print(f"  held {row['event_id']:44s} prop={row['proposal'] or '-':22s} "
                  f"gt={row['gt_cause']}", flush=True)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": "The proposal is the reasoning agent's own free-text cause, "
                "read from llm_classification. The committed cause is what "
                "the arbitration emitted. Both corpora are produced by "
                "this script so they are scored on identical terms.",
    }
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
