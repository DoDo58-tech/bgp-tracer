"""Out-of-sample validation of the arbitration gate.

The 39-event corpus the reported numbers come from is the corpus the
cause rule was developed against.  Every number computed on it is, by
construction, an in-sample number.  This script measures the same
thing on events the rule was never shown: the events present in the
earlier ground-truth corpora and absent from the reported one.

Three arms are scored on the held-out events, over the same caches and
through the same cause normaliser as the main evaluation:

  ``rule``   the deterministic physical rule alone.
  ``agent``  the agent's free-text cause proposal alone.
  ``gate``   the production arbitration: the physical rule decides,
             except where an independent physical record corroborates
             the agent's proposal, and except where the physical layer
             observed nothing at all.

The gate arm is also compared against the strongest purely
deterministic alternative (cross-origin promotion with no agent
input).  If the gate does not beat that alternative out of sample, the
agent layer is not what earns the improvement.

Writes results/eval/heldout_validation.json.
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

EVAL = PROJECT_ROOT / "results" / "eval"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
HELDOUT_PATH = EVAL / "heldout_events.json"
OUT_PATH = EVAL / "heldout_validation.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim", "roa_misconfig")


def normalize_cause(raw: str) -> str:
    """Map a free-text cause onto the corpus vocabulary.

    This is the same mapping the main evaluation uses, so the two
    corpora are scored on identical terms.
    """
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


def run_agent_arm(quick: dict) -> dict:
    """The agent's proposal and the cause it committed to.

    The two are different quantities and the arbitration needs both.
    The *proposal* is the agent's own free-text cause, which is what the
    corroboration gate tests; the *committed* cause is what the
    arbitration finally emitted.  Scoring the committed cause as the
    agent arm would fold the gate into the agent and make the gate
    untestable, so the proposal is read from the reasoning agent's own
    classification record.
    """
    from chief_agent import analyze_deep_from_quick

    res = analyze_deep_from_quick(
        quick_result=quick, analysis_mode="traffic_first"
    )
    ec = res.get("evidence_chain") or {}
    cea = res.get("chief_expert_analysis") or {}
    arbitration = ec.get("arbitration") or {}
    committed = ec.get("cause") or cea.get("cause") or ""

    reasoning = res.get("reasoning_result") or {}
    classification = reasoning.get("llm_classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    if classification.get("source") != "llm":
        classification = {}
    proposal_raw = (
        classification.get("cause")
        or classification.get("incident_type")
        or ""
    )

    return {
        "success": bool(res.get("success")),
        "cause": normalize_cause(committed),
        "cause_raw": str(committed or ""),
        "proposal": normalize_cause(proposal_raw),
        "proposal_raw": str(proposal_raw or ""),
        "agent_confidence": arbitration.get("agent_confidence"),
        "agent_overrode_rule": bool(arbitration.get("agent_overrode_rule")),
    }


def run_rule_arm(quick: dict) -> dict:
    """The deterministic physical rule alone."""
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    builder = EvidenceChainBuilder()
    traffic = quick.get("traffic") or {}
    routing = quick.get("routing") or {}
    hard = builder.hard_physical_signature(traffic, routing)
    cause = hard or builder.cause_from_evidence(traffic, routing, "")
    return {"success": True, "cause": cause, "cause_raw": cause}


def count_cross_origin(quick: dict, victim_asn: str) -> int:
    """Physical corroboration: a third party announcing the victim's prefixes."""
    routing = quick.get("routing") or {}
    victim = str(
        routing.get("target_asn") or routing.get("asn") or victim_asn
    ).replace("AS", "").strip()
    if not victim:
        return 0
    count = 0
    for rec in routing.get("origin_hijacked") or []:
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin_as") or "").replace("AS", "").strip()
        legitimate = {
            str(x).replace("AS", "").strip()
            for x in (rec.get("legitimate_origins") or [])
        }
        if origin and origin != victim and victim in legitimate:
            count += 1
    return count


def traffic_observed(quick: dict) -> bool:
    traffic = quick.get("traffic") or {}
    return bool(
        traffic.get("data_available", traffic.get("success", False))
    )


def score(rows: list[dict], predict) -> dict:
    per_class: dict = {}
    correct = 0
    for row in rows:
        gt = row["gt_cause"]
        slot = per_class.setdefault(gt, {"n": 0, "correct": 0})
        slot["n"] += 1
        if predict(row) == gt:
            correct += 1
            slot["correct"] += 1
    recalls = [
        slot["correct"] / slot["n"] for slot in per_class.values()
        if slot["n"]
    ]
    return {
        "n": len(rows),
        "correct": correct,
        "micro": round(correct / len(rows), 4) if rows else None,
        "balanced": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "per_class": {
            cls: {
                "n": slot["n"],
                "correct": slot["correct"],
                "recall": round(slot["correct"] / slot["n"], 4),
            }
            for cls, slot in sorted(per_class.items())
        },
    }


def gate_predict(row: dict) -> str:
    """The production arbitration rule, applied to one row."""
    proposal = row.get("agent_cause") or ""
    rule = row.get("rule_cause") or ""
    if proposal and proposal == "origin_hijack_victim" and row["cross_origin"] > 0:
        return proposal
    if proposal in ("outage", "route_leak") and not row["traffic_available"]:
        return proposal
    return rule


def deterministic_cross_origin(row: dict) -> str:
    """Strongest purely deterministic alternative: no agent input at all."""
    if row["cross_origin"] > 0 and row["rule_cause"] != "origin_hijack_victim":
        return "origin_hijack_victim"
    return row["rule_cause"]


def constant_gate(constant: str):
    """The gate with the agent's proposal replaced by a fixed label.

    This is the control that separates the gate from the agent's own
    proposal: a constant that reproduces the gate arm's accuracy means
    the free-text cause contributed nothing.
    """
    def predict(row: dict) -> str:
        proposal = constant
        rule = row.get("rule_cause") or ""
        if proposal == "origin_hijack_victim" and row["cross_origin"] > 0:
            return proposal
        if proposal in ("outage", "route_leak") and not row["traffic_available"]:
            return proposal
        return rule
    return predict


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    heldout = json.loads(HELDOUT_PATH.read_text())
    if args.limit:
        heldout = heldout[: args.limit]

    rows: list[dict] = []
    for entry in heldout:
        match = resolve_cache(
            entry["asn"], entry["start"], entry["end"], QUICK_DIR,
            event_id=entry["event_id"], allow_same_date=True,
        )
        if match is None or not match.path.exists():
            continue
        quick = json.loads(match.path.read_text())
        row = {
            "event_id": entry["event_id"],
            "gt_cause": entry["gt_cause"],
            "gt_subtype": entry.get("gt_subtype"),
            "asn": entry["asn"],
            "source_corpus": entry.get("source_corpus"),
            "cache": str(match.path),
            "cross_origin": count_cross_origin(quick, entry["asn"]),
            "traffic_available": traffic_observed(quick),
        }
        row.update(run_rule_arm(quick))
        row["rule_cause"] = row.pop("cause")
        row["rule_cause_raw"] = row.pop("cause_raw")
        agent = run_agent_arm(quick)
        row["agent_cause"] = agent["proposal"]
        row["agent_cause_raw"] = agent["proposal_raw"]
        row["committed_cause"] = agent["cause"]
        row["agent_success"] = agent["success"]
        row["agent_confidence"] = agent["agent_confidence"]
        rows.append(row)
        print(
            f"  {row['event_id']:38s} rule={row['rule_cause'] or '-':22s} "
            f"prop={row['agent_cause'] or '-':22s} "
            f"gt={row['gt_cause']:22s} cross={row['cross_origin']} "
            f"traffic={row['traffic_available']}",
            flush=True,
        )

    if not rows:
        print("no held-out events resolved; nothing to score")
        return 1

    arms = {
        "rule_only": lambda r: r["rule_cause"],
        "agent_only": lambda r: r["agent_cause"],
        "corroboration_gate": gate_predict,
        "deterministic_cross_origin": deterministic_cross_origin,
    }
    for constant in ("origin_hijack_victim", "outage", "route_leak"):
        arms[f"gate_constant_{constant}"] = constant_gate(constant)
    out = {
        "n_events": len(rows),
        "events": rows,
        "arms": {name: score(rows, fn) for name, fn in arms.items()},
    }
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "corpus": "events present in heldout_events.json and absent from "
                  "the canonical final_ground_truth.csv, which is the "
                  "corpus the cause rule was developed against",
        "note": "The same caches, the same cause normaliser and the same "
                "arbitration code as the main evaluation; the only "
                "difference is that these events were not used to develop "
                "the rule.",
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print()
    print(f"{'arm':30s} {'correct':>9s} {'micro':>8s} {'balanced':>9s}")
    for name, slot in out["arms"].items():
        print(
            f"{name:30s} {slot['correct']:>4d}/{slot['n']:<4d} "
            f"{slot['micro']:>8} {slot['balanced']:>9}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
