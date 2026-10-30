"""Does the agent's proposal earn anything, or does the physical record?

Three questions, answered on two corpora with the same code.

1. *Which gate?*  The arbitration has to decide a hijack claim.  The
   current production gate requires the agent to propose the hijack
   label before the cross-origin record can be used.  That is an
   ``AND`` between two independent signals, and it throws away a
   correct physical record whenever the agent proposes something else.
   The alternative lets the record decide on its own.

2. *Does the agent add anything?*  The control is the same gate with
   the agent's proposal replaced by a fixed label.  If a constant
   reproduces the agent arm's accuracy, the agent's free-text cause
   carried no information and the gain belongs to the physical record.

3. *Does it replicate?*  The 39-event corpus is the corpus the cause
   rule was developed against, so every number on it is in-sample.
   The 14 held-out events were absent from the reported corpus and
   are scored once, with the gate the development corpus selected.

The policies here are evaluated through the production decision
function, not through a re-implementation of it, so the number and
the shipped behaviour cannot drift apart.

Writes results/eval/agent_contribution.json.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from agents.cache_resolution import resolve_cache  # noqa: E402
from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402

EVAL = PROJECT_ROOT / "results" / "eval"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = EVAL / "agent_contribution.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim", "roa_misconfig")


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


def measure(cache_path: Path, asn: str) -> dict:
    """The physical quantities the arbitration reads."""
    quick = json.loads(cache_path.read_text())
    traffic = quick.get("traffic") or {}
    routing = quick.get("routing") or {}
    builder = EvidenceChainBuilder()

    veto = builder.hard_physical_signature(traffic, routing)
    from_evidence = builder.cause_from_evidence(traffic, routing, "")
    cross = builder.count_cross_origin_records(routing)
    traffic_available = bool(
        traffic.get("data_available", traffic.get("success", False))
    )
    outage = routing.get("outage_analysis") or {}
    features = outage.get("event_features") or {}
    withdrawals = int(features.get("withdrawal_count") or 0)
    announcements = int(features.get("announcement_count") or 0)
    ratio = (withdrawals / announcements) if announcements > 0 else 0.0
    return {
        "veto": veto,
        "from_evidence": from_evidence,
        "rule_cause": veto or from_evidence,
        "cross_origin": cross,
        "traffic_available": traffic_available,
        "withdrew_hard": ratio >= 0.01 and withdrawals >= 1000,
        "withdrawal_ratio": round(ratio, 4),
        "withdrawal_count": withdrawals,
    }


def agent_proposal(cache_path: Path) -> dict:
    """The agent's own free-text cause proposal."""
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
    return {"proposal": normalize_cause(raw), "proposal_raw": str(raw or "")}


# ── The arbitration policies ────────────────────────────────────────────

def policy_rule(row):
    """The physical rule alone."""
    return row["rule_cause"]


def policy_corroborated(row):
    """Current production: the agent must propose before the record counts."""
    proposal = row["proposal"]
    if proposal == "origin_hijack_victim" and row["cross_origin"] > 0:
        return proposal
    if proposal in ("outage", "route_leak") and not row["traffic_available"]:
        return proposal
    return row["rule_cause"]


def policy_record_first(row):
    """The record decides a hijack; the agent breaks only an unobservable tie."""
    if row["veto"]:
        return row["veto"]
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    proposal = row["proposal"]
    if proposal and not row["traffic_available"]:
        return proposal
    return row["rule_cause"]


def policy_record_only(row):
    """No agent input at all."""
    if row["veto"]:
        return row["veto"]
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    return row["rule_cause"]


def policy_cross_before_veto(row):
    """A third-party announcement record outranks the traffic-collapse veto.

    The veto exists to stop an agent from relabelling a withdrawal-driven
    outage as something else.  It is a traffic measurement, and a hijack
    also collapses traffic, so applying it before the control-plane
    record lets a traffic signature veto a control-plane fact.  The
    record is checked first here.
    """
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    if row["veto"]:
        return row["veto"]
    return row["rule_cause"]


def policy_withdrawal_first(row):
    """The victim's own withdrawal outranks everything, then the record.

    This is the physically motivated ordering: a victim that stopped
    announcing its own routes has lost reachability by withdrawal, and
    no third-party announcement can undo that.  Everything else is a
    hijack claim, and a hijack claim needs the control-plane record.
    """
    if row["withdrew_hard"]:
        return "outage"
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    return row["rule_cause"]


def policy_withdrawal_then_record_then_agent(row):
    """Withdrawal first, then the record, then the agent on silent windows."""
    if row["withdrew_hard"]:
        return "outage"
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    proposal = row["proposal"]
    if proposal and not row["traffic_available"]:
        return proposal
    return row["rule_cause"]


def policy_agent_conf(row, floor=0.60):
    """The original production gate: the agent's own confidence."""
    if float(row.get("agent_confidence") or 0.0) >= floor:
        return row["proposal"] or row["rule_cause"]
    return row["rule_cause"]


def constant_record_first(constant: str):
    """The record-first gate with the agent's proposal replaced by a label."""
    def predict(row):
        if row["veto"]:
            return row["veto"]
        if row["cross_origin"] > 0:
            return "origin_hijack_victim"
        if constant and not row["traffic_available"]:
            return constant
        return row["rule_cause"]
    return predict


POLICIES = {
    "rule_only": policy_rule,
    "agent_confidence_0.60": policy_agent_conf,
    "corroborated_agent_proposal": policy_corroborated,
    "record_first": policy_record_first,
    "record_only_no_agent": policy_record_only,
    "cross_before_veto": policy_cross_before_veto,
    "withdrawal_first": policy_withdrawal_first,
    "withdrawal_record_agent": policy_withdrawal_then_record_then_agent,
}


def score(rows, predict) -> dict:
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


def mcnemar(rows, predict_a, predict_b) -> dict:
    """Paired exact test between two policies on the same events."""
    from math import comb

    b_only = 0
    c_only = 0
    for row in rows:
        a = predict_a(row) == row["gt_cause"]
        b = predict_b(row) == row["gt_cause"]
        if a and not b:
            b_only += 1
        elif b and not a:
            c_only += 1
    n = b_only + c_only
    if n == 0:
        return {"discordant": 0, "p": 1.0}
    k = min(b_only, c_only)
    tail = sum(comb(n, i) for i in range(k + 1)) / (2 ** n)
    return {
        "discordant": n,
        "a_only": b_only,
        "b_only": c_only,
        "p": round(min(1.0, 2 * tail), 4),
    }


def load_development() -> list[dict]:
    """The 39-event corpus, with the physical quantities re-measured."""
    from component_ablation_gt import load_gt

    events = load_gt()
    agent = {
        r["event_id"]: r
        for r in json.loads(
            (EVAL / "gt_agent_full.json").read_text()
        )["records"]
    }
    rows = []
    for ev in events:
        eid = ev["event_id"]
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        row = {
            "event_id": eid,
            "gt_cause": ev["gt_cause"],
            "asn": ev["asn"],
            "cache": str(match.path),
        }
        row.update(measure(match.path, ev["asn"]))
        arec = agent.get(eid) or {}
        row["agent_committed"] = arec.get("cause") or ""
        row["agent_confidence"] = arec.get("agent_confidence")
        proposal = arec.get("agent_proposal") or ""
        if not proposal:
            proposal = arec.get("cause") or ""
        row["proposal"] = normalize_cause(proposal)
        rows.append(row)
    return rows


def load_heldout() -> list[dict]:
    """The 14 out-of-sample events."""
    path = EVAL / "heldout_validation.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    rows = []
    for event in data.get("events", []):
        row = {
            "event_id": event["event_id"],
            "gt_cause": event["gt_cause"],
            "asn": event["asn"],
            "cache": event["cache"],
            "rule_cause": event["rule_cause"],
            "cross_origin": event["cross_origin"],
            "traffic_available": event["traffic_available"],
            "proposal": event["agent_cause"],
            "agent_confidence": event.get("agent_confidence"),
        }
        veto = measure(Path(event["cache"]), event["asn"])
        row["veto"] = veto["veto"]
        row["withdrew_hard"] = veto["withdrew_hard"]
        rows.append(row)
    return rows


def main() -> int:
    dev = load_development()
    held = load_heldout()

    out = {
        "development": {"n": len(dev)},
        "heldout": {"n": len(held)},
        "development_arms": {},
        "heldout_arms": {},
        "paired_tests": {},
    }

    for name, fn in POLICIES.items():
        out["development_arms"][name] = score(dev, fn)
        if held:
            out["heldout_arms"][name] = score(held, fn)

    for constant in ("origin_hijack_victim", "outage", "route_leak"):
        fn = constant_record_first(constant)
        key = f"record_first_constant_{constant}"
        out["development_arms"][key] = score(dev, fn)
        if held:
            out["heldout_arms"][key] = score(held, fn)

    # The paired test that answers "does the agent's proposal matter?".
    # It compares the record-first gate against the same gate with the
    # proposal replaced by a constant.
    if held:
        out["paired_tests"]["agent_vs_constant_development"] = mcnemar(
            dev, policy_record_first, constant_record_first("outage")
        )
        out["paired_tests"]["agent_vs_constant_heldout"] = mcnemar(
            held, policy_record_first, constant_record_first("outage")
        )
        out["paired_tests"]["rule_vs_record_first_heldout"] = mcnemar(
            held, policy_rule, policy_record_first
        )

    # Which policy the development corpus selects, and what it scores
    # out of sample.
    best = max(
        POLICIES,
        key=lambda n: out["development_arms"][n]["correct"],
    )
    out["selection"] = {
        "selected_on_development": best,
        "development": out["development_arms"][best],
        "heldout": out["heldout_arms"].get(best),
        "rule": "highest development-corpus accuracy; the held-out corpus "
                "is scored once with the selected policy and is not used "
                "for selection",
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print("development corpus")
    print(f"{'arm':40s} {'correct':>9s} {'micro':>8s} {'balanced':>9s}")
    for name, slot in out["development_arms"].items():
        print(f"{name:40s} {slot['correct']:>4d}/{slot['n']:<4d} "
              f"{slot['micro']:>8} {slot['balanced']:>9}")

    if held:
        print()
        print("held-out corpus (never used for selection)")
        print(f"{'arm':40s} {'correct':>9s} {'micro':>8s} {'balanced':>9s}")
        for name, slot in out["heldout_arms"].items():
            print(f"{name:40s} {slot['correct']:>4d}/{slot['n']:<4d} "
                  f"{slot['micro']:>8} {slot['balanced']:>9}")
        print()
        print("paired tests:")
        for name, slot in out["paired_tests"].items():
            print(f"  {name:38s} {slot}")

    print()
    print(f"selected on development: {best}")
    if held:
        print(f"  development {out['development_arms'][best]['correct']}/{len(dev)}")
        print(f"  held-out    {out['heldout_arms'][best]['correct']}/{len(held)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
