"""Ground-truth evaluation of the **agent layer's own verdict**."""
#!/usr/bin/env python3
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
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
OUT_PATH = EVAL / "agent_ground_truth.json"

# ── The agent's verdict vocabulary → the label vocabulary ──────────────────
AGENT_VERDICT_TO_CAUSE = {
    "real_incident": {
        "origin_hijack_victim", "route_leak", "outage", "roa_misconfig",
    },
    "correlation_uncertain": {
        "origin_hijack_victim", "route_leak", "outage", "roa_misconfig",
    },
    "silent_alert": {"route_leak", "outage", "roa_misconfig"},
    "traffic_only": {"traffic_anomaly_only"},
    "no_clear_anomaly": {"no_clear_anomaly", "traffic_anomaly_only"},
}

# The labels the corpus actually uses.
LABEL_CAUSES = ("outage", "route_leak", "origin_hijack_victim", "roa_misconfig")


def load_gt() -> tuple[list[dict], list[dict]]:
    """Load the corpus, separating label-conflicting windows.

    Two events in the corpus share an (ASN, window) pair but carry
    different cause labels (CANTV 2024-08-01: outage and route_leak).
    A single cache cannot answer two different questions about the same
    measurement, so the conflicting pair is reported but *excluded* from
    scoring.  Silently counting one label as a hit (or a miss) would be
    a rigged comparison — the measurement cannot be both an outage and
    a leak signature at once.
    """
    import csv

    rows = list(csv.DictReader(GT_CSV.open()))
    by_window: dict = {}
    for r in rows:
        asn = str(r.get("victim_as") or "").replace("AS", "").strip()
        by_window.setdefault((asn, (r.get("start_utc") or "").strip(),
                              (r.get("end_utc") or "").strip()), []).append(r)
    out = []
    conflicted = []
    for (asn, start, end), group in by_window.items():
        causes = {str(r.get("cause") or "").strip() for r in group}
        if len(causes) > 1:
            conflicted.append({
                "asn": asn, "window": f"{start} -> {end}",
                "labels": sorted(causes),
                "event_ids": [r["event_id"] for r in group],
            })
            continue
        for r in group:
            out.append(
                {
                    "event_id": r["event_id"],
                    "asn": asn,
                    "start": start,
                    "end": end,
                    "gt_cause": (r.get("cause") or "").strip(),
                    "gt_subtype": (r.get("subtype") or "").strip(),
                    "detector_fired": r.get("cause") != "",
                }
            )
    return out, conflicted


def load_detector_fired() -> dict[str, bool]:
    """Whether the traffic detector fired, per event."""
    audit_dir = PROJECT_ROOT / "results" / "gt_audit_v22"
    out: dict[str, bool] = {}
    if not audit_dir.is_dir():
        return out
    for p in audit_dir.glob("*.json"):
        if p.name == "audit_summary.json":
            continue
        try:
            d = json.loads(p.read_text())
        except (ValueError):  # noqa: BLE001
            continue
        ev = d.get("evidence") or {}
        fired = bool(ev.get("traffic_anomaly_count")) or bool(
            d.get("has_traffic_anomaly")
        )
        out[d.get("event_id")] = fired
    return out


def norm_verdict(raw: str) -> str:
    r = (raw or "").strip().lower()
    aliases = {
        "cooccurring_anomalies": "correlation_uncertain",
        "correlated_observations": "real_incident",
        "routing_only_anomaly": "silent_alert",
        "traffic_only_anomaly": "traffic_only",
        "verified_normal": "no_clear_anomaly",
        "inconclusive_missing_traffic": "no_clear_anomaly",
        "inconclusive_missing_routing": "no_clear_anomaly",
        "inconclusive": "no_clear_anomaly",
    }
    return aliases.get(r, r)


def run_agent(quick: dict) -> dict:
    """Run the full agent pipeline and extract what it committed."""
    from chief_agent import analyze_deep_from_quick

    res = analyze_deep_from_quick(quick_result=quick, analysis_mode="traffic_first")
    cea = res.get("chief_expert_analysis") or {}
    eb = res.get("evidence_board") or {}

    def count(key):
        v = eb.get(key)
        if isinstance(v, dict):
            v = v.get("value")
        return len(v) if isinstance(v, list) else 0

    ec = res.get("evidence_chain") or {}
    cause_raw = ec.get("cause") or cea.get("cause") or ""
    arbitration = ec.get("arbitration") or {}
    return {
        "success": bool(res.get("success")),
        "verdict": norm_verdict(cea.get("evidence_verdict")),
        "verdict_raw": cea.get("evidence_verdict"),
        "confidence": cea.get("confidence_score"),
        "cause": normalize_cause_label(cause_raw) or str(cause_raw or ""),
        "cause_raw": cause_raw,
        "hypothesis": ec.get("hypothesis") or "",
        "joint_tier": res.get("joint_tier") or "",
        "joint_score": res.get("joint_score"),
        "observations": count("observations"),
        "claims": count("claims"),
        "challenges": count("challenges"),
        "alternatives": count("alternatives"),
        "gaps": count("gaps"),
        "trace_steps": len(res.get("reasoning_trace") or []),
        "reasoning_steps": len(ec.get("reasoning_steps") or []),
        "rule_verdict": arbitration.get("rule_verdict"),
        "agent_proposed_verdict": arbitration.get("agent_proposed_verdict"),
        "agent_overrode_rule": bool(arbitration.get("agent_overrode_rule")),
        "agent_confidence": arbitration.get("agent_confidence"),
        "html": bool(res.get("report_result", {}).get("html")
                     or cea.get("html_report_path")),
    }


def normalize_cause_label(raw: str) -> str:
    """Map a free-text cause onto the corpus's cause labels.

    Both arms are scored through this function, so the comparison is
    about the reasoning, not about which arm happened to emit a
    canonical label.  The monolithic arm answers in prose ("route leaks
    with concurrent traffic drop"); the agent answers with a label.
    Scoring the prose by exact string match would be a rigged
    comparison, so both go through the same mapping.
    """
    text = str(raw or "").strip().lower().replace("-", " ")
    if not text:
        return ""
    # Ordered: the more specific phrase wins.
    rules = (
        ("origin hijack", "origin_hijack_victim"),
        ("path forgery", "origin_hijack_victim"),
        ("roa misconfig", "roa_misconfig"),
        ("route leak", "route_leak"),
        ("leak", "route_leak"),
        ("outage", "outage"),
        ("traffic only", "traffic_anomaly_only"),
        ("traffic anomaly only", "traffic_anomaly_only"),
        ("no anomaly", "no_clear_anomaly"),
        ("no clear anomaly", "no_clear_anomaly"),
    )
    for needle, label in rules:
        if needle in text:
            return label
    return ""


def run_baseline(quick: dict, event_id: str) -> dict:
    """Score the monolithic one-shot LLM arm on the same evidence.

    This is the control for the agent pipeline: one LLM call, one pass
    over the Phase-1 detector evidence, no coordination layer, no
    blackboard, no hypothesis/arbitration, no report.  It is the arm
    the agent has to beat on correctness to justify its cost.
    """
    from scripts.agent_value_ablation import run_monolithic

    res = run_monolithic(quick, run_id=f"gt-mono-{event_id}")
    return {
        "success": bool(res.get("verdict")),
        "verdict": norm_verdict(res.get("verdict")),
        "verdict_raw": res.get("verdict"),
        "confidence": res.get("confidence"),
        "cause": normalize_cause_label(res.get("cause")),
        "cause_raw": res.get("cause") or "",
        "hypothesis": "",
        "joint_tier": "",
        "joint_score": None,
        "observations": 0,
        "claims": 0,
        "challenges": 0,
        "alternatives": 0,
        "gaps": 0,
        "trace_steps": 0,
        "reasoning_steps": 1,
        "html": False,
        "latency_s": res.get("latency_s"),
        "tokens": res.get("tokens"),
    }


def run_rule_only(quick: dict) -> dict:
    """Score the pure-detector arm: no LLM at all.

    Runs the deterministic decision tree (physical veto + cause tree)
    directly on the cached detector evidence.  This is the correct
    reference point for "what the agent adds on top of rules": the
    comparison isolates the marginal value of the LLM layer (verdict
    arbitration, textual hypothesis, report) over the threshold logic
    that both arms share.
    """
    from detectors.evidence_chain_builder import EvidenceChainBuilder

    b = EvidenceChainBuilder()
    tr = quick.get("traffic") or {}
    rr = quick.get("routing") or {}
    hard = b.hard_physical_signature(tr, rr)
    cause = hard or b.cause_from_evidence(tr, rr, "")
    return {
        "success": True,
        "verdict": "",
        "verdict_raw": "",
        "confidence": None,
        "cause": cause,
        "cause_raw": cause,
        "hypothesis": "",
        "joint_tier": "",
        "joint_score": None,
        "observations": 0,
        "claims": 0,
        "challenges": 0,
        "alternatives": 0,
        "gaps": 0,
        "trace_steps": 0,
        "reasoning_steps": 0,
        "rule_verdict": None,
        "agent_proposed_verdict": None,
        "agent_overrode_rule": False,
        "agent_confidence": None,
        "html": False,
        "latency_s": 0.0,
        "tokens": 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument(
        "--arm",
        choices=("agent", "baseline", "rule"),
        default="agent",
        help="Which arm to run: full agent pipeline, monolithic one-shot "
             "LLM baseline, or pure-detector rules with no LLM.",
    )
    ap.add_argument(
        "--baseline", action="store_true",
        help="(legacy alias for --arm baseline)",
    )
    args = ap.parse_args()

    arm = "baseline" if args.baseline else args.arm

    events, conflicted = load_gt()
    if args.limit:
        events = events[: args.limit]
    if conflicted:
        print("excluded label-conflicting window(s):", flush=True)
        for c in conflicted:
            print(f"  AS{c['asn']} {c['window']} labels={c['labels']} events={c['event_ids']}", flush=True)
    fired = load_detector_fired()

    out: dict = {"records": [], "meta": {}}
    if args.resume and Path(args.out).exists():
        out = json.loads(Path(args.out).read_text())
    done = {r.get("event_id") for r in out.get("records", [])}
    out["records"] = [r for r in out.get("records", []) if r.get("resolved")]

    for ev in events:
        if ev["event_id"] in done:
            continue
        rec = dict(ev)
        rec["detector_fired"] = fired.get(ev["event_id"])
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=ev["event_id"], allow_same_date=False,
        )
        if match is None:
            rec.update({"resolved": False, "reason": "no_cache_resolved"})
            out["records"].append(rec)
            print(f"  {ev['event_id']:42s} UNRESOLVED", flush=True)
            continue
        rec["resolved"] = True
        rec["cache"] = str(match.path)
        rec["match_kind"] = match.kind
        rec["strict_match"] = match.strict
        try:
            quick = json.loads(match.path.read_text())
            if arm == "baseline":
                rec.update(run_baseline(quick, ev["event_id"]))
            elif arm == "rule":
                rec.update(run_rule_only(quick))
            else:
                rec.update(run_agent(quick))
            rec["error"] = None
        except (KeyError, IndexError, AttributeError) as exc:  # noqa: BLE001
            rec["error"] = f"{type(exc).__name__}: {exc}"
            rec["success"] = False
        # Score
        gt = ev["gt_cause"]
        pred_cause = rec.get("cause") or ""
        rec["gt_cause"] = gt
        rec["predicted_cause"] = pred_cause
        if pred_cause and rec.get("success"):
            rec["cause_correct"] = (pred_cause == gt)
        else:
            rec["cause_correct"] = False
        # Verdict-level scoring: does the committed verdict admit the true cause?
        adm = AGENT_VERDICT_TO_CAUSE.get(rec.get("verdict") or "", set())
        rec["verdict_admits_gt"] = gt in adm
        verdict_label = str(rec.get("verdict") or "-")
        print(f"  {ev['event_id']:42s} {verdict_label:22s} "
              f"cause={pred_cause or '-':22s} gt={gt:22s} "
              f"correct={rec['cause_correct']}", flush=True)
        out["records"].append(rec)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(out, indent=1, default=str))

    # ── aggregate ────────────────────────────────────────────────────────
    recs = out["records"]
    resolved = [r for r in recs if r.get("resolved")]
    ran = [r for r in resolved if r.get("success")]
    total = len(events)

    def acc(rows):
        if not rows:
            return {"n": 0, "correct": 0, "accuracy": None}
        c = sum(1 for r in rows if r.get("cause_correct"))
        return {"n": len(rows), "correct": c,
                "accuracy": round(c / len(rows), 4)}

    per_cause = {}
    for cls in LABEL_CAUSES:
        rows = [r for r in ran if r.get("gt_cause") == cls]
        per_cause[cls] = acc(rows)

    # Verdict-level: the fraction of runs whose verdict is *compatible* with
    # the true cause.  This is the weaker but more honest claim.
    verdict_acc = (round(sum(1 for r in ran if r.get("verdict_admits_gt")) / len(ran), 4)
                   if ran else None)

    # Detection bias: accuracy restricted to the events on which the traffic
    # detector fired, vs the rest.
    fired_rows = [r for r in ran if r.get("detector_fired")]
    unfired_rows = [r for r in ran if not r.get("detector_fired")]

    out["summary"] = {
        "corpus_total": total,
        "resolved": len(resolved),
        "unresolved": total - len(resolved),
        "excluded_label_conflicts": conflicted,
        "agent_ran": len(ran),
        "agent_failed": len(resolved) - len(ran),
        "cause_accuracy_evaluable": acc(ran),
        "cause_accuracy_whole_corpus": {
            "n": total,
            "correct": sum(1 for r in ran if r.get("cause_correct")),
            "accuracy": round(
                sum(1 for r in ran if r.get("cause_correct")) / total, 4
            ) if total else None,
        },
        "verdict_compatibility_accuracy": verdict_acc,
        "per_cause": per_cause,
        "detector_fired_subset": acc(fired_rows),
        "detector_silent_subset": acc(unfired_rows),
        "strict_match_only": acc([r for r in ran if r.get("strict_match")]),
    }
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "arm": {"agent": "agent_full", "baseline": "baseline_monolithic",
                "rule": "rule_only"}[arm],
        "gt_source": str(GT_CSV.relative_to(PROJECT_ROOT)),
        "cache_resolver": "agents.cache_resolution.resolve_cache "
                          "(structural; no oracle selection)",
        "note": "The agent's five-class verdict is an anomaly-class axis; the "
                "labels are a cause axis. cause_accuracy scores the cause the "
                "agent derives; verdict_compatibility_accuracy scores the "
                "weaker claim that the committed verdict admits the true "
                "cause. detector_fired_subset exposes the selection bias "
                "inherited from gt_audit_v22.",
    }
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(out["summary"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())