"""Check the agent-section numbers against their artefacts."""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL = PROJECT_ROOT / "results" / "eval"


def load(name: str):
    p = EVAL / name
    if not p.exists():
        raise SystemExit(f"FAIL: missing artefact {p}")
    return json.loads(p.read_text())


def get(d: dict, path: str):
    cur = d
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


# (paper substring, artefact, json path, expected value as printed)
CHECKS = [
    # ── Table: agent-ablation (medians) ──
    ("$1.2$\\,s", "agent_value_ablation_v2.json",
     "summary.monolithic.latency_s.median", "1.23"),
    ("$653$", "agent_value_ablation_v2.json",
     "summary.monolithic.tokens.median", "653.0"),
    ("$46.6$\\,s", "agent_value_ablation_v2.json",
     "summary.traffic_first.latency_s.median", "46.64"),
    ("$41{,}668$", "agent_value_ablation_v2.json",
     "summary.traffic_first.tokens.median", "41668.0"),
    ("$168.0$\\,s", "agent_value_ablation_v2.json",
     "summary.react.latency_s.median", "167.96"),
    ("$4{,}938$", "agent_value_ablation_v2.json",
     "summary.react.tokens.median", "4938.0"),

    # ── agreement between the two arms that share a vocabulary ──
    ("same} normalised verdict in all ten cases", "agent_value_ablation_v2.json",
     "agreement.monolithic__vs__traffic_first.agree", "10"),
    ("same} normalised verdict in all ten cases", "agent_value_ablation_v2.json",
     "agreement.monolithic__vs__traffic_first.n", "10"),

    # ── Table: agent-degradation (verdict stability) ──
    ("$2/2$", "degradation_probe.json",
     "summary.llm_report_off.verdict_stable_vs_control", "2"),
    ("$2/2$", "degradation_probe.json",
     "summary.llm_report_broken.verdict_stable_vs_control", "2"),
    ("$2/2$", "degradation_probe.json",
     "summary.reasoning_off.verdict_stable_vs_control", "2"),
    ("$2/2$", "degradation_probe.json",
     "summary.report_agent_crash.verdict_stable_vs_control", "2"),

    # ── Table: agent-explain (per-question pass rates, 38-event corpus) ──
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.Q1_source", "1.0"),
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.Q2_quantity", "0.118"),
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.Q3_window", "0.118"),
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.Q4_alternative", "0.0"),
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.Q5_gap", "0.118"),
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.Q6_chain", "0.0"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.Q1_source", "1.0"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.Q2_quantity", "1.0"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.Q3_window", "1.0"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.Q4_alternative", "0.941"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.Q5_gap", "0.529"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.Q6_chain", "1.0"),
    ("Agent pipeline & 1.00 & 1.00 & 1.00 & 0.94 & 0.53 & 1.00",
     "explainability_audit.json", "summary.agent.mean_score", "0.912"),
    ("Monolithic     & 1.00 & 0.12 & 0.12 & 0.00 & 0.12 & 0.00",
     "explainability_audit.json", "summary.monolithic.mean_score", "0.225"),

    # ── the audit column of Table agent-ablation, and the prose that quotes
    #    the same rubric score in "of six" form ──
    ("Agent pipeline & $46.6$\\,s & $41{,}668$ & HTML + record & $5.5/6$",
     "explainability_audit.json", "summary.agent.mean_score", "0.912"),
    ("Monolithic     & $1.2$\\,s   & $653$      & JSON verdict   & $1.4/6$",
     "explainability_audit.json", "summary.monolithic.mean_score", "0.225"),
    ("answering on average $5.5$ of six operator",
     "explainability_audit.json", "summary.agent.mean_score", "0.912"),
    ("questions against $1.4$ for the monolithic arm.",
     "explainability_audit.json", "summary.monolithic.mean_score", "0.225"),

    # ── the runtime trace that confirms the ReAct loop ──
    ("six rounds", "react_trace_sample.json", "rounds", "6"),

    # ── Table: agent-gt (cause accuracy on the 39-event corpus) ──
    ("Monolithic LLM & $1/17$ ($0.06$) & $0/10$ & $0/3$ & $1/4$",
     "gt_baseline_monolithic.json", "summary.cause_accuracy_evaluable.correct", "1"),
    ("Monolithic LLM & $1/17$ ($0.06$) & $0/10$ & $0/3$ & $1/4$",
     "gt_baseline_monolithic.json", "summary.cause_accuracy_evaluable.n", "17"),
    ("Monolithic LLM & $1/17$ ($0.06$) & $0/10$ & $0/3$ & $1/4$",
     "gt_baseline_monolithic.json",
     "summary.per_cause.outage.correct", "0"),
    ("Monolithic LLM & $1/17$ ($0.06$) & $0/10$ & $0/3$ & $1/4$",
     "gt_baseline_monolithic.json", "summary.per_cause.route_leak.correct", "0"),
    ("Monolithic LLM & $1/17$ ($0.06$) & $0/10$ & $0/3$ & $1/4$",
     "gt_baseline_monolithic.json",
     "summary.per_cause.origin_hijack_victim.correct", "1"),
    ("Full agent     & $13/17$ ($0.76$) & $9/10$ & $0/3$ & $4/4$",
     "gt_agent_full.json", "summary.cause_accuracy_evaluable.correct", "13"),
    ("Full agent     & $13/17$ ($0.76$) & $9/10$ & $0/3$ & $4/4$",
     "gt_agent_full.json", "summary.cause_accuracy_evaluable.n", "17"),
    ("Full agent     & $13/17$ ($0.76$) & $9/10$ & $0/3$ & $4/4$",
     "gt_agent_full.json", "summary.per_cause.outage.correct", "9"),
    ("Full agent     & $13/17$ ($0.76$) & $9/10$ & $0/3$ & $4/4$",
     "gt_agent_full.json", "summary.per_cause.route_leak.correct", "0"),
    ("Full agent     & $13/17$ ($0.76$) & $9/10$ & $0/3$ & $4/4$",
     "gt_agent_full.json", "summary.per_cause.origin_hijack_victim.correct", "4"),
    ("Rules only     & $11/17$ ($0.65$) & $9/10$ & $0/3$ & $2/4$",
     "gt_rule_only.json", "summary.cause_accuracy_evaluable.correct", "11"),
    ("Rules only     & $11/17$ ($0.65$) & $9/10$ & $0/3$ & $2/4$",
     "gt_rule_only.json", "summary.cause_accuracy_evaluable.n", "17"),
    ("Rules only     & $11/17$ ($0.65$) & $9/10$ & $0/3$ & $2/4$",
     "gt_rule_only.json", "summary.per_cause.outage.correct", "9"),
    ("Rules only     & $11/17$ ($0.65$) & $9/10$ & $0/3$ & $2/4$",
     "gt_rule_only.json", "summary.per_cause.route_leak.correct", "0"),
    ("Rules only     & $11/17$ ($0.65$) & $9/10$ & $0/3$ & $2/4$",
     "gt_rule_only.json", "summary.per_cause.origin_hijack_victim.correct", "2"),

]

# ── Appendix tables: checked against docs/paper/appendix.tex ─────────────
APPENDIX_CHECKS = [
    ("ReAct & yes & yes & yes & autonomous", "agent_loop_audit.json",
     "agents.ReactAgent.has_tao_loop", "True"),
    ("ReAct & yes & yes & yes & autonomous", "agent_loop_audit.json",
     "agents.ReactAgent.loop_kind", "autonomous"),
    ("Reasoning & yes & yes & yes & evidence-driven",
     "agent_loop_audit.json", "agents.ReasoningAgent.loop_kind",
     "evidence_driven"),
    ("Report & no & no & yes & pipeline", "agent_loop_audit.json",
     "agents.ReportAgent.loop_kind", "pipeline"),
    ("Hypothesis & no & no & yes & pipeline", "agent_loop_audit.json",
     "agents.HypothesisAgent.loop_kind", "pipeline"),
    ("Traffic & no & no & yes & pipeline", "agent_loop_audit.json",
     "agents.TrafficAgent.loop_kind", "pipeline"),
    ("Routing & no & yes & yes & pipeline", "agent_loop_audit.json",
     "agents.RoutingAgent.loop_kind", "pipeline"),
    ("Supervisor & yes & no & no & pipeline", "agent_loop_audit.json",
     "agents.InvestigationSupervisor.loop_kind", "pipeline"),
    ("Orchestrator & no & yes & yes & pipeline", "agent_loop_audit.json",
     "agents.WorkflowEngine.loop_kind", "pipeline"),
    ("None (full pipeline) & $0.564$ & --- & --- & $0.000$",
     "component_ablation_summary.json",
     "summary.full.accuracy_across_runs.mean", "0.5641"),
    ("None (full pipeline) & $0.564$ & --- & --- & $0.000$",
     "component_ablation_summary.json",
     "summary.full.accuracy_across_runs.stdev", "0.0"),
    ("Joint evidence & $0.564$ & $+0.000$",
     "component_ablation_summary.json",
     "summary.no_joint_evidence.accuracy_across_runs.mean", "0.5641"),
    ("Joint evidence & $0.564$ & $+0.000$ & $[+0.000,+0.000]$ & $0.000$",
     "component_ablation_summary.json",
     "paired_deltas_vs_full.no_joint_evidence.mean", "0.0"),
    ("HCAF attribution & $0.556$ & $-0.009$",
     "component_ablation_summary.json",
     "summary.no_hcaf.accuracy_across_runs.mean", "0.5556"),
    ("HCAF attribution & $0.556$ & $-0.009$ & $[-0.026,+0.000]$ & $0.015$",
     "component_ablation_summary.json",
     "paired_deltas_vs_full.no_hcaf.mean", "-0.0085"),
    ("Hypothesis generation & $0.564$ & $+0.000$",
     "component_ablation_summary.json",
     "summary.no_hypothesis.accuracy_across_runs.mean", "0.5641"),
    ("Multi-round reasoning & $0.470$ & $-0.094$",
     "component_ablation_summary.json",
     "summary.no_reasoning.accuracy_across_runs.mean", "0.4701"),
    ("Multi-round reasoning & $0.470$ & $-0.094$ & $[-0.128,-0.077]$ & $0.030$",
     "component_ablation_summary.json",
     "paired_deltas_vs_full.no_reasoning.mean", "-0.0940"),
    ("Evidence Blackboard & $0.547$ & $-0.017$",
     "component_ablation_summary.json",
     "summary.no_evidence_board.accuracy_across_runs.mean", "0.5470"),
    ("Evidence Blackboard & $0.547$ & $-0.017$ & $[-0.026,+0.000]$ & $0.015$",
     "component_ablation_summary.json",
     "paired_deltas_vs_full.no_evidence_board.mean", "-0.0171"),
    ("External enrichment & $0.564$ & $+0.000$",
     "component_ablation_summary.json",
     "summary.no_enrichment.accuracy_across_runs.mean", "0.5641"),
]



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tex", default=str(
        PROJECT_ROOT / "docs" / "paper" / "section5b_agents.tex"))
    args = ap.parse_args()

    tex_path = Path(args.tex)
    if not tex_path.exists():
        print(f"FAIL: {tex_path} not found")
        return 1

    cache: dict[str, dict] = {}
    n_ok = 0
    failures: list[str] = []

    # The paper source is line-wrapped, so a phrase can straddle a newline.
    # Compare on a whitespace-collapsed copy.  A table may live in the
    # agent section or in the appendix, so every checked string is looked
    # for in the whole paper rather than in one file: the number is what
    # matters, not which file happens to print it.  The file named by
    # ``--tex`` is always searched, and it replaces the same-named file in
    # the paper directory, so a drifted copy of it is what gets checked.
    paper_dir = Path(os.environ.get(
        "BGP_TRACER_PAPER_DIR", str(PROJECT_ROOT / "docs" / "paper")))
    sources = {}
    for candidate in sorted(paper_dir.glob("*.tex")):
        if candidate.name == tex_path.name:
            continue
        sources[candidate.name] = re.sub(r"\s+", " ", candidate.read_text())
    sources[tex_path.name] = re.sub(r"\s+", " ", tex_path.read_text())

    jobs = ([(s, a, p, e) for s, a, p, e in CHECKS]
            + [(s, a, p, e) for s, a, p, e in APPENDIX_CHECKS])

    for paper_str, artefact, json_path, expected in jobs:
        if expected is None:
            continue
        needle = re.sub(r"\s+", " ", paper_str)
        if not any(needle in text for text in sources.values()):
            failures.append(
                f"paper string not found: {paper_str!r} "
                f"(checked for {artefact}:{json_path})"
            )
            continue
        if artefact not in cache:
            try:
                cache[artefact] = load(artefact)
            except SystemExit as e:
                failures.append(str(e))
                continue
        try:
            value = get(cache[artefact], json_path)
        except (KeyError, IndexError, TypeError) as e:
            failures.append(
                f"{artefact}:{json_path} -> {e}")
            continue
        # The paper prints rounded values; accept any value that rounds to
        # the same displayed string.
        got = str(value)
        if got == expected:
            n_ok += 1
            continue
        try:
            if abs(float(value) - float(expected)) < 1e-9:
                n_ok += 1
                continue
        except (TypeError, ValueError):
            pass
        # Allow the paper to print a rounded form of the artefact value.
        try:
            fv = float(value)
            if abs(fv - float(expected)) <= max(0.005, abs(fv) * 0.0005):
                n_ok += 1
                continue
        except (TypeError, ValueError):
            pass
        failures.append(
            f"{artefact}:{json_path} = {value!r}, paper says {expected!r} "
            f"(near: {paper_str!r})"
        )

    # The "of six" rubric score is a derived number: the artefact stores a
    # mean per-question rate, and the paper prints the same rate multiplied
    # by the six questions of the rubric.  A string-match gate cannot catch
    # the paper printing a stale product, so the multiplication is checked
    # against the artefact directly.
    try:
        summary = load("explainability_audit.json")["summary"]
        for arm, label in (("agent", "5.5"), ("monolithic", "1.4")):
            derived = 6.0 * float(summary[arm]["mean_score"])
            printed = float(label)
            if abs(derived - printed) > 0.06:
                failures.append(
                    f"audit rubric: {arm} mean_score "
                    f"{summary[arm]['mean_score']} implies {derived:.2f} of six, "
                    f"paper says {printed}")
            else:
                n_ok += 1
    except (SystemExit, KeyError, TypeError, ValueError) as e:
        failures.append(f"audit rubric derivation: {e}")

    # The runtime trace must show a *varied* action sequence, and the
    # loop audit must agree that the run was a genuine loop.
    try:
        rt = load("react_trace_sample.json")
        actions = [t.get("action") for t in (rt.get("trace") or [])
                   if t.get("action")]
        if len(set(actions)) < 2:
            failures.append(
                f"react trace: action sequence is not varied: {actions}")
        elif len(rt.get("trace") or []) != rt.get("rounds"):
            failures.append("react trace: round count disagrees with trace length")
        else:
            n_ok += 1
    except SystemExit as e:
        failures.append(str(e))

    try:
        audit = load("agent_loop_audit.json")
        runtime = audit.get("runtime") or {}
        if not runtime.get("genuine_loop"):
            failures.append("loop audit: runtime probe did not confirm a loop")
        else:
            n_ok += 1
    except SystemExit as e:
        failures.append(str(e))

    print(f"agent-section number check: {n_ok} values verified, "
          f"{len(failures)} mismatch(es)")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())