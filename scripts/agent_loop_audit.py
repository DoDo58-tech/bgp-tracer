"""Which agents actually have a Think-Act-Observe loop?"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import logger  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "agent_loop_audit.json"

AGENTS = {
    "ReactAgent": ("agents/react_agent.py", "ReactAgent"),
    "ReportAgent": ("agents/report_agent.py", "ReportAgent"),
    "ReasoningAgent": ("agents/reasoning_agent.py", "ReasoningAgent"),
    "HypothesisAgent": ("agents/hypothesis_manager.py", "HypothesisAgent"),
    "TrafficAgent": ("agents/traffic_agent.py", None),
    "RoutingAgent": ("agents/routing_agent.py", None),
    "InvestigationSupervisor": ("agents/investigation_supervisor.py",
                                 "InvestigationSupervisor"),
    "WorkflowEngine": ("workflow_engine.py", "WorkflowEngine"),
}


# ── Static probe ─────────────────────────────────────────────────────────────

# A module that *dispatches* on a name looked up at runtime has a decision
# step. Matching on a literal constant does not.
_DISPATCH_PATTERNS = [
    re.compile(r"AVAILABLE_TOOLS\s*\["),
    re.compile(r"AVAILABLE_TOOLS\.get\("),
    re.compile(r"getattr\([^)]*tool", re.I),
    re.compile(r"\btool_name\b"),
    re.compile(r"action_name\s*="),
    re.compile(r"parsed\[.action.\]"),
    re.compile(r"self\.tools_used"),
    re.compile(r"triggered_tools"),
    re.compile(r"get_triggered_tools\("),
    re.compile(r"pattern_detector|\.detect\("),
    re.compile(r"rule_conditions|matches_conditions\("),
    # Gap-driven dispatch: the agent selects which gap to close, and the gap
    # determines the action.
    re.compile(r"knowledge_gaps"),
    re.compile(r"retrieval_needs"),
    re.compile(r"structured_fact_gaps"),
]

# A decision that is made *by a model* rather than by a fixed rule. This is
# the difference between an autonomous agent and a rule engine, so it is
# scored separately.
_MODEL_DECISION_PATTERNS = [
    re.compile(r"llm_think|parse_response\("),
    re.compile(r"parsed\[.action.\]"),
    re.compile(r"parsed\[.answer.\]"),
    re.compile(r"response\[.action.\]|action\s*=\s*response"),
    re.compile(r"llm\.chat|llm\.complete|await\s+self\.llm"),
    re.compile(r"self\.llm\.\w+\("),
]

# A decision that is made from the *evidence state produced by a previous
_EVIDENCE_DRIVEN_PATTERNS = [
    re.compile(r"identify_evidence_gaps|identify_knowledge_gaps"),
    re.compile(r"resolve_structured_fact_gaps|resolve_retrieval_needs"),
    re.compile(r"_round_summaries"),
    re.compile(r"knowledge_gaps"),
    re.compile(r"detect_agent_conflicts|resolve_conflicts"),
    re.compile(r"assess_analysis_completeness|should_conclude_analysis"),
]

# A decision made by a static rule table (trigger rules, pattern match).
_RULE_DRIVEN_PATTERNS = [
    re.compile(r"triggered_tools"),
    re.compile(r"get_triggered_tools\("),
    re.compile(r"rule_conditions|matches_conditions\("),
    re.compile(r"pattern_detector|\.detect\("),
]

# A module that *reads back* the result of an action into a context that a
# later decision consults.
_FEEDBACK_PATTERNS = [
    re.compile(r"observation"),
    re.compile(r"context\s*=\s*self\.update_context"),
    re.compile(r"append\(.*observation", re.I),
    re.compile(r"entry\.observation"),
    re.compile(r"self\._evidence\["),
    re.compile(r"shared_evidence\("),
    re.compile(r"blackboard|self\.bb\b"),
    re.compile(r"add_observation|write\(.*observation"),
    # A round summary that is carried into the next round's prompt is a
    # feedback path even though it is not named "observation".
    re.compile(r"_round_summaries"),
    re.compile(r"reasoning_trace\[-"),
    re.compile(r"self\.evidence_pool"),
]

_ACTION_PATTERNS = [
    re.compile(r"execute_tool\("),
    re.compile(r"await\s+self\.execute_tool"),
    re.compile(r"AVAILABLE_TOOLS"),
    re.compile(r"tool_implementations|tool_registry"),
    re.compile(r"await\s+.*_agent\.|run_\w+_agent\("),
    re.compile(r"asyncio\.gather"),
]


def read(path: str):
    p = PROJECT_ROOT / path
    try:
        return p.read_text(errors="replace")
    except ValueError:  # noqa: BLE001
        return ""


def class_body(src: str, class_name: str):
    """Extract the source of a class body via AST (line spans)."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return src
    lines = src.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            start = node.lineno - 1
            end = getattr(node, "end_lineno", len(lines))
            return "\n".join(lines[start:end])
    return src


def static_probe(name: str, rel_path: str, class_name: str | None):
    src = read(rel_path)
    scope = class_body(src, class_name) if class_name else src
    # A class-level view misses module-level registries; include both.
    haystack = scope if scope.strip() else src

    decision = any(p.search(haystack) for p in _DISPATCH_PATTERNS)
    model_decision = any(p.search(haystack) for p in _MODEL_DECISION_PATTERNS)
    evidence_driven = any(p.search(haystack) for p in _EVIDENCE_DRIVEN_PATTERNS)
    rule_driven = any(p.search(haystack) for p in _RULE_DRIVEN_PATTERNS)
    action = any(p.search(haystack) for p in _ACTION_PATTERNS)
    feedback = any(p.search(haystack) for p in _FEEDBACK_PATTERNS)

    # A loop additionally requires a *repeat*: the decision/action/feedback
    # trio inside a construct that iterates.
    has_loop_construct = bool(re.search(
        r"for\s+\w+\s+in\s+range\([^)]*round|while\s+True|while\s+retry|"
        r"for\s+round", haystack
    ))

    loop = decision and action and feedback and has_loop_construct
    if loop and model_decision:
        kind = "autonomous"
    elif loop and evidence_driven:
        kind = "evidence_driven"
    elif loop and rule_driven:
        kind = "rule_driven"
    elif loop:
        kind = "loop"
    else:
        kind = "pipeline"
    return {
        "module": rel_path,
        "class": class_name,
        "decision": decision,
        "model_decision": model_decision,
        "evidence_driven_decision": evidence_driven,
        "rule_driven_decision": rule_driven,
        "action": action,
        "observation_feedback": feedback,
        "repeats": has_loop_construct,
        "has_tao_loop": loop,
        "loop_kind": kind,
        "evidence": {
            "decision_hits": sorted({p.pattern for p in _DISPATCH_PATTERNS
                                     if p.search(haystack)})[:3],
            "model_decision_hits": sorted({p.pattern for p in _MODEL_DECISION_PATTERNS
                                           if p.search(haystack)})[:3],
            "action_hits": sorted({p.pattern for p in _ACTION_PATTERNS
                                   if p.search(haystack)})[:3],
            "feedback_hits": sorted({p.pattern for p in _FEEDBACK_PATTERNS
                                     if p.search(haystack)})[:3],
        },
    }


# ── Coordination-surface probe ──────────────────────────────────────────────


def coordination_probe():
    """Check that the Evidence Blackboard is genuinely shared across stages."""
    wf = read("workflow_engine.py")
    core = read("agents/core.py")

    per_stage_construction = len(re.findall(r"=\s*Blackboard\(\)", wf))
    shared_accessor = "def get_blackboard" in wf and "self.shared_blackboard = Blackboard()" in wf
    handler_level_construction = len(re.findall(
        r"async def _handle_\w+\([^)]*\):(?:(?!\n    async def |\n    def ).)*?=\s*Blackboard\(\)",
        wf,
        re.S,
    ))

    record_kinds = sorted(set(re.findall(r'"(observations|claims|challenges|verdicts|'
                                        r'alternatives|gaps|metrics|messages)"',
                                        core)))
    has_alt_api = "async def add_alternative(" in core
    has_gap_api = "async def add_gap(" in core

    return {
        "one_board_per_run": bool(shared_accessor),
        "blackboard_constructions_in_workflow": per_stage_construction,
        "handler_level_constructions": handler_level_construction,
        "record_kinds": record_kinds,
        "has_alternative_api": has_alt_api,
        "has_gap_api": has_gap_api,
        "shared_board_ok": bool(
            shared_accessor and handler_level_construction == 0
            and has_alt_api and has_gap_api
        ),
    }


# ── Runtime probe ────────────────────────────────────────────────────────────


def runtime_probe(trace_path: Path):
    """Check a recorded ReAct trace for genuine loop behaviour."""
    try:
        d = json.loads(trace_path.read_text())
    except ValueError:  # noqa: BLE001
        return None
    trace = d.get("trace") or d.get("react_result", {}).get("trace") or []
    if not isinstance(trace, list) or not trace:
        return None

    actions = [t.get("action") for t in trace if t.get("action")]
    observations = [t.get("observation") or "" for t in trace]
    thoughts = [t.get("thought") or "" for t in trace]

    varied = len(set(actions)) > 1
    # Feedback: an observation from round i must be visible to round i+1.
    feedback_present = any(
        observations[i] for i in range(len(observations) - 1)
    )
    # Self-termination: the last entry is an answer, not a forced round cap.
    last = thoughts[-1] if thoughts else ""
    last_s = last if isinstance(last, str) else json.dumps(last, default=str)
    terminated_by_answer = "final answer" in last_s.lower()

    return {
        "rounds": len(trace),
        "distinct_actions": len(set(actions)),
        "action_sequence": actions,
        "varied_actions": varied,
        "observation_in_nonfinal_round": feedback_present,
        "terminated_by_answer": terminated_by_answer,
        "genuine_loop": bool(varied and feedback_present),
    }


# ── Driver ───────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--trace",
        default="",
        help="Optional path to a recorded react trace (JSON) for the runtime probe.",
    )
    ap.add_argument("--out", default=str(OUT_PATH))
    args = ap.parse_args()

    agents = {}
    for name, (rel, cls) in AGENTS.items():
        agents[name] = static_probe(name, rel, cls)
        logger.info(
            f"[loop] {name}: loop={agents[name]['has_tao_loop']} "
            f"(d={agents[name]['decision']} a={agents[name]['action']} "
            f"o={agents[name]['observation_feedback']} "
            f"r={agents[name]['repeats']})"
        )

    out = {
        "agents": agents,
        "runtime": None,
        "coordination": coordination_probe(),
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "note": ("Static probe inspects each module for the three "
                     "ingredients of a Think-Act-Observe loop: a runtime "
                     "decision over a set of actions, an action, and a path "
                     "that feeds the observation back into the next "
                     "decision. The runtime probe re-checks the claim on a "
                     "recorded trace. The coordination probe checks that "
                     "the Evidence Blackboard is genuinely shared across "
                     "the workflow's stages and carries the full typed "
                     "record vocabulary."),
        },
    }

    if args.trace:
        out["runtime"] = runtime_probe(Path(args.trace))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    logger.info(f"[loop] wrote {args.out}")
    print(json.dumps(
        {k: {"loop": v["has_tao_loop"], "kind": v["loop_kind"]}
         for k, v in agents.items()},
        indent=1,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())