"""Graceful-degradation experiment: what happens when an agent fails?"""
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import logger  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "degradation_probe.json"

FAULTS = [
    "none",
    "llm_report_off",
    "llm_report_broken",
    "reasoning_off",
    "report_agent_crash",
]


# ── Fault injection ──────────────────────────────────────────────────────────


class _Fault:
    """Context manager that installs a fault for the duration of a run."""

    def __init__(self, kind: str):
        self.kind = kind
        self._restore = []

    def __enter__(self):
        kind = self.kind
        if kind == "none":
            return self
        if kind == "llm_report_off":
            old = os.environ.get("BGP_TRACER_DISABLE_LLM_REPORT")
            os.environ["BGP_TRACER_DISABLE_LLM_REPORT"] = "1"

            def restore_env():
                if old is None:
                    os.environ.pop("BGP_TRACER_DISABLE_LLM_REPORT", None)
                else:
                    os.environ["BGP_TRACER_DISABLE_LLM_REPORT"] = old

            self._restore.append(restore_env)
            return self
        if kind == "llm_report_broken":
            self.patch("agents.report_agent.ReportAgent._generate_report_html",
                        broken_report)
            return self
        if kind == "report_agent_crash":
            self.patch("agents.report_agent.ReportAgent._generate_report_html",
                        crashing_report)
            return self
        if kind == "reasoning_off":
            self.patch("workflow_engine.WorkflowEngine._handle_reasoning",
                        skipped_reasoning)
            return self
        raise ValueError(f"unknown fault: {kind}")

    def __exit__(self, *exc):
        for restore in reversed(self._restore):
            try:
                restore()
            except ValueError:  # noqa: BLE001
                pass
        self._restore = []
        return False

    def patch(self, dotted: str, replacement):
        """Patch ``module.attr`` or ``module.Class.attr``."""
        import importlib

        parts = dotted.split(".")
        # Find the longest importable module prefix.
        mod = None
        rest: list[str] = []
        for i in range(len(parts), 0, -1):
            try:
                mod = importlib.import_module(".".join(parts[:i]))
                rest = parts[i:]
                break
            except ImportError:
                continue
        if mod is None or not rest:
            raise ImportError(f"cannot patch {dotted}")
        # Walk any intermediate class(es) down to the final attribute.
        owner = mod
        for name in rest[:-1]:
            owner = getattr(owner, name)
        attr = rest[-1]
        orig = getattr(owner, attr)
        setattr(owner, attr, replacement)

        def restore_attr():
            setattr(owner, attr, orig)

        self._restore.append(restore_attr)


async def broken_report(self, *args, **kwargs):
    raise RuntimeError("injected: report model call failed")


async def crashing_report(self, *args, **kwargs):
    raise RuntimeError("injected: report agent crashed")


async def skipped_reasoning(self, context):
    """Reasoning stage is bypassed entirely."""
    context.reasoning_result = {
        "success": True,
        "skipped": True,
        "reason": "injected_fault:reasoning_off",
    }
    from workflow_engine import WorkflowEvent
    return WorkflowEvent.REASONING_COMPLETE


# ── Run one (event, fault) ───────────────────────────────────────────────────


def artefact_class(html: str):
    if not html:
        return "none"
    head = html[:2000].lower()
    if "fallback report" in head or "deterministic fallback" in head:
        return "deterministic_fallback"
    return "llm_report"


def find_html(res: dict):
    cea = res.get("chief_expert_analysis") or {}
    rep = res.get("report_result") or res.get("analysis_report") or {}
    html = rep.get("html") or ""
    if html:
        return html
    path = cea.get("html_report_path") or rep.get("html_report_path") or ""
    if path:
        try:
            p = Path(path)
            if not p.is_absolute():
                p = PROJECT_ROOT / p
            if p.exists():
                return p.read_text(errors="replace")
        except ValueError:  # noqa: BLE001
            pass
    return ""


def run_one(quick: dict, fault: str):
    from chief_agent import analyze_deep_from_quick

    t0 = time.perf_counter()
    err = None
    res: dict = {}
    try:
        with _Fault(fault):
            res = analyze_deep_from_quick(quick_result=quick, analysis_mode="traffic_first")
    except AttributeError as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        logger.error(f"[degradation] {fault} raised: {exc}")
        traceback.print_exc()
    elapsed = round(time.perf_counter() - t0, 2)

    html = find_html(res)
    cea = res.get("chief_expert_analysis") or {}
    eb = res.get("evidence_board") or {}
    n_obs = len(eb.get("observations") or []) if isinstance(eb, dict) else 0
    claims = eb.get("claims") if isinstance(eb, dict) else None
    if isinstance(claims, dict):
        claims = claims.get("value")
    n_claims = len(claims or [])

    return {
        "fault": fault,
        "success": bool(res.get("success")) if res else False,
        "raised": err,
        "verdict": cea.get("evidence_verdict") or "",
        "confidence": cea.get("confidence_score"),
        "artefact": artefact_class(html),
        "html_bytes": len(html),
        "evidence_records": n_obs,
        "claims": n_claims,
        "reasoning_trace_steps": len(res.get("reasoning_trace") or []),
        "latency_s": elapsed,
        "report_path": cea.get("html_report_path") or "",
    }


# ── Driver ───────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=3)
    ap.add_argument("--faults", default=",".join(FAULTS))
    ap.add_argument("--out", default=str(OUT_PATH))
    args = ap.parse_args()

    faults = [f.strip() for f in args.faults.split(",") if f.strip()]

    from agent_value_ablation import pick_events  # reuse the same selection
    events = pick_events(PROJECT_ROOT / "results" / "quick", 1)[: args.events]

    out = {"records": [], "faults": faults}
    for path in events:
        quick = json.loads(path.read_text())
        eid = quick.get("event_id") or path.stem
        for fault in faults:
            logger.info(f"[degradation] {eid} :: {fault}")
            rec = run_one(quick, fault)
            rec["event"] = eid
            rec["quick_verdict"] = quick.get("quick_verdict")
            out["records"].append(rec)
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=1, default=str))

    # ── aggregate: does a fault change the verdict? ──
    by_event: dict[str, dict] = {}
    for r in out["records"]:
        by_event.setdefault(r["event"], {})[r["fault"]] = r

    summary = {}
    for fault in faults:
        rows = [r for r in out["records"] if r["fault"] == fault]
        if not rows:
            continue
        summary[fault] = {
            "n": len(rows),
            "completed": sum(1 for r in rows if r["success"]),
            "raised": sum(1 for r in rows if r["raised"]),
            "artefacts": {},
            "verdict_stable_vs_control": 0,
            "verdict_compared": 0,
            "mean_html_bytes": round(
                sum(r["html_bytes"] for r in rows) / len(rows), 1
            ),
            "mean_evidence_records": round(
                sum(r["evidence_records"] for r in rows) / len(rows), 2
            ),
            "mean_reasoning_steps": round(
                sum(r["reasoning_trace_steps"] for r in rows) / len(rows), 2
            ),
        }
        for r in rows:
            a = r["artefact"]
            summary[fault]["artefacts"][a] = summary[fault]["artefacts"].get(a, 0) + 1

    for eid, fr in by_event.items():
        ctrl = fr.get("none")
        if not ctrl:
            continue
        for fault, r in fr.items():
            if fault == "none":
                continue
            summary[fault]["verdict_compared"] += 1
            if r["verdict"] == ctrl["verdict"]:
                summary[fault]["verdict_stable_vs_control"] += 1

    out["summary"] = summary
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    logger.info(f"[degradation] wrote {args.out}")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())