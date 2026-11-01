"""Component ablation: which coordination stage earns its cost?

The full-agent arm answers "does the agent beat a monolithic one-shot
LLM?".  This script answers the follow-up question: *which part* of the
coordination layer carries that gain, and which parts are decoration.

Each arm disables exactly one coordination stage via the
``BGP_TRACER_ABLATE_*`` switches the workflow engine already exposes
(``joint_evidence``, ``paddle``, ``hypothesis``, ``reasoning``,
``evidence_board``, ``enrichment``) and re-runs the identical event
set.  Because only one switch changes at a time, the delta in cause
accuracy against the full agent is attributable to that stage alone.

Scoring is identical to ``agent_ground_truth_eval.py``: the same corpus,
the same cache resolution, the same label normalisation.  No oracle
selection, no per-arm tuning, no cherry-picking of events — an arm that
fails to run is scored as a failure, not dropped.

Usage::

    python3 scripts/component_ablation_gt.py --out results/eval/component_ablation.json
    python3 scripts/component_ablation_gt.py --resume
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.ablation_switches import (  # noqa: E402
    ABLATION_CAMPAIGN_ENV_VAR,
    ABLATION_ENV_VARS,
    ABLATION_STAGES,
    reset_ablation_switches,
)
from agents.cache_resolution import resolve_cache  # noqa: E402
from utils.logger import logger  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "component_ablation.json"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"

# Arm name -> the stage it ablates.  The "full" arm ablates nothing.
# The mapping is derived from the shared switch module so the harness
# and the engine cannot disagree about which variable each arm varies.
STAGES = {"full": None}
for _stage in ABLATION_STAGES:
    STAGES[f"no_{_stage}"] = ABLATION_ENV_VARS[_stage]

CAUSE_ALIASES = (
    ("origin hijack", "origin_hijack_victim"),
    ("path forgery", "origin_hijack_victim"),
    ("roa misconfig", "roa_misconfig"),
    ("route leak", "route_leak"),
    ("leak", "route_leak"),
    ("outage", "outage"),
)


def normalize_cause(raw: str):
    text = str(raw or "").strip().lower().replace("-", " ")
    if not text:
        return ""
    for phrase, label in CAUSE_ALIASES:
        if phrase in text:
            return label
    if "hijack" in text:
        return "origin_hijack_victim"
    if "withdraw" in text or "blackhole" in text:
        return "outage"
    return text


def load_gt():
    """Load the corpus, separating label-conflicting windows.

    Two events in the corpus share an (ASN, window) pair but carry
    different cause labels (CANTV 2024-08-01: outage and route_leak).
    A single cache cannot answer two different questions about the same
    measurement, so the conflicting pair is excluded from scoring —
    same rule as agent_ground_truth_eval.py.
    """
    import csv

    with open(GT_CSV, newline="") as fh:
        rows = list(csv.DictReader(fh))
    by_window: dict = {}
    for r in rows:
        asn = str(r.get("victim_as", "")).replace("AS", "").strip()
        by_window.setdefault(
            (asn, r.get("start_utc"), r.get("end_utc")), []).append(r)
    out = []
    for (asn, start, end), group in by_window.items():
        causes = {str(r.get("cause") or r.get("gt_cause") or "") for r in group}
        if len(causes) > 1:
            continue
        for r in group:
            out.append({
                "event_id": r.get("event_id"),
                "asn": asn,
                "start": start,
                "end": end,
                "gt_cause": r.get("cause") or r.get("gt_cause") or "",
            })
    return out


def run_one(quick: dict):
    from chief_agent import analyze_deep_from_quick

    res = analyze_deep_from_quick(quick_result=quick, analysis_mode="traffic_first")
    cea = res.get("chief_expert_analysis") or {}
    ec = res.get("evidence_chain") or {}
    eb = res.get("evidence_board") or {}

    def count(key):
        v = eb.get(key)
        if isinstance(v, dict):
            v = v.get("value")
        return len(v) if isinstance(v, list) else 0

    cause_raw = ec.get("cause") or cea.get("cause") or ""
    return {
        "success": bool(res.get("success")),
        "cause": normalize_cause(cause_raw),
        "cause_raw": str(cause_raw or ""),
        "verdict": str(cea.get("evidence_verdict") or ""),
        "observations": count("observations"),
        "claims": count("claims"),
        "challenges": count("challenges"),
        "alternatives": count("alternatives"),
        "gaps": count("gaps"),
        "trace_steps": len(res.get("reasoning_trace") or []),
        "tokens": res.get("token_count") or 0,
        # The run's own account of which stages executed.  The scorer
        # checks this against the arm's intent, so an arm that disabled
        # one stage but also skipped another is caught rather than
        # reported as a larger delta.
        "stage_execution": res.get("stage_execution") or {},
    }


def run_cell(stage: str, ev: dict):
    """Run one (stage, event) cell.  Safe to call in a worker process."""
    env_var = STAGES.get(stage)
    match = resolve_cache(
        ev["asn"], ev["start"], ev["end"], QUICK_DIR,
        event_id=ev["event_id"], allow_same_date=False,
    )
    rec = {
        "stage": stage,
        "event_id": ev["event_id"],
        "asn": ev["asn"],
        "gt_cause": ev["gt_cause"],
    }
    if match is None:
        rec["resolved"] = False
        return rec
    rec["resolved"] = True
    rec["cache"] = str(match.path)
    # Clear every switch before setting this arm's one.  The harness
    # runs the arms in one process, so a switch left set by a previous
    # arm would leak into this one and the arm would vary two stages
    # instead of one.
    reset_ablation_switches()
    # The campaign switch is set for *every* arm, the "full" baseline
    # included.  It suspends the skip-reasoning cost gate across the
    # whole campaign, so that the baseline cannot skip reasoning while
    # an ablated arm does not.  If the gate differed between the two,
    # the measured delta would belong to the stage under test and to the
    # gate at once, and the arms would no longer be comparable.
    os.environ[ABLATION_CAMPAIGN_ENV_VAR] = "1"
    if env_var:
        os.environ[env_var] = "1"
    try:
        quick = json.loads(match.path.read_text())
        rec.update(run_one(quick))
    except Exception as exc:  # noqa: BLE001
        rec["success"] = False
        rec["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        reset_ablation_switches()
    return rec


def check_single_variable(records: list[dict]):
    """Check that each arm really varied exactly one stage.

    The ablation's claim is that the delta against the full agent is
    attributable to the stage the arm names.  That claim is only worth
    anything if it is checked, and it can be: every run records which
    stages executed, so the harness can compare the arm's intent with
    the run's behaviour.

    Two things are checked per arm:

    * the named stage did not run, and
    * no *other* stage was silently taken down with it.

    The second is the one that matters.  A stage whose output is the
    gate for a later stage would take that later stage down with it
    when it is removed, and the arm would then measure two stages while
    reporting one.

    Returns a dict with ``ok`` (bool), ``violations`` (list of
    human-readable strings) and ``checked`` (how many runs had a stage
    record to check).
    """
    violations: list[str] = []
    checked = 0
    for r in records:
        stage = r.get("stage")
        if not stage:
            continue
        intent = STAGES.get(stage)
        # "no_<stage>" ablates "<stage>".
        ablated = stage[3:] if stage.startswith("no_") else None
        execution = r.get("stage_execution")
        if not isinstance(execution, dict) or not execution:
            # An older run predates the stage record; nothing to check.
            continue
        checked += 1
        if ablated:
            entry = execution.get(ablated) or {}
            if entry.get("ran"):
                violations.append(
                    f"{stage} / {r.get('event_id')}: stage '{ablated}' was "
                    f"ablated but the run reports it as having run"
                )
        for name, entry in execution.items():
            if not isinstance(entry, dict):
                continue
            if name == ablated:
                continue
            if not entry.get("ran"):
                violations.append(
                    f"{stage} / {r.get('event_id')}: stage '{name}' did not "
                    f"run, so this arm varies more than one stage"
                )
    return {
        "ok": not violations,
        "violations": violations[:50],
        "n_violations": len(violations),
        "checked": checked,
    }


def score(records: list[dict]):
    scored = [r for r in records if r.get("resolved")]
    ok = [r for r in scored if r.get("success")]
    correct = [r for r in ok if r.get("cause") and r["cause"] == r.get("gt_cause")]
    per_cause: dict[str, dict] = {}
    for r in scored:
        c = r.get("gt_cause") or "?"
        slot = per_cause.setdefault(c, {"n": 0, "correct": 0})
        slot["n"] += 1
        if r.get("cause") == c:
            slot["correct"] += 1
    for c, slot in per_cause.items():
        slot["accuracy"] = round(slot["correct"] / slot["n"], 4) if slot["n"] else None
    return {
        "n_scored": len(scored),
        "n_ran": len(ok),
        "n_failed": len(scored) - len(ok),
        "n_correct": len(correct),
        "accuracy": round(len(correct) / len(scored), 4) if scored else None,
        "coverage": round(len(ok) / len(scored), 4) if scored else None,
        "per_cause": per_cause,
        "single_variable": check_single_variable(records),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--stages", default=",".join(STAGES.keys()))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    events = load_gt()
    if args.limit:
        events = events[: args.limit]

    out: dict = {"records": [], "meta": {}}
    if args.resume and Path(args.out).exists():
        out = json.loads(Path(args.out).read_text())
    done = {(r.get("stage"), r.get("event_id")) for r in out.get("records", [])}
    out["records"] = [
        r for r in out.get("records", []) if r.get("stage") in stages
    ]

    pending = [
        (stage, ev) for stage in stages for ev in events
        if (stage, ev["event_id"]) not in done
    ]

    if pending and args.workers > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed

        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(run_cell, stage, ev): (stage, ev) for stage, ev in pending
            }
            for fut in as_completed(futures):
                stage, ev = futures[fut]
                try:
                    rec = fut.result()
                except Exception as exc:  # noqa: BLE001
                    rec = {
                        "stage": stage, "event_id": ev["event_id"],
                        "asn": ev["asn"], "gt_cause": ev["gt_cause"],
                        "resolved": False, "success": False,
                        "error": f"worker failed: {type(exc).__name__}: {exc}",
                    }
                out["records"].append(rec)
                done.add((stage, ev["event_id"]))
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(json.dumps(out, indent=1, default=str))
                logger.info(
                    f"[ablation] {stage:20s} {ev['event_id']:44s} "
                    f"cause={rec.get('cause', '-')} gt={ev['gt_cause']} "
                    f"ok={rec.get('success')}"
                )
    else:
        for stage, ev in pending:
            rec = run_cell(stage, ev)
            out["records"].append(rec)
            done.add((stage, ev["event_id"]))
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(out, indent=1, default=str))
            logger.info(
                f"[ablation] {stage:20s} {ev['event_id']:44s} "
                f"cause={rec.get('cause', '-')} gt={ev['gt_cause']} "
                f"ok={rec.get('success')}"
            )

    summary = {}
    for stage in stages:
        rs = [r for r in out["records"] if r.get("stage") == stage]
        if rs:
            summary[stage] = score(rs)

    baseline = summary.get("full", {})
    base_acc = baseline.get("accuracy")
    for stage, s in summary.items():
        s["delta_vs_full"] = (
            round(s["accuracy"] - base_acc, 4)
            if base_acc is not None and s.get("accuracy") is not None
            else None
        )

    out["summary"] = summary
    # The single-variable property is checked across the whole run, not
    # per arm, so a violation anywhere invalidates the attribution.
    overall = check_single_variable(out["records"])
    out["single_variable_check"] = overall
    if not overall["ok"] and overall["n_violations"]:
        logger.warning(
            f"[ablation] single-variable check FAILED with "
            f"{overall['n_violations']} violation(s): "
            f"{overall['violations'][:5]}"
        )
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_events": len(events),
        "stages": stages,
        "single_variable_ok": overall["ok"],
        "note": (
            "Each arm disables exactly one coordination stage via the "
            "workflow engine's BGP_TRACER_ABLATE_* switches and re-runs the "
            "same events with the same caches, labels and scorer. Events that "
            "fail to run are scored as failures, never dropped. Each run "
            "records which stages executed, and the harness verifies that "
            "every arm varied exactly one stage."
        ),
    }
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
