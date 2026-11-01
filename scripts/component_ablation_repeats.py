"""Repeated component ablation: variance across runs.

The single-pass component ablation in ``component_ablation_gt.py``
cannot separate a stage's effect from run-to-run noise, because the
pipeline calls an LLM and the LLM's answer is not deterministic.  This
script runs the ablation repeatedly and reports, for every arm, the
distribution of the cause accuracy across runs, so that a difference
between two arms can be compared against the spread of the arm that
produced it.

It reports, for each arm:

  * the number of runs,
  * the mean, standard deviation and interquartile range of accuracy,
  * the bootstrap confidence interval of the mean,
  * the paired difference against the full pipeline, computed per run
    (the two arms see the same events in the same run, so the pairing
    removes the event-level variance),
  * the per-event agreement rate between runs of the same arm, which is
    the direct measurement of how noisy a single run is.

The paired test is the one that answers the question the paper asks:
a stage's delta is real when the paired difference is larger than the
run-to-run spread of that difference.

Writes results/eval/component_ablation_repeats.json.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
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

OUT_PATH = (
    PROJECT_ROOT / "results" / "eval" / "component_ablation_repeats.json"
)
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
EVAL = PROJECT_ROOT / "results" / "eval"

# Derived from the shared switch module, so this harness and the
# engine agree on which variable each arm varies.
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


def load_events():
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def run_cell(stage: str, ev: dict):
    from chief_agent import analyze_deep_from_quick

    env_var = STAGES.get(stage)
    match = resolve_cache(
        ev["asn"], ev["start"], ev["end"], QUICK_DIR,
        event_id=ev["event_id"], allow_same_date=False,
    )
    rec = {
        "stage": stage,
        "event_id": ev["event_id"],
        "gt_cause": ev["gt_cause"],
    }
    if match is None:
        rec["resolved"] = False
        return rec
    rec["resolved"] = True
    # Clear every switch before setting this arm's one: the arms run in
    # one process, and a switch left set would leak into the next arm.
    reset_ablation_switches()
    # The campaign switch is set for every arm, the "full" baseline
    # included, so that the skip-reasoning cost gate is suspended
    # identically in all of them.  Otherwise the baseline could skip
    # reasoning while an ablated arm did not, and the delta would
    # measure two variables instead of one.
    os.environ[ABLATION_CAMPAIGN_ENV_VAR] = "1"
    if env_var:
        os.environ[env_var] = "1"
    try:
        quick = json.loads(match.path.read_text())
        res = analyze_deep_from_quick(quick_result=quick, analysis_mode="traffic_first")
        cea = res.get("chief_expert_analysis") or {}
        ec = res.get("evidence_chain") or {}
        cause_raw = ec.get("cause") or cea.get("cause") or ""
        rec.update({
            "success": bool(res.get("success")),
            "cause": normalize_cause(cause_raw),
            "cause_raw": str(cause_raw or ""),
            "verdict": str(cea.get("evidence_verdict") or ""),
            "stage_execution": res.get("stage_execution") or {},
        })
    except Exception as exc:  # noqa: BLE001
        rec["success"] = False
        rec["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        reset_ablation_switches()
    return rec


def run_stage(stage: str, events: list, workers: int):
    """The cells of one arm, in parallel when there is more than one.

    The ablation switch is an environment variable, so each cell has to
    run in its own process: a switch set for one event would leak into
    the next one.
    """
    if not events:
        return []
    if workers <= 1 or len(events) == 1:
        return [run_cell(stage, ev) for ev in events]

    from concurrent.futures import ProcessPoolExecutor, as_completed

    records = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_cell, stage, ev): ev for ev in events}
        for fut in as_completed(futures):
            ev = futures[fut]
            try:
                records.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                records.append({
                    "stage": stage,
                    "event_id": ev["event_id"],
                    "gt_cause": ev["gt_cause"],
                    "resolved": True,
                    "success": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })
    return records


def summarize(values: list[float]):
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 4),
        "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "q1": round(ordered[len(ordered) // 4], 4),
        "median": round(statistics.median(values), 4),
        "q3": round(ordered[(3 * len(ordered)) // 4], 4),
    }


def bootstrap_ci(values: list[float], n: int = 2000, seed: int = 20240117):
    if len(values) < 2:
        return [values[0], values[0]] if values else [None, None]
    rng = random.Random(seed)
    means = []
    for _ in range(n):
        sample = [values[rng.randrange(len(values))] for _ in range(len(values))]
        means.append(statistics.mean(sample))
    means.sort()
    return [
        round(means[int(0.025 * (n - 1))], 4),
        round(means[int(0.975 * (n - 1))], 4),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--stages", default=",".join(STAGES.keys()))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    args = ap.parse_args()

    stages = [s.strip() for s in args.stages.split(",") if s.strip()]
    events = load_events()
    if args.limit:
        events = events[: args.limit]

    out: dict = {"runs": [], "meta": {}}
    out_path = Path(args.out)
    if out_path.exists():
        try:
            out = json.loads(out_path.read_text())
        except ValueError:
            out = {"runs": [], "meta": {}}

    done = {
        (r.get("repeat"), r.get("stage"), r.get("event_id"))
        for run in out.get("runs", [])
        for r in run.get("records", [])
    }

    for rep in range(args.repeats):
        for stage in stages:
            run_rec = None
            for candidate in out.get("runs", []):
                if candidate.get("repeat") == rep and candidate.get("stage") == stage:
                    run_rec = candidate
                    break
            if run_rec is None:
                run_rec = {
                    "repeat": rep,
                    "stage": stage,
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "records": [],
                }
                out.setdefault("runs", []).append(run_rec)

            pending = [ev for ev in events
                       if (rep, stage, ev["event_id"]) not in done]
            records = run_stage(stage, pending, args.workers)
            for rec in records:
                run_rec["records"].append(rec)
                done.add((rep, stage, rec.get("event_id")))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(out, indent=1, default=str))
            for rec in records:
                logger.info(
                    f"[repeat {rep}] {stage:20s} {rec.get('event_id', ''):44s} "
                    f"cause={rec.get('cause', '-')} ok={rec.get('success')}"
                )

    # ── Aggregate ──────────────────────────────────────────────────────
    per_run: dict = {}
    for run in out.get("runs", []):
        rep = run.get("repeat")
        stage = run.get("stage")
        if stage is None:
            continue
        rows = run.get("records", [])
        scored = [r for r in rows if r.get("resolved")]
        ok = [r for r in scored if r.get("success")]
        correct = [r for r in ok if r.get("cause") == r.get("gt_cause")]
        # A resolved event whose pipeline run failed is a wrong answer, not a
        # missing one: the arm was asked to answer every event in the corpus,
        # so dropping the failures from the denominator would quietly reward
        # an arm for crashing on the events it could not handle.
        acc = len(correct) / len(scored) if scored else None
        per_run.setdefault(stage, {})[rep] = {
            "n_scored": len(scored),
            "n_ran": len(ok),
            "n_correct": len(correct),
            "accuracy": round(acc, 4) if acc is not None else None,
            "causes": {r["event_id"]: r.get("cause") for r in ok},
        }

    # Paired differences against the full arm, computed within a run.
    paired: dict = {}
    full_runs = per_run.get("full", {})
    for stage in stages:
        if stage == "full":
            continue
        diffs = []
        for rep, slot in per_run.get(stage, {}).items():
            base = full_runs.get(rep)
            if not base or base.get("accuracy") is None or slot.get("accuracy") is None:
                continue
            diffs.append(slot["accuracy"] - base["accuracy"])
        if diffs:
            paired[stage] = {
                "n_paired_runs": len(diffs),
                **summarize(diffs),
                "bootstrap_ci95": bootstrap_ci(diffs),
                "all_deltas_zero": all(abs(d) < 1e-9 for d in diffs),
            }

    # Run-to-run agreement within an arm.
    agreement: dict = {}
    for stage, runs in per_run.items():
        reps = sorted(runs)
        pairs = 0
        same = 0
        for i in range(len(reps)):
            for j in range(i + 1, len(reps)):
                a = runs[reps[i]].get("causes") or {}
                b = runs[reps[j]].get("causes") or {}
                for eid in set(a) & set(b):
                    pairs += 1
                    if a[eid] == b[eid]:
                        same += 1
        agreement[stage] = {
            "n_event_pairs": pairs,
            "agreement": round(same / pairs, 4) if pairs else None,
        }

    out["summary"] = {
        stage: {
            "accuracy_across_runs": summarize([
                slot["accuracy"] for slot in runs.values()
                if slot.get("accuracy") is not None
            ]),
            "bootstrap_ci95_of_mean": bootstrap_ci([
                slot["accuracy"] for slot in runs.values()
                if slot.get("accuracy") is not None
            ]),
            "run_to_run_agreement": agreement[stage],
        }
        for stage, runs in per_run.items()
    }
    out["headline"] = {
        "full": {
            "accuracy": (per_run.get("full") or {}).get(0, {}).get("accuracy"),
            "n_correct": (per_run.get("full") or {}).get(0, {}).get("n_correct"),
            "n_scored": (per_run.get("full") or {}).get(0, {}).get("n_scored"),
        },
    }
    monolithic = EVAL / "gt_baseline_monolithic.json"
    if monolithic.exists():
        try:
            mono = json.loads(monolithic.read_text())
            acc = (mono.get("summary") or {}).get("cause_accuracy_evaluable")
            out["headline"]["monolithic"] = {
                "accuracy": (acc or {}).get("accuracy"),
                "n_correct": (acc or {}).get("correct"),
                "n_scored": (acc or {}).get("n"),
            }
        except (OSError, ValueError):
            pass
    out["paired_deltas_vs_full"] = paired
    out["meta"] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "n_events": len(events),
        "repeats": args.repeats,
        "stages": stages,
        "note": (
            "Each repeat re-runs every arm over the identical events with "
            "the identical caches. The pipeline calls an LLM, so a repeat "
            "is an independent draw of the stochastic part of the pipeline "
            "and the spread across repeats is the noise floor against "
            "which an arm's delta must be judged."
        ),
    }
    out_path.write_text(json.dumps(out, indent=1, default=str))

    print()
    print(f"{'arm':22s} {'mean':>7s} {'stdev':>7s} {'ci95':>18s} {'agreement':>10s}")
    for stage in stages:
        slot = out["summary"].get(stage)
        if not slot:
            continue
        s = slot["accuracy_across_runs"]
        ci = slot["bootstrap_ci95_of_mean"]
        ag = slot["run_to_run_agreement"]["agreement"]
        print(f"{stage:22s} {s['mean']:>7} {s['stdev']:>7} "
              f"[{ci[0]:>6},{ci[1]:>6}] {str(ag):>10}")
    print()
    print("paired deltas vs full:")
    for stage, slot in paired.items():
        print(f"  {stage:22s} mean={slot['mean']:+.4f} stdev={slot['stdev']:.4f} "
              f"ci95=[{slot['bootstrap_ci95'][0]:+.4f},{slot['bootstrap_ci95'][1]:+.4f}] "
              f"n={slot['n_paired_runs']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
