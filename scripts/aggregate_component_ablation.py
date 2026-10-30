"""Recompute the aggregate summary of the component-ablation repeats.

``component_ablation_repeats.py`` writes the aggregate ``summary`` and
``paired_deltas_vs_full`` blocks only when the whole sweep finishes.
This script recomputes those blocks from the per-run records already in
the artefact, so the summary can be refreshed without re-running the
sweep.  The per-run records are the ground truth; this script only
aggregates them, and it uses exactly the same arithmetic as the sweep
itself, so the two agree by construction.

Writes results/eval/component_ablation_repeats.json in place.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = PROJECT_ROOT / "results" / "eval" / "component_ablation_repeats.json"
#: The sweep overwrites its own output while it runs, so the aggregate
#: summary is written to a separate, stable artefact that the gates read.
SUMMARY_PATH = (
    PROJECT_ROOT / "results" / "eval" / "component_ablation_summary.json"
)


def summarize(values: list[float]) -> dict:
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
        "q3": round(ordered[(3 * len(values)) // 4], 4),
    }


def bootstrap_ci(values: list[float], n: int = 2000,
                 seed: int = 20240117) -> list:
    if len(values) < 2:
        return [values[0], values[0]] if values else [None, None]
    rng = random.Random(seed)
    means = []
    for _ in range(n):
        sample = [values[rng.randrange(len(values))] for _ in range(len(values))]
        means.append(statistics.mean(sample))
    means.sort()
    return [round(means[int(0.025 * (n - 1))], 4),
            round(means[int(0.975 * (n - 1))], 4)]


def per_run_stats(runs: list[dict]) -> dict:
    table: dict = {}
    for run in runs:
        rep = run.get("repeat")
        stage = run.get("stage")
        if rep is None or stage is None:
            continue
        rows = run.get("records") or []
        scored = [r for r in rows if r.get("resolved")]
        ok = [r for r in scored if r.get("success")]
        correct = [r for r in ok if r.get("cause") == r.get("gt_cause")]
        # A resolved event whose run failed counts as a wrong answer: the arm
        # was asked to answer every event, so excluding the failures would
        # reward an arm for crashing on the events it could not handle.
        acc = len(correct) / len(scored) if scored else None
        table.setdefault(stage, {})[rep] = {
            "n_scored": len(scored),
            "n_ran": len(ok),
            "n_correct": len(correct),
            "accuracy": round(acc, 4) if acc is not None else None,
            "causes": {r["event_id"]: r.get("cause") for r in ok},
        }
    return table


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=str(DEFAULT_PATH))
    args = ap.parse_args()

    path = Path(args.path)
    data = json.loads(path.read_text())
    runs = data.get("runs") or []
    table = per_run_stats(runs)
    stages = list(table.keys())

    summary = {}
    for stage, slots in table.items():
        accs = [s["accuracy"] for s in slots.values()
                if s.get("accuracy") is not None]
        reps = sorted(slots)
        pairs = same = 0
        for i in range(len(reps)):
            for j in range(i + 1, len(reps)):
                a = slots[reps[i]].get("causes") or {}
                b = slots[reps[j]].get("causes") or {}
                for eid in set(a) & set(b):
                    pairs += 1
                    if a[eid] == b[eid]:
                        same += 1
        summary[stage] = {
            "accuracy_across_runs": summarize(accs),
            "bootstrap_ci95_of_mean": bootstrap_ci(accs),
            "run_to_run_agreement": {
                "n_event_pairs": pairs,
                "agreement": round(same / pairs, 4) if pairs else None,
            },
        }

    full_runs = table.get("full", {})
    paired = {}
    for stage in stages:
        if stage == "full":
            continue
        diffs = []
        for rep, slot in table.get(stage, {}).items():
            base = full_runs.get(rep)
            if not base or base.get("accuracy") is None \
                    or slot.get("accuracy") is None:
                continue
            diffs.append(slot["accuracy"] - base["accuracy"])
        if diffs:
            paired[stage] = {
                "n_paired_runs": len(diffs),
                **summarize(diffs),
                "bootstrap_ci95": bootstrap_ci(diffs),
                "all_deltas_zero": all(abs(d) < 1e-9 for d in diffs),
            }

    data["summary"] = summary
    data["paired_deltas_vs_full"] = paired

    headline = {"full": {
        "accuracy": (full_runs.get(0) or {}).get("accuracy"),
        "n_correct": (full_runs.get(0) or {}).get("n_correct"),
        "n_scored": (full_runs.get(0) or {}).get("n_scored"),
    }}
    mono_path = PROJECT_ROOT / "results" / "eval" / "gt_baseline_monolithic.json"
    if mono_path.exists():
        try:
            mono = json.loads(mono_path.read_text())
            acc = (mono.get("summary") or {}).get("cause_accuracy_evaluable")
            headline["monolithic"] = {
                "accuracy": (acc or {}).get("accuracy"),
                "n_correct": (acc or {}).get("correct"),
                "n_scored": (acc or {}).get("n"),
            }
        except (OSError, ValueError):
            pass
    data["headline"] = headline

    path.write_text(json.dumps(data, indent=1, default=str))
    SUMMARY_PATH.write_text(json.dumps(data, indent=1, default=str))
    print(f"{path}")
    print(f"{SUMMARY_PATH}")
    for stage, slot in summary.items():
        s = slot["accuracy_across_runs"]
        print(f"  {stage:22s} mean={s['mean']:.4f} stdev={s['stdev']:.4f} "
              f"n={s['n']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
