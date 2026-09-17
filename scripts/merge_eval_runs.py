"""Combine multiple eval run metrics into a single comparison report.

Usage:
    python3 scripts/merge_eval_runs.py data_check/evaluation/run_*/metrics.json \\
        -o data_check/evaluation/FINAL_REPORT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict


def merge_metrics(metrics_files: list[Path]) -> dict:
    """Merge multiple metrics.json files into one."""
    merged = {
        "M1_detection_accuracy": defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "per_type": defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})}),
        "M2_causal_direction": defaultdict(lambda: {"agree": 0, "total": 0, "per_direction": defaultdict(lambda: {"agree": 0, "total": 0})}),
        "M3_scientific_soundness": defaultdict(lambda: {"pass": 0, "fail": 0}),
        "M4_report_quality": defaultdict(lambda: defaultdict(list)),
        "M5_efficiency": defaultdict(lambda: {"times": [], "tokens": [], "sizes": [], "n_runs": 0}),
        "M6_robustness": defaultdict(lambda: {"completed": 0, "fallback": 0, "timeouts": 0, "reasons": defaultdict(int)}),
        "meta": {"runs": [], "total_runtime_seconds": 0, "total_events_unique": set()},
    }

    for mf in metrics_files:
        with open(mf) as f:
            m = json.load(f)

        merged["meta"]["runs"].append({
            "file": str(mf),
            "timestamp": m["meta"]["timestamp"],
            "events": m["meta"]["n_events"],
            "modes": m["meta"]["modes"],
        })
        merged["meta"]["total_runtime_seconds"] += m["meta"].get("total_runtime_seconds", 0)

        for mode in m["M1_detection_accuracy"]:
            mm = m["M1_detection_accuracy"][mode]
            merged["M1_detection_accuracy"][mode]["tp"] += mm.get("tp", 0)
            merged["M1_detection_accuracy"][mode]["fp"] += mm.get("fp", 0)
            merged["M1_detection_accuracy"][mode]["tn"] += mm.get("tn", 0)
            merged["M1_detection_accuracy"][mode]["fn"] += mm.get("fn", 0)
            for t, v in mm.get("per_type", {}).items():
                merged["M1_detection_accuracy"][mode]["per_type"][t]["tp"] += v.get("tp", 0)
                merged["M1_detection_accuracy"][mode]["per_type"][t]["fp"] += v.get("fp", 0)
                merged["M1_detection_accuracy"][mode]["per_type"][t]["tn"] += v.get("tn", 0)
                merged["M1_detection_accuracy"][mode]["per_type"][t]["fn"] += v.get("fn", 0)

        for mode in m["M2_causal_direction"]:
            mm = m["M2_causal_direction"][mode]
            merged["M2_causal_direction"][mode]["total"] += mm.get("total_evaluated", 0)
            # Per-direction aggregation is harder to merge across runs; we keep max
            for d, v in mm.get("per_direction", {}).items():
                cur = merged["M2_causal_direction"][mode]["per_direction"][d]
                cur["total"] += v.get("total", 0)
                cur["agree"] += v.get("agree", 0)

        for mode in m["M3_scientific_soundness"]:
            mm = m["M3_scientific_soundness"][mode]
            merged["M3_scientific_soundness"][mode]["pass"] += mm.get("stationarity_checks_pass", 0)
            merged["M3_scientific_soundness"][mode]["fail"] += mm.get("stationarity_checks_fail", 0)

        for mode in m["M4_report_quality"]:
            mm = m["M4_report_quality"][mode]
            for metric_k, v in mm.items():
                if isinstance(v, dict) and "mean" in v:
                    merged["M4_report_quality"][mode][metric_k].append(v["mean"])

        for mode in m["M5_efficiency"]:
            mm = m["M5_efficiency"][mode]
            if mm.get("avg_time_seconds", 0) > 0:
                merged["M5_efficiency"][mode]["times"].append(mm["avg_time_seconds"])
            if mm.get("avg_tokens"):
                merged["M5_efficiency"][mode]["tokens"].append(mm["avg_tokens"])
            if mm.get("avg_report_kb"):
                merged["M5_efficiency"][mode]["sizes"].append(mm["avg_report_kb"])
            merged["M5_efficiency"][mode]["n_runs"] += mm.get("n_runs", 0)

        for mode in m["M6_robustness"]:
            mm = m["M6_robustness"][mode]
            merged["M6_robustness"][mode]["completed"] += mm.get("completed", 0)
            merged["M6_robustness"][mode]["fallback"] += mm.get("fallback", 0)
            merged["M6_robustness"][mode]["timeouts"] += mm.get("timeouts", 0)
            for r, c in mm.get("fallback_reasons", {}).items():
                merged["M6_robustness"][mode]["reasons"][r] += c

    return merged


def render_markdown(merged: dict) -> str:
    """Render merged metrics as markdown report."""
    modes = sorted(set(merged["M1_detection_accuracy"].keys()))
    lines = []
    lines.append("# Final Multi-Metric Evaluation Report (Merged)")
    lines.append("")
    lines.append(f"**Combined from {len(merged['meta']['runs'])} run(s)**")
    lines.append(f"**Total runtime**: {merged['meta']['total_runtime_seconds']/3600:.2f} hours")
    lines.append("")
    lines.append("## Run Source Files")
    lines.append("")
    for r in merged["meta"]["runs"]:
        lines.append(f"- `{r['file']}` ({r['timestamp']}, {r['events']} events, modes: {', '.join(r['modes'])})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # M1
    lines.append("## M1: Detection Accuracy (Aggregated)")
    lines.append("")
    lines.append("| Mode | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for mode in modes:
        mm = merged["M1_detection_accuracy"][mode]
        tp, fp, tn, fn = mm["tp"], mm["fp"], mm["tn"], mm["fn"]
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / max(1e-9, prec + rec)
        acc = (tp + tn) / max(1, tp + fp + tn + fn)
        lines.append(f"| {mode} | {prec:.3f} | {rec:.3f} | {f1:.3f} | {acc:.3f} | "
                     f"{tp} | {fp} | {tn} | {fn} |")
    lines.append("")

    # M1 per-type
    for mode in modes:
        per_type = merged["M1_detection_accuracy"][mode]["per_type"]
        if not per_type:
            continue
        lines.append(f"### Per-type: {mode}")
        lines.append("")
        lines.append("| Event type | Precision | Recall | F1 | TP | FP | FN |")
        lines.append("|---|---|---|---|---|---|---|")
        for t, v in per_type.items():
            tp, fp, fn = v["tp"], v["fp"], v["fn"]
            prec = tp / max(1, tp + fp)
            rec = tp / max(1, tp + fn)
            f1 = 2 * prec * rec / max(1e-9, prec + rec)
            lines.append(f"| {t} | {prec:.3f} | {rec:.3f} | {f1:.3f} | {tp} | {fp} | {fn} |")
        lines.append("")

    # M2
    lines.append("## M2: Causal Direction Agreement (Aggregated)")
    lines.append("")
    lines.append("| Mode | Agreement rate | Total evaluated |")
    lines.append("|---|---|---|")
    for mode in modes:
        mm = merged["M2_causal_direction"][mode]
        total = mm["total"]
        # Sum agreement across per_direction
        agree = sum(d["agree"] for d in mm["per_direction"].values())
        rate = agree / max(1, total)
        lines.append(f"| {mode} | {rate:.3f} | {total} |")
    lines.append("")

    # M3
    lines.append("## M3: Scientific Soundness")
    lines.append("")
    lines.append("| Mode | Pass | Fail | Pass rate |")
    lines.append("|---|---|---|---|")
    for mode in modes:
        mm = merged["M3_scientific_soundness"][mode]
        total = mm["pass"] + mm["fail"]
        rate = mm["pass"] / max(1, total)
        lines.append(f"| {mode} | {mm['pass']} | {mm['fail']} | {rate:.3f} |")
    lines.append("")

    # M4
    lines.append("## M4: Report Quality (Average across runs)")
    lines.append("")
    lines.append("| Mode | Content score | Section completeness | HTML balanced | LLM-driven |")
    lines.append("|---|---|---|---|---|")
    for mode in modes:
        mm = merged["M4_report_quality"][mode]
        cs = sum(mm.get("content_score", []) or [0]) / max(1, len(mm.get("content_score", []) or [1]))
        sc = sum(mm.get("section_completeness", []) or [0]) / max(1, len(mm.get("section_completeness", []) or [1]))
        hb = sum(mm.get("html_balanced", []) or [0]) / max(1, len(mm.get("html_balanced", []) or [1]))
        ld = sum(mm.get("llm_driven", []) or [0]) / max(1, len(mm.get("llm_driven", []) or [1]))
        lines.append(f"| {mode} | {cs:.3f} | {sc:.3f} | {hb:.3f} | {ld:.3f} |")
    lines.append("")

    # M5
    lines.append("## M5: Efficiency (Aggregated)")
    lines.append("")
    lines.append("| Mode | Avg time/run | N runs | Total time (h) |")
    lines.append("|---|---|---|---|")
    for mode in modes:
        mm = merged["M5_efficiency"][mode]
        n = mm["n_runs"]
        avg = (sum(mm["times"]) / max(1, len(mm["times"]))) if mm["times"] else 0
        total = avg * n
        lines.append(f"| {mode} | {avg:.0f}s | {n} | {total/3600:.2f} |")
    lines.append("")

    # M6
    lines.append("## M6: Robustness")
    lines.append("")
    lines.append("| Mode | Completed | Fallback | Fallback rate | Timeouts |")
    lines.append("|---|---|---|---|---|")
    for mode in modes:
        mm = merged["M6_robustness"][mode]
        completed = mm["completed"]
        fallback = mm["fallback"]
        rate = fallback / max(1, completed)
        lines.append(f"| {mode} | {completed} | {fallback} | {rate:.3f} | {mm['timeouts']} |")
    lines.append("")

    # Reasons breakdown
    lines.append("### Fallback Reasons")
    lines.append("")
    for mode in modes:
        reasons = dict(merged["M6_robustness"][mode]["reasons"])
        if reasons:
            lines.append(f"**{mode}**:")
            for r, c in sorted(reasons.items(), key=lambda x: -x[1]):
                lines.append(f"  - `{r}`: {c}")
            lines.append("")

    # Verdict
    lines.append("---")
    lines.append("")
    lines.append("## Cross-Mode Comparison")
    lines.append("")
    lines.append("### Which mode is best at each task?")
    lines.append("")
    lines.append("| Metric | traffic_first | traffic_first_enhanced | react | react_enhanced |")
    lines.append("|---|---|---|---|---|")
    lines.append("| F1 (detection) | ... | ... | ... | ... |")
    lines.append("| Direction agreement | ... | ... | ... | ... |")
    lines.append("| Content quality | ... | ... | ... | ... |")
    lines.append("| Speed | fastest | slow | medium | slowest |")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics_files", nargs="+", help="metrics.json files to merge")
    parser.add_argument("-o", "--output", default=None,
                        help="Output markdown path (default: stdout)")
    args = parser.parse_args()

    files = [Path(f) for f in args.metrics_files]
    merged = merge_metrics(files)
    md = render_markdown(merged)

    if args.output:
        Path(args.output).write_text(md)
        print(f"Wrote {args.output}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
