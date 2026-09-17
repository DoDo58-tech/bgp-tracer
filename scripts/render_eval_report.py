"""Render evaluation metrics.json into a markdown report.

Usage:
    python3 scripts/render_eval_report.py <metrics.json> [output.md]

If output path is omitted, writes alongside metrics.json as report.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def render(metrics_path: Path) -> str:
    with open(metrics_path) as f:
        m = json.load(f)
    modes = m["meta"]["modes"]
    lines = []
    lines.append(f"# Multi-Metric Evaluation Report")
    lines.append("")
    lines.append(f"**Source**: `{metrics_path}`")
    lines.append(f"**Generated**: {m['meta']['timestamp']}")
    lines.append(f"**Total events**: {m['meta']['n_events']}")
    lines.append(f"**Modes**: {', '.join(modes)}")
    lines.append(f"**Total runtime**: {m['meta']['total_runtime_seconds']/60:.1f} min")
    if m['meta'].get('skipped_budget', 0) > 0:
        lines.append(f"**Skipped (budget exhausted)**: {m['meta']['skipped_budget']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # M1
    lines.append("## M1: Detection Accuracy")
    lines.append("")
    lines.append("| Mode | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for mode in modes:
        mm = m["M1_detection_accuracy"].get(mode, {})
        lines.append(
            f"| {mode} | {mm.get('precision', 0):.3f} | {mm.get('recall', 0):.3f} | "
            f"{mm.get('f1', 0):.3f} | {mm.get('accuracy', 0):.3f} | "
            f"{mm.get('tp', 0)} | {mm.get('fp', 0)} | {mm.get('tn', 0)} | {mm.get('fn', 0)} |"
        )
    lines.append("")
    lines.append("### Per-event-type breakdown")
    lines.append("")
    for mode in modes:
        per_type = m["M1_detection_accuracy"].get(mode, {}).get("per_type", {})
        if per_type:
            lines.append(f"**{mode}**:")
            lines.append("")
            lines.append("| Event type | Precision | Recall | F1 | TP | FP | FN |")
            lines.append("|---|---|---|---|---|---|---|")
            for t, v in per_type.items():
                lines.append(
                    f"| {t} | {v['precision']:.3f} | {v['recall']:.3f} | "
                    f"{v['f1']:.3f} | {v['tp']} | {v['fp']} | {v['fn']} |"
                )
            lines.append("")

    # M2
    lines.append("## M2: Causal Direction Agreement")
    lines.append("")
    lines.append("| Mode | Agreement rate | N evaluated |")
    lines.append("|---|---|---|")
    for mode in modes:
        mm = m["M2_causal_direction"].get(mode, {})
        lines.append(f"| {mode} | {mm.get('agreement_rate', 0):.3f} | {mm.get('total_evaluated', 0)} |")
    lines.append("")

    # M3
    lines.append("## M3: Scientific Soundness")
    lines.append("")
    lines.append("| Mode | Stationarity checks pass | Fail | Pass rate |")
    lines.append("|---|---|---|---|")
    for mode in modes:
        mm = m["M3_scientific_soundness"].get(mode, {})
        lines.append(
            f"| {mode} | {mm.get('stationarity_checks_pass', 0)} | "
            f"{mm.get('stationarity_checks_fail', 0)} | {mm.get('pass_rate', 0):.3f} |"
        )
    lines.append("")

    # M4
    lines.append("## M4: Report Quality")
    lines.append("")
    lines.append("| Mode | Content score | Section completeness | Images (mean) | Tables (mean) | HTML balanced | LLM-driven |")
    lines.append("|---|---|---|---|---|---|---|")
    for mode in modes:
        mm = m["M4_report_quality"].get(mode, {})
        cs = mm.get("content_score", {}).get("mean", 0)
        sc = mm.get("section_completeness", {}).get("mean", 0)
        ic = mm.get("image_count", {}).get("mean", 0)
        tc = mm.get("table_count", {}).get("mean", 0)
        hb = mm.get("html_balanced", {}).get("mean", 0)
        ld = mm.get("llm_driven", {}).get("mean", 0)
        lines.append(
            f"| {mode} | {cs:.3f} | {sc:.3f} | {ic:.2f} | {tc:.2f} | {hb:.3f} | {ld:.3f} |"
        )
    lines.append("")

    # M5
    lines.append("## M5: Efficiency")
    lines.append("")
    lines.append("| Mode | Avg time (s) | Median time (s) | Total time (h) | N runs | Avg tokens | Avg report KB |")
    lines.append("|---|---|---|---|---|---|---|")
    for mode in modes:
        mm = m["M5_efficiency"].get(mode, {})
        lines.append(
            f"| {mode} | {mm.get('avg_time_seconds', 0):.0f} | "
            f"{mm.get('median_time_seconds', 0):.0f} | "
            f"{mm.get('total_time_hours', 0):.2f} | "
            f"{mm.get('n_runs', 0)} | "
            f"{mm.get('avg_tokens', 'N/A')} | {mm.get('avg_report_kb', 'N/A')} |"
        )
    lines.append("")

    # M6
    lines.append("## M6: Robustness")
    lines.append("")
    lines.append("| Mode | Completed | Fallback | Fallback rate | Timeouts |")
    lines.append("|---|---|---|---|---|")
    for mode in modes:
        mm = m["M6_robustness"].get(mode, {})
        lines.append(
            f"| {mode} | {mm.get('completed', 0)} | "
            f"{mm.get('fallback', 0)} | {mm.get('fallback_rate', 0):.3f} | "
            f"{mm.get('timeouts', 0)} |"
        )
    lines.append("")

    # Final verdict
    lines.append("---")
    lines.append("")
    lines.append("## Summary Verdict")
    lines.append("")
    for mode in modes:
        m1 = m["M1_detection_accuracy"].get(mode, {})
        m4 = m["M4_report_quality"].get(mode, {})
        m5 = m["M5_efficiency"].get(mode, {})
        lines.append(f"**{mode}**:")
        lines.append(f"  - F1={m1.get('f1', 0):.3f}, "
                     f"content_score={m4.get('content_score', {}).get('mean', 0):.3f}, "
                     f"avg_time={m5.get('avg_time_seconds', 0):.0f}s")
        lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 render_eval_report.py <metrics.json> [output.md]",
              file=sys.stderr)
        return 1
    metrics_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else metrics_path.with_name("report.md")
    text = render(metrics_path)
    output_path.write_text(text)
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
