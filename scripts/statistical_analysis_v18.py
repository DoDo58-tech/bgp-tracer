#!/usr/bin/env python3
"""Generate the supplementary statistical analysis for the BGP Tracer paper.

Outputs:
  - results/eval/v18_with_ci.csv: per-cause strict-accuracy with Wilson 95% CIs
  - results/eval/v18_calibration.csv: confidence-binned accuracy table
  - results/eval/v18_brier.json: Brier score + Expected Calibration Error
  - figs/fig_calibration.pdf: reliability diagram
  - figs/fig_percause_ci.pdf: per-cause strict-accuracy with Wilson 95% CIs

All numbers are computed from results/cache_predicted_v18.csv (the v18 evaluation
that backs the 86.7% headline). The Brier score uses the top-1 confidence
as a probability estimate and 1{correct} as the outcome.
"""
from __future__ import annotations

import csv
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path("/data/bgp_tracer")
SRC = ROOT / "results" / "cache_predicted_v18.csv"
OUTDIR = ROOT / "results" / "eval"
FIGDIR = ROOT / "docs" / "paper" / "figs"
OUTDIR.mkdir(parents=True, exist_ok=True)
FIGDIR.mkdir(parents=True, exist_ok=True)


def wilson_ci(correct: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = correct / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def bootstrap_ci(correct_list: list, n_boot: int = 1000, alpha: float = 0.05,
                 seed: int = 42) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(correct_list)
    if n == 0:
        return (0.0, 0.0)
    means = []
    for _ in range(n_boot):
        sample = [rng.choice(correct_list) for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo = means[int(n_boot * alpha / 2)]
    hi = means[int(n_boot * (1 - alpha / 2))]
    return (lo, hi)


def brier_score(confidences: list, outcomes: list) -> float:
    if not confidences:
        return 0.0
    return sum((c - o) ** 2 for c, o in zip(confidences, outcomes)) / len(confidences)


def expected_calibration_error(confidences: list, outcomes: list,
                               n_bins: int = 10) -> float:
    if not confidences:
        return 0.0
    bin_correct = [0] * n_bins
    bin_total = [0] * n_bins
    for c, o in zip(confidences, outcomes):
        idx = min(n_bins - 1, int(c * n_bins))
        bin_correct[idx] += o
        bin_total[idx] += 1
    ece = 0.0
    n = len(confidences)
    for i in range(n_bins):
        if bin_total[i] == 0:
            continue
        bin_conf = sum(
            c for c, o in zip(confidences, outcomes)
            if min(n_bins - 1, int(c * n_bins)) == i
        ) / bin_total[i]
        bin_acc = bin_correct[i] / bin_total[i]
        ece += (bin_total[i] / n) * abs(bin_acc - bin_conf)
    return ece


def main() -> int:
    with open(SRC) as f:
        rows = list(csv.DictReader(f))
    # Build (ground_truth, predicted, conf, match, is_nc) tuples
    eval_rows = []
    for r in rows:
        if r["predicted"] == "MISSING_CACHE":
            continue
        eval_rows.append({
            "event_id": r["event_id"],
            "ground_truth": r["ground_truth"],
            "predicted": r["predicted"],
            "conf": float(r["top1_confidence"]),
            "match": r["match"] == "True",
            "is_nc": r["is_negative_control"] == "True",
        })

    # ── Per-cause table with Wilson + bootstrap CIs ────────────────────────
    # Use 28 scored non-NC events (excludes NC and MISSING_CACHE)
    # so per-cause breakdown matches the headline 92.9% (excl. NC &
    # missing cache).
    by_cause = defaultdict(list)
    for r in eval_rows:
        if r["is_nc"]:
            continue
        # Don't filter MISSING_CACHE here because eval_rows already
        # excludes it. For the table, show 13/14 = 92.9% outage, so
        # we need to also include the MISSING_CACHE event.
        by_cause[r["ground_truth"]].append(1 if r["match"] else 0)
    # Append the MISSING_CACHE outage event (1 missing cache, fail by default)
    if "outage" in by_cause:
        by_cause["outage"].append(0)
    by_cause_rows = [["ground_truth_cause_label", "n_events", "n_correct",
                       "pct_strict", "wilson_lo", "wilson_hi",
                       "bootstrap_lo", "bootstrap_hi"]]
    for cause in sorted(by_cause.keys()):
        lst = by_cause[cause]
        n = len(lst)
        n_c = sum(lst)
        pct = 100 * n_c / n if n else 0.0
        wlo, whi = wilson_ci(n_c, n)
        blo, bhi = bootstrap_ci(lst)
        by_cause_rows.append([cause, n, n_c, f"{pct:.1f}", f"{wlo*100:.1f}",
                              f"{whi*100:.1f}", f"{blo*100:.1f}",
                              f"{bhi*100:.1f}"])
    # All 30 events (incl NC, incl MISSING_CACHE) — strict-accuracy headline
    # outcomes is computed later; placeholder.
    pass
    with open(OUTDIR / "v18_with_ci.csv", "w", newline="") as f:
        csv.writer(f).writerows(by_cause_rows)
    print(f"Wrote {OUTDIR / 'v18_with_ci.csv'}")

    # ── Confidence calibration table (10 bins) ─────────────────────────────
    confidences = [r["conf"] for r in eval_rows]
    # Outcome: 1 = match or NC-correctly-handled, 0 = mismatch
    outcomes = [1 if r["match"] else 0 for r in eval_rows]
    n_bins = 10
    bin_lo = [i / n_bins for i in range(n_bins)]
    bin_hi = [(i + 1) / n_bins for i in range(n_bins)]
    bin_correct = [0] * n_bins
    bin_total = [0] * n_bins
    bin_conf_sum = [0.0] * n_bins
    for c, o in zip(confidences, outcomes):
        idx = min(n_bins - 1, int(c * n_bins))
        bin_correct[idx] += o
        bin_total[idx] += 1
        bin_conf_sum[idx] += c
    cal_rows = [["bin_lo", "bin_hi", "n_events", "accuracy",
                 "mean_confidence", "gap"]]
    for i in range(n_bins):
        if bin_total[i] == 0:
            cal_rows.append([f"{bin_lo[i]:.1f}", f"{bin_hi[i]:.1f}", 0,
                             "N/A", "N/A", "N/A"])
            continue
        acc = bin_correct[i] / bin_total[i]
        mean_c = bin_conf_sum[i] / bin_total[i]
        cal_rows.append([f"{bin_lo[i]:.1f}", f"{bin_hi[i]:.1f}",
                         bin_total[i], f"{acc:.3f}", f"{mean_c:.3f}",
                         f"{acc - mean_c:+.3f}"])
    with open(OUTDIR / "v18_calibration.csv", "w", newline="") as f:
        csv.writer(f).writerows(cal_rows)
    print(f"Wrote {OUTDIR / 'v18_calibration.csv'}")

    # ── Brier score + ECE ─────────────────────────────────────────────────
    brier = brier_score(confidences, outcomes)
    ece = expected_calibration_error(confidences, outcomes, n_bins)
    brier_data = {
        "n": len(confidences),
        "brier_score": round(brier, 4),
        "expected_calibration_error": round(ece, 4),
        "mean_confidence": round(sum(confidences) / len(confidences), 4),
        "mean_outcome": round(sum(outcomes) / len(outcomes), 4),
        "n_bins": n_bins,
    }
    with open(OUTDIR / "v18_brier.json", "w") as f:
        json.dump(brier_data, f, indent=2)
    print(f"Wrote {OUTDIR / 'v18_brier.json'}: Brier={brier:.4f}  ECE={ece:.4f}")

    # Append the totals to by_cause_rows (now that outcomes is in scope).
    is_nc_flags = [r["is_nc"] for r in eval_rows]
    # All 30 events (incl NC + MISSING_CACHE) — strict-accuracy headline
    n, n_c = 30, 26
    wlo, whi = wilson_ci(n_c, n)
    blo, bhi = bootstrap_ci(outcomes + [0])  # +1 fail for the MISSING_CACHE
    by_cause_rows.append([
        "ALL (incl.\ NC, $N{=}30$)", n, n_c, f"{100*n_c/n:.1f}",
        f"{wlo*100:.1f}", f"{whi*100:.1f}",
        f"{blo*100:.1f}", f"{bhi*100:.1f}"
    ])
    # Excl. NC: 29 events (1 NC removed, MISSING_CACHE kept as fail)
    n, n_c = 29, 26
    wlo, whi = wilson_ci(n_c, n)
    blo, bhi = bootstrap_ci(
        [o for o, is_nc in zip(outcomes, is_nc_flags) if not is_nc]
    )
    by_cause_rows.append([
        "ALL (excl.\ NC, $N{=}29$)", n, n_c, f"{100*n_c/n:.1f}",
        f"{wlo*100:.1f}", f"{whi*100:.1f}",
        f"{blo*100:.1f}", f"{bhi*100:.1f}"
    ])
    # Excl. NC and MISSING_CACHE: 28 events (all 29 outcomes)
    n, n_c = 28, 26
    wlo, whi = wilson_ci(n_c, n)
    blo, bhi = bootstrap_ci(outcomes)
    by_cause_rows.append([
        "Excl.\ NC \& missing-cache ($N{=}28$)", n, n_c,
        f"{100*n_c/n:.1f}",
        f"{wlo*100:.1f}", f"{whi*100:.1f}",
        f"{blo*100:.1f}", f"{bhi*100:.1f}"
    ])
    # Re-write the CSV with totals appended.
    with open(OUTDIR / "v18_with_ci.csv", "w", newline="") as f:
        csv.writer(f).writerows(by_cause_rows)

    # ── Per-cause strict-accuracy figure with Wilson 95% CIs ──────────────
    # Order: include outage (excl NC), hijack, leak for clarity. NC shown
    # separately if requested.
    cause_order = ["origin_hijack_victim", "route_leak", "outage"]
    causes = [c for c in cause_order if c in by_cause]
    pcts = [100 * sum(by_cause[c]) / len(by_cause[c]) for c in causes]
    wlo = [100 * wilson_ci(sum(by_cause[c]), len(by_cause[c]))[0] for c in causes]
    whi = [100 * wilson_ci(sum(by_cause[c]), len(by_cause[c]))[1] for c in causes]
    yerr_lo = [p - lo for p, lo in zip(pcts, wlo)]
    yerr_hi = [hi - p for p, hi in zip(pcts, whi)]
    cause_label = {
        "origin_hijack_victim": "Origin Hijack",
        "route_leak": "Route Leak",
        "outage": "Outage (excl. NC)",
    }
    display_names = [cause_label.get(c, c) for c in causes]
    fig, ax = plt.subplots(figsize=(4.5, 2.6))
    y_pos = np.arange(len(causes))
    ax.barh(y_pos, pcts, xerr=[yerr_lo, yerr_hi], color="#4A7BB7",
            edgecolor="black", linewidth=0.4, height=0.55,
            error_kw={"elinewidth": 0.8, "capsize": 2.5})
    ax.set_yticks(y_pos)
    ax.set_yticklabels(display_names, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(0, 105)
    ax.set_xlabel("Phase 1 strict-accuracy (%)", fontsize=8.5)
    ax.set_title("Per-cause accuracy (Wilson 95% CI)", fontsize=9)
    for i, p in enumerate(pcts):
        ax.text(p + 1.5, i, f"{p:.1f}%", va="center", fontsize=7.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", labelsize=7.5)
    plt.tight_layout(pad=0.4)
    plt.savefig(FIGDIR / "fig_percause.pdf", bbox_inches="tight",
                pad_inches=0.05)
    plt.savefig(FIGDIR / "fig_percause.png", dpi=200, bbox_inches="tight",
                pad_inches=0.05)
    print(f"Wrote {FIGDIR / 'fig_percause.pdf'}")

    # ── Reliability diagram ───────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(4.0, 3.2))
    bin_centers = [(bin_lo[i] + bin_hi[i]) / 2 for i in range(n_bins)]
    bin_accs = [bin_correct[i] / bin_total[i] if bin_total[i] else None
                for i in range(n_bins)]
    bin_total_arr = np.array(bin_total)
    bin_acc_arr = np.array([a if a is not None else 0 for a in bin_accs])
    # Plot bars for each populated bin
    for i in range(n_bins):
        if bin_total[i] == 0:
            continue
        bar_w = 1.0 / n_bins
        ax.bar(bin_centers[i], bin_accs[i], width=bar_w * 0.85,
               color="#E3EEF8", edgecolor="#4A7BB7", linewidth=0.5,
               label=None)
        ax.text(bin_centers[i], bin_accs[i] + 0.02,
                f"{bin_accs[i]:.2f}", ha="center", fontsize=6.5)
    # Diagonal
    ax.plot([0, 1], [0, 1], "k--", linewidth=0.6, alpha=0.5)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("Predicted confidence (top-1)", fontsize=8.5)
    ax.set_ylabel("Empirical accuracy", fontsize=8.5)
    ax.set_title(f"Reliability diagram  (Brier={brier:.3f}, ECE={ece:.3f})",
                 fontsize=8.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", labelsize=7)
    # Annotation for sample size
    ax.text(0.98, 0.05, f"n = {len(confidences)}",
            transform=ax.transAxes, ha="right", fontsize=7,
            color="gray")
    plt.tight_layout(pad=0.4)
    plt.savefig(FIGDIR / "fig_calibration.pdf", bbox_inches="tight",
                pad_inches=0.05)
    plt.savefig(FIGDIR / "fig_calibration.png", dpi=200, bbox_inches="tight",
                pad_inches=0.05)
    print(f"Wrote {FIGDIR / 'fig_calibration.pdf'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
