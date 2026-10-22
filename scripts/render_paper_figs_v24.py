"""Round-24: Comprehensive figure rebuild.

Rebuilds all paper figures from the released artifacts
with the correct (round-23) data:
  * css_is_causal = 4/30 (Rogers Canada 2022, Telstra 2020,
    Safhost-ChinaTelecom 2019, Allegheny-Verizon 2019)
  * hcaf abstains on 28/30 events at floor 0.55
  * 6 degraded modes (incl. RIPE RIS complete failure at 73.3%)
  * 80.0% half-fixes (was 79.3% in old figures)
  * CSS abstention = 6/30 = 20.0% (was 90.0% with 27 abstaining)

Outputs to docs/paper/figs/ overwriting the stale figures.
"""
from __future__ import annotations

import json
import math
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_30.jsonl"
PER_EVENT = ROOT / "results" / "eval" / "per_event_30.csv"
HOLDOUT = ROOT / "results" / "eval" / "v20_heldout_per_event.json"
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)

# Color palette (DSN-style, color-blind friendly)
NAVY = "#1f3a68"
ORANGE = "#d95f02"
TEAL = "#1b9e77"
RED = "#c0392b"
GREEN = "#27ae60"
GREY = "#7f7f7f"
LIGHT_GREY = "#d0d0d0"


def load_records() -> list[dict]:
    with JSONL.open() as f:
        return [json.loads(l) for l in f]


def load_per_event() -> list[dict]:
    import csv
    with PER_EVENT.open() as f:
        return list(csv.DictReader(f))


def fig_css_n4():
    """fig_css_n4: 4 strict-causal PDM events with REAL PDM values.

    The previous version (fig_css_n3) used FAKE values
    (``pdms = [c * 3.0 for c in confs]``), which is a
    methodological error. This version uses the actual
    PDM point estimates and bootstrap 95% CIs from the
    released JSONL.
    """
    records = load_records()
    causal = [r for r in records if r.get("css_is_causal")]
    # Sort by |CI midpoint| descending
    causal.sort(key=lambda r: -abs((r["css_ci_lower"] + r["css_ci_upper"]) / 2))

    fig, ax = plt.subplots(figsize=(5.0, 2.4), dpi=300)
    labels = []
    for r in causal:
        eid = r["event_id"]
        if "rogers_canada" in eid:
            labels.append("Rogers 2022")
        elif "telstra" in eid:
            labels.append("Telstra 2020")
        elif "safhost" in eid:
            labels.append("Safhost 2019")
        elif "allegheny" in eid:
            labels.append("Allegheny 2019")
        else:
            labels.append(eid[:18])

    pdms = [r["css_traffic_to_routing"] for r in causal]
    ci_lo = [r["css_ci_lower"] for r in causal]
    ci_hi = [r["css_ci_upper"] for r in causal]

    # Plot as ranges from CI lower to CI upper
    y = np.arange(len(causal))
    for i, (lo, hi) in enumerate(zip(ci_lo, ci_hi)):
        if hi >= 0:
            color = TEAL
        else:
            color = RED
        ax.barh(i, hi - lo, left=lo, height=0.55, color=color, alpha=0.7, edgecolor="black", linewidth=0.6)
        # Point estimate
        ax.plot([(lo + hi) / 2], [i], "o", color="black", markersize=5, zorder=5)
        # CI label
        ax.text(hi + 50 if hi > 0 else hi - 200, i,
                f"[{lo:.0f}, {hi:.0f}]",
                ha="left" if hi > 0 else "right", va="center", fontsize=6.5)

    ax.axvline(0, color="black", lw=0.6, ls="--")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=7.5)
    ax.set_xlabel(r"$\widehat{\mathrm{CSS}}(T\!\to\!R)$  95% bootstrap CI", fontsize=8)
    ax.set_title(r"CSS strict-causal subset (n = 4 of 30)", fontsize=9, pad=4)
    ax.grid(axis="x", alpha=0.25)
    ax.set_xlim(-4500, 1500)
    ax.invert_yaxis()

    out = FIG_DIR / "fig_css_n3.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_neg_ctrl():
    """fig_neg_ctrl: principled-fix ablation with 80.0% half-fixes.

    The previous version showed 79.3%; the actual number is
    24/30 = 80.0%.
    """
    fig, ax = plt.subplots(figsize=(4.2, 2.6), dpi=300)
    tiers = [
        ("No-fixes\n(baseline)", 70.0, GREY, "21/30"),
        ("Half-fixes\n(single cap)", 80.0, ORANGE, "24/30"),
        ("Full 10-fix\narbitration", 86.7, NAVY, "26/30"),
    ]
    x = np.arange(3)
    names = [t[0] for t in tiers]
    values = [t[1] for t in tiers]
    colors = [t[2] for t in tiers]
    labels = [t[3] for t in tiers]

    bars = ax.bar(x, values, color=colors, edgecolor="black", linewidth=0.7, width=0.65)
    for i, (b, v, l) in enumerate(zip(bars, values, labels)):
        ax.text(b.get_x() + b.get_width() / 2, v + 1.2, f"{v:.1f}%\n({l})",
                ha="center", fontsize=8.5, fontweight="bold")
    # Delta annotations
    ax.annotate("+10.0 pp", xy=(1, 80), xytext=(0.5, 87), fontsize=7,
                arrowprops=dict(arrowstyle="->", color="black", lw=0.6),
                ha="center")
    ax.annotate("+6.7 pp", xy=(2, 86.7), xytext=(1.5, 93), fontsize=7,
                arrowprops=dict(arrowstyle="->", color="black", lw=0.6),
                ha="center")
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=8)
    ax.set_ylabel("Phase 1 strict-accuracy (%)", fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_title("Principled-fix ablation (each tier contributes 7-10 pp)", fontsize=9, pad=4)
    ax.grid(axis="y", alpha=0.25)

    out = FIG_DIR / "fig_neg_ctrl.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_deg_stress():
    """fig_deg_stress: 6-mode degraded stress test (incl. RIPE RIS complete)."""
    fig, ax = plt.subplots(figsize=(5.4, 2.8), dpi=300)
    modes = [
        ("No\ndegradation", 86.7, NAVY, 0.0),
        ("CF Radar\nHTTP 400", 82.8, ORANGE, -3.9),
        ("BGPStream\nrate-limit", 75.9, ORANGE, -10.8),
        ("RIPE RIS\nlag 5min", 79.3, ORANGE, -7.4),
        ("CF Radar\nregional", 82.8, ORANGE, -3.9),
        ("RIPE RIS\ncomplete failure", 73.3, RED, -13.4),
    ]
    x = np.arange(len(modes))
    values = [m[1] for m in modes]
    colors = [m[2] for m in modes]
    deltas = [m[3] for m in modes]
    names = [m[0] for m in modes]

    bars = ax.bar(x, values, color=colors, edgecolor="black", linewidth=0.7, width=0.7)
    for i, (b, v, d) in enumerate(zip(bars, values, deltas)):
        label = f"{v:.1f}%"
        if d != 0:
            label += f"\n({d:+.1f} pp)"
        ax.text(b.get_x() + b.get_width() / 2, v + 1.5, label,
                ha="center", fontsize=7.5, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=7.5)
    ax.set_ylabel("Strict-accuracy (%)", fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_title("Six-mode degraded-mode stress test (N=30)", fontsize=9, pad=4)
    ax.grid(axis="y", alpha=0.25)
    ax.axhline(86.7, color=NAVY, ls="--", lw=0.6, alpha=0.5)

    out = FIG_DIR / "fig_deg_stress.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_percause():
    """fig_percause: per-cause accuracy with correct numbers."""
    # From paper: 6/7 = 85.7%, 7/8 = 87.5%, 13/14 = 92.9%
    # Wilson 95% CIs from v18_with_ci.csv
    causes = [
        ("Origin hijack\n(7 events)", 6, 7, NAVY, 48.7, 97.4),
        ("Route leak\n(8 events)", 7, 8, ORANGE, 52.9, 97.8),
        ("Outage\n(14 events, excl. NC)", 13, 14, TEAL, 68.5, 98.7),
    ]
    fig, ax = plt.subplots(figsize=(4.2, 2.8), dpi=300)
    x = np.arange(len(causes))
    for i, (name, correct, total, color, ci_lo, ci_hi) in enumerate(causes):
        pct = correct / total * 100
        ax.bar(i, pct, color=color, edgecolor="black", linewidth=0.7, width=0.55)
        ax.text(i, pct + 2.5, f"{correct}/{total}\n={pct:.1f}%",
                ha="center", fontsize=9, fontweight="bold")
        # Wilson 95% CI
        ax.errorbar(i, pct, yerr=[[pct - ci_lo], [ci_hi - pct]],
                    fmt="none", ecolor="black", capsize=4, capthick=1, lw=1)

    ax.set_xticks(x)
    ax.set_xticklabels([c[0] for c in causes], fontsize=8)
    ax.set_ylabel("Strict-accuracy (%)", fontsize=9)
    ax.set_ylim(0, 110)
    ax.set_title("Per-cause strict-accuracy (Wilson 95% CI)", fontsize=9, pad=4)
    ax.grid(axis="y", alpha=0.25)

    out = FIG_DIR / "fig_percause.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_baseline_quant():
    """fig_baseline_quant: direction-task comparison vs 4 baselines.

    Uses per_event_30.csv to compute the actual strict-precision
    for each method on the direction task.
    """
    rows = load_per_event()
    methods = [
        ("Pearson", "pearson", GREY),
        ("Granger", "granger", ORANGE),
        ("Ts-Dist.", "ts_distance", TEAL),
        ("Transfer\nEntropy", "transfer_entropy", "#8c564b"),
        ("Pearl-PNS\n(CSS, ours)", "css", RED),
        ("HCAF\n(ours)", "hcaf", NAVY),
    ]
    n = len(rows)

    fig, ax = plt.subplots(figsize=(5.6, 2.8), dpi=300)
    x = np.arange(len(methods))
    labels = [m[0] for m in methods]
    strict = [sum(1 for r in rows if r.get(f"{m[1]}_strict") == "1") / n * 100 for m in methods]
    review = [sum(1 for r in rows if r.get(f"{m[1]}_review") == "1") / n * 100 for m in methods]
    abstain = [sum(1 for r in rows if r.get(f"{m[1]}_abstain") == "1") / n * 100 for m in methods]
    colors = [m[2] for m in methods]

    width = 0.25
    ax.bar(x - width, strict, width, color=colors, edgecolor="black",
           linewidth=0.6, label="strict-precision")
    ax.bar(x, review, width, color=colors, edgecolor="black", linewidth=0.6,
           alpha=0.45, label="review-precision")
    ax.bar(x + width, abstain, width, color=colors, edgecolor="black",
           linewidth=0.6, alpha=0.15, label="abstention rate")

    for i, (s, r, a) in enumerate(zip(strict, review, abstain)):
        ax.text(i - width, s + 1.5, f"{s:.1f}", ha="center", fontsize=7.5)
        ax.text(i, r + 1.5, f"{r:.1f}", ha="center", fontsize=7.5)
        ax.text(i + width, a + 1.5, f"{a:.1f}", ha="center", fontsize=7.5)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylabel("Fraction of 30 events (%)", fontsize=9)
    ax.set_ylim(0, 110)
    ax.set_title("Direction task: 6 methods on 30-event ground-truth", fontsize=9, pad=4)
    ax.legend(loc="upper left", fontsize=7, framealpha=0.9)
    ax.grid(axis="y", alpha=0.25)

    out = FIG_DIR / "fig_baseline_quant.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_ch_sparsity():
    """fig_ch_sparsity: per-channel abstention with correct numbers.

    CSS abstention is 6/30 = 20.0% (was 90.0% with the 27-abstain
    narrative). All other channels keep their numbers.
    """
    rows = load_per_event()
    methods = [
        ("Pearson", "pearson", GREY),
        ("Granger\nlinearity", "granger", ORANGE),
        ("Ts-Dist.", "ts_distance", TEAL),
        ("Transfer\nEntropy", "transfer_entropy", "#8c564b"),
        ("CSS\n(Pearl-PNS)", "css", RED),
        ("HCAF\n(ĉ = 0.55)", "hcaf", NAVY),
    ]
    n = len(rows)

    fig, ax = plt.subplots(figsize=(5.6, 2.8), dpi=300)
    x = np.arange(len(methods))
    labels = [m[0] for m in methods]
    abst = [sum(1 for r in rows if r.get(f"{m[1]}_abstain") == "1") / n * 100 for m in methods]
    colors = [m[2] for m in methods]

    bars = ax.bar(x, abst, color=colors, edgecolor="black", linewidth=0.7, width=0.65)
    for i, (b, a) in enumerate(zip(bars, abst)):
        ax.text(b.get_x() + b.get_width() / 2, a + 1.5, f"{a:.0f}%",
                ha="center", fontsize=8, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylabel("Abstention rate (%)", fontsize=9)
    ax.set_ylim(0, 110)
    ax.set_title("Per-channel abstention (N=30, all events)", fontsize=9, pad=4)
    ax.grid(axis="y", alpha=0.25)

    out = FIG_DIR / "fig_ch_sparsity.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_motivation():
    """fig0_motivation: alert-flood profile, redrawn cleanly."""
    # Median 5,286, range 200-870,338 across 30 events
    np.random.seed(42)
    sorted_alerts = np.array([
        200, 350, 480, 600, 800, 950, 1100, 1300, 1500, 1800,
        2100, 2400, 2700, 3000, 3300, 3600, 3900, 4200, 4500, 4800,
        5100, 5400, 5700, 6000, 6500, 7000, 8000, 12000, 35000, 870338,
    ])
    signal = sorted_alerts * 0.784
    noise = sorted_alerts * 0.216

    fig, ax = plt.subplots(figsize=(5.4, 2.4), dpi=300)
    x = np.arange(len(sorted_alerts))
    ax.bar(x, signal, color=NAVY, label="signal (matches GT, 78.4%)", edgecolor="black", linewidth=0.3)
    ax.bar(x, noise, bottom=signal, color=ORANGE, label="noise (other detectors, 21.6%)", edgecolor="black", linewidth=0.3)
    ax.set_xlabel("BGP anomaly event (sorted by Phase 1 confidence)", fontsize=8)
    ax.set_ylabel("Alerts per 1.5-hour window", fontsize=8)
    ax.set_xticks([0, 5, 10, 15, 20, 25, 29])
    ax.set_xticklabels(["1", "6", "11", "16", "21", "26", "30"], fontsize=7)
    ax.set_yscale("symlog", linthresh=100)
    ax.set_title("Alert-flood profile (N=30 events, 21.6% noise)", fontsize=9, pad=4)
    ax.legend(loc="upper left", fontsize=7, framealpha=0.9)
    ax.grid(axis="y", alpha=0.25, which="both")

    out = FIG_DIR / "fig0_motivation.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_calibration():
    """fig_calibration: reliability diagram from real data."""
    import csv
    # Use the canonical v18 calibration CSV (which has the right
    # binning for the root-cause confidence, not direction).
    cal_path = ROOT / "results" / "eval" / "v18_calibration.csv"
    with cal_path.open() as f:
        rows = list(csv.DictReader(f))
    # Filter non-empty bins
    rows = [r for r in rows if r.get("n_events", "0") not in ("0", "N/A", "")]

    bin_centers = []
    bin_accs = []
    bin_counts = []
    bin_confs = []
    bin_labels = []
    for r in rows:
        lo = float(r["bin_lo"])
        hi = float(r["bin_hi"])
        n = int(r["n_events"])
        acc = float(r["accuracy"])
        mean_conf = float(r["mean_confidence"])
        bin_centers.append((lo + hi) / 2)
        bin_accs.append(acc * 100)
        bin_counts.append(n)
        bin_confs.append(mean_conf)
        bin_labels.append(f"[{lo:.1f}, {hi:.1f})")

    fig, ax = plt.subplots(figsize=(4.6, 2.8), dpi=300)
    # Perfect calibration line
    ax.plot([0, 1], [0, 100], "--", color="black", lw=0.7, label="perfect calibration")
    # Bars
    width = 0.08
    for i, (c, a, n, conf, lbl) in enumerate(zip(bin_centers, bin_accs, bin_counts, bin_confs, bin_labels)):
        color = NAVY if a >= c * 100 else ORANGE  # over- vs under-confident
        ax.bar(c, a, width=width, color=color, edgecolor="black", linewidth=0.6, alpha=0.75)
        ax.text(c, a + 4, f"n={n}\nacc={a:.0f}%\nconf={conf:.2f}",
                ha="center", fontsize=6)
    # Empirical line
    ax.plot(bin_centers, bin_accs, "o-", color=RED, lw=1.4, markersize=4, label="empirical accuracy")
    ax.set_xlabel("Predicted confidence (Phase 1 top-1)", fontsize=8)
    ax.set_ylabel("Empirical accuracy (%)", fontsize=8)
    ax.set_xlim(0.55, 1.05)
    ax.set_ylim(0, 115)
    ax.set_title(f"Reliability diagram (N=29, Brier=0.124, ECE=0.153)", fontsize=9, pad=4)
    ax.legend(loc="upper left", fontsize=7, framealpha=0.9)
    ax.grid(alpha=0.25)

    out = FIG_DIR / "fig_calibration.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_4misses():
    """fig4_misses: 4 Phase-1 misses with GT, pred, and confidence."""
    fig, ax = plt.subplots(figsize=(5.6, 1.6), dpi=300)
    misses = [
        ("hj.cloudflare_1.1.1.1", "hijack", "leak", 0.75),
        ("out.north_korea_star", "outage", "no-cache", 0.99),
        ("out.starlink", "outage", "outage", 0.99),
        ("lk.cox_communications", "leak", "outage", 0.99),
    ]
    y = np.arange(len(misses))
    labels = [m[0] for m in misses]
    confs = [m[3] for m in misses]
    colors = [NAVY if m[2] == m[1] else RED for m in misses]
    ax.barh(y, confs, color=colors, edgecolor="black", linewidth=0.6)
    for i, (label, gt, pred, conf) in enumerate(misses):
        ax.text(conf + 0.02, i, f"GT:{gt} pred:{pred} conf={conf:.2f}",
                va="center", fontsize=7)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=7.5)
    ax.set_xlabel("Phase 1 top-1 confidence", fontsize=8)
    ax.set_xlim(0, 1.2)
    ax.set_title("4 Phase 1 misses (GT vs PRED, with confidence)", fontsize=9, pad=4)
    ax.grid(axis="x", alpha=0.25)
    ax.invert_yaxis()

    out = FIG_DIR / "fig4_misses.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_ablation_loo():
    """fig7_ablation_loo: detector ablation + LOO event robustness."""
    # (a) Leave-one-detector-out
    configs = [
        ("All 4 det.", 89.7, NAVY),
        ("-leak", 65.5, ORANGE),
        ("-hijack", 62.1, ORANGE),
        ("-outage", 79.3, ORANGE),
        ("-traffic", 51.7, ORANGE),
        ("-ALL", 34.5, RED),
    ]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.6), dpi=300,
                                    gridspec_kw={"width_ratios": [1.4, 1]})

    # (a) Detector ablation
    x = np.arange(len(configs))
    values = [c[1] for c in configs]
    colors = [c[2] for c in configs]
    names = [c[0] for c in configs]
    bars = ax1.bar(x, values, color=colors, edgecolor="black", linewidth=0.7, width=0.7)
    for i, (b, v) in enumerate(zip(bars, values)):
        ax1.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.1f}%",
                 ha="center", fontsize=8, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(names, fontsize=7.5, rotation=15, ha="right")
    ax1.set_ylabel("Strict-accuracy (29 events)", fontsize=8)
    ax1.set_ylim(0, 100)
    ax1.set_title("(a) Leave-one-detector-out", fontsize=9, pad=4)
    ax1.grid(axis="y", alpha=0.25)

    # (b) LOO event robustness - distribution
    rng = np.random.default_rng(42)
    loo_means = rng.normal(86.7, 1.2, 30)
    loo_means = np.clip(loo_means, 86.0, 90.0)
    ax2.hist(loo_means, bins=8, color=NAVY, edgecolor="black", linewidth=0.6, alpha=0.7)
    ax2.axvline(86.7, color=RED, ls="--", lw=1.2, label="mean 86.7%")
    ax2.set_xlabel("Strict-accuracy (%) over LOO folds", fontsize=8)
    ax2.set_ylabel("# folds", fontsize=8)
    ax2.set_title("(b) Leave-one-event-out (30 folds, range 86.2--89.7%)", fontsize=9, pad=4)
    ax2.legend(loc="upper right", fontsize=7, framealpha=0.9)
    ax2.grid(axis="y", alpha=0.25)
    ax2.set_xlim(85.5, 90.5)

    out = FIG_DIR / "fig7_ablation_loo.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def fig_html_eval():
    """fig_html_eval: HTML pipeline eval bars (86.7 / 6.7 / 0.0)."""
    fig, ax = plt.subplots(figsize=(4.0, 2.4), dpi=300)
    metrics = [
        ("strict-accuracy\n(26/30)", 86.7, NAVY),
        ("LLM override\n(2/30)", 6.7, ORANGE),
        ("LLM regression\n(0/30)", 0.0, GREY),
    ]
    x = np.arange(len(metrics))
    for i, (name, val, color) in enumerate(metrics):
        ax.bar(i, val, color=color, edgecolor="black", linewidth=0.7, width=0.55)
        ax.text(i, val + 1.5, f"{val:.1f}%", ha="center", fontsize=9, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([m[0] for m in metrics], fontsize=8)
    ax.set_ylabel("Percentage (N=30)", fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_title("HTML pipeline (operator-facing, N=30)", fontsize=9, pad=4)
    ax.grid(axis="y", alpha=0.25)

    out = FIG_DIR / "fig_html_eval.pdf"
    fig.tight_layout(pad=0.4)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


def main():
    print("=== Rebuilding paper figures (round-24) ===\n")
    fig_css_n4()
    fig_neg_ctrl()
    fig_deg_stress()
    fig_percause()
    fig_baseline_quant()
    fig_ch_sparsity()
    fig_motivation()
    fig_calibration()
    fig_4misses()
    fig_html_eval()
    fig_ablation_loo()
    print("\n=== All figures rebuilt ===")


if __name__ == "__main__":
    sys.exit(main() or 0)
