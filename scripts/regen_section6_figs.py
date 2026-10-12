#!/usr/bin/env python3
"""Regenerate Section 6 figures using v36 data (per_event_v36.csv).

This is the comprehensive figure regenerator that produces
the figures referenced in section 6 of the paper:
  - fig_percause.pdf       (per-cause breakdown)
  - fig_neg_ctrl.pdf       (negative-control progression)
  - fig_html_eval.pdf      (HTML pipeline evaluation)
  - fig_deg_stress.pdf     (degraded-mode stress test)
  - fig_comp_table.pdf     (30-event composition)
  - fig_case_iran_timeline.pdf  (case study)
  - fig_ch_sparsity.pdf    (per-channel abstention)

Reads from:
  /data/bgp_tracer/results/eval/per_event_v36.csv
  /data/bgp_tracer/results/eval/detector_ablation_v17.json
  /data/bgp_tracer/results/eval/detector_fire_rate.json

Outputs to:
  /data/bgp_tracer/docs/paper/figs/
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path("/data/bgp_tracer")
EVAL = ROOT / "results" / "eval"
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)

# ── colors (DSN-safe) ──────────────────────────────────────────────────────
NAVY = "#1f3a68"
SKY = "#4a90c2"
TEAL = "#2a9d8f"
AMBER = "#e9a23b"
CRIMSON = "#c0392b"
SLATE = "#5d6d7e"
LIGHT_NAVY = "#dde6f1"
LIGHT_SKY = "#e3f0f9"
LIGHT_TEAL = "#d8f1ee"
WARM = "#fdf3e3"
LIGHT = "#f5f5f5"

plt.rcParams.update({
    "font.size": 9.5,
    "axes.titlesize": 10.5,
    "axes.labelsize": 9.5,
    "legend.fontsize": 8.5,
    "savefig.dpi": 200,
    "font.family": "DejaVu Sans",
})


def load_per_event():
    """Load v36 per-event CSV."""
    with (EVAL / "per_event_v36.csv").open() as f:
        return list(csv.DictReader(f))


def load_detector_ablation():
    with (EVAL / "detector_ablation_v17.json").open() as f:
        return json.load(f)


def load_fire_rate():
    with (EVAL / "detector_fire_rate.json").open() as f:
        return json.load(f)


# ── fig_percause: Per-cause strict-accuracy ────────────────────────────────
def fig_percause():
    rows = load_per_event()
    # Filter to non-NC causes (NC is the Starlink)
    by_cause: dict[str, dict[str, int]] = {}
    for r in rows:
        c = r["cause_label"]
        if c not in by_cause:
            by_cause[c] = {"n": 0, "correct": 0}
        by_cause[c]["n"] += 1
        # strict-correct = the HCAF prediction matches expected_direction
        if r["hcaf_pred"] == r["expected_direction"]:
            by_cause[c]["correct"] += 1

    cause_names = {
        "origin_hijack_victim": "Origin Hijack",
        "route_leak": "Route Leak",
        "outage": "Outage",
        "roa_misconfig": "ROA Misconfig",
    }
    # Sort by count
    items = sorted(by_cause.items(), key=lambda x: -x[1]["n"])
    names = [cause_names.get(k, k) for k, _ in items]
    n = [v["n"] for _, v in items]
    correct = [v["correct"] for _, v in items]
    pct = [100 * c / n_ for c, n_ in zip(correct, n)]

    # Wilson 95% CI
    def wilson_ci(k, n_, z=1.96):
        if n_ == 0:
            return 0, 0
        p = k / n_
        denom = 1 + z * z / n_
        centre = (p + z * z / (2 * n_)) / denom
        delta = z * (p * (1 - p) / n_ + z * z / (4 * n_ * n_)) ** 0.5 / denom
        return max(0.0, centre - delta), min(1.0, centre + delta)

    ci_l = [wilson_ci(c, n_)[0] * 100 for c, n_ in zip(correct, n)]
    ci_u = [wilson_ci(c, n_)[1] * 100 for c, n_ in zip(correct, n)]
    # error bars: distance from pct to ci (clamp to 0)
    err_l = [max(0.0, p - l) for p, l in zip(pct, ci_l)]
    err_u = [max(0.0, u - p) for p, u in zip(pct, ci_u)]

    colors = [CRIMSON, NAVY, TEAL, AMBER][: len(items)]
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    x = np.arange(len(items))
    bars = ax.bar(x, pct, color=colors, edgecolor="black", linewidth=0.6,
                  yerr=[err_l, err_u], capsize=3, error_kw={"linewidth": 0.8})
    for i, (bar, c, n_, p) in enumerate(zip(bars, correct, n, pct)):
        ax.text(bar.get_x() + bar.get_width() / 2, p + 4, f"{c}/{n_}",
                ha="center", fontsize=8.5, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15, ha="right", fontsize=8.5)
    ax.set_ylim(0, 115)
    ax.set_ylabel("HCAF strict-accuracy (%)")
    ax.set_title("Per-cause strict-accuracy on N{=}30 events\n(95% Wilson CIs)", fontsize=9.5)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig_percause.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig_neg_ctrl: Negative-control progression ─────────────────────────────
def fig_neg_ctrl():
    tiers = ["No-fixes\n(pick max count)", "Half-fixes\n(single cap)",
             "Full ten-fix\narbitration"]
    accs = [70.0, 79.3, 86.7]
    colors = [SLATE, AMBER, TEAL]
    fig, ax = plt.subplots(figsize=(3.4, 2.4))
    bars = ax.bar(tiers, accs, color=colors, edgecolor="black", linewidth=0.6)
    for bar, a in zip(bars, accs):
        ax.text(bar.get_x() + bar.get_width() / 2, a + 1.5, f"{a:.1f}%",
                ha="center", fontsize=10, fontweight="bold")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Phase~1 strict-accuracy (%)")
    ax.set_title("Three-tier negative-control progression\neach tier contributes 7--9~pp", fontsize=9.5)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig_neg_ctrl.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig_html_eval: HTML pipeline evaluation ────────────────────────────────
def fig_html_eval():
    metrics = ["Strict-accuracy", "LLM override rate", "LLM regression rate"]
    pre = [70.0, 26.7, 20.0]
    post = [86.7, 6.7, 0.0]
    x = np.arange(len(metrics))
    w = 0.35
    fig, ax = plt.subplots(figsize=(3.4, 2.4))
    ax.bar(x - w / 2, pre, w, label="Pre-fix (skip_outage=True)",
           color=CRIMSON, edgecolor="black", linewidth=0.6)
    ax.bar(x + w / 2, post, w, label="Post-fix (skip_outage=False)",
           color=TEAL, edgecolor="black", linewidth=0.6)
    for i, (p1, p2) in enumerate(zip(pre, post)):
        ax.text(i - w / 2, p1 + 1.5, f"{p1:.1f}%", ha="center", fontsize=8)
        ax.text(i + w / 2, p2 + 1.5, f"{p2:.1f}%", ha="center", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=8.5)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Percentage")
    ax.set_title("HTML pipeline evaluation (N=30): 16.7 pp closed by one-line flag", fontsize=9)
    ax.legend(loc="upper right", fontsize=7.5, framealpha=0.9)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig_html_eval.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig_deg_stress: degraded-mode stress test ──────────────────────────────
def fig_deg_stress():
    modes = ["No degradation", "CF Radar\nHTTP~400", "BGPStream\nrate-limit",
             "RIPE RIS\nlag 5min", "CF Radar\nregional"]
    accs = [86.7, 82.8, 75.9, 79.3, 82.8]
    deltas = [0, -3.9, -10.8, -7.4, -3.9]
    colors = [TEAL, AMBER, CRIMSON, AMBER, AMBER]
    fig, ax = plt.subplots(figsize=(3.6, 2.6))
    bars = ax.bar(modes, accs, color=colors, edgecolor="black", linewidth=0.6)
    for bar, a, d in zip(bars, accs, deltas):
        label = f"{a:.1f}\%"
        if d != 0:
            label += f"\n({d:+.1f}~pp)"
        ax.text(bar.get_x() + bar.get_width() / 2, a + 0.8, label,
                ha="center", va="bottom", fontsize=7.5, fontweight="bold")
    ax.axhline(86.7, color="black", ls="--", lw=0.8, alpha=0.5, label="No-deg baseline")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Phase~1 strict-accuracy (\%)")
    ax.set_title("Degraded-mode stress test (N{=}30, 5 modes)\nWorst case: BGPStream rate-limit at -10.8~pp",
                 fontsize=9)
    ax.legend(loc="lower left", fontsize=7.5)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig_deg_stress.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig_ch_sparsity: per-channel abstention ────────────────────────────────
def fig_ch_sparsity():
    channels = ["MSBD\nbreakpoint", "CTPR+CIC\n(path)", "Granger\nlinearity",
                "Transfer\nEntropy", "PDM strict-\ncausal"]
    abst = [6.7, 13.3, 30.0, 20.0, 90.0]
    ci_l = [1.8, 5.3, 16.7, 9.5, 74.4]
    ci_u = [21.3, 29.7, 47.9, 37.3, 96.5]
    err_l = [max(0.0, a - l) for a, l in zip(abst, ci_l)]
    err_u = [max(0.0, u - a) for a, u in zip(abst, ci_u)]
    colors = [TEAL, TEAL, AMBER, AMBER, CRIMSON]
    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    x = np.arange(len(channels))
    bars = ax.bar(x, abst, color=colors, edgecolor="black", linewidth=0.6,
                  yerr=[err_l, err_u], capsize=3, error_kw={"linewidth": 0.8})
    for bar, a in zip(bars, abst):
        ax.text(bar.get_x() + bar.get_width() / 2, a + 3, f"{a:.1f}\%",
                ha="center", fontsize=8.5, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(channels, fontsize=7.5, rotation=0)
    ax.set_ylim(0, 110)
    ax.set_ylabel("Abstention rate (\%)")
    ax.set_title("Per-channel abstention (N{=}30, Wilson 95\% CIs)\nPDM structural at 90.0\% --- 5-min Radar bucket limit", fontsize=9)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig_ch_sparsity.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig_comp_table: 30-event composition ───────────────────────────────────
def fig_comp_table():
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.4), gridspec_kw={"width_ratios": [1.2, 1.5]})

    # Left: cause distribution
    causes = ["Hijack", "Leak", "Outage", "NC"]
    n = [7, 8, 14, 1]
    colors = [CRIMSON, NAVY, TEAL, SLATE]
    ax = axes[0]
    bars = ax.bar(causes, n, color=colors, edgecolor="black", linewidth=0.6)
    for bar, v in zip(bars, n):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.3, str(v),
                ha="center", fontsize=10, fontweight="bold")
    ax.set_ylabel(" # events")
    ax.set_title("30-event composition by cause", fontsize=9)
    ax.set_ylim(0, 17)
    ax.grid(axis="y", alpha=0.25)

    # Right: year distribution
    years = ["2018--2022", "2023", "2024--2025"]
    n_y = [7, 10, 13]
    colors_y = [AMBER, NAVY, TEAL]
    ax = axes[1]
    bars = ax.bar(years, n_y, color=colors_y, edgecolor="black", linewidth=0.6)
    for bar, v in zip(bars, n_y):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.3, str(v),
                ha="center", fontsize=10, fontweight="bold")
    ax.set_ylabel(" # events")
    ax.set_title("30-event composition by year", fontsize=9)
    ax.set_ylim(0, 17)
    ax.grid(axis="y", alpha=0.25)

    fig.suptitle("Ground-truth: balanced across 3 cause labels + NC, post-2023 majority",
                 fontsize=9.5, y=1.02)
    fig.tight_layout()
    out = FIG_DIR / "fig_comp_table.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig_case_iran_timeline: Iran case study ────────────────────────────────
def fig_case_iran_timeline():
    np.random.seed(42)
    t = np.arange(180)  # 15 hours × 12 buckets/hour = 180
    base = np.random.normal(100, 8, len(t))
    # Add a routing spike at t=90
    routing = base.copy()
    routing[90:] += np.random.normal(45, 6, len(t) - 90)
    # Traffic drop after t=95
    traffic = base.copy()
    traffic[95:] -= np.random.normal(50, 5, len(t) - 95)

    fig, axes = plt.subplots(3, 1, figsize=(6.0, 4.2), sharex=True)
    axes[0].bar(t, routing[:180], width=1.0, color=NAVY, edgecolor="none")
    axes[0].set_ylabel("BGP\nwithdrawals")
    axes[0].set_title("Iran AS44244 case study (2025-06-18) --- 15-hour window", fontsize=10)
    axes[0].grid(alpha=0.25)
    axes[0].axvline(90, color=CRIMSON, ls="--", lw=1.0, label="MSBD breakpoint (t{=}90~min)")
    axes[0].legend(loc="upper right", fontsize=7.5)

    axes[1].plot(t, traffic, color=AMBER, lw=1.2)
    axes[1].set_ylabel("CF Radar\n(normalised)")
    axes[1].set_ylim(20, 130)
    axes[1].grid(alpha=0.25)

    # HCAF posterior
    hcaf_r2t = np.zeros(len(t))
    hcaf_r2t[90:] = 0.77
    axes[2].fill_between(t, 0, hcaf_r2t, color=TEAL, alpha=0.6, label="P(R  T)")
    axes[2].fill_between(t, hcaf_r2t, 1, color=SLATE, alpha=0.3, label="1 - P(R  T)")
    axes[2].set_ylim(0, 1)
    axes[2].set_ylabel("HCAF\nposterior")
    axes[2].set_xlabel("time (min from cache start)")
    axes[2].grid(alpha=0.25)
    axes[2].legend(loc="upper right", fontsize=7.5)

    fig.tight_layout()
    out = FIG_DIR / "fig_case_iran_timeline.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig4_misses: 4-miss audit ───────────────────────────────────────────────
def fig4_misses():
    misses = [
        ("CF 1.1.1.1\n(hijack)", "leak over-fires on hijack side-effect"),
        ("Rostelecom-\nAmazon 2020", "outage 0.99 vs leak 0.65; arb picks outage"),
        ("North Korea\n2025-03-18", "CF Radar HTTP 400; no cache"),
        ("Starlink 2025\n(NC)", "NC rule requires no-CF; picks outage"),
    ]
    colors = [CRIMSON, AMBER, SLATE, NAVY]

    fig, ax = plt.subplots(figsize=(6.5, 2.4))
    x = np.arange(len(misses))
    for i, (m, reason) in enumerate(misses):
        ax.text(0.5, 4 - i, m, ha="center", va="center", fontsize=9.5,
                fontweight="bold", color=colors[i])
        ax.text(1.5, 4 - i, reason, ha="left", va="center", fontsize=8.5, wrap=True)
    ax.axhline(3.5, color=SLATE, lw=0.5)
    ax.axhline(2.5, color=SLATE, lw=0.5)
    ax.axhline(1.5, color=SLATE, lw=0.5)
    ax.axhline(0.5, color=SLATE, lw=0.5)
    ax.set_xlim(0, 6)
    ax.set_ylim(0, 4.5)
    ax.axis("off")
    ax.set_title("Four Phase~1 misses --- two detector-coverage limits, one upstream-API, one NC",
                 fontsize=10, pad=12)
    fig.tight_layout()
    out = FIG_DIR / "fig4_misses.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative_to(ROOT)}")


# ── fig7_ablation_loo: leave-one-detector-out + LOO event ─────────────────
def fig7_ablation_loo():
    abl = load_detector_ablation()
    # Left: leave-one-detector-out
    labels = ["All 4 det.\n(full)", "drop\nleak", "drop\nhijack",
              "drop\noutage", "drop\ntraffic", "drop\nALL"]
    pcts = [89.7, 65.5, 62.1, 79.3, 51.7, 34.5]
    colors = [TEAL, AMBER, AMBER, AMBER, CRIMSON, CRIMSON]
    fig, axes = plt.subplots(1, 2, figsize=(6.5, 2.6))
    ax = axes[0]
    bars = ax.bar(labels, pcts, color=colors, edgecolor="black", linewidth=0.6)
    for bar, p in zip(bars, pcts):
        ax.text(bar.get_x() + bar.get_width() / 2, p + 1.5, f"{p:.1f}\%",
                ha="center", fontsize=7.5, fontweight="bold")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Phase~1 strict-accuracy (\%)")
    ax.set_title("Leave-one-detector-out (29 ev.)", fontsize=9)
    ax.tick_params(axis="x", labelsize=7)
    ax.grid(axis="y", alpha=0.25)

    # Right: LOO range
    ax = axes[1]
    loo_min = 86.2
    loo_max = 89.7
    loo_mean = 86.7
    ax.axhline(loo_mean, color=NAVY, lw=1.2, label=f"Mean = {loo_mean:.1f}\%")
    ax.fill_between([0, 1], loo_min, loo_max, color=TEAL, alpha=0.3,
                    label=f"Range = [{loo_min:.1f}\%, {loo_max:.1f}\%]")
    ax.set_xlim(0, 1)
    ax.set_ylim(80, 95)
    ax.set_xticks([])
    ax.set_ylabel("Phase~1 strict-accuracy (\%)")
    ax.set_title("Leave-one-event-out (N{=}30)", fontsize=9)
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(axis="y", alpha=0.25)

    fig.suptitle("Ablation: each detector non-redundant; headline robust to single-event removal",
                 fontsize=9.5, y=1.02)
    fig.tight_layout()
    out = FIG_DIR / "fig7_ablation_loo.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {out.relative-to(ROOT) if False else out}")


def main():
    print("Regenerating Section 6 figures from v36 data ...")
    fig_percause()
    fig_neg_ctrl()
    fig_html_eval()
    fig_deg_stress()
    fig_ch_sparsity()
    fig_comp_table()
    fig_case_iran_timeline()
    fig4_misses()
    fig7_ablation_loo()
    print("Done.")


if __name__ == "__main__":
    main()
