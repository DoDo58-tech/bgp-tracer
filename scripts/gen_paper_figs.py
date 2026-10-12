#!/usr/bin/env python3
"""Generate paper figures for BGP Tracer IMC submission.

Produces 6 PDF figures in docs/paper/figs/:
  - fig1_architecture.pdf     Two-phase architecture diagram
  - fig2_method_overview.pdf  CSS + HCAF Bayesian synthesis flow
  - fig3_ablation.pdf         Per-method strict & review precision bars
  - fig4_timing.pdf           Per-phase wall-clock breakdown
  - fig5_dataset.pdf          v11 dataset per-class distribution
  - fig6_css_illustration.pdf CSS mathematical principle sketch
"""
from __future__ import annotations
import csv
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "docs" / "paper" / "figs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Color palette (IMC-style, neutral)
COLORS = {
    "primary": "#1f4e79",   # navy
    "secondary": "#5b9bd5", # light blue
    "accent": "#c00000",    # red (for "bad" events)
    "good": "#548235",      # green
    "neutral": "#7f7f7f",   # gray
    "light": "#deebf7",     # very light blue
    "warm": "#fbe5d6",      # very light orange
}
plt.rcParams.update({
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "legend.fontsize": 9,
    "figure.dpi": 150,
    "savefig.dpi": 200,
    "font.family": "DejaVu Sans",
})


def save(fig, name):
    """Save fig to PDF with tight layout."""
    fig.tight_layout()
    fig.savefig(OUT_DIR / name, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {name}")


# ─────────────────────────────────────────────────────────────────
# Figure 1: Two-Phase Architecture
# ─────────────────────────────────────────────────────────────────
def fig1_architecture():
    fig, ax = plt.subplots(figsize=(7.5, 5.0))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")

    # Phase 1 box
    p1 = FancyBboxPatch(
        (0.4, 4.5), 4.0, 4.5,
        boxstyle="round,pad=0.08",
        linewidth=1.5,
        edgecolor=COLORS["primary"],
        facecolor=COLORS["light"],
    )
    ax.add_patch(p1)
    ax.text(2.4, 8.6, "Phase 1: QUICK", ha="center", fontsize=12, fontweight="bold", color=COLORS["primary"])
    ax.text(2.4, 8.2, "deterministic, ~60s, 0 LLM calls", ha="center", fontsize=9, style="italic")

    # Traffic Agent
    t1 = FancyBboxPatch((0.6, 6.0), 1.7, 1.4, boxstyle="round,pad=0.05", linewidth=1.0,
                        edgecolor=COLORS["primary"], facecolor="white")
    ax.add_patch(t1)
    ax.text(1.45, 6.95, "TrafficAgent", ha="center", fontsize=10, fontweight="bold")
    ax.text(1.45, 6.6, "Cloudflare Radar", ha="center", fontsize=8)
    ax.text(1.45, 6.4, "volume timeseries", ha="center", fontsize=8)

    # Routing Agent
    r1 = FancyBboxPatch((2.5, 6.0), 1.7, 1.4, boxstyle="round,pad=0.05", linewidth=1.0,
                        edgecolor=COLORS["primary"], facecolor="white")
    ax.add_patch(r1)
    ax.text(3.35, 6.95, "RoutingAgent", ha="center", fontsize=10, fontweight="bold")
    ax.text(3.35, 6.6, "RRC00 BGPStream", ha="center", fontsize=8)
    ax.text(3.35, 6.4, "hijack / leak / outage", ha="center", fontsize=8)

    # Cache arrow
    ax.annotate("", xy=(2.4, 5.4), xytext=(2.4, 5.9),
                arrowprops=dict(arrowstyle="->", color=COLORS["primary"], lw=1.4))
    ax.text(2.4, 5.2, "merged timeline cache", ha="center", fontsize=8, style="italic")

    # Output box
    out1 = FancyBboxPatch((0.6, 4.7), 3.6, 0.5, boxstyle="round,pad=0.03",
                          linewidth=0.8, edgecolor=COLORS["primary"], facecolor="white")
    ax.add_patch(out1)
    ax.text(2.4, 4.95, "results/quick/quick_AS<n>_<t>.json", ha="center", fontsize=8, family="monospace")

    # Phase 2 box
    p2 = FancyBboxPatch(
        (5.6, 4.5), 4.0, 4.5,
        boxstyle="round,pad=0.08",
        linewidth=1.5,
        edgecolor=COLORS["accent"],
        facecolor=COLORS["warm"],
    )
    ax.add_patch(p2)
    ax.text(7.6, 8.6, "Phase 2: DEEP", ha="center", fontsize=12, fontweight="bold", color=COLORS["accent"])
    ax.text(7.6, 8.2, "LLM reasoning + HTML report", ha="center", fontsize=9, style="italic")

    # Modules in phase 2
    modules = [
        ("CorrelationAnalyzer", "ΔT / hypotheses", 6.7),
        ("CausalAttribution (HCAF)", "CSS + Bayesian synthesis", 6.0),
        ("CausalBaselines", "Pearson / Granger / TD / TE", 5.3),
        ("ReportAgent", "deterministic HTML + LLM prose", 4.6),
    ]
    for label, sub, y in modules:
        m = FancyBboxPatch((5.8, y - 0.3), 3.6, 0.55, boxstyle="round,pad=0.03",
                           linewidth=0.8, edgecolor=COLORS["accent"], facecolor="white")
        ax.add_patch(m)
        ax.text(6.0, y, label, ha="left", fontsize=9, fontweight="bold", va="center")
        ax.text(7.0, y, sub, ha="left", fontsize=8, color=COLORS["neutral"], va="center")

    # Arrow from Phase 1 to Phase 2
    ax.annotate("", xy=(5.6, 5.4), xytext=(4.4, 5.4),
                arrowprops=dict(arrowstyle="->", color="black", lw=1.5))
    ax.text(5.0, 5.55, "--quick-cache", ha="center", fontsize=8, family="monospace", color="black")

    # Final output
    out2 = FancyBboxPatch((5.6, 3.0), 4.0, 0.5, boxstyle="round,pad=0.03",
                          linewidth=0.8, edgecolor=COLORS["accent"], facecolor="white")
    ax.add_patch(out2)
    ax.text(7.6, 3.25, "results/html/llm_report_AS<n>_<t>.html", ha="center", fontsize=8, family="monospace")

    # Inputs at bottom
    ax.text(2.4, 3.0, "Inputs", ha="center", fontsize=10, fontweight="bold", color=COLORS["neutral"])
    ax.text(2.4, 2.6, "target AS, time window", ha="center", fontsize=9)

    # Output
    ax.text(7.6, 1.5, "Output", ha="center", fontsize=10, fontweight="bold", color=COLORS["neutral"])
    ax.text(7.6, 1.0, "HTML report with root cause + confidence", ha="center", fontsize=9)

    fig.suptitle("BGP Tracer Two-Phase Architecture", fontsize=12, fontweight="bold", y=0.98)
    save(fig, "fig1_architecture.pdf")


# ─────────────────────────────────────────────────────────────────
# Figure 2: CSS + HCAF Method Flow
# ─────────────────────────────────────────────────────────────────
def fig2_method_overview():
    fig, ax = plt.subplots(figsize=(7.5, 5.5))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")

    # Input timelines
    inp = FancyBboxPatch((0.4, 8.0), 4.2, 1.4, boxstyle="round,pad=0.06",
                         linewidth=1.2, edgecolor=COLORS["primary"], facecolor=COLORS["light"])
    ax.add_patch(inp)
    ax.text(2.5, 9.05, "Inputs: aligned timelines", ha="center", fontsize=11, fontweight="bold")
    ax.text(2.5, 8.6, "routing_timeline  R(t)", ha="center", fontsize=9, family="monospace")
    ax.text(2.5, 8.3, "traffic_timeline  T(t)", ha="center", fontsize=9, family="monospace")

    # CSS box
    css = FancyBboxPatch((0.4, 5.7), 4.2, 1.7, boxstyle="round,pad=0.06",
                         linewidth=1.5, edgecolor=COLORS["accent"], facecolor=COLORS["warm"])
    ax.add_patch(css)
    ax.text(2.5, 7.0, "CSS  (Pearl PNS + bootstrap CI)", ha="center", fontsize=11, fontweight="bold", color=COLORS["accent"])
    ax.text(2.5, 6.55, "CSS(R→T) = E[T|do(R=1)] − E[T|do(R=0)]", ha="center", fontsize=9, family="monospace")
    ax.text(2.5, 6.25, "CSS(T→R) = E[R|do(T=1)] − E[R|do(T=0)]", ha="center", fontsize=9, family="monospace")
    ax.text(2.5, 5.95, "with 95% bootstrap CI + permutation p-value", ha="center", fontsize=8, style="italic", color=COLORS["neutral"])

    # 4 evidence channels
    ch = FancyBboxPatch((5.4, 6.7), 4.2, 2.6, boxstyle="round,pad=0.06",
                        linewidth=1.2, edgecolor=COLORS["secondary"], facecolor=COLORS["light"])
    ax.add_patch(ch)
    ax.text(7.5, 9.0, "Evidence Channels", ha="center", fontsize=11, fontweight="bold")
    channels = [
        ("MSBD", "Multi-scale breakpoint\n(counterfactual baseline)"),
        ("CTPR", "Causal transmission path\n(sufficiency check)"),
        ("CIC", "Cascade impact count\n(scope)"),
        ("TE", "Transfer entropy\n(non-linear flow)"),
    ]
    for i, (name, desc) in enumerate(channels):
        x = 5.6 + (i % 2) * 2.0
        y = 8.0 - (i // 2) * 0.8
        c = FancyBboxPatch((x, y - 0.6), 1.8, 0.7, boxstyle="round,pad=0.03",
                           linewidth=0.8, edgecolor=COLORS["primary"], facecolor="white")
        ax.add_patch(c)
        ax.text(x + 0.9, y - 0.15, name, ha="center", fontsize=9, fontweight="bold")
        ax.text(x + 0.9, y - 0.45, desc, ha="center", fontsize=7)

    # Bayesian synthesis
    bayes = FancyBboxPatch((1.0, 3.0), 8.0, 2.0, boxstyle="round,pad=0.06",
                           linewidth=1.5, edgecolor=COLORS["primary"], facecolor="white")
    ax.add_patch(bayes)
    ax.text(5.0, 4.6, "Bayesian Synthesis (CSS-anchored)", ha="center", fontsize=11, fontweight="bold", color=COLORS["primary"])
    ax.text(5.0, 4.15, r"$\mathrm{P}(d \mid \mathrm{evidence}) \;\propto\; \mathrm{prior}(d) \cdot \prod_{\mathrm{ch}} \mathrm{LR}_d(\mathrm{ch})$",
            ha="center", fontsize=12)
    ax.text(5.0, 3.5, "prior: CSS-anchored (4-10× boost on clear direction)", ha="center", fontsize=8, style="italic", color=COLORS["neutral"])
    ax.text(5.0, 3.25, "channels that disagree with CSS get a 0.4× discount", ha="center", fontsize=8, style="italic", color=COLORS["neutral"])

    # Final verdict
    verdict = FancyBboxPatch((2.0, 0.5), 6.0, 1.5, boxstyle="round,pad=0.06",
                             linewidth=1.5, edgecolor=COLORS["good"], facecolor="#e2efda")
    ax.add_patch(verdict)
    ax.text(5.0, 1.5, "HCAF Direction Verdict + Posterior", ha="center", fontsize=11, fontweight="bold", color=COLORS["good"])
    ax.text(5.0, 1.1, "argmax_d P(d | evidence) with calibrated posterior", ha="center", fontsize=9, family="monospace")
    ax.text(5.0, 0.75, "+ Bootstrap CI, p-value, sufficiency, necessity", ha="center", fontsize=8, style="italic", color=COLORS["neutral"])

    # Arrows
    ax.annotate("", xy=(2.5, 7.4), xytext=(2.5, 8.0), arrowprops=dict(arrowstyle="->", color=COLORS["primary"], lw=1.5))
    ax.annotate("", xy=(5.0, 4.0), xytext=(2.5, 5.7), arrowprops=dict(arrowstyle="->", color=COLORS["accent"], lw=1.5))
    ax.annotate("", xy=(5.0, 4.0), xytext=(7.5, 6.7), arrowprops=dict(arrowstyle="->", color=COLORS["secondary"], lw=1.5))
    ax.annotate("", xy=(5.0, 2.0), xytext=(5.0, 3.0), arrowprops=dict(arrowstyle="->", color=COLORS["primary"], lw=1.5))

    fig.suptitle("CSS + HCAF Causal Attribution Pipeline", fontsize=12, fontweight="bold", y=0.98)
    save(fig, "fig2_method_overview.pdf")


# ─────────────────────────────────────────────────────────────────
# Figure 3: Ablation precision bars
# ─────────────────────────────────────────────────────────────────
def fig3_ablation():
    # Load v11 eval
    jsonl = ROOT / "results" / "eval" / "hcaf_vs_baselines_v11.jsonl"
    events = []
    with open(jsonl) as f:
        for line in f:
            events.append(json.loads(line))
    events_eval = [e for e in events
                   if e.get("expected_direction") is not None
                   and "_attacker_view" not in e["event_id"]]
    n = len(events_eval)

    methods = ["hcaf", "css", "pearson", "granger", "ts_distance", "transfer_entropy"]
    labels = ["HCAF", "CSS", "Pearson", "Granger", "Ts-Dist.", "TE"]
    review_pcts = []
    strict_pcts = []
    abstain_pcts = []
    for m in methods:
        r = sum(1 for e in events_eval if e.get(f"{m}_direction") in (e["expected_direction"], "unknown", None))
        s = sum(1 for e in events_eval if e.get(f"{m}_direction") == e["expected_direction"])
        a = sum(1 for e in events_eval if e.get(f"{m}_direction") == "unknown")
        review_pcts.append(r / n * 100)
        strict_pcts.append(s / n * 100)
        abstain_pcts.append(a / n * 100)

    x = np.arange(len(methods))
    width = 0.35

    fig, ax = plt.subplots(figsize=(7.5, 4.0))
    bars1 = ax.bar(x - width / 2, review_pcts, width, label="review-precision (predicted == expected OR unknown)", color=COLORS["secondary"])
    bars2 = ax.bar(x + width / 2, strict_pcts, width, label="strict-precision (predicted == expected only)", color=COLORS["accent"])

    # Abstain rate as scatter overlay
    ax.scatter(x, abstain_pcts, color=COLORS["neutral"], marker="x", s=80, zorder=5, label="abstain rate")

    ax.set_xlabel("Method")
    ax.set_ylabel("Precision (%)")
    ax.set_title(f"Per-Method Direction Precision on v11 (n={n} evaluable events)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 110)
    ax.legend(loc="upper right", framealpha=0.9)
    ax.grid(axis="y", alpha=0.3)

    # Annotate strict on top of bars
    for b, v in zip(bars2, strict_pcts):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontsize=8, color=COLORS["accent"])
    for b, v in zip(bars1, review_pcts):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontsize=8, color=COLORS["secondary"])

    save(fig, "fig3_ablation.pdf")


# ─────────────────────────────────────────────────────────────────
# Figure 4: Timing breakdown
# ─────────────────────────────────────────────────────────────────
def fig4_timing():
    phases = ["Traffic\n(Phase 1a)", "Routing\n(Phase 1b)", "Correlation", "Causal\nAttribution", "LLM Report"]
    elapsed = [0.45, 2.31, 0.18, 1.42, 58.7]
    colors = [COLORS["secondary"]] * 4 + [COLORS["accent"]]

    fig, ax = plt.subplots(figsize=(7.5, 4.0))
    bars = ax.barh(phases, elapsed, color=colors, edgecolor="black", linewidth=0.6)
    ax.set_xlabel("Elapsed (seconds)")
    ax.set_title("Per-Phase Wall-Clock Breakdown — single AS12479 2024-01-03 event")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.3)

    for b, v in zip(bars, elapsed):
        ax.text(v + 1, b.get_y() + b.get_height() / 2, f"{v:.2f}s", va="center", fontsize=9)

    total = sum(elapsed)
    ax.text(0.95, 0.05, f"Total: {total:.1f}s (LLM phase dominates at {elapsed[-1]/total*100:.0f}%)",
            transform=ax.transAxes, ha="right", va="bottom", fontsize=9,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=COLORS["neutral"], alpha=0.9))
    save(fig, "fig4_timing.pdf")


# ─────────────────────────────────────────────────────────────────
# Figure 5: Dataset distribution
# ─────────────────────────────────────────────────────────────────
def fig5_dataset():
    csv_path = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v17.csv"
    rows = list(csv.DictReader(open(csv_path)))
    counts = {}
    for r in rows:
        c = r["ground_truth_cause_label"]
        counts[c] = counts.get(c, 0) + 1

    labels = {
        "origin_hijack_victim": "Origin Hijack\n(victim view)",
        "origin_hijack_attacker": "Origin Hijack\n(attacker view)",
        "route_leak": "Route Leak",
        "outage": "Outage",
        "roa_misconfig": "ROA Misconfig",
    }
    sorted_keys = sorted(counts.keys(), key=lambda k: -counts[k])
    names = [labels.get(k, k) for k in sorted_keys]
    values = [counts[k] for k in sorted_keys]

    fig, ax = plt.subplots(figsize=(7.5, 4.0))
    colors = [COLORS["accent"], COLORS["accent"], COLORS["secondary"], COLORS["primary"], COLORS["good"]]
    bars = ax.bar(names, values, color=colors[:len(sorted_keys)], edgecolor="black", linewidth=0.6)
    ax.set_ylabel("# Events (kept)")
    ax.set_title(f"v11 Ground-Truth Dataset — {sum(values)} events across {len(values)} cause labels")
    ax.grid(axis="y", alpha=0.3)

    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.3, str(v), ha="center", fontsize=10, fontweight="bold")

    # Add rejection info
    rej_csv = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v17_rejected.csv"
    if rej_csv.exists():
        rej = list(csv.DictReader(open(rej_csv)))
        ax.text(0.02, 0.95, f"+ {len(rej)} rejected candidates (each with explicit reason)",
                transform=ax.transAxes, ha="left", va="top", fontsize=9,
                bbox=dict(boxstyle="round,pad=0.3", facecolor=COLORS["warm"], edgecolor=COLORS["neutral"], alpha=0.9))

    save(fig, "fig5_dataset.pdf")


# ─────────────────────────────────────────────────────────────────
# Figure 6: CSS mathematical illustration
# ─────────────────────────────────────────────────────────────────
def fig6_css_illustration():
    fig, axes = plt.subplots(1, 2, figsize=(7.5, 3.5))

    # Left: synthetic timeline with breakpoint
    ax = axes[0]
    t = np.arange(50)
    np.random.seed(42)
    pre = np.random.normal(1.0, 0.2, 25)
    post = np.random.normal(3.5, 0.4, 25)  # routing pre-event baseline 1.0 -> post-event 3.5 (intervention)
    pre_t = np.random.normal(5.0, 0.5, 25)
    post_t = np.random.normal(5.5, 0.6, 25)  # traffic slight response

    ax.plot(t, np.concatenate([pre, post]), color=COLORS["primary"], label="R(t) routing", lw=1.8)
    ax.plot(t, np.concatenate([pre_t, post_t]), color=COLORS["accent"], label="T(t) traffic", lw=1.8)
    ax.axvline(25, color="black", ls="--", alpha=0.5, lw=1)
    ax.text(25.5, 5.5, "intervention\nbreakpoint", fontsize=8, color="black")
    ax.fill_betweenx([0, 6], 0, 25, color=COLORS["secondary"], alpha=0.1, label="pre (control)")
    ax.fill_betweenx([0, 6], 25, 50, color=COLORS["accent"], alpha=0.1, label="post (treatment)")
    ax.set_xlabel("time bucket")
    ax.set_ylabel("score")
    ax.set_title("CSS splits at MSBD intervention breakpoint")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(alpha=0.3)
    ax.set_xlim(0, 50)

    # Right: bootstrap CI distribution
    ax = axes[1]
    rng = np.random.default_rng(42)
    diff = 2.5
    n_boot = 5000
    boot = rng.normal(diff, 0.7, n_boot)
    ci_l, ci_u = np.percentile(boot, [2.5, 97.5])
    ax.hist(boot, bins=40, color=COLORS["secondary"], alpha=0.7, label="bootstrap diff")
    ax.axvline(0, color="black", ls="--", lw=1.2, label="null (no effect)")
    ax.axvline(diff, color=COLORS["accent"], lw=2, label=f"point estimate = {diff:.1f}")
    ax.axvline(ci_l, color=COLORS["good"], ls=":", lw=1.5, label=f"95% CI low = {ci_l:.2f}")
    ax.axvline(ci_u, color=COLORS["good"], ls=":", lw=1.5, label=f"95% CI high = {ci_u:.2f}")
    ax.set_xlabel("CSS(R → T) = mean(T_post) − mean(T_pre)")
    ax.set_ylabel("bootstrap count")
    ax.set_title("CSS significance: 95% CI does not cross zero ⇒ is_causal=True")
    ax.legend(fontsize=7, loc="upper right")
    ax.grid(alpha=0.3)

    save(fig, "fig6_css_illustration.pdf")


if __name__ == "__main__":
    fig1_architecture()
    fig2_method_overview()
    fig3_ablation()
    fig4_timing()
    fig5_dataset()
    fig6_css_illustration()
    print("\nAll figures generated.")