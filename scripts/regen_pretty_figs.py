#!/usr/bin/env python3
"""Regenerate fig1_workflow, fig2_method_overview, and fig_ch_sparsity
with cleaner, icon-driven designs that fit the DSN 2027 column width.

This replaces the old "plain-text-in-boxes" style with:
  - Iconography drawn from matplotlib primitives (radar disk, AS-path
    node chain, document, math symbol, etc.) so the figure is
    self-explanatory and does not depend on an emoji font.
  - A clear INPUT -> ENGINE -> OUTPUT flow with thick arrows and
    color-coded channels.
  - Compact layout sized for one LaTeX column (single-column figures
    in the two-column DSN format).

Outputs (in docs/paper/figs/):
  - fig1_workflow.pdf
  - fig2_method_overview.pdf
  - fig_ch_sparsity.pdf
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import (
    Circle,
    FancyArrowPatch,
    FancyBboxPatch,
    Polygon,
    Rectangle,
    Wedge,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "docs" / "paper" / "figs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Palette (DSN-friendly, color-blind safe-ish) ──
NAVY = "#1f3a68"     # primary
SKY = "#4a90c2"      # secondary
TEAL = "#2a9d8f"     # accent
AMBER = "#e9a23b"    # warm
CRIMSON = "#c0392b"  # alert/bad
SLATE = "#5d6d7e"    # neutral
PAPER = "#fafafa"
LINE = "#34495e"
LIGHT = "#e8eff7"

plt.rcParams.update({
    "font.size": 9,
    "font.family": "DejaVu Sans",
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "figure.dpi": 200,
    "savefig.dpi": 300,
    "pdf.fonttype": 42,   # embed TrueType so LaTeX renders correctly
    "ps.fonttype": 42,
})


def save(fig, name, pad=0.25):
    fig.savefig(OUT_DIR / name, format="pdf", bbox_inches="tight", pad_inches=pad)
    plt.close(fig)
    print(f"Wrote {name}")


# ═══════════════════════════════════════════════════════════════════
#  Icon primitives (drawn from matplotlib, no emoji font needed)
# ═══════════════════════════════════════════════════════════════════


def icon_radar(ax, cx, cy, r=0.18, color=NAVY):
    """Concentric circles with a sweep wedge (radar)."""
    for rr, alpha in [(r, 1.0), (r * 0.66, 0.7), (r * 0.33, 0.4)]:
        ax.add_patch(Circle((cx, cy), rr, fill=False,
                            edgecolor=color, linewidth=0.8, alpha=alpha))
    ax.add_patch(Wedge((cx, cy), r, 20, 75, fill=True,
                       facecolor=color, alpha=0.25, edgecolor=color, linewidth=0.5))
    ax.add_patch(Circle((cx, cy), 0.015, color=color, zorder=5))


def icon_aspath(ax, cx, cy, r=0.2, hops=4, color=NAVY):
    """Chain of small dots representing an AS path."""
    xs = np.linspace(cx - r, cx + r, hops)
    ys = np.full_like(xs, cy)
    # Slight curve
    ys = ys + 0.05 * np.sin(np.linspace(0, np.pi, hops))
    ax.plot(xs, ys, color=color, linewidth=1.2, alpha=0.6, zorder=2)
    for x, y in zip(xs, ys):
        ax.add_patch(Circle((x, y), 0.025, facecolor=color,
                            edgecolor="white", linewidth=0.6, zorder=3))
    # Origin arrow
    ax.annotate("", xy=(xs[0] - 0.06, cy), xytext=(xs[0] - 0.12, cy),
                arrowprops=dict(arrowstyle="->", color=color, lw=0.9))


def icon_traffic(ax, cx, cy, w=0.4, h=0.18, color=NAVY):
    """A small time-series plot (traffic volume)."""
    t = np.linspace(cx - w / 2, cx + w / 2, 40)
    y = h / 2 * (0.5 + 0.4 * np.sin(6 * (t - cx) * 4) + 0.3 * np.cos(9 * (t - cx) * 4))
    ax.plot(t, cy + y, color=color, linewidth=1.1)
    ax.plot([cx - w / 2, cx + w / 2], [cy - h / 2, cy - h / 2],
            color=SLATE, linewidth=0.5)
    ax.plot([cx - w / 2, cx - w / 2], [cy - h / 2, cy + h / 2],
            color=SLATE, linewidth=0.5)


def icon_clock(ax, cx, cy, r=0.16, color=NAVY):
    """A clock face."""
    ax.add_patch(Circle((cx, cy), r, fill=True, facecolor="white",
                        edgecolor=color, linewidth=0.9))
    ax.plot([cx, cx + r * 0.55], [cy, cy + r * 0.15],
            color=color, linewidth=1.0, solid_capstyle="round")
    ax.plot([cx, cx], [cy, cy + r * 0.7],
            color=color, linewidth=1.0, solid_capstyle="round")
    ax.add_patch(Circle((cx, cy), 0.015, color=color, zorder=5))


def icon_doc(ax, cx, cy, w=0.3, h=0.36, color=NAVY):
    """Document with fold corner and 3 text lines."""
    x0, y0 = cx - w / 2, cy - h / 2
    pts = [(x0, y0), (x0 + w - 0.08, y0), (x0 + w, y0 + 0.08),
           (x0 + w, y0 + h), (x0, y0 + h), (x0, y0)]
    ax.add_patch(Polygon(pts, closed=True, facecolor="white",
                         edgecolor=color, linewidth=0.9))
    # Fold
    fold = [(x0 + w - 0.08, y0), (x0 + w, y0 + 0.08), (x0 + w - 0.08, y0 + 0.08)]
    ax.add_patch(Polygon(fold, closed=True, facecolor=LIGHT,
                         edgecolor=color, linewidth=0.6))
    # Lines
    for i, ly in enumerate([0.07, 0.15, 0.23]):
        ax.plot([x0 + 0.04, x0 + w - 0.12], [y0 + ly, y0 + ly],
                color=SLATE, linewidth=0.5, alpha=0.6 - i * 0.1)


def icon_math(ax, cx, cy, color=NAVY):
    """A stylized 'f(x)' — math/estimator icon."""
    ax.text(cx, cy, r"$\widehat{\,\mathrm{PDM}\,}$",
            ha="center", va="center", fontsize=12, color=color,
            fontweight="bold", usetex=False)


def icon_shock(ax, cx, cy, r=0.18, color=AMBER):
    """Lightning bolt — anomalous event."""
    pts = [(cx - 0.04, cy + r), (cx + 0.06, cy + 0.02),
           (cx - 0.02, cy + 0.02), (cx + 0.04, cy - r),
           (cx - 0.06, cy - 0.02), (cx + 0.02, cy - 0.02)]
    ax.add_patch(Polygon(pts, closed=True, facecolor=color,
                         edgecolor=color, linewidth=0.6, alpha=0.9))


def icon_shield(ax, cx, cy, r=0.18, color=TEAL):
    """Shield — arbitration/verification."""
    pts = [(cx, cy + r), (cx + r * 0.85, cy + r * 0.5),
           (cx + r * 0.7, cy - r * 0.6), (cx, cy - r),
           (cx - r * 0.7, cy - r * 0.6), (cx - r * 0.85, cy + r * 0.5)]
    ax.add_patch(Polygon(pts, closed=True, facecolor="white",
                         edgecolor=color, linewidth=1.1))
    ax.plot([cx - 0.05, cx, cx + 0.05], [cy, cy - 0.05, cy - 0.1],
            color=color, linewidth=1.4, solid_capstyle="round")


def box(ax, x, y, w, h, text, fc=LIGHT, ec=NAVY, fontsize=8.5,
        fontweight="bold", textcolor=None, icon_fn=None, icon_offset=0.0):
    """Rounded box with optional icon and centered text."""
    if textcolor is None:
        textcolor = ec
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.05",
                       linewidth=1.0, edgecolor=ec, facecolor=fc)
    ax.add_patch(p)
    if icon_fn is not None:
        icon_fn(ax, x + 0.13, y + h / 2)
        ax.text(x + 0.28 + icon_offset, y + h / 2, text, ha="left", va="center",
                fontsize=fontsize, fontweight=fontweight, color=textcolor)
    else:
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
                fontsize=fontsize, fontweight=fontweight, color=textcolor)


def arrow(ax, x1, y1, x2, y2, color=NAVY, lw=1.6, style="-|>"):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle=style, mutation_scale=12,
        color=color, linewidth=lw))


# ═══════════════════════════════════════════════════════════════════
#  Figure 1: BGP Tracer two-phase workflow
# ═══════════════════════════════════════════════════════════════════


def fig1_workflow():
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_facecolor(PAPER)

    # ── Title strip ──
    ax.text(5, 9.55, "BGP Tracer — Two-Phase Workflow",
            ha="center", va="center", fontsize=11, fontweight="bold",
            color=NAVY)
    ax.add_patch(Rectangle((0.4, 9.30), 9.2, 0.02, color=NAVY))

    # ── Inputs column ──
    box(ax, 0.4, 7.2, 2.1, 1.0, "Cloudflare Radar\n(volume signal)",
        fc="white", ec=SKY, fontweight="bold", icon_fn=icon_radar, fontsize=8)
    box(ax, 0.4, 5.9, 2.1, 1.0, "RIPE RIS / RouteViews\n(BGP routes)",
        fc="white", ec=SKY, fontweight="bold", icon_fn=icon_aspath, fontsize=8)
    box(ax, 0.4, 4.6, 2.1, 1.0, "Public event reports\n(Kentik, APNIC blog…)",
        fc="white", ec=SKY, fontweight="bold", icon_fn=icon_doc, fontsize=8)
    ax.text(1.45, 8.45, "INPUTS", ha="center", fontsize=7.5,
            color=SLATE, fontweight="bold")

    # ── Phase 1 (QUICK) ──
    box(ax, 3.0, 4.5, 3.0, 3.8, "", fc=LIGHT, ec=NAVY, fontsize=8)
    ax.text(4.5, 8.05, "Phase 1 — QUICK", ha="center", fontsize=10,
            fontweight="bold", color=NAVY)
    ax.text(4.5, 7.7, "deterministic  •  ~60 s  •  0 LLM calls",
            ha="center", fontsize=7.5, color=SLATE, style="italic")
    # Detectors
    box(ax, 3.15, 6.0, 2.7, 0.55, "Traffic detector", fc="white", ec=NAVY,
        icon_fn=icon_traffic, fontsize=8, fontweight="normal")
    box(ax, 3.15, 5.3, 2.7, 0.55, "Routing detector", fc="white", ec=NAVY,
        icon_fn=icon_aspath, fontsize=8, fontweight="normal")
    box(ax, 3.15, 4.6, 2.7, 0.55, "Outage / leak detector", fc="white",
        ec=NAVY, icon_fn=icon_shock, fontsize=8, fontweight="normal",
        icon_offset=0.05)

    # ── Phase 2 (DEEP) ──
    box(ax, 6.5, 4.5, 3.0, 3.8, "", fc="#fdf3e7", ec=AMBER, fontsize=8)
    ax.text(8.0, 8.05, "Phase 2 — DEEP", ha="center", fontsize=10,
            fontweight="bold", color=AMBER)
    ax.text(8.0, 7.7, "LLM reasoning  •  HTML report",
            ha="center", fontsize=7.5, color=SLATE, style="italic")
    box(ax, 6.65, 6.6, 2.7, 0.55, "Pearl-PNS estimator", fc="white",
        ec=AMBER, icon_fn=icon_math, fontsize=8, fontweight="normal",
        icon_offset=0.10)
    box(ax, 6.65, 5.9, 2.7, 0.55, "4 evidence channels", fc="white",
        ec=AMBER, icon_fn=icon_shield, fontsize=8, fontweight="normal")
    box(ax, 6.65, 5.2, 2.7, 0.55, "Bayesian synthesis", fc="white",
        ec=AMBER, icon_fn=icon_shield, fontsize=8, fontweight="normal")
    box(ax, 6.65, 4.6, 2.7, 0.5, "LLM report agent", fc="white", ec=AMBER,
        icon_fn=icon_doc, fontsize=8, fontweight="normal")

    # ── Output row ──
    box(ax, 3.0, 2.6, 3.0, 0.9, "Merged timeline cache",
        fc="white", ec=SLATE, icon_fn=icon_clock, fontsize=8, fontweight="normal")
    box(ax, 6.5, 2.6, 3.0, 0.9, "Verdict + 95% CI + p-value",
        fc="white", ec=TEAL, icon_fn=icon_shield, fontsize=8, fontweight="bold")

    box(ax, 3.0, 1.3, 6.5, 0.8,
        "Operator-facing HTML: root cause, confidence, evidence trail",
        fc="white", ec=TEAL, icon_fn=icon_doc, fontsize=8.5, fontweight="bold")

    # ── Arrows: inputs → phase1 → cache → phase2 → output → report ──
    arrow(ax, 2.5, 7.7, 3.0, 6.6, color=SKY)
    arrow(ax, 2.5, 6.4, 3.0, 6.1, color=SKY)
    arrow(ax, 2.5, 5.1, 3.0, 5.0, color=SKY)
    arrow(ax, 6.0, 5.7, 6.5, 6.0, color=NAVY, lw=1.4)
    arrow(ax, 8.0, 4.5, 8.0, 3.5, color=AMBER, lw=1.4)
    arrow(ax, 4.5, 2.6, 4.5, 2.1, color=SLATE, lw=1.2)
    arrow(ax, 6.0, 5.7, 6.5, 5.4, color=AMBER, lw=1.2)

    # ── Phase legend at bottom ──
    ax.add_patch(Rectangle((0.4, 0.2), 9.2, 0.7, facecolor=PAPER,
                           edgecolor=SLATE, linewidth=0.4))
    ax.text(2.2, 0.55, "▼ Inputs", ha="center", fontsize=7.5, color=SKY,
            fontweight="bold")
    ax.text(4.5, 0.55, "▼ Phase 1 (deterministic)", ha="center", fontsize=7.5,
            color=NAVY, fontweight="bold")
    ax.text(8.0, 0.55, "▼ Phase 2 (LLM-augmented)", ha="center", fontsize=7.5,
            color=AMBER, fontweight="bold")

    save(fig, "fig1_workflow.pdf")


# ═══════════════════════════════════════════════════════════════════
#  Figure 2: CSS + HCAF causal attribution pipeline
# ═══════════════════════════════════════════════════════════════════


def fig2_method_overview():
    fig, ax = plt.subplots(figsize=(7.2, 5.0))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_facecolor(PAPER)

    # Title
    ax.text(5, 9.65, "Causal Attribution Pipeline",
            ha="center", va="center", fontsize=11, fontweight="bold",
            color=NAVY)
    ax.text(5, 9.32, "(Pearl-PNS estimator + 4-channel Bayesian synthesis)",
            ha="center", fontsize=8, color=SLATE, style="italic")
    ax.add_patch(Rectangle((0.4, 9.15), 9.2, 0.02, color=NAVY))

    # ── LEFT: Inputs ──
    box(ax, 0.3, 7.5, 2.4, 1.2, "Aligned timelines\n$R(t)$, $T(t)$",
        fc="white", ec=SKY, icon_fn=icon_clock, fontsize=8, fontweight="bold")
    ax.text(1.5, 8.85, "INPUT", ha="center", fontsize=7, color=SLATE,
            fontweight="bold")

    # ── CENTER: Estimator (Pearl-PNS) ──
    box(ax, 3.2, 6.8, 3.6, 2.0, "", fc=LIGHT, ec=NAVY, fontsize=8)
    ax.text(5.0, 8.5, "Pearl-PNS Estimator", ha="center", fontsize=9.5,
            fontweight="bold", color=NAVY)
    ax.text(5.0, 8.15, "(non-parametric, pre/post windows)",
            ha="center", fontsize=7.5, color=SLATE, style="italic")
    # Two sub-estimates
    box(ax, 3.35, 6.95, 1.65, 0.85, r"$\widehat{\mathrm{PDM}}(R \!\to\! T)$",
        fc="white", ec=NAVY, icon_fn=icon_math, fontsize=8, fontweight="bold",
        icon_offset=0.15)
    box(ax, 5.10, 6.95, 1.65, 0.85, r"$\widehat{\mathrm{PDM}}(T \!\to\! R)$",
        fc="white", ec=NAVY, icon_fn=icon_math, fontsize=8, fontweight="bold",
        icon_offset=0.15)
    ax.text(5.0, 6.85, "+ bootstrap 95% CI, permutation p-value",
            ha="center", fontsize=7, color=SLATE, style="italic")

    # ── RIGHT: 4 evidence channels ──
    box(ax, 7.2, 5.5, 2.5, 3.3, "", fc="#fdf3e7", ec=AMBER, fontsize=8)
    ax.text(8.45, 8.6, "Evidence Channels", ha="center", fontsize=9.5,
            fontweight="bold", color=AMBER)
    channels = [
        ("MSBD", "multi-scale\nbreakpoint", icon_aspath),
        ("CTPR", "causal transmission\npath", icon_aspath),
        ("CIC", "cascade impact\ncount", icon_shock),
        ("TE", "transfer entropy\n(non-linear flow)", icon_traffic),
    ]
    for i, (name, desc, icn) in enumerate(channels):
        y = 8.0 - i * 0.65
        box(ax, 7.35, y, 2.2, 0.55, f"{name}: {desc}", fc="white",
            ec=AMBER, icon_fn=icn, fontsize=7.2, fontweight="normal",
            icon_offset=0.05)

    # ── BOTTOM: Bayesian synthesis ──
    box(ax, 0.6, 3.0, 8.8, 1.8, "", fc="white", ec=TEAL, fontsize=8)
    ax.text(5.0, 4.55, "Bayesian Synthesis (PDM-anchored)",
            ha="center", fontsize=10, fontweight="bold", color=TEAL)
    ax.text(5.0, 4.15,
            r"$\Pr(\text{cause} \mid \text{evidence}) \;\propto\; \Pr(\text{cause}) \cdot \prod_{\text{ch}} \mathrm{LR}(\text{ch})$",
            ha="center", fontsize=11)
    ax.text(5.0, 3.55,
            "prior: PDM-anchored  •  disagreeing channels get 0.4× discount",
            ha="center", fontsize=7.5, color=SLATE, style="italic")
    ax.text(5.0, 3.2,
            "→ argmax posterior cause  +  95% CI  +  necessity  +  sufficiency",
            ha="center", fontsize=7.5, color=TEAL, fontweight="bold")

    # ── Verdict output ──
    box(ax, 1.5, 1.4, 7.0, 0.9, "Final Verdict  →  Operator HTML report",
        fc="#e8f5e9", ec=TEAL, icon_fn=icon_shield, fontsize=9, fontweight="bold")

    # ── Arrows ──
    arrow(ax, 2.7, 8.0, 3.2, 7.7, color=SKY)               # input -> estimator
    arrow(ax, 5.0, 6.8, 5.0, 4.8, color=NAVY)               # estimator -> bayes
    arrow(ax, 8.45, 5.5, 7.0, 4.0, color=AMBER)             # channels -> bayes
    arrow(ax, 5.0, 3.0, 5.0, 2.3, color=TEAL)               # bayes -> verdict

    # ── Color legend ──
    legend_items = [
        (1.0, "Inputs", SKY),
        (3.5, "Pearl-PNS", NAVY),
        (6.0, "Channels", AMBER),
        (8.0, "Synthesis + Verdict", TEAL),
    ]
    for x, label, color in legend_items:
        ax.add_patch(Rectangle((x, 0.4), 0.25, 0.18, color=color))
        ax.text(x + 0.35, 0.49, label, ha="left", va="center", fontsize=7.5)

    save(fig, "fig2_method_overview.pdf")


# ═══════════════════════════════════════════════════════════════════
#  Figure 3 (rebuilt): per-channel abstention on the 30-event GT
# ═══════════════════════════════════════════════════════════════════


def fig_ch_sparsity():
    # Data from section4_method.tex table (n=30)
    labels = [
        "MSBD breakpoint",
        "CTPR + CIC (path)",
        "Granger linearity",
        "Transfer entropy",
        "PDM strict-causal",
    ]
    abstention = [6.7, 13.3, 30.0, 20.0, 90.0]
    ci_low = [1.8, 5.3, 16.7, 9.5, 74.4]
    ci_high = [21.3, 29.7, 47.9, 37.3, 96.5]
    colors = [TEAL, TEAL, SKY, SKY, NAVY]

    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    y_pos = np.arange(len(labels))[::-1]  # top-to-bottom: MSBD at top

    for y, label, val, lo, hi, c in zip(y_pos, labels, abstention,
                                         ci_low, ci_high, colors):
        # Error bar (95% CI)
        ax.barh(y, val, xerr=[[val - lo], [hi - val]],
                color=c, edgecolor="white", linewidth=0.8,
                height=0.55, alpha=0.85,
                error_kw=dict(ecolor=LINE, elinewidth=1.0, capsize=3))
        # Numeric label to the right of the bar
        ax.text(val + 2.5, y, f"{val:.1f}%", va="center", ha="left",
                fontsize=8, color=c, fontweight="bold")

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.set_xlim(0, 115)
    ax.set_xlabel("Abstention rate on the 30-event ground-truth (%)",
                  fontsize=8.5)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0", "25", "50", "75", "100"], fontsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(SLATE)
    ax.spines["bottom"].set_color(SLATE)
    ax.tick_params(axis="y", length=0)
    ax.set_axisbelow(True)
    ax.grid(axis="x", linestyle=":", alpha=0.4, color=SLATE)
    ax.set_facecolor(PAPER)

    # Title
    ax.set_title("Per-channel abstention (with Wilson 95% CIs)",
                 fontsize=10, fontweight="bold", color=NAVY, loc="left",
                 pad=8)

    # Note the right side
    ax.text(112, -0.7, "← most abstaining (sparse, structural)",
            ha="right", va="top", fontsize=7, color=SLATE, style="italic")

    save(fig, "fig_ch_sparsity.pdf")


# ═══════════════════════════════════════════════════════════════════


if __name__ == "__main__":
    fig1_workflow()
    fig2_method_overview()
    fig_ch_sparsity()
    print("Done.")
