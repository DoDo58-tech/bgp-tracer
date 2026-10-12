#!/usr/bin/env python3
"""Generate a cleaner, more visually striking version of the BGP Tracer
workflow figure, then export it to a PowerPoint file so the user can
edit it directly.

The matplotlib PDF/PDF is a reference; the .pptx is the editable
deliverable.

Usage:
    python3 scripts/regen_workflow_pretty.py
Outputs:
    docs/paper/figs/fig1_workflow.pdf   (paper-ready, v3)
    docs/paper/figs/fig1_workflow.pptx  (editable)
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

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "docs" / "paper" / "figs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Bold, high-contrast palette (v3) ──
NAVY = "#0b2545"
SKY = "#1d6fb8"
TEAL = "#0e8a73"
AMBER = "#e08520"
CRIMSON = "#c0392b"
SLATE = "#5a6a7a"
PAPER = "#ffffff"
LINE = "#1a2a3a"
LIGHT = "#e8eff7"
WARM = "#fde9d2"
COOL = "#e0f0fa"

plt.rcParams.update({
    "font.size": 10,
    "font.family": "DejaVu Sans",
    "axes.titlesize": 12,
    "axes.labelsize": 10,
    "figure.dpi": 200,
    "savefig.dpi": 300,
    "pdf.fonttype": 42,
})


def save(fig, name, pad=0.15):
    fig.savefig(OUT_DIR / name, format="pdf", bbox_inches="tight", pad_inches=pad)
    plt.close(fig)
    print(f"Wrote {name}")


# ═══════════════════════════════════════════════════════════════════
#  Icon primitives — bolder, larger, easier to spot at column width
# ═══════════════════════════════════════════════════════════════════


def icon_radar(ax, cx, cy, r=0.30, color=NAVY):
    """Concentric circles with a coloured sweep wedge (radar)."""
    for rr, alpha in [(r, 1.0), (r * 0.66, 0.65), (r * 0.33, 0.35)]:
        ax.add_patch(Circle((cx, cy), rr, fill=False,
                            edgecolor=color, linewidth=1.6, alpha=alpha))
    ax.add_patch(Wedge((cx, cy), r, 25, 80, fill=True,
                       facecolor=color, alpha=0.35, edgecolor=color, linewidth=1.0))
    ax.add_patch(Circle((cx, cy), 0.04, color=color, zorder=5))


def icon_aspath(ax, cx, cy, r=0.32, hops=5, color=NAVY):
    """Chain of dots representing an AS path, with a clear origin arrow."""
    xs = np.linspace(cx - r, cx + r, hops)
    ys = np.full_like(xs, cy) + 0.08 * np.sin(np.linspace(0, np.pi, hops))
    ax.plot(xs, ys, color=color, linewidth=2.0, alpha=0.7, zorder=2)
    for x, y in zip(xs, ys):
        ax.add_patch(Circle((x, y), 0.045, facecolor=color,
                            edgecolor="white", linewidth=1.0, zorder=3))
    ax.annotate("", xy=(xs[0] - 0.10, cy), xytext=(xs[0] - 0.20, cy),
                arrowprops=dict(arrowstyle="->", color=color, lw=1.6,
                                mutation_scale=12))


def icon_traffic(ax, cx, cy, w=0.55, h=0.30, color=NAVY):
    """Time-series signal (volume) with axis lines."""
    t = np.linspace(cx - w / 2, cx + w / 2, 60)
    y = (h / 2) * (0.5 + 0.4 * np.sin(6 * (t - cx) * 4)
                   + 0.3 * np.cos(9 * (t - cx) * 4))
    # baseline
    ax.plot([cx - w / 2, cx + w / 2], [cy - h / 2, cy - h / 2],
            color=SLATE, linewidth=1.0)
    ax.plot([cx - w / 2, cx - w / 2], [cy - h / 2, cy + h / 2],
            color=SLATE, linewidth=1.0)
    ax.plot(t, cy + y, color=color, linewidth=2.0)


def icon_clock(ax, cx, cy, r=0.28, color=NAVY):
    ax.add_patch(Circle((cx, cy), r, fill=True, facecolor="white",
                        edgecolor=color, linewidth=2.0))
    ax.plot([cx, cx + r * 0.55], [cy, cy + r * 0.15],
            color=color, linewidth=2.0, solid_capstyle="round")
    ax.plot([cx, cx], [cy, cy + r * 0.7],
            color=color, linewidth=2.0, solid_capstyle="round")
    for ang in np.linspace(0, 2 * np.pi, 12, endpoint=False):
        ax.plot([cx + 0.20 * np.cos(ang), cx + 0.25 * np.cos(ang)],
                [cy + 0.20 * np.sin(ang), cy + 0.25 * np.sin(ang)],
                color=color, linewidth=0.8)
    ax.add_patch(Circle((cx, cy), 0.04, color=color, zorder=5))


def icon_doc(ax, cx, cy, w=0.45, h=0.55, color=NAVY):
    """Document with fold corner and 4 visible text lines."""
    x0, y0 = cx - w / 2, cy - h / 2
    pts = [(x0, y0), (x0 + w - 0.12, y0), (x0 + w, y0 + 0.12),
           (x0 + w, y0 + h), (x0, y0 + h), (x0, y0)]
    ax.add_patch(Polygon(pts, closed=True, facecolor="white",
                         edgecolor=color, linewidth=1.6))
    fold = [(x0 + w - 0.12, y0), (x0 + w, y0 + 0.12),
            (x0 + w - 0.12, y0 + 0.12)]
    ax.add_patch(Polygon(fold, closed=True, facecolor=LIGHT,
                         edgecolor=color, linewidth=1.0))
    for i, ly in enumerate([0.10, 0.20, 0.30, 0.40]):
        ax.plot([x0 + 0.06, x0 + w - 0.18], [y0 + ly, y0 + ly],
                color=SLATE, linewidth=1.0, alpha=0.8 - i * 0.1)


def icon_math(ax, cx, cy, color=NAVY):
    ax.text(cx, cy, r"$\widehat{\mathrm{PDM}}\,$, $\mathrm{CI}$",
            ha="center", va="center", fontsize=11, color=color,
            fontweight="bold", usetex=False)


def icon_shock(ax, cx, cy, r=0.28, color=AMBER):
    """Lightning bolt — anomalous event."""
    pts = [(cx - 0.07, cy + r), (cx + 0.10, cy + 0.05),
           (cx - 0.03, cy + 0.05), (cx + 0.07, cy - r),
           (cx - 0.10, cy - 0.05), (cx + 0.03, cy - 0.05)]
    ax.add_patch(Polygon(pts, closed=True, facecolor=color,
                         edgecolor=color, linewidth=1.0, alpha=0.95))


def icon_shield(ax, cx, cy, r=0.28, color=TEAL):
    """Shield with a check mark."""
    pts = [(cx, cy + r), (cx + r * 0.85, cy + r * 0.5),
           (cx + r * 0.7, cy - r * 0.6), (cx, cy - r),
           (cx - r * 0.7, cy - r * 0.6), (cx - r * 0.85, cy + r * 0.5)]
    ax.add_patch(Polygon(pts, closed=True, facecolor="white",
                         edgecolor=color, linewidth=1.8))
    ax.plot([cx - 0.10, cx - 0.02], [cy, cy - 0.08],
            color=color, linewidth=2.2, solid_capstyle="round")
    ax.plot([cx - 0.02, cx + 0.12], [cy - 0.08, cy + 0.10],
            color=color, linewidth=2.2, solid_capstyle="round")


def box(ax, x, y, w, h, text, fc=LIGHT, ec=NAVY, fontsize=10,
        fontweight="bold", textcolor=None, icon_fn=None, lw=1.4):
    """Rounded box with optional icon and text."""
    if textcolor is None:
        textcolor = ec
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.10",
                       linewidth=lw, edgecolor=ec, facecolor=fc)
    ax.add_patch(p)
    if icon_fn is not None:
        icon_fn(ax, x + 0.27, y + h / 2)
        ax.text(x + 0.50, y + h / 2, text, ha="left", va="center",
                fontsize=fontsize, fontweight=fontweight, color=textcolor)
    else:
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
                fontsize=fontsize, fontweight=fontweight, color=textcolor)


def thick_arrow(ax, x1, y1, x2, y2, color=NAVY, lw=2.2, style="-|>"):
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2), arrowstyle=style, mutation_scale=20,
        color=color, linewidth=lw))


# ═══════════════════════════════════════════════════════════════════
#  Figure 1 (v3): bolder, larger, more readable
# ═══════════════════════════════════════════════════════════════════


def fig1_workflow_pdf():
    fig, ax = plt.subplots(figsize=(7.6, 5.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_facecolor(PAPER)

    # Title bar
    ax.add_patch(Rectangle((0.0, 9.30), 10.0, 0.7, facecolor=NAVY))
    ax.text(5.0, 9.65, "BGP Tracer — Two-Phase Workflow",
            ha="center", va="center", fontsize=13, fontweight="bold",
            color="white")

    # ── Inputs column ──
    ax.text(1.45, 8.85, "INPUTS", ha="center", fontsize=9,
            color=SKY, fontweight="bold")
    box(ax, 0.30, 7.0, 2.30, 1.40,
        "Cloudflare Radar\n(volume)",
        fc="white", ec=SKY, icon_fn=icon_radar, fontsize=9.5, lw=1.8)
    box(ax, 0.30, 5.4, 2.30, 1.40,
        "RIPE RIS / RouteViews\n(BGP routes)",
        fc="white", ec=SKY, icon_fn=icon_aspath, fontsize=9.5, lw=1.8)
    box(ax, 0.30, 3.8, 2.30, 1.40,
        "Public event reports\n(Kentik, APNIC…)",
        fc="white", ec=SKY, icon_fn=icon_doc, fontsize=9.5, lw=1.8)

    # ── Phase 1 (QUICK) ──
    p1 = FancyBboxPatch((3.10, 3.7), 3.20, 5.10,
                        boxstyle="round,pad=0.04,rounding_size=0.12",
                        linewidth=2.0, edgecolor=NAVY,
                        facecolor=COOL)
    ax.add_patch(p1)
    ax.text(4.70, 8.50, "Phase 1 — QUICK", ha="center", fontsize=12,
            fontweight="bold", color=NAVY)
    ax.text(4.70, 8.10, "deterministic  •  ~60 s  •  0 LLM calls",
            ha="center", fontsize=8.5, color=SLATE, style="italic")
    box(ax, 3.30, 6.50, 2.80, 0.85, "Traffic detector",
        fc="white", ec=NAVY, icon_fn=icon_traffic,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 3.30, 5.50, 2.80, 0.85, "Routing detector",
        fc="white", ec=NAVY, icon_fn=icon_aspath,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 3.30, 4.50, 2.80, 0.85, "Outage / leak detector",
        fc="white", ec=NAVY, icon_fn=icon_shock,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 3.30, 3.85, 2.80, 0.55,
        "→ merged timeline cache", fc=LIGHT, ec=NAVY,
        icon_fn=icon_clock, fontsize=8.5, fontweight="normal", lw=1.0)

    # ── Phase 2 (DEEP) ──
    p2 = FancyBboxPatch((6.80, 3.7), 3.10, 5.10,
                        boxstyle="round,pad=0.04,rounding_size=0.12",
                        linewidth=2.0, edgecolor=AMBER, facecolor=WARM)
    ax.add_patch(p2)
    ax.text(8.35, 8.50, "Phase 2 — DEEP", ha="center", fontsize=12,
            fontweight="bold", color=AMBER)
    ax.text(8.35, 8.10, "LLM reasoning  •  HTML report",
            ha="center", fontsize=8.5, color=SLATE, style="italic")
    box(ax, 6.95, 6.95, 2.80, 0.65, "Pearl-PNS estimator",
        fc="white", ec=AMBER, icon_fn=icon_math,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 6.95, 6.15, 2.80, 0.65, "4 evidence channels",
        fc="white", ec=AMBER, icon_fn=icon_shield,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 6.95, 5.35, 2.80, 0.65, "Bayesian synthesis",
        fc="white", ec=AMBER, icon_fn=icon_shield,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 6.95, 4.55, 2.80, 0.65, "LLM report agent",
        fc="white", ec=AMBER, icon_fn=icon_doc,
        fontsize=9, fontweight="normal", lw=1.4)
    box(ax, 6.95, 3.85, 2.80, 0.55,
        "→ verdict + 95% CI", fc=LIGHT, ec=AMBER,
        icon_fn=icon_shield, fontsize=8.5, fontweight="normal", lw=1.0)

    # ── Bottom operator report ──
    box(ax, 3.10, 2.30, 6.80, 1.10,
        "Operator-facing HTML: root cause, confidence, evidence trail",
        fc="white", ec=TEAL, icon_fn=icon_doc, fontsize=10.5,
        fontweight="bold", lw=1.8)

    # ── Output row: timeline cache marker ──
    box(ax, 3.10, 1.0, 6.80, 1.0,
        "30-event ground-truth  +  13-event held-out stress test",
        fc=LIGHT, ec=NAVY, icon_fn=icon_clock, fontsize=9.5,
        fontweight="normal", lw=1.2)

    # ── Arrows ──
    thick_arrow(ax, 2.60, 7.7, 3.10, 6.9, color=SKY)     # input -> phase1
    thick_arrow(ax, 2.60, 6.1, 3.10, 5.8, color=SKY)
    thick_arrow(ax, 2.60, 4.5, 3.10, 4.8, color=SKY)
    thick_arrow(ax, 6.30, 5.6, 6.80, 5.6, color=NAVY)    # phase1 -> phase2
    thick_arrow(ax, 8.35, 3.7, 8.35, 2.45, color=AMBER)  # phase2 -> html
    thick_arrow(ax, 4.70, 1.0, 4.70, 0.55, color=TEAL)   # html -> evidence
    thick_arrow(ax, 5.50, 1.0, 5.50, 0.55, color=TEAL)

    # ── Bottom legend ──
    ax.add_patch(Rectangle((0.30, 0.05), 9.40, 0.40, facecolor=NAVY))
    legend_items = [
        (1.30, "Inputs", SKY),
        (4.0, "Phase 1 (deterministic)", NAVY),
        (7.0, "Phase 2 (LLM-augmented)", AMBER),
    ]
    for x, label, color in legend_items:
        ax.add_patch(Rectangle((x, 0.18), 0.30, 0.14, color=color))
        ax.text(x + 0.40, 0.25, label, ha="left", va="center", fontsize=8.5,
                color="white", fontweight="bold")

    save(fig, "fig1_workflow.pdf")


# ═══════════════════════════════════════════════════════════════════
#  PPTX export — same layout, native shapes & text boxes (editable)
# ═══════════════════════════════════════════════════════════════════


def add_box(slide, x, y, w, h, text, fill, line, font_size=10,
            font_bold=True, font_color=None, border_w=1.25):
    """Add a rounded rectangle (mso shape ROUNDED_RECTANGLE) with text."""
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                   Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor.from_string(fill.lstrip("#"))
    shape.line.color.rgb = RGBColor.from_string(line.lstrip("#"))
    shape.line.width = Pt(border_w)
    tf = shape.text_frame
    tf.margin_left = Inches(0.05)
    tf.margin_right = Inches(0.05)
    tf.margin_top = Inches(0.02)
    tf.margin_bottom = Inches(0.02)
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = 2  # left
    if "\n" in text:
        lines = text.split("\n")
        for i, line_text in enumerate(lines):
            if i == 0:
                run = p.add_run()
            else:
                p2 = tf.add_paragraph()
                p2.alignment = 2
                run = p2.add_run()
            run.text = line_text
            run.font.size = Pt(font_size)
            run.font.bold = font_bold
            if font_color:
                run.font.color.rgb = RGBColor.from_string(
                    font_color.lstrip("#"))
            else:
                run.font.color.rgb = RGBColor.from_string(
                    line.lstrip("#"))
    else:
        run = p.add_run()
        run.text = text
        run.font.size = Pt(font_size)
        run.font.bold = font_bold
        if font_color:
            run.font.color.rgb = RGBColor.from_string(
                font_color.lstrip("#"))
        else:
            run.font.color.rgb = RGBColor.from_string(line.lstrip("#"))
    return shape


def add_text(slide, x, y, w, h, text, size, color, bold=True, align="left"):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    if align == "center":
        p.alignment = 1
    elif align == "right":
        p.alignment = 2
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor.from_string(color.lstrip("#"))
    return tb


def add_arrow(slide, x1, y1, x2, y2, color=NAVY, weight=2.0):
    line = slide.shapes.add_connector(
        1,  # straight
        Inches(x1), Inches(y1), Inches(x2), Inches(y2)
    )
    line.line.color.rgb = RGBColor.from_string(color.lstrip("#"))
    line.line.width = Pt(weight)
    # Add arrow head
    from pptx.oxml.ns import qn
    ln = line.line._get_or_add_ln()
    head = ln.find(qn("a:headEnd"))
    if head is None:
        from lxml import etree
        head = etree.SubElement(ln, qn("a:headEnd"))
    head.set("type", "none")
    tail = ln.find(qn("a:tailEnd"))
    if tail is None:
        from lxml import etree
        tail = etree.SubElement(ln, qn("a:tailEnd"))
    tail.set("type", "triangle")
    tail.set("w", "med")
    tail.set("len", "med")


def add_rect(slide, x, y, w, h, fill, line=None, border_w=0.5):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                   Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor.from_string(fill.lstrip("#"))
    if line:
        shape.line.color.rgb = RGBColor.from_string(line.lstrip("#"))
        shape.line.width = Pt(border_w)
    else:
        shape.line.fill.background()
    return shape


def fig1_workflow_pptx():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    blank = prs.slide_layouts[6]
    slide = prs.slides.add_slide(blank)

    # Background
    add_rect(slide, 0, 0, 13.333, 7.5, "#ffffff", line=None)

    # Title bar
    add_rect(slide, 0, 0, 13.333, 0.7, NAVY, line=None)
    add_text(slide, 0, 0, 13.333, 0.7,
             "BGP Tracer — Two-Phase Workflow",
             size=20, color="#ffffff", bold=True, align="center")

    # ── INPUTS column ──
    add_text(slide, 0.3, 0.85, 2.3, 0.35, "INPUTS",
             size=11, color=SKY, bold=True, align="center")
    add_box(slide, 0.3, 1.25, 2.6, 1.0,
            "Cloudflare Radar  (volume)",
            fill="#ffffff", line=SKY, font_size=11, border_w=1.5)
    add_box(slide, 0.3, 2.40, 2.6, 1.0,
            "RIPE RIS / RouteViews  (BGP)",
            fill="#ffffff", line=SKY, font_size=11, border_w=1.5)
    add_box(slide, 0.3, 3.55, 2.6, 1.0,
            "Public event reports  (Kentik, APNIC)",
            fill="#ffffff", line=SKY, font_size=11, border_w=1.5)

    # ── PHASE 1 ──
    add_rect(slide, 3.3, 1.05, 4.0, 5.3, COOL, line=NAVY, border_w=2.0)
    add_text(slide, 3.3, 1.15, 4.0, 0.45,
             "Phase 1 — QUICK",
             size=16, color=NAVY, bold=True, align="center")
    add_text(slide, 3.3, 1.55, 4.0, 0.30,
             "deterministic  •  ~60 s  •  0 LLM calls",
             size=10, color=SLATE, bold=False, align="center")
    add_box(slide, 3.45, 2.10, 3.7, 0.65, "Traffic detector",
            fill="#ffffff", line=NAVY, font_size=11, border_w=1.2)
    add_box(slide, 3.45, 2.85, 3.7, 0.65, "Routing detector",
            fill="#ffffff", line=NAVY, font_size=11, border_w=1.2)
    add_box(slide, 3.45, 3.60, 3.7, 0.65, "Outage / leak detector",
            fill="#ffffff", line=NAVY, font_size=11, border_w=1.2)
    add_box(slide, 3.45, 4.40, 3.7, 0.65,
            "→ merged timeline cache",
            fill=LIGHT, line=NAVY, font_size=10, border_w=1.0)
    add_box(slide, 3.45, 5.20, 3.7, 0.95,
            "27 of 30 events → Phase 2 directly\n(3 of 30 trigger a re-query)",
            fill="#ffffff", line=NAVY, font_size=9, border_w=1.0,
            font_bold=False)

    # ── PHASE 2 ──
    add_rect(slide, 7.5, 1.05, 4.0, 5.3, WARM, line=AMBER, border_w=2.0)
    add_text(slide, 7.5, 1.15, 4.0, 0.45,
             "Phase 2 — DEEP",
             size=16, color=AMBER, bold=True, align="center")
    add_text(slide, 7.5, 1.55, 4.0, 0.30,
             "LLM reasoning  •  HTML report",
             size=10, color=SLATE, bold=False, align="center")
    add_box(slide, 7.65, 2.10, 3.7, 0.65, "Pearl-PNS estimator",
            fill="#ffffff", line=AMBER, font_size=11, border_w=1.2)
    add_box(slide, 7.65, 2.85, 3.7, 0.65, "4 evidence channels",
            fill="#ffffff", line=AMBER, font_size=11, border_w=1.2)
    add_box(slide, 7.65, 3.60, 3.7, 0.65, "Bayesian synthesis",
            fill="#ffffff", line=AMBER, font_size=11, border_w=1.2)
    add_box(slide, 7.65, 4.40, 3.7, 0.65, "LLM report agent",
            fill="#ffffff", line=AMBER, font_size=11, border_w=1.2)
    add_box(slide, 7.65, 5.20, 3.7, 0.95,
            "→ verdict + 95% CI + p-value",
            fill=LIGHT, line=AMBER, font_size=10, border_w=1.0,
            font_bold=False)

    # ── Bottom operator report ──
    add_box(slide, 3.3, 6.50, 8.2, 0.75,
            "Operator-facing HTML:  root cause  •  confidence  •  evidence trail",
            fill="#ffffff", line=TEAL, font_size=12, border_w=1.8)

    # ── Arrows ──
    add_arrow(slide, 2.90, 1.75, 3.30, 1.75, color=SKY, weight=2.0)
    add_arrow(slide, 2.90, 2.90, 3.30, 2.90, color=SKY, weight=2.0)
    add_arrow(slide, 2.90, 4.05, 3.30, 4.05, color=SKY, weight=2.0)
    add_arrow(slide, 7.30, 2.80, 7.50, 2.80, color=NAVY, weight=2.0)
    add_arrow(slide, 9.50, 6.15, 9.50, 6.50, color=AMBER, weight=2.0)

    # ── Footer legend ──
    add_rect(slide, 0, 7.10, 13.333, 0.4, NAVY, line=None)
    add_text(slide, 0.5, 7.10, 4, 0.4, "■  Inputs",
             size=11, color="#ffffff", bold=True)
    add_text(slide, 5.0, 7.10, 4, 0.4, "■  Phase 1  (deterministic)",
             size=11, color="#ffffff", bold=True)
    add_text(slide, 8.7, 7.10, 4, 0.4, "■  Phase 2  (LLM-augmented)",
             size=11, color="#ffffff", bold=True)

    out_pptx = OUT_DIR / "fig1_workflow.pptx"
    prs.save(out_pptx)
    print(f"Wrote {out_pptx.name}")


# ═══════════════════════════════════════════════════════════════════


if __name__ == "__main__":
    fig1_workflow_pdf()
    fig1_workflow_pptx()
    print("Done.")
