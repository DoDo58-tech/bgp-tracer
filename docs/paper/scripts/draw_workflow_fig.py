#!/usr/bin/env python3
"""BGP Tracer conceptual workflow figure (SIGCOMM/IMC style, 2:1 landscape).

Outputs:
  figs/fig_workflow_conceptual.svg   (vector, source of truth)
  figs/fig_workflow_conceptual.pdf   (vector, for LaTeX)
  figs/fig_workflow_conceptual.png   (raster preview, 2x)
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wf_style import *  # noqa: F401,F403
import wf_style as S

OUT = "/data/bgp_tracer/docs/paper/figs"

# ---------------------------------------------------------------- canvas ---
W, H = 2600, 1300

# column anchors
X_SEL, SEL_W = 40, 150                 # target event selector
X_IN, IN_W = 212, 176                  # input cards
X_P1, P1_W = 412, 772                  # phase 1 panel
X_P2, P2_W = 1252, 852                 # phase 2 panel
X_OUT, OUT_W = 2136, 384               # output group

Y_TOP, Y_BOT = 104, 744                # panel vertical extent
Y_BAND_TOP, Y_BAND_BOT = 850, 1000     # shared cache band
Y_STRIP_TOP, Y_STRIP_BOT = 1040, 1200  # offline evaluation strip

parts: list[str] = []


def add(s: str) -> None:
    parts.append(s)


# =============================================================== title =====
add(text(W / 2, 58, "BGP Tracer: Joint Traffic–BGP Anomaly Attribution",
         25, 700, NAVY, "middle", spacing=0.2))
add(line(40, 80, W - 40, 80, GRAY_LINE, 1.4))


# =============================================================== inputs ===
# --- target event selector -------------------------------------------------
sel_x, sel_y, sel_h = X_SEL, 236, 118
add(rect(sel_x, sel_y, SEL_W, sel_h, GRAY_FILL, GRAY_LINE, 2, 10))
add(icon_target(sel_x + 14, sel_y + 16, SLATE, 22, 16))
add(text(sel_x + 14, sel_y + 56, "Target event", 10, 600, NAVY))
add(text(sel_x + 14, sel_y + 74, "ASN + time window", 8.5, 400, GRAY))
add(line(sel_x + 14, sel_y + 86, sel_x + SEL_W - 14, sel_y + 86, GRAY_LINE, 1))

# --- three input cards ------------------------------------------------------
INPUTS = [
    ("Cloudflare Radar", "5-min AS traffic telemetry", icon_waveform),
    ("RIPE RIS · RouteViews", "BGP updates + AS paths", icon_routers),
    ("CAIDA AS-rel · RPKI ROA", "Topology + origin validation", icon_graph),
]
in_y0, in_h, in_gap = 190, 112, 14
for i, (t, b, ic) in enumerate(INPUTS):
    y = in_y0 + i * (in_h + in_gap)
    add(rect(X_IN, y, IN_W, in_h, WHITE, GRAY_LINE, 2, 10))
    add(ic(X_IN + IN_W - 14 - 24, y + 14, NAVY, 24, 17))
    add(text(X_IN + 14, y + 28, t, 9, 600, NAVY))
    add(text(X_IN + 14, y + 50, b, 8, 400, GRAY))
    add(line(X_IN + 14, y + 62, X_IN + IN_W - 14, y + 62, GRAY_LINE, 1))
    add(text(X_IN + 14, y + 80, ["data-plane", "control-plane", "topology"][i],
             7.5, 400, "#9AA5B4"))

# --- bus from inputs into Phase 1 ------------------------------------------
bus_x = 398
for i in range(3):
    y = in_y0 + i * (in_h + in_gap) + in_h / 2
    add(path(f"M {X_IN + IN_W} {y} H {bus_x}", GRAY_LINE, 2, dash="5 4"))
add(path(f"M {bus_x} {in_y0 + in_h / 2} V {in_y0 + 2 * (in_h + in_gap) + in_h / 2}",
         GRAY_LINE, 2, dash="5 4"))
add(arrow(bus_x, in_y0 + 2 * (in_h + in_gap) + in_h / 2, X_P1 + 18, 315,
          "solid", SLATE, 2))


# =============================================================== phase 1 ====
p1x, p1w = X_P1, P1_W
add(rect(p1x, Y_TOP, p1w, Y_BOT - Y_TOP, AMBER_TINT, AMBER_SOFT, 2.4, 14))
add(text(p1x + 22, Y_TOP + 34, "QUICK · PHASE 1", 13.5, 700, AMBER))
add(text(p1x + 22, Y_TOP + 52, "Deterministic Joint Detection — no LLM",
         9, 400, GRAY))
add(line(p1x + 22, Y_TOP + 64, p1x + p1w - 22, Y_TOP + 64, AMBER_SOFT, 1.2))

# --- coarse screen ----------------------------------------------------------
add(card(p1x + 22, 250, 145, 132, "Coarse Screen",
         ["Periodic baseline", "+ impact score"],
         accent=AMBER, tint=WHITE, border=AMBER_SOFT, align="center", t_size=9.5))

# --- two parallel agents ----------------------------------------------------
AG_Y, AG_H = 200, 118
add(card(p1x + 185, AG_Y, 170, AG_H, "Traffic Agent",
         ["Sudden / sustained anomalies", "Peak–trough excursion"],
         accent=AMBER, tint=WHITE, border=AMBER_SOFT, align="center", t_size=9.5))
add(card(p1x + 185, AG_Y + 150, 170, AG_H, "Routing Agent",
         ["MSBD · CTPR · CIC", "Outage · leak · hijack detectors"],
         accent=AMBER, tint=WHITE, border=AMBER_SOFT, align="center", t_size=9.5))
# parallel collection bracket
add(path(f"M {p1x + 180} {AG_Y + AG_H / 2} H {p1x + 168} V {AG_Y + 150 + AG_H / 2} H {p1x + 180}",
         AMBER_SOFT, 1.6, dash="4 4"))

# --- evidence arbitration ----------------------------------------------------
arb_x = p1x + 374
add(card(arb_x, 285, 168, 122, "Evidence Arbitration",
         ["Suspension · evidential gating", "temporal correlation"],
         accent=AMBER, tint="#FFFFFF", border=AMBER, align="center", t_size=9.5))
# converge agents into arbitration
for yy in (AG_Y + AG_H / 2, AG_Y + 150 + AG_H / 2):
    add(path(f"M {p1x + 355} {yy} H {arb_x - 10}", AMBER_SOFT, 2))
add(path(f"M {arb_x - 10} {AG_Y + AG_H / 2} V {AG_Y + 150 + AG_H / 2}", AMBER_SOFT, 2))

# --- five class chips --------------------------------------------------------
CH_X, CH_W, CH_H = p1x + 538, 178, 30
CH_Y = [196, 232, 334, 370, 406]
CHIPS = ["real_incident", "correlation_uncertain", "silent_alert",
         "traffic_only", "no_clear_anomaly"]
# fan-out bracket from arbitration to the class column
add(path(f"M {arb_x + 168} 346 H {CH_X - 12}", AMBER, 2))
add(path(f"M {CH_X - 12} {CH_Y[0] + CH_H / 2} V {CH_Y[-1] + CH_H / 2}", AMBER, 2))
for y in CH_Y:
    add(arrow(CH_X - 12, y + CH_H / 2, CH_X, y + CH_H / 2, "solid", AMBER, 1.6))
for i, (name, y) in enumerate(zip(CHIPS, CH_Y)):
    add(chip(CH_X, y, CH_W, CH_H, name, "hi" if i < 2 else "lo", AMBER, 8.5))

# gate label under the two highlighted classes
GATE_X, GATE_Y, GATE_W, GATE_H = CH_X, 272, CH_W, 50
add(rect(GATE_X, GATE_Y, GATE_W, GATE_H, "#FFFFFF", AMBER_SOFT, 1.6, 8))
add(text(GATE_X + GATE_W / 2, GATE_Y + 21, "Only real_incident and", 8, 600, AMBER, "middle"))
add(text(GATE_X + GATE_W / 2, GATE_Y + 35, "correlation_uncertain continue", 8, 600, AMBER, "middle"))

# --- recorded stop (short-circuit) ------------------------------------------
STOP_X, STOP_Y, STOP_W, STOP_H = CH_X, 470, CH_W, 68
add(card(STOP_X, STOP_Y, STOP_W, STOP_H, "Recorded stop",
         ["Reason preserved"],
         accent=GRAY, tint=GRAY_FILL, border=GRAY_LINE, align="center", t_size=9))
dotted_x = CH_X + CH_W + 16
for y in (CH_Y[2] + CH_H / 2, CH_Y[3] + CH_H / 2, CH_Y[4] + CH_H / 2):
    add(path(f"M {CH_X + CH_W} {y} H {dotted_x}", GRAY, 1.6, dash="2 4"))
add(path(f"M {dotted_x} {CH_Y[2] + CH_H / 2} V {STOP_Y + 30} H {STOP_X + STOP_W + 4}",
         GRAY, 1.6, dash="2 4"))
add(f'<polygon points="{STOP_X + STOP_W + 4},{STOP_Y + 30} '
    f'{STOP_X + STOP_W + 10},{STOP_Y + 26.6} {STOP_X + STOP_W + 10},{STOP_Y + 33.4}" fill="{GRAY}"/>')

# --- phase 1 -> phase 2 handoff ---------------------------------------------
CONT_Y = 296
add(arrow(GATE_X + GATE_W + 4, CONT_Y, X_P2 - 4, CONT_Y, "solid", SLATE, 2.4))


# --- PART2 ---

# =============================================================== phase 2 ====
p2x, p2w = X_P2, P2_W
add(rect(p2x, Y_TOP, p2w, Y_BOT - Y_TOP, NAVY_TINT, NAVY, 2.4, 14))
add(text(p2x + 22, Y_TOP + 34, "DEEP · PHASE 2", 13.5, 700, NAVY))
add(text(p2x + 22, Y_TOP + 52, "Causal Attribution — evidence before narrative",
         9, 400, GRAY))
add(line(p2x + 22, Y_TOP + 64, p2x + p2w - 22, Y_TOP + 64, NAVY_SOFT, 1.2))

# --- correlation analyzer ----------------------------------------------------
CA_X, CA_Y, CA_W, CA_H = p2x + 20, 240, 122, 122
add(card(CA_X, CA_Y, CA_W, CA_H, "Correlation", ["Timeline alignment", "ΔT + hypothesis", "generation"],
         accent=NAVY, tint=WHITE, border=NAVY_SOFT, align="center", t_size=9.5, b_size=8))
add(text(CA_X + CA_W / 2, CA_Y + 22, "Analyzer", 9.5, 600, NAVY, "middle"))
add(arrow(CA_X + CA_W + 4, 296, p2x + 176, 296, "solid", SLATE, 2))

# --- CSS anchor (prominent) -------------------------------------------------
CSS_X, CSS_Y, CSS_W, CSS_H = p2x + 180, 200, 222, 196
add(rect(CSS_X, CSS_Y, CSS_W, CSS_H, "#FFFFFF", NAVY, 3, 12))
add(text(CSS_X + CSS_W / 2, CSS_Y + 32, "CSS Anchor", 13, 700, NAVY, "middle"))
add(text(CSS_X + CSS_W / 2, CSS_Y + 52, "Pearl-PNS-anchored", 9, 500, GRAY, "middle"))
add(rect(CSS_X + 16, CSS_Y + 64, CSS_W - 32, 42, NAVY_TINT, NAVY_SOFT, 1.4, 7))
add(text(CSS_X + CSS_W / 2, CSS_Y + 84, "CSS(X→Y) = E[Y | do(X=1)] − E[Y | do(X=0)]",
         7.6, 500, NAVY, "middle"))
add(text(CSS_X + CSS_W / 2, CSS_Y + 122, "R→T / T→R · bootstrap 95% CI · permutation p",
         7.8, 400, GRAY, "middle"))
add(text(CSS_X + CSS_W / 2, CSS_Y + 150, "R→T / T→R", 8, 400, GRAY, "middle"))
add(text(CSS_X + CSS_W / 2, CSS_Y + 150, "", 8, 400, GRAY, "middle"))
add(text(CSS_X + CSS_W / 2, CSS_Y + 172, "Pearl-PNS-anchored prior on direction",
         7.8, 400, GRAY, "middle"))
add(arrow(CSS_X + CSS_W + 4, 296, p2x + 428, 296, "solid", SLATE, 2))

# --- five supporting evidence channels ---------------------------------------
SUP_X, SUP_W, SUP_H = p2x + 432, 96, 44
add(text(SUP_X + SUP_W / 2, 190, "Five supporting evidence channels", 8, 600, GRAY, "middle"))
SUP_NAMES = ["MSBD", "CTPR", "CIC", "Granger", "Transfer Entropy"]
sup_ys = []
for i, nm in enumerate(SUP_NAMES):
    y = 202 + i * (SUP_H + 8)
    sup_ys.append(y)
    add(rect(SUP_X, y, SUP_W, SUP_H, WHITE, NAVY_SOFT, 1.8, 8))
    add(text(SUP_X + SUP_W / 2, y + 27, nm, 8.5, 600, NAVY, "middle"))
# the vetoes that gate the estimator
hub_x = p2x + 546
for y in sup_ys:
    add(path(f"M {SUP_X + SUP_W + 4} {y + SUP_H / 2} H {hub_x}", NAVY_SOFT, 1.6))
add(path(f"M {hub_x} {sup_ys[0] + SUP_H / 2} V {sup_ys[-1] + SUP_H / 2}", NAVY_SOFT, 1.6))
add(arrow(hub_x, sup_ys[-1] + SUP_H / 2, hub_x + 10, 296, "solid", NAVY, 2))
add(path(f"M {hub_x + 6} 296 H {p2x + 578}", NAVY, 2))
add(f'<polygon points="{p2x + 578},296 {p2x + 570},292.4 {p2x + 570},299.6" fill="{NAVY}"/>')

# --- the estimator -----------------------------------------------------------
HC_X, HC_Y, HC_W, HC_H = p2x + 582, 248, 118, 112
add(card(HC_X, HC_Y, HC_W, HC_H, "HCAF",
         ["Bayesian evidence", "synthesis", "CSS prior + channel", "likelihood ratios"],
         accent=NAVY, tint=WHITE, border=NAVY, align="center", t_size=10, b_size=7.6))
add(arrow(HC_X + HC_W + 4, 304, p2x + 714, 304, "solid", SLATE, 2))

# --- commit / abstain gate ---------------------------------------------------
GT_X, GT_Y, GT_W, GT_H = p2x + 718, 196, 132, 74
add(card(GT_X, GT_Y, GT_W, GT_H, "Commit / Abstain Gate",
         ["CI excludes zero", "p < 0.05", "temporal precedence"],
         accent=NAVY, tint=WHITE, border=NAVY, align="center", t_size=9, b_size=7.8))
# fork
FK_Y, FK_H = 292, 46
add(path(f"M {GT_X + GT_W / 2} {GT_Y + GT_H} V {FK_Y - 8}", NAVY, 2))
add(path(f"M {GT_X + 40} {FK_Y - 8} H {GT_X + GT_W - 34}", NAVY, 2))
add(arrow(GT_X + 40, FK_Y - 8, GT_X + 40, FK_Y, "solid", NAVY, 1.8))
add(arrow(GT_X + GT_W - 34, FK_Y - 8, GT_X + GT_W - 34, FK_Y, "solid", NAVY, 1.8))
add(rect(GT_X + 4, FK_Y, 76, FK_H, "#FFFFFF", NAVY, 2, 8))
add(text(GT_X + 42, FK_Y + 28, "Commit", 9, 600, NAVY, "middle"))
add(rect(GT_X + 88, FK_Y, 132, FK_H, "#FFFFFF", NAVY_SOFT, 2, 8))
add(text(GT_X + 154, FK_Y + 20, "Abstain with", 8.5, 600, GRAY, "middle"))
add(text(GT_X + 154, FK_Y + 34, "recorded reason", 8.5, 600, GRAY, "middle"))

# --- output state ------------------------------------------------------------
CD_X, CD_Y, CD_W, CD_H = p2x + 714, 352, 206, 62
add(card(CD_X, CD_Y, CD_W, CD_H, "Causal Direction",
         ["R→T / T→R / abstain"],
         accent=NAVY, tint=WHITE, border=NAVY, align="center", t_size=9.5, b_size=8))
add(arrow(GT_X + 42, FK_Y + FK_H, CD_X + 42, CD_Y, "solid", NAVY, 1.8))
add(arrow(GT_X + GT_W - 34, FK_Y + FK_H, CD_X + 130, CD_Y, "solid", NAVY_SOFT, 1.8, dash="6 5"))
CT_Y = CD_Y + CD_H + 12
add(card(CD_X, CT_Y, CD_W, 62, "Cause type",
         ["outage / route leak / origin hijack"],
         accent=NAVY, tint=WHITE, border=NAVY, align="center", t_size=9.5, b_size=8))
add(arrow(CD_X + CD_W / 2, CD_Y + CD_H, CD_X + CD_W / 2, CT_Y, "solid", SLATE, 2))

# --- phase 2 -> output group -------------------------------------------------
add(arrow(CD_X + CD_W + 4, CT_Y + 31, X_OUT - 4, CT_Y + 31, "solid", SLATE, 2.4))


# =============================================================== output =====
add(text(X_OUT, 182, "LLM renders evidence; it does not create the verdict",
         8.5, 400, GRAY, "start", style="italic"))
OUT_CARDS = [
    ("Structured Evidence Chain", "Direction · cause type · confidence · provenance", NAVY, WHITE, 100),
    ("Report Agent", "LLM narrative renderer only", GRAY, GRAY_FILL, 82),
    ("HTML incident report", "Human-readable evidence", GRAY, WHITE, 82),
    ("NOC handoff", "auto-escalate or human review", GRAY, WHITE, 82),
]
oy = 208
for i, (t, b, acc, tint, h) in enumerate(OUT_CARDS):
    add(card(X_OUT, oy, OUT_W, h, t, [b], accent=acc, tint=tint,
             border=acc if acc == NAVY else GRAY_LINE, align="center", t_size=9.5, b_size=8))
    if i < len(OUT_CARDS) - 1:
        add(arrow(X_OUT + OUT_W / 2, oy + h, X_OUT + OUT_W / 2, oy + h + 22, "solid", SLATE, 2))
    oy += h + 22
