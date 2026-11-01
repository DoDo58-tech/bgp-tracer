"""Layout for the BGP Tracer conceptual workflow figure.

Design target: a full-width (two-column) figure in an ACM-style paper, text
width ~516 pt.  The canvas is 2800 x 1400 user units; the SVG/PDF is emitted
at 1400 x 700 pt and LaTeX scales it to \\linewidth, so the body text lands at
~4.2 pt and the panel titles at ~5.3 pt.

Column budget (canvas units, all anchors absolute so arrows stay orthogonal):
  margin 26 | inputs 370 | 22 | phase 1 1080 | 60 | phase 2 1090 | 22 |
  output 104 | margin
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wf_style import *          # noqa: F401,F403
import wf_style as S

OUT = "/data/bgp_tracer/docs/paper/figs"
W, H = 2800, 1400

# type scale (canvas units)
F_TITLE = 52
F_HEAD = 36
F_SUB = 25
F_CARD_T = 29
F_BODY = 23
F_CHIP = 24
F_MICRO = 21
F_CALL = 23

parts: list[str] = []


def add(s: str) -> None:
    parts.append(s)


# ============================================================ geometry =====
M = 26.0

# --- left cluster ----------------------------------------------------------
IN_X, IN_W = M, 370.0
BUS_X = IN_X + IN_W + 22.0

# --- phase 1 ---------------------------------------------------------------
P1X, P1W = 418.0, 1080.0
P1_IN = P1X + 34.0
P1_R = P1X + P1W - 34.0

# --- corridor between the phases (carries the C1 badge) ---------------------
COR_X = P1X + P1W
COR_W = 60.0

# --- phase 2 ---------------------------------------------------------------
P2X, P2W = 1558.0, 1090.0
P2_IN = P2X + 34.0
P2_R = P2X + P2W - 34.0

# --- output column ----------------------------------------------------------
OUTX, OUTW = 2670.0, 104.0

PANEL_Y, PANEL_B = 124, 800

# --- shared cache band -------------------------------------------------------
BAND_X, BAND_W = P1X, (P2X + P2W) - P1X
BAND_Y, BAND_H = 856, 196

# --- offline evaluation strip -------------------------------------------------
EVAL_X, EVAL_W = M, W - 2 * M
EVAL_Y, EVAL_H = 1100, 200


def draw_title() -> None:
    add(text(W / 2, 76, "BGP Tracer: Joint Traffic–BGP Anomaly Attribution",
             F_TITLE, 700, NAVY, "middle", spacing=0.6))
    add(line(M, 100, W - M, 100, GRAY_LINE, 1.6))


def build_svg() -> str:
    """Draw every region and return the SVG document."""
    draw_title()
    draw_inputs()
    draw_phase1()
    draw_phase2_head()
    draw_phase2_channels()
    draw_phase2_gate()
    draw_output()
    draw_cache_band()
    draw_eval_strip()

    body = "\n".join(parts)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{W / 2}pt" '
            f'height="{H / 2}pt" viewBox="0 0 {W} {H}">\n'
            f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>\n'
            f'{body}\n</svg>\n')


def draw_inputs() -> None:
    """Target-event selector plus the three telemetry source cards."""
    # --- target event selector (top of the left cluster) -------------------
    sel_y, sel_h = 150, 190
    add(rect(IN_X, sel_y, IN_W, sel_h, GRAY_FILL, GRAY_LINE, 2.0, 14))
    add(icon_target(IN_X + 26, sel_y + 18, SLATE, 56, 36))
    add(text(IN_X + IN_W / 2, sel_y + 100, "Target event", F_CARD_T, 600, NAVY, "middle"))
    add(text(IN_X + IN_W / 2, sel_y + 136, "ASN + time window", F_BODY, 400, GRAY,
             "middle"))
    add(line(IN_X + 18, sel_y + 156, IN_X + IN_W - 18, sel_y + 156, GRAY_LINE, 1.0))

    # --- three input cards --------------------------------------------------
    INPUTS = [
        ("Cloudflare Radar", "5-min AS traffic telemetry", icon_waveform),
        ("RIPE RIS · RouteViews", "BGP updates + AS paths", icon_routers),
        ("CAIDA AS-rel · RPKI ROA", "Topology + origin validation", icon_graph),
    ]
    in_y0, in_h, in_gap = 372, 134, 24
    for i, (t, b, ic) in enumerate(INPUTS):
        y = in_y0 + i * (in_h + in_gap)
        add(rect(IN_X, y, IN_W, in_h, WHITE, GRAY_LINE, 2.0, 14))
        add(ic(IN_X + IN_W - 62, y + 16, NAVY, 50, 32))
        add(text(IN_X + 14, y + 42, t, F_CARD_T, 600, NAVY))
        add(text(IN_X + 14, y + 82, b, F_BODY, 400, GRAY))
        add(line(IN_X + 14, y + 100, IN_X + IN_W - 14, y + 100, GRAY_LINE, 1.0))
        add(text(IN_X + 14, y + 122, ["data-plane", "control-plane",
                                      "topology"][i], F_MICRO, 400, "#98A3B3"))

    # --- bus from the inputs into phase 1 -----------------------------------
    card_cy = [in_y0 + i * (in_h + in_gap) + in_h / 2 for i in range(3)]
    for cy in card_cy:
        add(path(f"M {IN_X + IN_W} {cy} H {BUS_X}", GRAY_LINE, 1.8, dash="7 6"))
    add(path(f"M {BUS_X} {card_cy[0]} V {card_cy[-1]}", GRAY_LINE, 1.8, dash="7 6"))
    add(path(f"M {IN_X + IN_W / 2} {sel_y + sel_h} V {card_cy[0]}",
             GRAY_LINE, 1.8, dash="7 6"))
    add(arrow(BUS_X, 512, P1_IN, 512, "solid", SLATE, 2.4))


def draw_phase1() -> None:
    """QUICK · PHASE 1 — deterministic joint detection."""
    add(rect(P1X, PANEL_Y, P1W, PANEL_B - PANEL_Y, AMBER_TINT, AMBER_SOFT, 2.4, 22))
    add(text(P1_IN, 178, "QUICK · PHASE 1", F_HEAD, 700, AMBER))
    add(text(P1_IN, 216, "Deterministic Joint Detection — no LLM", F_SUB, 400, GRAY))
    add(line(P1_IN, 240, P1_R, 240, AMBER_SOFT, 1.4))

    # --- coarse screen ------------------------------------------------------
    CS_X, CS_W = P1_IN, 234.0
    add(card(CS_X, 300, CS_W, 252, "Coarse Screen",
             ["Periodic baseline", "+ impact score"],
             accent=AMBER, border=AMBER_SOFT, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.0, r=14, pad=14))

    # --- two parallel evidence agents --------------------------------------
    AG_X, AG_W = CS_X + CS_W + 30.0, 280.0
    add(card(AG_X, 284, AG_W, 212, "Traffic Agent",
             ["Sudden / sustained anomalies", "Peak–trough excursion"],
             accent=AMBER, border=AMBER_SOFT, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.0, r=14, pad=14))
    add(card(AG_X, 528, AG_W, 212, "Routing Agent",
             ["MSBD · CTPR · CIC", "Outage · leak · hijack detectors"],
             accent=AMBER, border=AMBER_SOFT, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.0, r=14, pad=14))
    # coarse screen fans out to the two agents
    add(path(f"M {CS_X + CS_W} 426 H {AG_X - 18}", AMBER, 2.2))
    add(path(f"M {AG_X - 18} 390 V 634", AMBER, 2.2))
    add(arrow(AG_X - 18, 390, AG_X, 390, "solid", AMBER, 2.0, 9))
    add(arrow(AG_X - 18, 634, AG_X, 634, "solid", AMBER, 2.0, 9))

    # --- evidence arbitration ----------------------------------------------
    AR_X, AR_W = AG_X + AG_W + 30.0, 310.0
    add(card(AR_X, 374, AR_W, 280, "Evidence Arbitration",
             ["Suspension · evidential gating", "temporal correlation"],
             accent=AMBER, border=AMBER, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.4, r=14, pad=14))
    # parallel evidence converges into arbitration
    add(path(f"M {AG_X + AG_W} 390 H {AR_X - 18}", AMBER, 2.0))
    add(path(f"M {AG_X + AG_W} 634 H {AR_X - 18}", AMBER, 2.0))
    add(path(f"M {AR_X - 18} 390 V 634", AMBER, 2.0))
    add(arrow(AR_X - 18, 514, AR_X, 514, "solid", AMBER, 2.2, 9))

    # --- five class chips ----------------------------------------------------
    CH_X, CH_W, CH_H = AR_X + AR_W + 28.0, 168.0, 52
    CHIPS = [("real_incident", 268, "hi"),
             ("correlation_uncertain", 328, "hi"),
             ("silent_alert", 544, "lo"),
             ("traffic_only", 604, "lo"),
             ("no_clear_anomaly", 664, "lo")]
    add(path(f"M {AR_X + AR_W} 514 H {CH_X - 20}", AMBER, 2.2))
    add(path(f"M {CH_X - 20} 294 V 690", AMBER, 2.2))
    for name, y, st in CHIPS:
        add(arrow(CH_X - 20, y + CH_H / 2, CH_X, y + CH_H / 2, "solid", AMBER, 1.8, 8))
        add(chip(CH_X, y, CH_W, CH_H, name, st, AMBER, F_CHIP))

    # --- continuation gate ---------------------------------------------------
    add(card(CH_X, 396, CH_W, 104, None,
             ["Only real_incident and", "correlation_uncertain continue"],
             accent=AMBER, border=AMBER_SOFT, tint=WHITE, b_size=F_MICRO,
             sw=1.8, r=10, pad=10))

    # --- recorded stop (short-circuit) ---------------------------------------
    add(card(CH_X, 716, CH_W, 80, "Recorded stop", ["Reason preserved"],
             accent=GRAY, border=GRAY_LINE, tint=GRAY_FILL, t_size=F_CARD_T,
             b_size=F_BODY, t_color=GRAY, sw=1.8, r=12, pad=12))
    for name, y, st in CHIPS[2:]:
        add(path(f"M {CH_X + CH_W} {y + CH_H / 2} H {CH_X + CH_W + 24}",
                 GRAY, 1.6, dash="4 7"))
    add(path(f"M {CH_X + CH_W + 24} 570 V 756 H {CH_X + CH_W + 4}",
             GRAY, 1.6, dash="4 7"))
    add(f'<polygon points="{CH_X + CH_W + 4},756 {CH_X + CH_W + 12},751 '
        f'{CH_X + CH_W + 12},761" fill="{GRAY}"/>')

    # --- phase 1 -> phase 2 ----------------------------------------------------
    add(arrow(CH_X + CH_W, 448, COR_X + COR_W - 4, 448, "solid", SLATE, 2.8, 11))
    add(callout(COR_X + COR_W / 2 + 20, 330, "C1", "Coarse-to-fine",
                "two-phase workflow", r=22, size=F_CALL, align="end",
                leader=f"M {COR_X + COR_W / 2 + 20} 354 V 440",
                lead_color=GRAY_LINE))


def draw_phase2_head() -> None:
    """DEEP · PHASE 2 — panel frame, correlation analyzer, CSS anchor."""
    add(rect(P2X, PANEL_Y, P2W, PANEL_B - PANEL_Y, NAVY_TINT, NAVY, 2.4, 22))
    add(text(P2_IN, 178, "DEEP · PHASE 2", F_HEAD, 700, NAVY))
    add(text(P2_IN, 216, "Causal Attribution — evidence before narrative",
             F_SUB, 400, GRAY))
    add(line(P2_IN, 240, P2_R, 240, NAVY_SOFT, 1.4))

    # --- correlation analyzer -------------------------------------------------
    CA_X, CA_W = P2_IN, 310.0
    add(card(CA_X, 360, CA_W, 244, "Correlation Analyzer",
             ["Timeline alignment", "ΔT + hypothesis generation"],
             accent=NAVY, border=NAVY_SOFT, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.0, r=14, pad=14))
    add(arrow(CA_X + CA_W, 482, CA_X + CA_W + 26, 482, "solid", SLATE, 2.4, 10))

    # --- CSS anchor: the prominent central block ------------------------------
    CSS_X, CSS_W = CA_X + CA_W + 40.0, 410.0
    CSS_Y, CSS_H = 262, 424
    add(rect(CSS_X, CSS_Y, CSS_W, CSS_H, WHITE, NAVY, 3.0, 18))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 54, "CSS Anchor", 36, 700, NAVY, "middle"))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 92, "Pearl-PNS-anchored", F_SUB, 500, GRAY,
             "middle"))
    add(rect(CSS_X + 18, CSS_Y + 116, CSS_W - 36, 104, NAVY_TINT, NAVY_SOFT, 1.4, 10))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 154, "CSS(X→Y) = E[Y | do(X=1)]",
             21, 500, NAVY, "middle"))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 190, "− E[Y | do(X=0)]", 21, 500, NAVY, "middle"))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 254, "R→T / T→R", F_BODY + 2, 400, GRAY,
             "middle"))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 294, "bootstrap 95% CI", F_BODY, 400, GRAY,
             "middle"))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 328, "permutation p", F_BODY, 400, GRAY,
             "middle"))
    add(text(CSS_X + CSS_W / 2, CSS_Y + 386, "Pearl-PNS-anchored prior on direction",
             F_MICRO, 400, GRAY, "middle"))
    add(arrow(CSS_X + CSS_W, 482, CSS_X + CSS_W + 26, 482, "solid", SLATE, 2.4, 10))


def draw_phase2_channels() -> None:
    """The PADDLE estimator and the four vetoes that gate it."""
    SUP_X, SUP_W, SUP_H = 2020.0, 208.0, 56
    add(text(SUP_X + SUP_W / 2, 252, "Five supporting evidence channels",
             F_MICRO + 1, 600, GRAY, "middle"))
    SUP_NAMES = ["MSBD", "CTPR", "CIC", "Granger", "Transfer Entropy"]
    sup_ys = []
    for i, nm in enumerate(SUP_NAMES):
        y = 272 + i * (SUP_H + 16)
        sup_ys.append(y)
        add(rect(SUP_X, y, SUP_W, SUP_H, WHITE, NAVY_SOFT, 1.8, 8))
        add(text(SUP_X + SUP_W / 2, y + 36, nm, F_BODY + 1, 600, NAVY, "middle"))

    # --- the vetoes that gate the estimator -----------------------------------
    HUB = SUP_X + SUP_W + 28.0
    for y in sup_ys:
        add(path(f"M {SUP_X + SUP_W} {y + SUP_H / 2} H {HUB}", NAVY_SOFT, 1.8))
    add(path(f"M {HUB} {sup_ys[0] + SUP_H / 2} V {sup_ys[-1] + SUP_H / 2}",
             NAVY_SOFT, 1.8))
    HC_X = HUB + 28.0
    add(path(f"M {HUB} 482 H {HC_X}", NAVY, 2.2))
    add(f'<polygon points="{HC_X},482 {HC_X - 9},477 {HC_X - 9},487" fill="{NAVY}"/>')

    # --- the estimator --------------------------------------------------------------
    HC_Y, HC_W, HC_H = 374, 210.0, 218
    add(card(HC_X, HC_Y, HC_W, HC_H, "HCAF",
             ["Bayesian evidence", "synthesis", "CSS prior + channel", "likelihood ratios"],
             accent=NAVY, border=NAVY, t_size=34, b_size=F_BODY, sw=2.8, r=14,
             pad=14))
    add(arrow(HC_X + HC_W, 484, P2_R - 330.0, 484, "solid", SLATE, 2.4, 10))


def draw_phase2_gate() -> None:
    """Commit / Abstain Gate and the resulting output state."""
    GT_X = P2_R - 310.0
    GT_Y, GT_W, GT_H = 262, 310.0, 194
    add(card(GT_X, GT_Y, GT_W, GT_H, "Commit / Abstain Gate",
             ["CI excludes zero", "p < 0.05", "temporal precedence"],
             accent=NAVY, border=NAVY, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.4, r=14, pad=14))

    # --- fork into Commit and Abstain ------------------------------------------
    FK_Y, FK_H = 490, 70
    add(path(f"M {GT_X + GT_W / 2} {GT_Y + GT_H} V {FK_Y - 18}", NAVY, 2.2))
    add(path(f"M {GT_X + 74} {FK_Y - 18} H {GT_X + GT_W - 70}", NAVY, 2.2))
    add(arrow_v(GT_X + 74, FK_Y - 18, FK_Y, "solid", NAVY, 2.0, 9))
    add(arrow_v(GT_X + GT_W - 70, FK_Y - 18, FK_Y, "solid", NAVY, 2.0, 9))
    add(rect(GT_X + 4, FK_Y, 138, FK_H, WHITE, NAVY, 2.2, 10))
    add(text(GT_X + 73, FK_Y + 43, "Commit", F_CARD_T, 600, NAVY, "middle"))
    add(rect(GT_X + 150, FK_Y, 156, FK_H, WHITE, NAVY_SOFT, 2.2, 10))
    add(text(GT_X + 228, FK_Y + 30, "Abstain with", F_MICRO, 600, GRAY, "middle"))
    add(text(GT_X + 228, FK_Y + 54, "recorded reason", F_MICRO, 600, GRAY, "middle"))

    # --- output state -------------------------------------------------------------
    CD_X, CD_Y, CD_W, CD_H = GT_X, 598, GT_W, 100
    add(card(CD_X, CD_Y, CD_W, CD_H, "Causal Direction",
             ["R→T / T→R / abstain"],
             accent=NAVY, border=NAVY, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.6, r=12, pad=12))
    add(arrow(GT_X + 74, FK_Y + FK_H, CD_X + 84, CD_Y, "solid", NAVY, 2.2, 9))
    add(arrow(GT_X + GT_W - 70, FK_Y + FK_H, CD_X + 226, CD_Y, "solid", NAVY_SOFT,
              2.0, 9))
    CT_Y = CD_Y + CD_H + 20
    add(card(CD_X, CT_Y, CD_W, 92, "Cause type",
             ["outage / route leak", "/ origin hijack"],
             accent=NAVY, border=NAVY, t_size=F_CARD_T, b_size=F_BODY,
             sw=2.6, r=12, pad=12))
    add(arrow(CD_X + CD_W / 2, CD_Y + CD_H, CD_X + CD_W / 2, CT_Y, "solid", SLATE, 2.4, 10))


def draw_output() -> None:
    """VERDICT & REPORT — the LLM sits downstream of the verdict."""
    add(text(OUTX + OUTW / 2, 178, "VERDICT", F_HEAD, 700, NAVY, "middle",
             spacing=0.5))
    add(text(OUTX + OUTW / 2, 218, "& REPORT", F_HEAD, 700, NAVY, "middle",
             spacing=0.5))
    add(line(OUTX, 236, OUTX + OUTW, 236, GRAY_LINE, 1.4))
    add(text(OUTX + OUTW / 2, 262, "LLM renders", F_MICRO, 400, GRAY,
             "middle", style="italic"))
    add(text(OUTX + OUTW / 2, 288, "evidence; it does", F_MICRO, 400, GRAY,
             "middle", style="italic"))
    add(text(OUTX + OUTW / 2, 314, "not create the verdict", F_MICRO, 400,
             GRAY, "middle", style="italic"))

    OUT_CARDS = [
        ("Structured Evidence Chain", "Direction · cause type ·", 172, True),
        ("Report Agent", "LLM narrative renderer only", 128, False),
        ("HTML incident report", "Human-readable evidence", 128, False),
        ("NOC handoff", "auto-escalate or human review", 128, False),
    ]
    oy = 342
    for i, (t, b, h, first) in enumerate(OUT_CARDS):
        add(card(OUTX, oy, OUTW, h, t, [b],
                 accent=NAVY if first else GRAY,
                 tint=WHITE if first else GRAY_FILL,
                 border=NAVY if first else GRAY_LINE,
                 t_size=F_CARD_T, b_size=F_BODY,
                 t_color=NAVY if first else GRAY,
                 sw=2.6 if first else 1.8, r=12, pad=12))
        if i < len(OUT_CARDS) - 1:
            add(arrow(OUTX + OUTW / 2, oy + h, OUTX + OUTW / 2, oy + h + 22,
                      "solid", SLATE, 2.2, 10))
        oy += h + 22

    # phase 2 -> output
    add(arrow(P2_R + 6, 648, OUTX - 6, 648, "solid", SLATE, 2.6, 11))


def draw_cache_band() -> None:
    """The shared interpretability cache: the audit backbone under both phases."""
    add(rect(BAND_X, BAND_Y, BAND_W, BAND_H, TEAL_TINT, TEAL_SOFT, 2.4, 20))
    add(text(BAND_X + 36, BAND_Y + 54, "Shared Interpretability Cache",
             34, 700, TEAL))
    add(text(BAND_X + 36, BAND_Y + 88, "audit backbone — every verdict is replayable",
             F_BODY, 400, GRAY))

    GROUPS = ["Immutable evidence records", "Content-addressed replay",
              "Degraded-mode provenance"]
    gx, gw, ggap = BAND_X + 36, 340.0, 26.0
    for i, g in enumerate(GROUPS):
        x = gx + i * (gw + ggap)
        add(rect(x, BAND_Y + 112, gw, 64, WHITE, TEAL_SOFT, 1.8, 10))
        add(text(x + gw / 2, BAND_Y + 152, g, F_BODY, 500, TEAL, "middle"))

    # --- workflow-engine badge ------------------------------------------------
    add(rect(BAND_X + BAND_W - 510.0, BAND_Y + 24, 474.0, 52, TEAL, None, 0, 8))
    add(text(BAND_X + BAND_W - 273.0, BAND_Y + 58,
             "Workflow Engine — gate · replay · degrade", F_BODY, 600, WHITE, "middle"))
    add(text(BAND_X + BAND_W - 36, BAND_Y + 100,
             "No ground-truth label enters the runtime cache", F_BODY, 600, TEAL,
             "end", style="italic"))

    # --- bidirectional dashed links to both phases -----------------------------
    for px in (P1X + 320.0, P2X + 320.0):
        add(arrow_v(px, PANEL_B + 8, BAND_Y - 8, "dashed", TEAL, 2.2, 10))
        add(arrow_v(px, BAND_Y - 22, PANEL_B + 8, "dashed", TEAL, 2.2, 10))
        add(text(px, BAND_Y - 32, "write evidence", F_MICRO, 500, TEAL, "middle"))
        add(text(px, PANEL_B + 40, "replay", F_MICRO, 500, TEAL, "middle"))

    add(callout(BAND_X + 1150.0, BAND_Y + 144, "C4", "Deterministic · auditable",
                "degradation-safe design", r=22, size=F_CALL, align="end",
                leader=f"M {BAND_X + 1150.0} {BAND_Y + 122} V {BAND_Y + 140}",
                lead_color=GRAY_LINE))


def draw_eval_strip() -> None:
    """The offline evaluation strip, isolated from the inference path."""
    add(rect(EVAL_X, EVAL_Y, EVAL_W, EVAL_H, WHITE, GRAY_LINE, 1.6, 14, dash="13 10"))
    add(text(EVAL_X + 36, EVAL_Y + 52, "Offline Evaluation — not on the inference path",
             30, 700, GRAY))
    add(text(EVAL_X + EVAL_W - 36, EVAL_Y + 52,
             "Evaluation-only data is isolated from runtime execution",
             F_MICRO, 400, GRAY, "end", style="italic"))

    ITEMS = [
        ("Ground-truth event set", 400.0),
        ("HCAF vs Pearson lag · Granger · timestamp distance · Transfer Entropy", 1080.0),
        ("Ablation · robustness · significance", 640.0),
    ]
    x = EVAL_X + 36
    for i, (t, w) in enumerate(ITEMS):
        add(rect(x, EVAL_Y + 102, w, 64, GRAY_FILL, GRAY_LINE, 1.6, 8))
        add(text(x + w / 2, EVAL_Y + 142, t, F_BODY + 1, 500, GRAY, "middle"))
        x += w
        if i < len(ITEMS) - 1:
            add(arrow(x + 12, EVAL_Y + 134, x + 52, EVAL_Y + 134, "solid", GRAY, 2.2, 10))
            x += 64
