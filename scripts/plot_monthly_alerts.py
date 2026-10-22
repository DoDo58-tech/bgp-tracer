#!/usr/bin/env python3
"""Monthly alert volume comparison between GRIP and BGPWatch.

Data source: monthly alert counts collected from 2025-09 to 2026-09.
Output: docs/paper/figs/fig_monthly_alerts.pdf (and .png preview).

Palette follows the paper's DSN-style, color-blind friendly set
(see scripts/render_paper_figs_v24.py).
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MultipleLocator

ROOT = Path(__file__).resolve().parent.parent
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)

# ---- Paper palette -------------------------------------------------------
NAVY = "#1f3a68"      # GRIP
TEAL = "#1b9e77"      # BGPWatch
GREY = "#7f7f7f"
TEXT = "#2b2b2b"
GRID = "#d8dde5"

MONTHS = ["2025-09", "2025-10", "2025-11", "2025-12",
          "2026-01", "2026-02", "2026-03", "2026-04",
          "2026-05", "2026-06", "2026-07", "2026-08", "2026-09"]
GRIP = [272, 638, 766, 623, 614, 600, 447, 492, 2708, 1289, 2094, 1809, 552]
BGPWATCH = [481, 1296, 520, 264, 219, 345, 271, 116, 91, 62, 99, 162, 240]


def main() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Linux Libertine O", "DejaVu Serif"],
        "font.size": 9,
        "axes.labelsize": 9.5,
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
    })

    x = np.arange(len(MONTHS))
    w = 0.38

    fig, ax = plt.subplots(figsize=(7.1, 3.0))

    b1 = ax.bar(x - w / 2, GRIP, w, label="GRIP",
                color=NAVY, edgecolor="white", linewidth=0.6, zorder=3)
    b2 = ax.bar(x + w / 2, BGPWATCH, w, label="BGPWatch",
                color=TEAL, edgecolor="white", linewidth=0.6, zorder=3)

    ax.set_xticks(x)
    ax.set_xticklabels(MONTHS, rotation=45, ha="right")
    ax.set_ylabel("Number of alerts")
    ax.set_xlabel("Month")
    ax.set_ylim(0, 3200)
    ax.yaxis.set_major_locator(MultipleLocator(400))

    ax.grid(axis="y", color=GRID, linewidth=0.6, alpha=0.9, zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#9aa3ae")
        ax.spines[s].set_linewidth(0.8)

    ax.tick_params(colors=TEXT, length=3)
    leg = ax.legend(loc="upper left", frameon=False, ncol=2,
                    handlelength=1.2, columnspacing=1.2)
    for t in leg.get_texts():
        t.set_color(TEXT)

    fig.tight_layout(pad=0.4)
    out_pdf = FIG_DIR / "fig_monthly_alerts.pdf"
    out_png = FIG_DIR / "fig_monthly_alerts.png"
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_png, dpi=200, bbox_inches="tight")
    print("wrote", out_pdf)
    print("wrote", out_png)

    tot_g, tot_b = sum(GRIP), sum(BGPWATCH)
    print(f"total GRIP={tot_g}  BGPWatch={tot_b}  ratio={tot_g / tot_b:.2f}")


if __name__ == "__main__":
    main()
