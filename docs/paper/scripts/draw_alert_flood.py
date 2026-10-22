#!/usr/bin/env python3
"""
BGP Tracer — Background figure: alert-flood across platforms.

DEPRECATED (2026-10-19): This script generates synthetic numbers from public
reports (ARTEMIS 2018, HEAP). It is kept for backward-compatibility only and
is NOT cited by the paper: the paper takes the alert-flood pathology from the
published alert-management literature (see section2_background.tex) and does
not convert it into a measured reduction ratio for BGP Tracer.

The paper's own alert-load evidence is the live replay in
section6_evaluation.tex: 192 enqueued alerts, 130 adjudicated, 14 real
incidents. There is deliberately no pooled per-day alert-volume figure.
"""
import matplotlib.pyplot as plt
import numpy as np
import os

# Representative figures synthesised from public reports:
#   - ARTEMIS-style control-plane monitor: ~ 1k–3k alarms/day  [Sermpezis 2018]
#   - HEAP-style hybrid monitor:          ~ 500–1.2k alarms/day
#   - Pure traffic-anomaly monitor:       ~ 5k–15k alarms/day
# We aggregate per month (30 days) for the past 12 months.

months = ["2025-06", "2025-07", "2025-08", "2025-09", "2025-10",
          "2025-11", "2025-12", "2026-01", "2026-02", "2026-03",
          "2026-04", "2026-05"]

control_plane = [48_300, 51_200, 53_800, 56_100, 58_900,
                 61_400, 64_200, 67_500, 70_800, 73_100,
                 75_600, 78_400]   # ARTEMIS-class / month

hybrid         = [22_500, 24_100, 25_300, 26_400, 27_200,
                  28_600, 29_400, 30_500, 31_200, 32_100,
                  32_900, 33_800]  # HEAP-class / month

traffic_only   = [142_000, 151_200, 158_700, 165_400, 173_600,
                  182_300, 190_800, 199_100, 208_400, 217_600,
                  226_900, 236_500]  # unsupervised traffic monitor / month

# Actionable fraction (<= 1 %)
actionable = [0.7, 0.8, 0.6, 0.7, 0.5, 0.6, 0.4, 0.5, 0.3, 0.4, 0.3, 0.3]

fig, ax = plt.subplots(figsize=(9, 4.2), dpi=200)

x = np.arange(len(months))
w = 0.27

b1 = ax.bar(x - w, control_plane, w, label="Control-plane monitor (ARTEMIS-class)",
            color="#1A73E8", edgecolor="white", linewidth=0.5)
b2 = ax.bar(x,     hybrid,       w, label="Hybrid monitor (HEAP-class)",
            color="#F57C00", edgecolor="white", linewidth=0.5)
b3 = ax.bar(x + w, traffic_only, w, label="Traffic-anomaly monitor (unsupervised)",
            color="#D93025", edgecolor="white", linewidth=0.5)

# Actionable line on secondary axis
ax2 = ax.twinx()
ax2.plot(x, actionable, "o-", color="#188038", lw=1.8, ms=5,
         label="Actionable rate (right axis)", zorder=5)
ax2.set_ylabel("Actionable rate (%)", color="#188038", fontsize=10)
ax2.set_ylim(0, 5)
ax2.tick_params(axis='y', colors="#188038")
ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.1f}%"))

# Annotate: max bar
max_idx = int(np.argmax(traffic_only))
ax.annotate(f"{traffic_only[max_idx]:,}/mo",
            xy=(max_idx + w, traffic_only[max_idx]),
            xytext=(max_idx + w, traffic_only[max_idx] + 12_000),
            ha='center', fontsize=9, color="#D93025", weight='bold')

ax.annotate("Actionable: < 1 %\nBGP Tracer target: 15 %",
            xy=(len(months)-2, 50_000), fontsize=10, color="#188038",
            bbox=dict(boxstyle="round,pad=0.3", fc="#E6F4EA", ec="#188038", lw=0.8))

ax.set_xticks(x)
ax.set_xticklabels(months, rotation=35, ha='right', fontsize=8.5)
ax.set_ylabel("Monthly alarms (count)", fontsize=10)
ax.set_yscale("log")
ax.set_ylim(1_000, 1_000_000)
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)
ax.set_title("Alert-flood pathology: monthly alarm volume vs.\ actionable rate\n"
             "across three classes of monitoring platforms (Jun 2025 – May 2026)",
             fontsize=11, weight='bold', pad=12)

# Combined legend
h1, l1 = ax.get_legend_handles_labels()
h2, l2 = ax2.get_legend_handles_labels()
ax.legend(h1 + h2, l1 + l2, loc='upper left', fontsize=8.5, framealpha=0.95)

plt.tight_layout()
out = '/data/bgp_tracer/docs/paper/figs/fig_alert_flood.pdf'
plt.savefig(out, bbox_inches='tight', facecolor='white')
print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
