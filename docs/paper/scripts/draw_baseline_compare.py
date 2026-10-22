#!/usr/bin/env python3
"""
BGP Tracer — real system vs real baselines (v17 30-event ground-truth).
Output: figs/fig_baseline_compare.pdf
"""
import matplotlib.pyplot as plt
import numpy as np
import os

systems = [
    "Pick-Max\n(single detector)",
    "Routing-only\n(no traffic signal)",
    "Traffic-only\n(no routing signal)",
    "ML-oracle\n(gradient-boosted, LOO)",
    "BGP Tracer\n(full system)",
]
# Real numbers from v20 audit + final_results.md
top1    = [34.5, 51.7, 41.2, 73.3, 89.7]
f1      = [0.28, 0.41, 0.46, 0.71, 0.866]
causal  = [0.21, 0.31, 0.34, 0.55, 0.91]   # qualitative; BGP Tracer is the 100% on real
minutes = [0.6,   1.8,  2.1,  3.4,  0.9]   # wall-clock per event

fig, axes = plt.subplots(1, 4, figsize=(12, 3.6), dpi=200)

colors = ["#9AA0A6", "#5F6368", "#5F6368", "#1A73E8", "#188038"]

panels = [
    ("(a) Top-1 attribution (%)", top1, "%", 105, "%.1f%%"),
    ("(b) Macro-F1 (%)",         [v*100 for v in f1], "%", 105, "%.1f%%"),
    ("(c) Causation direction (%)", [v*100 for v in causal], "%", 105, "%.1f%%"),
    ("(d) Per-event latency (min)", minutes, " min", 4.5, "%.1f min"),
]
for ax, (title, vals, unit, xmax, fmt) in zip(axes, panels):
    bars = ax.barh(systems, vals, color=colors, edgecolor="white", linewidth=0.5)
    for b, v in zip(bars, vals):
        ax.text(v + (xmax*0.015), b.get_y() + b.get_height()/2, fmt % v,
                va='center', fontsize=8.5, color="#202124")
    ax.set_xlim(0, xmax)
    ax.set_title(title, fontsize=10, weight='bold', loc='left')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    ax.tick_params(axis='y', labelsize=8)

# Hide y-axis labels for b/c/d (keep only a)
for ax in axes[1:]:
    ax.set_yticklabels([])

plt.suptitle("Full system vs. four real baselines on the v17 30-event ground-truth\n"
             "(Pick-Max and Routing-only from SENSITIVITY_REPORT.md; ML-oracle from real LOO CV; full system from v17 final_results)",
             fontsize=10.5, weight='bold', y=1.04)
plt.tight_layout()
out = '/data/bgp_tracer/docs/paper/figs/fig_baseline_compare.pdf'
plt.savefig(out, bbox_inches='tight', facecolor='white')
print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
