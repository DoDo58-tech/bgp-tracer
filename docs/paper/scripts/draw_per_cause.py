#!/usr/bin/env python3
"""
BGP Tracer — per-cause attribution accuracy bar chart (real v17 numbers).
Output: figs/fig_per_cause.pdf
"""
import matplotlib.pyplot as plt
import numpy as np
import os

classes = ["outage", "route leak", "origin hijack"]
n_events = [14, 8, 7]
top1 = [13/14, 7/8, 6/7]
f1   = [0.93, 0.88, 0.86]

x = np.arange(len(classes))
w = 0.35

fig, ax = plt.subplots(figsize=(7.5, 3.4), dpi=200)
b1 = ax.bar(x - w/2, [v*100 for v in top1], w, label="Top-1 accuracy (%)",
            color="#1A73E8", edgecolor="white")
b2 = ax.bar(x + w/2, [v*100 for v in f1],   w, label="F1 (%)",
            color="#F57C00", edgecolor="white")

for b, v, n in zip(b1, top1, n_events):
    ax.text(b.get_x() + b.get_width()/2, v*100 + 1, f"{v*100:.1f}%\n(n={n})",
            ha='center', fontsize=8.5, color="#1A73E8")
for b, v in zip(b2, f1):
    ax.text(b.get_x() + b.get_width()/2, v*100 + 1, f"{v*100:.1f}",
            ha='center', fontsize=8.5, color="#F57C00")

ax.set_ylim(0, 115)
ax.set_xticks(x)
ax.set_xticklabels(classes, fontsize=9.5)
ax.set_ylabel("Score (%)", fontsize=10)
ax.set_title("Per-cause attribution accuracy on the v17 30-event ground-truth\n"
             "(deterministic cache path, all 3 detectors real on the 21-event subset)",
             fontsize=10.5, weight='bold')
ax.legend(loc='lower right', fontsize=9, framealpha=0.95)
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)

plt.tight_layout()
out = '/data/bgp_tracer/docs/paper/figs/fig_per_cause.pdf'
plt.savefig(out, bbox_inches='tight', facecolor='white')
print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
