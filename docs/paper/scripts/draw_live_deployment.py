#!/usr/bin/env python3
"""
BGP Tracer — v17 ground-truth evaluation results.
Three side-by-side bar charts:
  (a) Cache-only Top-1 by class
  (b) HTML extraction accuracy (pre-fix, post-fix)
  (c) M1-M4 operational metrics
Output: figs/fig_live_deployment.pdf
"""
import matplotlib.pyplot as plt
import numpy as np
import os

# Real v17 numbers (from v20 audit + FINAL_RESULTS)
months = ["v17\n30 ev.", "honest-21\n(3 det)", "honest-21\n(−NC)"]
top1   = [86.7, 85.7, 90.0]
n      = [30,   21,   20]
miss   = [4,    3,    2]

fig, ax = plt.subplots(figsize=(7.5, 3.5), dpi=200)
x = np.arange(len(months))
w = 0.30
b1 = ax.bar(x - w/2, top1, w, label="Top-1 strict (%)",
            color="#1A73E8", edgecolor="white")
b2 = ax.bar(x + w/2, [100-m for m in miss], w, label="Correct verdicts (%)",
            color="#188038", edgecolor="white")
for b, v, n_ in zip(b1, top1, n):
    ax.text(b.get_x() + b.get_width()/2, v + 1.5,
            f"{v:.1f}%\n({round(v*n_/100)}/{n_})",
            ha='center', fontsize=8.5, color="#1A73E8", weight='bold')
for b, v, m, n_ in zip(b2, [100-m for m in miss], miss, n):
    ax.text(b.get_x() + b.get_width()/2, (100-m) + 1.5,
            f"{100-m:.1f}%\n({n_-m}/{n_})",
            ha='center', fontsize=8.5, color="#188038")

ax.set_xticks(x)
ax.set_xticklabels(months, fontsize=9)
ax.set_ylim(0, 115)
ax.set_ylabel("Strict accuracy (%)", fontsize=10)
ax.set_title("Phase-1 strict Top-1 across three v17 evaluation regimes\n"
             "(all 30, all 3-detectors-real 21, all 3-detectors-real 20 excluding NC)",
             fontsize=10.5, weight='bold')
ax.legend(loc='lower right', fontsize=9, framealpha=0.95)
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)

plt.tight_layout()
out = '/data/bgp_tracer/docs/paper/figs/fig_live_deployment.pdf'
plt.savefig(out, bbox_inches='tight', facecolor='white')
print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
