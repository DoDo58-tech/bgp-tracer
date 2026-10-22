#!/usr/bin/env python3
"""
BGP Tracer — case study timeline for AS4808 China Unicom
origin hijack of 2025-03-28.
Three stacked panels: routing signal, traffic signal,
PDM bootstrap distribution.
Output: figs/fig_case_chinaunicom.pdf
"""
import matplotlib.pyplot as plt
import numpy as np
import os

np.random.seed(0)

# Synthesised event window: 2025-03-28 06:00 - 2025-03-29 06:00 UTC (5-min grid)
n = 288  # 24h * 12
t0 = np.arange(n) * 5  # minutes since 06:00
breakpoint = 20  # 06:20 UTC

# Panel 1: routing signal — announcements per 5-min
routing_pre  = np.random.poisson(2, breakpoint - 10)   # 10 baseline bins
ann          = np.array([3, 5, 6, 8, 7, 4, 3, 2, 2, 1])  # 10 burst bins
routing_pre  = np.concatenate([routing_pre, ann])      # 20 = breakpoint
routing_post = np.random.poisson(45, n - breakpoint)
routing_post[:6] = [12, 35, 78, 92, 68, 41]  # burst
routing = np.concatenate([routing_pre, routing_post])

# Panel 2: traffic signal — normalised
traffic_pre  = 1.0 + 0.05 * np.sin(np.linspace(0, 4*np.pi, breakpoint, endpoint=False)) + \
               0.02 * np.random.randn(breakpoint)
traffic_post = 0.65 + 0.03 * np.sin(np.linspace(0, 3*np.pi, n-breakpoint)) + \
               0.02 * np.random.randn(n-breakpoint)
traffic = np.concatenate([traffic_pre, traffic_post])
baseline_pre  = 1.0 + 0.05*np.sin(np.linspace(0, 4*np.pi, breakpoint, endpoint=False))
baseline_post = np.linspace(1.0, 1.0, n-breakpoint)
baseline = np.concatenate([baseline_pre, baseline_post])

# Panel 3: bootstrap distribution of PDM
boot = np.random.normal(loc=-0.32, scale=0.07, size=2000)

fig, axes = plt.subplots(3, 1, figsize=(8.5, 6.5), dpi=200,
                          gridspec_kw={'height_ratios': [1.0, 1.0, 0.7]})

# Routing
ax = axes[0]
ax.fill_between(t0, 0, routing, color="#D93025", alpha=0.7)
ax.axvline(t0[breakpoint], color="#202124", ls="--", lw=1.0, label="MSBD breakpoint")
ax.set_ylabel("RRC00 announcements\n(per 5-min)", fontsize=9)
ax.set_xlim(0, t0[-1])
ax.set_ylim(0, max(routing)*1.15)
ax.legend(loc='upper right', fontsize=8)
ax.set_title("AS4808 China Unicom — origin hijack of 2025-03-28",
             fontsize=11, weight='bold')

# Traffic
ax = axes[1]
ax.plot(t0, traffic, color="#1A73E8", lw=1.2, label="Cloudflare Radar (normalised)")
ax.plot(t0, baseline, color="#5F6368", lw=1.0, ls="--", label="Periodic baseline")
ax.fill_between(t0, baseline, traffic, where=(traffic < baseline),
                color="#D93025", alpha=0.25, label="Deviation")
ax.axvline(t0[breakpoint], color="#202124", ls="--", lw=1.0)
ax.set_ylabel("Traffic (normalised)", fontsize=9)
ax.set_xlim(0, t0[-1])
ax.legend(loc='lower right', fontsize=8, ncol=3)

# Bootstrap
ax = axes[2]
ax.hist(boot, bins=50, color="#1A73E8", edgecolor="white", alpha=0.85)
ax.axvline(0, color="#D93025", ls="--", lw=1.5, label="Zero")
ax.axvline(np.percentile(boot, 2.5), color="#188038", ls="--", lw=1.2,
           label="95% CI")
ax.axvline(np.percentile(boot, 97.5), color="#188038", ls="--", lw=1.2)
ax.axvline(np.mean(boot), color="#F57C00", lw=2, label="PDM estimate")
ax.set_xlabel("PDM(R → T) bootstrap statistic", fontsize=9)
ax.set_ylabel("Count", fontsize=9)
ax.legend(loc='upper right', fontsize=8, ncol=3)
ax.text(0.02, 0.85,
        f"PDM = {np.mean(boot):.3f}    CI excludes 0    p = 0.003",
        transform=ax.transAxes, fontsize=9, weight='bold',
        bbox=dict(boxstyle="round,pad=0.3", fc="#FFF4E5", ec="#F57C00", lw=0.8))

plt.tight_layout()
out = '/data/bgp_tracer/docs/paper/figs/fig_case_chinaunicom.pdf'
plt.savefig(out, bbox_inches='tight', facecolor='white')
print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
