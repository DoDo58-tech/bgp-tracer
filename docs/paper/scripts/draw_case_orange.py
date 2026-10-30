#!/usr/bin/env python3
"""BGP Tracer -- case-study figure (Orange Spain / AS12479, 2024-01-03).

The figure shows what the case study actually establishes, and nothing
more:

  (a) the routing side of the cached window, bucketed on a five-minute
      grid: 9,158 announcement-level detections in 25 of 39 non-empty
      buckets.  Density here is an artefact
      of a missing expected-origin baseline (``expected_origin: null``
      in every record), not a measurement of hijack intensity;

  (b) what Phase 2 sees of the same window on the estimator's grid: the
      merged timeline holds 50 records on two timestamps, so the
      91-bucket five-minute grid carries a single routing point and a
      single traffic point 89 empty buckets apart.  Neither series has
      an interior, no onset interval can be formed, and V1 refuses with
      onset_unresolved before any directional test runs.

Output: figs/fig_case_orange.pdf
"""
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path("/data/bgp_tracer")
CACHE = ROOT / "results/quick/quick_12479_2024-01-03_1445_2024-01-03_1800.json"
OUT = Path("/data/bgp_tracer/docs/paper/figs/fig_case_orange.pdf")

EVENT_COLOR = "#1f4e79"
MUTED = "#8c8c8c"
FLOOR_COLOR = "#c0392b"
TRAFFIC_COLOR = "#c0392b"

data = json.loads(CACHE.read_text())
events = data["correlation"]["routing_events_full"]

stamps = [datetime.fromisoformat(e["timestamp"]) for e in events]
t0 = min(stamps).replace(second=0, microsecond=0)
bucket_min = 5
counts = Counter(
    int((s - t0).total_seconds() // (bucket_min * 60)) for s in stamps
)
n_buckets = max(counts) + 1
series = [counts.get(i, 0) for i in range(n_buckets)]
labels = [
    (t0.timestamp() + i * bucket_min * 60) for i in range(n_buckets)
]

fig, (ax1, ax2) = plt.subplots(
    1, 2, figsize=(7.0, 2.5), gridspec_kw={"width_ratios": [1.9, 1.0]}
)

ax1.bar(
    range(n_buckets), series, width=0.85, color=EVENT_COLOR, linewidth=0
)
ax1.set_xlabel("five-minute bucket from 14:54 UTC, 2024-01-03",
               fontsize=8)
ax1.set_ylabel("routing detections", fontsize=8)
ax1.set_title(
    f"(a) {len(events):,} announcement-level detections, "
    f"{sum(1 for v in series if v)}/{n_buckets} buckets non-empty",
    fontsize=8.5,
)
ax1.tick_params(labelsize=7)
for side in ("top", "right"):
    ax1.spines[side].set_visible(False)
ax1.annotate(
    "expected_origin = null in every record:\n"
    "these are the victim's own announcements",
    xy=(n_buckets * 0.02, max(series) * 0.92),
    fontsize=6.5, color=MUTED, va="top",
)



# ---- panel (b): what Phase 2 sees on its own grid --------------------------
# The engine reads the merged timeline (50 records), not the full routing
# block: one traffic record at 07:22:30 and 49 routing records at 14:54:29.
timeline = data["correlation"]["timeline"]
tl_stamps = [datetime.fromisoformat(e["timestamp"]) for e in timeline]
is_traffic = [e.get("source") == "traffic" for e in timeline]
g0 = min(tl_stamps).replace(second=0, microsecond=0)
n_grid = int((max(tl_stamps) - g0).total_seconds() // (bucket_min * 60)) + 1
grid_idx = [int((s - g0).total_seconds() // (bucket_min * 60)) for s in tl_stamps]
traffic_idx = [i for i, t in zip(grid_idx, is_traffic) if t]
routing_idx = [i for i, t in zip(grid_idx, is_traffic) if not t]

ax2.scatter(routing_idx, [1] * len(routing_idx), marker="^", s=34,
            color=EVENT_COLOR, linewidth=0, zorder=3)
ax2.scatter(traffic_idx, [0] * len(traffic_idx), marker="v", s=34,
            color=TRAFFIC_COLOR, linewidth=0, zorder=3)
ax2.set_yticks([0, 1])
ax2.set_yticklabels(["traffic", "routing"], fontsize=8)
ax2.set_ylim(-0.75, 1.75)
ax2.set_xlim(-2, n_grid + 1)
ax2.set_xlabel(f"five-minute bucket ({n_grid} total)", fontsize=8)
ax2.set_title(
    f"(b) {len(set(grid_idx))} non-empty of {n_grid}: no onset interval",
    fontsize=8.5,
)
ax2.tick_params(labelsize=7)
for side in ("top", "right"):
    ax2.spines[side].set_visible(False)
ax2.annotate(
    f"{n_grid - len(set(grid_idx))} empty buckets,\nfloored at $\\varepsilon$",
    xy=(n_grid / 2.0, 1.42), ha="center", va="center",
    fontsize=6.5, color=MUTED,
)

fig.tight_layout(pad=0.4)
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, bbox_inches="tight")
print(f"wrote {OUT}")
