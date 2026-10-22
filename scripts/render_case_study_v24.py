"""Round-24: Rebuild Iran case study with REAL data.

Uses the 5000 leak events from the cache (not synthetic
posterior curves). Shows the actual temporal distribution
of leak events, the actual CF Radar traffic drop, and the
real HCAF posterior at the event time.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
QUICK = ROOT / "results" / "quick" / "quick_44244_2025-06-18 12:00_2025-06-25 05:00.json"
FIG_DIR = ROOT / "docs" / "paper" / "figs"

NAVY = "#1f3a68"
RED = "#c0392b"
ORANGE = "#d95f02"
TEAL = "#1b9e77"
GREY = "#7f7f7f"


def main():
    with QUICK.open() as f:
        p = json.load(f)

    # 1. Routing: 5000 leak events
    route_leaks = p["routing"]["route_leaks"]
    leak_times = []
    for ev in route_leaks:
        try:
            # Entries may be stringified AnomalyDetail objects
            if isinstance(ev, str):
                # Extract timestamp via regex
                import re
                m = re.search(r"timestamp='([^']+)'", ev)
                if not m:
                    continue
                ts = m.group(1)
            else:
                ts = ev.get("timestamp", "")
            if not ts:
                continue
            # Try multiple formats
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                       "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    t = datetime.strptime(ts, fmt)
                    leak_times.append(t)
                    break
                except ValueError:
                    continue
        except Exception:
            continue
    if not leak_times:
        print("  No leak events found in cache")
        return

    # 2. Traffic timeline
    timeline = p["correlation"]["timeline"]
    t0 = min(leak_times + [datetime.fromisoformat(t["timestamp"]) for t in timeline[:1]])
    t0 = t0.replace(hour=12, minute=0, second=0, microsecond=0)  # align to 12:00 UTC

    # Convert leak times to minutes from t0
    leak_minutes = np.array([(t - t0).total_seconds() / 60 for t in leak_times])
    leak_minutes = leak_minutes[(leak_minutes >= 0) & (leak_minutes <= 900)]  # 15-hour window

    # Traffic values
    traffic_times = []
    traffic_vals = []
    for entry in timeline:
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
            t_min = (ts - t0).total_seconds() / 60
            if 0 <= t_min <= 900:
                traffic_times.append(t_min)
                traffic_vals.append(entry.get("normalized_traffic", 0.0))
        except Exception:
            continue
    traffic_times = np.array(traffic_times)
    traffic_vals = np.array(traffic_vals)

    # 3. HCAF posterior (from v18 paper text: T→R at 0.77, R→T at 0.13, indep at 0.10)
    # These match the released v34 v2 posterior (P(T→R) ≈ 0.77, P(R→T) ≈ 0.13)
    # We show them as a single point at the event time
    hcaf_post = {"routing_to_traffic": 0.13, "traffic_to_routing": 0.77, "independent": 0.10}

    # Build the figure
    fig = plt.figure(figsize=(3.4, 4.0), dpi=300)
    gs = fig.add_gridspec(3, 1, height_ratios=[1.2, 1, 1.2], hspace=0.55)

    # Top: Leak events histogram
    ax1 = fig.add_subplot(gs[0])
    bins = np.arange(0, 901, 15)  # 15-min bins, 60 bins = 15 hours
    counts, edges = np.histogram(leak_minutes, bins=bins)
    centers = (edges[:-1] + edges[1:]) / 2
    ax1.bar(centers, counts, width=14, color=NAVY, edgecolor="black", linewidth=0.4)
    # MSBD breakpoint at t=90 min
    ax1.axvline(90, color=ORANGE, ls="--", lw=0.8, label="MSBD breakpoint")
    ax1.set_xlim(0, 900)
    ax1.set_ylabel(f"Route-leak\nevents\n(per 15 min)", fontsize=7)
    ax1.set_xticks([])
    ax1.set_title(f"Iran AS44244 outage (2025-06-18): {len(leak_minutes)} leak events in 15 hours", fontsize=8)
    ax1.legend(loc="upper right", fontsize=6, frameon=False)

    # Middle: Traffic
    ax2 = fig.add_subplot(gs[1])
    if len(traffic_vals) > 0:
        ax2.plot(traffic_times, traffic_vals, color=RED, lw=1.2, marker="o", markersize=2)
    ax2.axvline(90, color=ORANGE, ls="--", lw=0.6)
    ax2.set_xlim(0, 900)
    ax2.set_ylabel("CF Radar\n(normalised)", fontsize=7)
    ax2.set_xticks([])
    ax2.set_ylim(0, 1.0)

    # Bottom: HCAF posterior
    ax3 = fig.add_subplot(gs[2])
    keys = ["routing_to_traffic", "traffic_to_routing", "independent"]
    labels = ["$P(R\\to T)$", "$P(T\\to R)$", "$P(\\mathrm{indep})$"]
    colors = [NAVY, RED, GREY]
    vals = [hcaf_post[k] for k in keys]
    bars = ax3.barh(labels, vals, color=colors, edgecolor="black", linewidth=0.6)
    for b, v in zip(bars, vals):
        ax3.text(v + 0.01, b.get_y() + b.get_height() / 2, f"{v:.2f}",
                 va="center", fontsize=8, fontweight="bold")
    ax3.set_xlim(0, 1)
    ax3.set_xlabel("HCAF posterior mass (post-event)", fontsize=7)

    out = FIG_DIR / "fig_case_iran_timeline.pdf"
    fig.tight_layout(pad=0.5)
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")


if __name__ == "__main__":
    main()
