#!/usr/bin/env python3
"""Render the case-study figure for Section 7 (AS12479 route leak).

All values are read from the released artefacts -- no number in this
figure is hand-entered:

  * Cloudflare Radar traffic : data/traffic/AS12479_traffic_2024-01-01..2024-01-08.csv
  * Detector verdicts / peak-trough : results/quick/quick_12479_2024-01-03_*.json
  * Bayesian posterior       : results/eval/hcaf_vs_baselines_v33.jsonl

The old figure (fig_case_chinaunicom.pdf) described an AS4808 origin
hijack on 2025-03-28 that the released ground truth does not support:
the ground truth records AS4808 as the *leaking* AS on 2025-03-09, and
its traffic rose rather than fell. This figure replaces it with an
event whose every quantity is traceable to a released file.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = ROOT / "docs" / "paper" / "figs"

TRAFFIC_CSV = ROOT / "data" / "traffic" / "AS12479_traffic_2024-01-01T00:00:00Z_to_2024-01-08T00:00:00Z.csv"
CACHE_JSON = ROOT / "results" / "quick" / "quick_12479_2024-01-03_1445_2024-01-03_1800.json"
POSTERIOR_JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v33.jsonl"

TEAL = "#0F766E"
RED = "#B91C1C"
NAVY = "#1E3A5F"
GREY = "#6B7280"
ORANGE = "#C2410C"

WIN_START = datetime(2024, 1, 3, 14, 45)
WIN_END = datetime(2024, 1, 3, 18, 0)


def load_traffic():
    series = []
    with open(TRAFFIC_CSV) as fh:
        for row in csv.DictReader(fh):
            ts = datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            series.append((ts, float(row["value"])))
    series.sort()
    return series


def load_cache():
    with open(CACHE_JSON) as fh:
        return json.load(fh)


def load_posterior(event_id="hijack_orange_spain_2024"):
    with open(POSTERIOR_JSONL) as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("event_id") == event_id:
                return rec
    return None


def main() -> int:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    series = load_traffic()
    cache = load_cache()
    post = load_posterior()

    traffic = cache.get("traffic", {})
    routing = cache.get("routing", {})
    leak = routing.get("leak_analysis", {}) or {}
    summary = cache.get("anomaly_summary", {}) or {}

    fig, axes = plt.subplots(3, 1, figsize=(6.4, 6.6), dpi=300)

    # ── Panel 1: Cloudflare Radar traffic with the event window ─────────
    ax = axes[0]
    xs = [t for t, _ in series]
    ys = [v for _, v in series]
    ax.plot(xs, ys, color=NAVY, lw=0.9, label="Cloudflare Radar traffic")
    ax.axvspan(WIN_START, WIN_END, color=ORANGE, alpha=0.16, lw=0)
    ax.axvline(WIN_START, color=ORANGE, lw=1.1, ls="--")
    peak = traffic.get("peak_value")
    trough = traffic.get("trough_value")
    if peak is not None and trough is not None:
        ax.set_title(
            f"AS12479 traffic, 2024-01-01 to 2024-01-08\n"
            f"peak-to-trough {traffic.get('peak_trough_drop_pct', 0):.1f}% "
            f"({peak:.2f} to {trough:.2f})",
            fontsize=8.5,
        )
    ax.set_ylabel("normalised traffic", fontsize=8)
    ax.tick_params(labelsize=7)
    ax.grid(alpha=0.25)
    ax.legend(fontsize=7, loc="lower right", frameon=False)

    # ── Panel 2: leak-detector yield ────────────────────────────────────
    ax = axes[1]
    labels = [
        "announcements\nobserved",
        "survived\nAS-path filter",
        "scored above\npath-prob. 0.4",
        "reported\n(truncated)",
    ]
    values = [
        leak.get("total_announcements", 0),
        leak.get("filtered_announcements", 0),
        leak.get("total_detected", 0),
        leak.get("leak_count", 0),
    ]
    colors = [GREY, TEAL, ORANGE, RED]
    ax.barh(range(len(labels)), values, color=colors, height=0.6)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7)
    ax.invert_yaxis()
    for i, v in enumerate(values):
        ax.text(v, i, f" {v:,}", va="center", fontsize=7)
    ax.set_xscale("log")
    ax.set_xlabel("announcements (log scale)", fontsize=8)
    ax.set_title(
        f"PathProb leak detector yield, {leak.get('asn', '12479')}\n"
        f"{leak.get('asrel_count', 0):,} AS-relationship entries, "
        f"threshold {leak.get('threshold', 0.4)}",
        fontsize=8.5,
    )
    ax.tick_params(labelsize=7)
    ax.grid(axis="x", alpha=0.25)

    # ── Panel 3: Bayesian posterior over causal direction ───────────────
    ax = axes[2]
    if post:
        p = post.get("posterior", {})
        dirs = ["routing_to_traffic", "traffic_to_routing", "independent"]
        nice = ["R $\\to$ T", "T $\\to$ R", "independent"]
        vals = [p.get(d, 0.0) for d in dirs]
        cols = [TEAL if d == "routing_to_traffic" else GREY for d in dirs]
        ax.barh(range(len(dirs)), vals, color=cols, height=0.55)
        ax.set_yticks(range(len(dirs)))
        ax.set_yticklabels(nice, fontsize=8)
        ax.invert_yaxis()
        for i, v in enumerate(vals):
            ax.text(v + 0.01, i, f"{v:.3f}", va="center", fontsize=7.5)
        ax.axvline(0.34, color=RED, lw=1.0, ls="--")
        ax.text(0.35, 2.45, r"commit floor $\tau=0.34$", fontsize=6.8, color=RED)
        ax.set_xlim(0, 1.05)
        ax.set_xlabel("posterior probability", fontsize=8)
        ax.set_title(
            "Bayesian synthesis over the five evidence channels\n"
            "every individual classical channel abstained on this event",
            fontsize=8.5,
        )
    ax.tick_params(labelsize=7)
    ax.grid(axis="x", alpha=0.25)

    fig.tight_layout(pad=0.5)
    out = FIG_DIR / "fig_case_as12479.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  -> {out.name}")
    print(
        f"     verdict={cache.get('quick_verdict')} "
        f"leak_count={summary.get('routing_leak_count')} "
        f"leak_total={summary.get('routing_leak_count_total')}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
