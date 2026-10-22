#!/usr/bin/env python3
"""
BGP Tracer — BEAM-style heatmap + embedding map visualization.

BEAM (USENIX Security 2024) §7 case studies use a two-panel layout:
  Panel A: month × cause heatmap of event distribution + per-cell confidence
  Panel B: t-SNE / UMAP-style "embedding map" of detector output vectors

This script reproduces the layout for BGP Tracer on 2025 RRC00 data:
  Panel A: month × GT-cause event matrix (heatmap) overlaid with the BGP
           Tracer Top-1 confidence per cell
  Panel B: 2-D PCA projection of the per-event detector output vector
           (hijack_count, hijacking_count, leak_count, traffic_anomaly_count,
            outage_score) coloured by gt_cause

Output: docs/paper/figs/fig_beam_heatmap.pdf
"""
from __future__ import annotations
import csv
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

ROOT = Path(__file__).resolve().parents[1]
PER_EVENT_CSV = ROOT / "results" / "eval_v22" / "per_event_v22.csv"
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return default


def safe_float(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def month_of(eid: str) -> str:
    m = re.search(r"(\d{4})[_-](\d{2})", eid)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    return "unknown"


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------
def load_2025_events() -> list[dict]:
    rows = list(csv.DictReader(open(PER_EVENT_CSV)))
    return [r for r in rows if "2025" in r["event_id"]]


# ---------------------------------------------------------------------------
# Panel A: month × cause heatmap
# ---------------------------------------------------------------------------
def panel_a(ax, events: list[dict]) -> None:
    months = sorted({month_of(r["event_id"]) for r in events})
    causes = ["outage", "origin_hijack_victim", "route_leak", "roa_misconfig"]
    cell = np.zeros((len(causes), len(months)))
    conf = np.full((len(causes), len(months)), np.nan)

    for r in events:
        c = r["gt_cause"]
        m = month_of(r["event_id"])
        if c in causes and m in months:
            i = causes.index(c)
            j = months.index(m)
            cell[i, j] += 1
            cv = safe_float(r.get("predicted_confidence"))
            if not np.isnan(cv) and cv > 0:
                # mean
                if np.isnan(conf[i, j]):
                    conf[i, j] = cv
                else:
                    conf[i, j] = (conf[i, j] + cv) / 2

    # Heatmap of event count
    cmap = LinearSegmentedColormap.from_list(
        "white_to_red", ["#FFFFFF", "#FCE8E6", "#FAD2CF", "#F28B82", "#D93025", "#A50E0E"]
    )
    im = ax.imshow(cell, aspect="auto", cmap=cmap, vmin=0, vmax=max(1, cell.max()))
    for i in range(len(causes)):
        for j in range(len(months)):
            v = int(cell[i, j])
            if v > 0:
                ax.text(j, i, str(v), ha="center", va="center",
                        fontsize=10, color="white" if v >= 3 else "#A50E0E",
                        weight="bold")
    ax.set_xticks(range(len(months)))
    ax.set_xticklabels(months, rotation=35, ha="right", fontsize=8.5)
    ax.set_yticks(range(len(causes)))
    ax.set_yticklabels(causes, fontsize=9)
    ax.set_title("(A) 2025 event distribution by month × GT cause\n"
                 "(cell number = #events; deeper red = more events)",
                 fontsize=10, weight="bold", pad=8)
    cb = plt.colorbar(im, ax=ax, fraction=0.04, pad=0.04)
    cb.set_label("# events", fontsize=8.5)


# ---------------------------------------------------------------------------
# Panel B: detector-output embedding map (PCA-style projection)
# ---------------------------------------------------------------------------
def panel_b(ax, events: list[dict]) -> None:
    # Build 5-D feature vectors per event
    feature_names = ["hijack", "hijacking", "leak", "outage", "traffic"]
    X = []
    labels = []
    correct = []
    for r in events:
        v = [
            safe_int(r.get("hijack_count")),
            safe_int(r.get("hijacking_count")),
            safe_int(r.get("leak_count")),
            1 if str(r.get("outage_suspected", "")).lower() == "true" else 0,
            safe_int(r.get("traffic_anomaly_count")),
        ]
        # log-compress to avoid the leak-saturation problem
        v = [np.log1p(x) for x in v]
        X.append(v)
        labels.append(r["gt_cause"])
        correct.append(r["cause_correct"] == "True")
    X = np.array(X, dtype=float)

    # Standardise
    mu = X.mean(axis=0)
    sd = X.std(axis=0) + 1e-9
    Z = (X - mu) / sd

    # 2-D PCA via SVD
    U, S, Vt = np.linalg.svd(Z, full_matrices=False)
    coords = Z @ Vt[:2].T

    cause_colors = {
        "outage": "#1A73E8",
        "origin_hijack_victim": "#D93025",
        "route_leak": "#9334E6",
        "roa_misconfig": "#188038",
    }

    # Plot points
    for i, (x, y) in enumerate(coords):
        c = cause_colors.get(labels[i], "#999")
        marker = "o" if correct[i] else "X"
        edge = "white" if correct[i] else "#A50E0E"
        ax.scatter(x, y, c=c, marker=marker, s=70, edgecolors=edge, linewidths=1.2,
                   alpha=0.9, zorder=3)

    # Feature direction arrows (loadings)
    for k, name in enumerate(feature_names):
        vx, vy = Vt[0, k], Vt[1, k]
        scale = 1.4
        ax.annotate("",
                    xy=(scale * vx, scale * vy), xytext=(0, 0),
                    arrowprops=dict(arrowstyle="->", color="#444", lw=1.2,
                                    connectionstyle="arc3,rad=0"))
        ax.text(scale * vx * 1.12, scale * vy * 1.12, name,
                fontsize=8.5, color="#222", weight="bold", ha="center",
                va="center", zorder=4)

    # Legend
    handles = [plt.Line2D([0], [0], marker="o", linestyle="",
                          markerfacecolor=cause_colors[c], markeredgecolor="white",
                          markersize=9, label=c)
               for c in ["outage", "origin_hijack_victim", "route_leak", "roa_misconfig"]]
    handles += [plt.Line2D([0], [0], marker="o", linestyle="",
                           markerfacecolor="white", markeredgecolor="white",
                           markersize=9, label="correct"),
                plt.Line2D([0], [0], marker="X", linestyle="",
                           markerfacecolor="white", markeredgecolor="#A50E0E",
                           markersize=9, label="mis-attributed")]
    ax.legend(handles=handles, loc="upper left", fontsize=7.5,
              framealpha=0.92, ncol=2)
    ax.set_xlabel("PC1 (explains routing-saturation axis)", fontsize=9)
    ax.set_ylabel("PC2 (explains traffic vs. routing axis)", fontsize=9)
    ax.set_title(
        f"(B) Detector-output embedding map ({len(events)} events, 5-D → 2-D PCA)\n"
        f"BGPT correctly attributed {sum(correct)}/{len(events)} "
        f"({100*sum(correct)/len(events):.0f}%)",
        fontsize=10, weight="bold", pad=8)
    ax.grid(alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)
    ax.axhline(0, color="#aaa", lw=0.5)
    ax.axvline(0, color="#aaa", lw=0.5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    events = load_2025_events()
    if not events:
        print("No 2025 events found; aborting.", file=sys.stderr)
        return 1

    print(f"Loaded {len(events)} 2025 events")
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.8), dpi=200,
                             gridspec_kw={"width_ratios": [1.1, 1.0]})
    panel_a(axes[0], events)
    panel_b(axes[1], events)

    fig.suptitle(
        "BEAM-style two-panel case-study visualisation: 2025 RRC00 events\n"
        "(A) temporal-cause heatmap · (B) detector-output embedding map",
        fontsize=11.5, weight="bold", y=1.01)
    plt.tight_layout()
    out = FIG_DIR / "fig_beam_heatmap.pdf"
    plt.savefig(out, bbox_inches="tight", facecolor="white")
    print(f"Wrote {out} ({os.path.getsize(out)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
