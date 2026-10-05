"""Paper §6 figure: posterior sensitivity under channel removal.

Two-panel:
  Left:  per-event posterior stacked bar (sorted by P(R→T))
  Right: avg L1 shift bar per channel-removal variant
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl"
SENS = ROOT / "results" / "eval" / "sensitivity_v36.csv"
FIG_DIR = ROOT / "docs" / "paper" / "figs"


def main() -> None:
    recs = [json.loads(l) for l in JSONL.open()]
    recs = [r for r in recs if r["ground_truth_cause_label"] != "origin_hijack_attacker"]
    # Defensive: skip any remaining rows whose expected_direction is undefined.
    recs = [r for r in recs if r.get("expected_direction") in ("routing_to_traffic", "traffic_to_routing")]
    # Sort by P(R→T) for the stacked bar
    recs.sort(key=lambda r: -r.get("posterior", {}).get("routing_to_traffic", 0))

    r2t = [r.get("posterior", {}).get("routing_to_traffic", 0) for r in recs]
    t2r = [r.get("posterior", {}).get("traffic_to_routing", 0) for r in recs]
    indep = [r.get("posterior", {}).get("independent", 0) for r in recs]
    expected = [r["expected_direction"] for r in recs]
    labels = [r["event_id"].replace("hijack_","").replace("outage_","").replace("leak_","").replace("_2024","").replace("_2025","").replace("_2021","")[:14] for r in recs]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.4), dpi=200,
                                    gridspec_kw={"width_ratios": [3, 1.4]})

    # Left: stacked bar
    y = np.arange(len(recs))
    ax1.barh(y, r2t, color="#3182bd", label="$P(R\\to T)$", edgecolor="black", linewidth=0.4)
    ax1.barh(y, t2r, left=r2t, color="#e6550d", label="$P(T\\to R)$", edgecolor="black", linewidth=0.4)
    ax1.barh(y, indep, left=[a+b for a,b in zip(r2t,t2r)], color="#f0f0f0", label="$P(\\text{indep})$", edgecolor="black", linewidth=0.4)

    # Mark correct side
    for i, e in enumerate(expected):
        col = "#2ca02c" if e == "routing_to_traffic" else "#d62728"
        ax1.plot(-0.04, i, "o", color=col, markersize=8, clip_on=False)
    ax1.text(-0.045, len(recs) - 0.5, "● GT=R→T", ha="right", va="bottom", fontsize=8, color="#2ca02c", transform=ax1.get_yaxis_transform())
    ax1.text(-0.045, -0.5, "● GT=T→R", ha="right", va="top", fontsize=8, color="#d62728", transform=ax1.get_yaxis_transform())

    ax1.set_yticks(y)
    ax1.set_yticklabels(labels, fontsize=8)
    ax1.set_xlim(-0.08, 1.0)
    ax1.set_xlabel("Posterior mass")
    ax1.set_title("§6.3 — Per-event calibrated posterior over {R→T, T→R, indep}\nSorted by P(R→T); left dot = ground truth direction")
    ax1.legend(loc="lower right", fontsize=8)
    ax1.grid(axis="x", alpha=0.25)

    # Right: L1 shift bar
    sens_rows = list(csv.DictReader(SENS.open()))
    names = [r["variant"] for r in sens_rows]
    shifts = [float(r["avg_L1_shift"]) for r in sens_rows]
    colors = ["#d62728" if "CSS prior" in n else "#3182bd" for n in names]
    ax2.barh(names, shifts, color=colors, edgecolor="black", linewidth=0.6)
    for i, s in enumerate(shifts):
        ax2.text(s + 0.005, i, f"{s:.3f}", va="center", fontsize=8)
    ax2.set_xlabel("Avg L1 shift vs original posterior")
    ax2.set_title("§6.4 — Posterior sensitivity\n(leave-one-channel-out)")
    ax2.grid(axis="x", alpha=0.25)

    fig.tight_layout()
    out = FIG_DIR / "fig12_posterior_sensitivity.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
