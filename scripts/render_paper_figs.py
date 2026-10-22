"""Generate paper figures for §6 (evaluation).

Inputs:
  results/eval/per_event_30.csv  (built by build_per_event_30_csv.py)
  --- 30-event v17 ground-truth with HCAF vs baselines
Outputs:
  docs/paper/figs/fig7_eval_overview.pdf      (review vs strict precision, 6 methods)
  docs/paper/figs/fig8_per_cause.pdf          (HCAF strict precision by cause)
  docs/paper/figs/fig9_event_direction_heatmap.pdf  (30 events × 6 methods)
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
CSV = ROOT / "results" / "eval" / "per_event_30.csv"
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)

METHODS = ["hcaf", "css", "pearson", "granger", "ts_distance", "transfer_entropy"]
LABELS = {
    "hcaf": "HCAF (ours)",
    "css": "CSS-only",
    "pearson": "Pearson",
    "granger": "Granger",
    "ts_distance": "Ts-Distance",
    "transfer_entropy": "Transfer Entropy",
}
COLORS = {
    "hcaf": "#d62728",
    "css": "#ff7f0e",
    "pearson": "#1f77b4",
    "granger": "#2ca02c",
    "ts_distance": "#9467bd",
    "transfer_entropy": "#8c564b",
}


def load_rows() -> list[dict]:
    with CSV.open() as f:
        return list(csv.DictReader(f))


def fig7_eval_overview(rows: list[dict]) -> Path:
    """Side-by-side bars: review-precision (light) + strict-precision (dark) per method."""
    n = len(rows)
    review = [sum(int(r[f"{m}_review"]) for r in rows) / n * 100 for m in METHODS]
    strict = [sum(int(r[f"{m}_strict"]) for r in rows) / n * 100 for m in METHODS]
    abstain = [sum(int(r[f"{m}_abstain"]) for r in rows) / n * 100 for m in METHODS]

    x = np.arange(len(METHODS))
    w = 0.27

    fig, ax = plt.subplots(figsize=(8.4, 4.2), dpi=200)
    ax.bar(x - w, review, w, label="review-precision", color="#9ecae1", edgecolor="black", linewidth=0.6)
    ax.bar(x,     strict, w, label="strict-precision", color="#3182bd", edgecolor="black", linewidth=0.6)
    ax.bar(x + w, abstain, w, label="abstain rate", color="#bdbdbd", edgecolor="black", linewidth=0.6)

    # Annotate HCAF bar
    for i, m in enumerate(METHODS):
        if m == "hcaf":
            for j, val in enumerate([review[i], strict[i], abstain[i]]):
                offset = (-w, 0, w)[j]
                ax.text(x[i] + offset, val + 1.2, f"{val:.1f}%", ha="center", fontsize=8, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[m] for m in METHODS], rotation=18, ha="right")
    ax.set_ylabel("Percentage (%)")
    ax.set_ylim(0, 110)
    ax.set_title("§6.2 — Method comparison on the v14 ground-truth (29 events)\nreview-precision treats abstain as non-error per review §1.3.3")
    ax.legend(loc="upper right", frameon=True, fontsize=8)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig7_eval_overview.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")
    return out


def fig8_per_cause(rows: list[dict]) -> Path:
    """HCAF strict precision by cause label."""
    by_cause: dict[str, dict[str, int]] = defaultdict(lambda: {"strict": 0, "total": 0})
    for r in rows:
        cause = r["cause_label"]
        by_cause[cause]["total"] += 1
        by_cause[cause]["strict"] += int(r["hcaf_strict"])

    causes = sorted(by_cause.keys(), key=lambda c: -by_cause[c]["strict"] / max(by_cause[c]["total"], 1))
    strict_pct = [by_cause[c]["strict"] / by_cause[c]["total"] * 100 for c in causes]
    totals = [by_cause[c]["total"] for c in causes]
    corrects = [by_cause[c]["strict"] for c in causes]

    fig, ax = plt.subplots(figsize=(7.0, 3.8), dpi=200)
    bars = ax.bar(causes, strict_pct, color="#3182bd", edgecolor="black", linewidth=0.6)
    for bar, c, t, correct in zip(bars, causes, totals, corrects):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                f"{correct}/{t}", ha="center", fontsize=9, fontweight="bold")

    ax.set_ylabel("HCAF strict-precision (%)")
    ax.set_ylim(0, 110)
    ax.set_title("§6.2 — HCAF strict-precision by ground-truth cause label")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig8_per_cause.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")
    return out


def fig9_event_direction_heatmap(rows: list[dict]) -> Path:
    """29 evaluable events × 6 methods; cell shows predicted direction (R2T/T2R/?).
    R2T = routing→traffic, T2R = traffic→routing, ? = unknown/abstain.
    Gold border = matches ground-truth direction; ✗ = mismatch.
    """
    SYMBOL = {
        "routing_to_traffic": "R→T",
        "traffic_to_routing": "T→R",
        "unknown": "—",
    }
    # Drop derived attacker-view rows (cause_label == origin_hijack_attacker) for clarity
    EVAL_ROWS = [r for r in rows if r["cause_label"] != "origin_hijack_attacker"]
    events = [r["event_id"] for r in EVAL_ROWS]
    expected = [r["expected_direction"] for r in EVAL_ROWS]
    cause = [r["cause_label"] for r in EVAL_ROWS]

    n_events = len(events)
    n_methods = len(METHODS)
    grid = np.zeros((n_events, n_methods), dtype=int)  # 0=R2T, 1=T2R, 2=unknown
    for i, r in enumerate(EVAL_ROWS):
        for j, m in enumerate(METHODS):
            pred = r[f"{m}_pred"]
            grid[i, j] = {"routing_to_traffic": 0, "traffic_to_routing": 1}.get(pred, 2)

    fig, ax = plt.subplots(figsize=(8.6, max(3.5, 0.32 * n_events + 1.5)), dpi=200)
    cmap = matplotlib.colors.ListedColormap(["#9ecae1", "#fdae6b", "#f0f0f0"])
    norm = matplotlib.colors.BoundaryNorm([-0.5, 0.5, 1.5, 2.5], cmap.N)
    ax.imshow(grid, cmap=cmap, norm=norm, aspect="auto")

    # Draw gold border for cells whose prediction matches expected direction
    for i, r in enumerate(EVAL_ROWS):
        exp = r["expected_direction"]
        for j, m in enumerate(METHODS):
            pred = r[f"{m}_pred"]
            if pred == exp:
                ax.add_patch(plt.Rectangle((j - 0.5, i - 0.5), 1, 1, fill=False,
                                           edgecolor="#d4a017", linewidth=2.4))

    # Annotate each cell
    for i in range(n_events):
        for j in range(n_methods):
            sym = SYMBOL[["routing_to_traffic", "traffic_to_routing", "unknown"][grid[i, j]]]
            ax.text(j, i, sym, ha="center", va="center", fontsize=8)

    # Y-tick labels: "cause · event_id" (short)
    short = {
        "origin_hijack_victim": "hijack",
        "origin_hijack_attacker": "hijack(atk)",
        "route_leak": "leak",
        "outage": "outage",
        "roa_misconfig": "roa",
    }
    ylabels = [f"{short.get(c, c):<12} · {eid}" for c, eid in zip(cause, events)]
    ax.set_yticks(np.arange(n_events))
    ax.set_yticklabels(ylabels, fontsize=7)
    ax.set_xticks(np.arange(n_methods))
    ax.set_xticklabels([LABELS[m] for m in METHODS], rotation=18, ha="right", fontsize=9)
    ax.set_title("§6.2 — Predicted direction per event × method (gold border = matches ground truth)")
    # Legend
    handles = [
        plt.Rectangle((0, 0), 1, 1, color="#9ecae1", label="R→T (routing→traffic)"),
        plt.Rectangle((0, 0), 1, 1, color="#fdae6b", label="T→R (traffic→routing)"),
        plt.Rectangle((0, 0), 1, 1, color="#f0f0f0", label="— (abstain)"),
        plt.Rectangle((0, 0), 1, 1, fill=False, edgecolor="#d4a017", linewidth=2, label="matches ground truth"),
    ]
    ax.legend(handles=handles, loc="upper right", bbox_to_anchor=(1.0, -0.08), ncol=4, fontsize=7, frameon=True)
    fig.tight_layout()
    out = FIG_DIR / "fig9_event_direction_heatmap.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")
    return out


def main():
    rows = load_rows()
    print(f"Loaded {len(rows)} events from {CSV.relative_to(ROOT)}")
    print()
    print("Generating §6 figures ...")
    fig7_eval_overview(rows)
    fig8_per_cause(rows)
    fig9_event_direction_heatmap(rows)
    print()
    print("Done.")


if __name__ == "__main__":
    main()
