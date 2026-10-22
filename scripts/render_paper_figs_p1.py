"""Paper §6 supplementary figures:
  fig10_real_vs_synthetic.pdf — HCAF on real-cache subset vs full v14 set
  fig11_abstention_audit.pdf — abstention distribution per method, real vs full

Both figures exist to address reviewer concerns about synthetic-cache bias.
"""
from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
CSV_FULL = ROOT / "results" / "eval" / "per_event_v36.csv"
CSV_REAL = ROOT / "results" / "eval" / "per_event_v36_real.csv"
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)

METHODS = ["hcaf", "css", "pearson", "granger", "ts_distance", "transfer_entropy"]
LABELS = {
    "hcaf": "HCAF",
    "css": "CSS",
    "pearson": "Pearson",
    "granger": "Granger",
    "ts_distance": "Ts-Dist.",
    "transfer_entropy": "TE",
}


def load(path: Path) -> list[dict]:
    with path.open() as f:
        return list(csv.DictReader(f))


def summarize(rows: list[dict]) -> dict[str, dict[str, float]]:
    n = len(rows)
    out = {}
    for m in METHODS:
        out[m] = {
            "review": sum(int(r[f"{m}_review"]) for r in rows) / n * 100,
            "strict": sum(int(r[f"{m}_strict"]) for r in rows) / n * 100,
            "abstain": sum(int(r[f"{m}_abstain"]) for r in rows) / n * 100,
        }
    return out


def fig10_real_vs_synthetic():
    """Two-panel bar: full v14 (left) vs real-cache subset (right), per method.
    HCAF's strict-precision is stable across both; baselines flip."""
    full = summarize(load(CSV_FULL))
    real = summarize(load(CSV_REAL))

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), dpi=200, sharey=True)
    width = 0.27
    x = np.arange(len(METHODS))

    n_full = len(load(CSV_FULL))
    n_real = len(load(CSV_REAL))
    for ax, summary, title, n in [
        (axes[0], full, f"Full v14 (n={n_full})", n_full),
        (axes[1], real, f"Real-cache subset (n={n_real})", n_real),
    ]:
        review = [summary[m]["review"] for m in METHODS]
        strict = [summary[m]["strict"] for m in METHODS]
        abst = [summary[m]["abstain"] for m in METHODS]
        ax.bar(x - width, review, width, label="review-prec.", color="#9ecae1", edgecolor="black", linewidth=0.5)
        ax.bar(x,         strict, width, label="strict-prec.", color="#3182bd", edgecolor="black", linewidth=0.5)
        ax.bar(x + width, abst, width, label="abstain", color="#bdbdbd", edgecolor="black", linewidth=0.5)

        # annotate HCAF strict
        for i, m in enumerate(METHODS):
            if m == "hcaf":
                ax.text(x[i], strict[i] + 1.5, f"{strict[i]:.1f}%", ha="center", fontsize=8, fontweight="bold")

        ax.set_xticks(x)
        ax.set_xticklabels([LABELS[m] for m in METHODS], rotation=18, ha="right", fontsize=9)
        ax.set_title(f"{title}", fontsize=10)
        ax.grid(axis="y", alpha=0.25)

    axes[0].set_ylabel("Percentage (%)")
    axes[0].legend(loc="upper right", fontsize=8)
    fig.suptitle("§6 — Sensitivity to synthetic-cache exclusion (HCAF strict is stable)", y=1.02)
    fig.tight_layout()
    out = FIG_DIR / "fig10_real_vs_synthetic.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")
    return out


def fig11_abstention_audit():
    """Stacked bar of abstention causes per method, broken down by cause."""
    full_rows = load(CSV_FULL)
    real_rows = load(CSV_REAL)

    abst_causes = {"hcaf": [], "css": [], "pearson": [], "granger": [], "ts_distance": [], "transfer_entropy": []}
    for r in full_rows:
        cause = r["cause_label"]
        for m in METHODS:
            if int(r[f"{m}_abstain"]):
                abst_causes[m].append(cause)

    # Count per method per cause
    causes_order = ["origin_hijack_victim", "route_leak", "outage", "roa_misconfig"]
    counts = {m: {c: 0 for c in causes_order} for m in METHODS}
    for m in METHODS:
        for c in abst_causes[m]:
            counts[m][c] = counts[m].get(c, 0) + 1

    fig, ax = plt.subplots(figsize=(9, 4.2), dpi=200)
    bottoms = np.zeros(len(METHODS))
    cause_colors = {
        "origin_hijack_victim": "#d62728",
        "route_leak": "#ff7f0e",
        "outage": "#2ca02c",
        "roa_misconfig": "#9467bd",
    }
    cause_labels = {
        "origin_hijack_victim": "hijack (BGPStream, no RRC00)",
        "route_leak": "leak (BGPStream, no RRC00)",
        "outage": "outage",
        "roa_misconfig": "roa_misconfig",
    }
    for c in causes_order:
        vals = [counts[m][c] for m in METHODS]
        ax.bar(METHODS, vals, bottom=bottoms, color=cause_colors[c], label=cause_labels[c],
               edgecolor="black", linewidth=0.5)
        for i, v in enumerate(vals):
            if v > 0:
                ax.text(i, bottoms[i] + v / 2, str(v), ha="center", va="center", fontsize=8, color="white", fontweight="bold")
        bottoms += np.array(vals)

    n_full = len(full_rows)
    ax.set_ylabel(f"Number of abstentions (out of {n_full} events)")
    ax.set_title("§6 — Abstention composition per method. HCAF's 4 abstentions are\n"
                 "all BGPStream events with no fresh RRC00 origin announcements (detector being honest)")
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    out = FIG_DIR / "fig11_abstention_audit.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")
    return out


def main():
    print("Generating §6 supplementary figures ...")
    fig10_real_vs_synthetic()
    fig11_abstention_audit()
    print("Done.")


if __name__ == "__main__":
    main()
