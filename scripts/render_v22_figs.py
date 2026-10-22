#!/usr/bin/env python3
"""
Render paper figures for the v22 results.

Generates:
  - fig_v22_per_cause.pdf    (per-cause F1 across GT versions)
  - fig_v22_metrics_radar.pdf (multi-tier metrics radar chart)
  - fig_v22_confusion.pdf    (confusion matrix)
  - fig_v22_robustness.pdf   (robustness across hard-case subsets)
  - fig_v22_calibration.pdf  (calibration plot)
  - fig_v22_dataset.pdf      (GT class balance)

Reads from results/eval_v22/.
"""
from __future__ import annotations
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "results" / "eval_v22"
FIG_DIR = ROOT / "docs" / "paper" / "figs"
FIG_DIR.mkdir(parents=True, exist_ok=True)
GT_FILES = {
    "v19": ROOT / "data_check/ground_truth_collection/final_balanced_v19_40.csv",
    "v20": ROOT / "data_check/ground_truth_collection/final_balanced_v20.csv",
    "v21": ROOT / "data_check/ground_truth_collection/final_balanced_v21.csv",
    "v22": ROOT / "data_check/ground_truth_collection/final_balanced_v22.csv",
}


def load_summary(gt_name):
    p = EVAL_DIR / f"summary_{gt_name}.json"
    if not p.exists():
        return None
    return json.load(open(p))


def load_per_event(gt_name):
    p = EVAL_DIR / f"per_event_{gt_name}.csv"
    if not p.exists():
        return None
    return list(csv.DictReader(open(p)))


def fig_v22_per_cause():
    """Bar chart of per-cause F1 across GT versions."""
    summaries = {n: load_summary(n) for n in ["v19", "v20", "v21", "v22"]}
    summaries = {n: s for n, s in summaries.items() if s}
    causes = ["outage", "origin_hijack_victim", "route_leak", "roa_misconfig"]
    width = 0.2
    x = np.arange(len(causes))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for i, gt in enumerate(["v19", "v20", "v21", "v22"]):
        if gt not in summaries:
            continue
        s = summaries[gt]
        f1s = []
        for c in causes:
            if c in s["tier1_cause"].get("per_class", {}):
                f1s.append(s["tier1_cause"]["per_class"][c]["f1"])
            else:
                f1s.append(0)
        ax.bar(x + (i - 1.5) * width, f1s, width, label=gt.upper())
    ax.set_xticks(x)
    ax.set_xticklabels(causes, rotation=20)
    ax.set_ylabel("F1 score")
    ax.set_ylim(0, 1.05)
    ax.set_title("Per-cause F1 across GT versions")
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_per_cause.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


def fig_v22_metrics_radar():
    """Radar chart of multi-tier metrics for v22."""
    s = load_summary("v22")
    if s is None:
        return
    metrics = [
        ("Top-1", s["tier1_cause"]["top1_accuracy"]),
        ("Macro-F1", s["tier1_cause"]["macro_f1"]),
        ("Balanced-Acc", s["tier1_cause"]["balanced_accuracy"]),
        ("NDCG@3", s["tier3_ranking"]["ndcg_at_3"]),
        ("MRR", s["tier3_ranking"]["mrr"]),
        ("Traffic-R", s["tier2_detection"]["traffic_recall"]),
        ("Hijack-R", s["tier2_detection"]["hijack_recall"]),
        ("Leak-R", s["tier2_detection"]["leak_recall"]),
        ("Outage-R", s["tier2_detection"]["outage_recall"]),
        ("1-Brier", max(0, 1.0 - s["tier4_calibration"]["brier"])),
        ("1-ECE", max(0, 1.0 - s["tier4_calibration"]["ece"])),
        ("Composite", s["composite"]),
    ]
    labels = [m[0] for m in metrics]
    values = [m[1] for m in metrics]
    n = len(labels)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    values = values + values[:1]
    angles = angles + angles[:1]
    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))
    ax.plot(angles, values, "o-", linewidth=2, color="C0")
    ax.fill(angles, values, alpha=0.25, color="C0")
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, size=9)
    ax.set_ylim(0, 1.0)
    ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(["0.2", "0.4", "0.6", "0.8", "1.0"], size=8)
    ax.set_title("V22 multi-tier evaluation metrics (35 events)")
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_metrics_radar.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


def fig_v22_confusion():
    """Confusion matrix for v22."""
    s = load_summary("v22")
    if s is None:
        return
    pairs = s["tier1_cause"]["top_confusion_pairs"]
    # Group by GT cause
    causes = ["outage", "origin_hijack_victim", "route_leak", "roa_misconfig", "traffic_anomaly_only", "no_clear_anomaly"]
    cm = np.zeros((len(causes), len(causes)))
    for p in pairs:
        i = causes.index(p["true"]) if p["true"] in causes else len(causes) - 1
        j = causes.index(p["pred"]) if p["pred"] in causes else len(causes) - 1
        if i < len(causes) and j < len(causes):
            cm[i, j] = p["count"]
    # Add per-class support (diagonal = correct)
    per = s["tier1_cause"]["per_class"]
    for c in causes:
        if c in per:
            i = causes.index(c)
            cm[i, i] = per[c].get("tp", 0)
    fig, ax = plt.subplots(figsize=(6, 5.5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(causes)))
    ax.set_xticklabels([c[:15] for c in causes], rotation=30, ha="right")
    ax.set_yticks(range(len(causes)))
    ax.set_yticklabels([c[:15] for c in causes])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Ground truth")
    ax.set_title("V22 confusion matrix (35 events)")
    for i in range(len(causes)):
        for j in range(len(causes)):
            if cm[i, j] > 0:
                ax.text(j, i, int(cm[i, j]), ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black", size=9)
    plt.colorbar(im)
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_confusion.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


def fig_v22_robustness():
    """Robustness across hard-case subsets."""
    s = load_summary("v22")
    if s is None:
        return
    rb = s["tier5_robustness"]
    subsets = [k for k, v in rb.items() if v["n"] > 0]
    accs = [rb[k]["accuracy"] for k in subsets]
    n = [rb[k]["n"] for k in subsets]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.barh(subsets, accs, color="C2")
    for bar, nn, a in zip(bars, n, accs):
        ax.text(min(a + 0.02, 1.0), bar.get_y() + bar.get_height() / 2,
                f"n={nn}, {a:.2f}", va="center", size=9)
    ax.set_xlim(0, 1.0)
    ax.set_xlabel("Top-1 accuracy")
    ax.set_title("V22 robustness across hard-case subsets (35 events)")
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_robustness.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


def fig_v22_calibration():
    """Calibration plot (reliability diagram)."""
    rows = load_per_event("v22")
    if not rows:
        return
    # Bin predictions by confidence
    bins = [(0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.01)]
    bin_conf = []
    bin_acc = []
    bin_count = []
    for lo, hi in bins:
        rs = [r for r in rows if lo <= float(r["predicted_confidence"] or 0) < hi]
        if not rs:
            continue
        bin_count.append(len(rs))
        bin_conf.append(sum(float(r["predicted_confidence"] or 0) for r in rs) / len(rs))
        bin_acc.append(sum(1 for r in rs if r["cause_correct"] == "True") / len(rs))
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot([0, 1], [0, 1], "k--", alpha=0.5, label="Perfect calibration")
    ax.bar(bin_conf, bin_acc, width=0.15, alpha=0.7, label="Model")
    for c, a, n in zip(bin_conf, bin_acc, bin_count):
        ax.scatter([c], [a], s=50, zorder=3)
        ax.annotate(f"n={n}", (c, a), textcoords="offset points", xytext=(5, 5), size=8)
    ax.set_xlabel("Mean confidence")
    ax.set_ylabel("Accuracy")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    s = load_summary("v22")
    ece = s["tier4_calibration"]["ece"]
    brier = s["tier4_calibration"]["brier"]
    ax.set_title(f"V22 reliability diagram (ECE={ece:.3f}, Brier={brier:.3f})")
    ax.legend(loc="upper left")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_calibration.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


def fig_v22_dataset():
    """GT class balance across versions."""
    versions = ["v19", "v20", "v21", "v22"]
    counts = {v: Counter() for v in versions}
    for v in versions:
        p = GT_FILES[v]
        if not p.exists():
            continue
        for r in csv.DictReader(open(p)):
            counts[v][r.get("cause", "unknown")] += 1
    causes = ["outage", "origin_hijack_victim", "route_leak", "roa_misconfig"]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = np.arange(len(versions))
    width = 0.2
    for i, c in enumerate(causes):
        vals = [counts[v].get(c, 0) for v in versions]
        ax.bar(x + (i - 1.5) * width, vals, width, label=c)
    ax.set_xticks(x)
    ax.set_xticklabels(versions)
    ax.set_ylabel("Number of events")
    ax.set_title("GT dataset class balance across versions")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_dataset.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


def fig_v22_metric_progression():
    """Show how the v22 metrics improved over v19/v20/v21."""
    summaries = {n: load_summary(n) for n in ["v19", "v20", "v21", "v22"]}
    summaries = {n: s for n, s in summaries.items() if s}
    metrics = ["top1_accuracy", "macro_f1", "balanced_accuracy", "composite"]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for i, m in enumerate(metrics):
        if m == "composite":
            vals = [s[m] for s in summaries.values()]
        else:
            vals = [s["tier1_cause"][m] for s in summaries.values()]
        ax.plot(list(summaries.keys()), vals, "o-", label=m, markersize=8)
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.0)
    ax.set_title("V22 metric progression across GT versions")
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    out = FIG_DIR / "fig_v22_progression.pdf"
    plt.savefig(out)
    plt.close()
    print(f"Wrote {out}")


if __name__ == "__main__":
    fig_v22_per_cause()
    fig_v22_metrics_radar()
    fig_v22_confusion()
    fig_v22_robustness()
    fig_v22_calibration()
    fig_v22_dataset()
    fig_v22_metric_progression()
    print("Done.")
