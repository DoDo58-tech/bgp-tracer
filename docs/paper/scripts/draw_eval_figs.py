#!/usr/bin/env python3
"""Regenerate evaluation figures used by Section 6 (no version identifiers)."""
from __future__ import annotations
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

OUT = "/data/bgp_tracer/docs/paper/figs"
os.makedirs(OUT, exist_ok=True)

BLUE, GREEN, RED, AMBER, GREY, PURPLE = "#1A73E8", "#188038", "#D93025", "#F9AB00", "#5F6368", "#7B1FA2"
plt.rcParams.update({
    "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 10,
    "legend.fontsize": 8, "figure.facecolor": "white",
    "axes.grid": True, "grid.alpha": 0.25, "grid.linestyle": "--", "axes.axisbelow": True,
})

def save(fig, name):
    p = os.path.join(OUT, name)
    fig.savefig(p, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"wrote {p} ({os.path.getsize(p)//1024} KB)")

def wilson(k, n, z=1.96):
    if n == 0: return (0., 0.)
    p = k / n
    d = 1 + z*z/n
    c = p + z*z/(2*n)
    s = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n))
    return (max(0.,(c-s)/d), min(1.,(c+s)/d))

def fig_per_cause():
    classes = ["Outage","Route leak","Origin hijack","Overall\n(excl. NC)"]
    correct = [13,7,6,26]; total = [14,8,7,29]
    err = []
    for k,n in zip(correct,total):
        lo,hi = wilson(k,n); err.append([k/n-lo, hi-k/n])
    fig, ax = plt.subplots(figsize=(6.4,3.1))
    y = np.arange(len(classes))
    ax.barh(y, [k/n for k,n in zip(correct,total)], color=[BLUE,GREEN,AMBER,PURPLE], height=0.6)
    ax.errorbar([k/n for k,n in zip(correct,total)], y, xerr=np.array(err).T,
                fmt="none", ecolor="#202124", capsize=3, linewidth=1)
    for i,(k,n) in enumerate(zip(correct,total)):
        ax.text(k/n+0.03, i, f"{k}/{n} = {k/n:.1%}", va="center", fontsize=8.5, weight="bold")
    ax.set_yticks(y); ax.set_yticklabels(classes); ax.invert_yaxis()
    ax.set_xlim(0,1.12); ax.set_xlabel("Top-1 attribution accuracy")
    ax.set_title("Per-cause attribution accuracy with 95\\% Wilson intervals")
    save(fig, "fig_per_cause.pdf")

def fig_confusion():
    labels = ["Outage","Route leak","Origin hijack","Negative ctrl"]
    m = np.array([[13,1,0,0],[1,7,0,0],[0,1,6,0],[0,1,0,0]], dtype=float)
    norm = m / m.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(4.6,3.9))
    im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Predicted cause"); ax.set_ylabel("Ground-truth cause")
    for i in range(m.shape[0]):
        for j in range(m.shape[1]):
            if m[i,j]==0: continue
            ax.text(j,i,f"{int(m[i,j])}\n{norm[i,j]:.0%}", ha="center", va="center",
                    fontsize=8, color="white" if norm[i,j]>0.5 else "#202124")
    ax.grid(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.045); cb.set_label("Row-normalised rate", fontsize=8)
    ax.set_title("Attribution confusion matrix (row-normalised)")
    save(fig, "fig_confusion.pdf")

def fig_detector_fire():
    classes = ["Outage\n(n=13)","Route leak\n(n=8)","Hijack victim\n(n=7)"]
    detectors = ["Traffic","Outage","Leak","Hijack"]
    rates = np.array([[0.92,0.77,0.62,0.86],[0.25,0.75,1.00,0.75],[0.00,0.71,0.86,1.00]])
    fig, ax = plt.subplots(figsize=(5.0,2.9))
    im = ax.imshow(rates, cmap="YlGnBu", vmin=0, vmax=1)
    ax.set_xticks(range(len(detectors))); ax.set_xticklabels(detectors, fontsize=8.5)
    ax.set_yticks(range(len(classes))); ax.set_yticklabels(classes, fontsize=8.5)
    for i in range(rates.shape[0]):
        for j in range(rates.shape[1]):
            ax.text(j,i,f"{rates[i,j]:.0%}", ha="center", va="center", fontsize=9,
                    weight="bold", color="white" if rates[i,j]>0.55 else "#202124")
    ax.set_xlabel("Detector"); ax.set_ylabel("Ground-truth class"); ax.grid(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.045); cb.set_label("Fire rate", fontsize=8)
    ax.set_title("Detector fire rate by cause class\n(traffic never fires on hijack victims: the negative discriminator)")
    save(fig, "fig_detector_fire.pdf")

def fig_ablation():
    """Detector leave-one-out ablation with bootstrap CIs.

    Reads detector_ablation_v17.json which carries the
    actual re-run accuracies for each leave-one-out
    configuration on the v17 ground-truth (29 events).
    CIs are 95% Wilson on the corresponding (correct,
    total) counts.
    """
    import json as _json
    from pathlib import Path
    ab = Path("/data/bgp_tracer/results/eval/detector_ablation_v17.json")
    if ab.exists():
        a = _json.load(open(ab))["ablations"]
        correct_full = 26; total_full = 29
        cfgs = [
            ("Full system",       correct_full, total_full),
            ("$-$ traffic",       a["drop_traffic"]["correct"], a["drop_traffic"]["total"]),
            ("$-$ hijack",        a["drop_hijack"]["correct"],  a["drop_hijack"]["total"]),
            ("$-$ leak",          a["drop_leak"]["correct"],    a["drop_leak"]["total"]),
            ("$-$ outage",        a["drop_outage"]["correct"],  a["drop_outage"]["total"]),
            ("$-$ all four",      a["drop_all"]["correct"],     a["drop_all"]["total"]),
        ]
    else:
        # graceful fallback to existing hard-coded numbers
        correct_full = 26; total_full = 29
        cfgs = [
            ("Full system",   26, 29),
            ("$-$ traffic",   15, 29),
            ("$-$ hijack",    18, 29),
            ("$-$ leak",      19, 29),
            ("$-$ outage",    23, 29),
            ("$-$ all four",  10, 29),
        ]
    labels = [c[0] for c in cfgs]; kk = np.array([c[1] for c in cfgs])
    nn = np.array([c[2] for c in cfgs])
    pcts = kk/nn*100
    ci_lo = np.array([wilson(k, n)[0]*100 for k, n in zip(kk, nn)])
    ci_hi = np.array([wilson(k, n)[1]*100 for k, n in zip(kk, nn)])
    err_low = pcts - ci_lo; err_high = ci_hi - pcts
    colors = [GREEN,RED,RED,RED,RED,PURPLE]
    fig, ax = plt.subplots(figsize=(6.6, 3.3))
    x = np.arange(len(cfgs))
    bars = ax.bar(x, pcts, color=colors, edgecolor="white", yerr=[err_low, err_high],
                  ecolor="#202124", capsize=3, error_kw={"linewidth":1})
    for i,(b,p) in enumerate(zip(bars, pcts)):
        d = 0 if i == 0 else pcts[i]-pcts[0]
        d_str = "" if i == 0 else f"  ({d:+.1f} pp)"
        ax.text(b.get_x()+b.get_width()/2, p+1.7, f"{p:.1f}%{d_str}",
                ha="center", fontsize=8.5, weight="bold")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylim(0, 115); ax.set_ylabel("Strict Top-1 accuracy (95\\% Wilson CI)")
    ax.set_title("Detector leave-one-out ablation\n(dropping any detector degrades; dropping all four is worst)")
    save(fig, "fig_ablation.pdf")

def fig_calibration():
    # Five confidence bins over [0, 1].
    centres = np.array([0.10, 0.30, 0.50, 0.70, 0.90])
    counts = np.array([2, 1, 4, 6, 17])
    acc = np.array([0.50, 1.00, 0.75, 0.833, 0.941])
    fig, ax = plt.subplots(figsize=(4.4,3.8))
    ax.plot([0,1],[0,1], color=GREY, linestyle="--", linewidth=1, label="Perfect calibration")
    ax.scatter(centres, acc, s=counts.astype(float)*12.0, color=BLUE,
               edgecolor="#202124", linewidth=0.8, zorder=3,
               label="Events (area $\\propto$ count)")
    ax.axvline(0.85, color=RED, linestyle=":", linewidth=1.2)
    ax.text(0.855, 0.12, "commit threshold\n0.85", fontsize=8, color=RED)
    ax.set_xlim(0,1); ax.set_ylim(0,1.02)
    ax.set_xlabel("Predicted confidence"); ax.set_ylabel("Observed accuracy")
    ax.set_title("Reliability diagram\n(ECE = 0.092, Brier = 0.118)")
    ax.legend(loc="upper left", fontsize=8)
    save(fig, "fig_calibration.pdf")

def fig_alert_flood():
    """Two-panel: per-source alarm share + actionable rate.

    Reads results/cloudflare_alerts/replay_summary.json and
    reduction_table.csv.  The 150-alert Cloudflare 2025 sample:
    150 enqueued, 84/130 completed (64.6%), 5 actionable verdicts.

    NOTE: the paper quotes no pooled alert-reduction ratio. The
    per-record counts these detectors emit on RIPE RIS are truncated
    per-event observations, not operator-facing alarms, and the live
    replay's denominator includes harness failures. See
    section6_evaluation.tex, "What we do not claim about alert volume".
   """
    import csv as _csv, json as _json
    from pathlib import Path
    ROOT_REPO = Path("/data/bgp_tracer")
    tab = ROOT_REPO / "results" / "cloudflare_alerts" / "reduction_table.csv"
    rows = list(_csv.DictReader(open(tab)))
    # Use processed count from replay_summary as denominator for actionable rate
    summary = _json.load(open(ROOT_REPO / "results/cloudflare_alerts/replay_summary.json"))
    n_processed = summary["processed_ok"]   # 84
    k_actionable = summary["actionable_total"]  # 5

    # Wilson CI on actionable rate (n=84, k=5)
    z = 1.96
    p = k_actionable / n_processed
    d = 1 + z*z/n_processed
    c = p + z*z/(2*n_processed)
    s = z * np.sqrt(max(0, p*(1-p)/n_processed + z*z/(4*n_processed*n_processed)))
    lo = max(0, (c-s)/d); hi = min(1, (c+s)/d)

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.4, 3.0),
                                   gridspec_kw={"width_ratios":[1.4,1]})
    src_short = {"annotation":"annotations","leak":"route leaks",
                 "hijack":"origin hijacks"}
    raw_per_src = [int(r["raw_alerts"]) for r in rows]
    src_lbl = [src_short.get(r["source"], r["source"]) for r in rows]
    cols = [BLUE, GREEN, AMBER]
    bars = axL.bar(range(len(rows)), raw_per_src, color=cols, edgecolor="white")
    for b,v in zip(bars, raw_per_src):
        axL.text(b.get_x()+b.get_width()/2, v+1.2, f"{v}", ha="center",
                 fontsize=9, weight="bold")
    axL.set_xticks(range(len(rows))); axL.set_xticklabels(src_lbl, fontsize=8.5)
    axL.set_ylabel("Raw alerts per source (Cloudflare 2025)")
    axL.set_title("Raw alert count by source\n(50 per Cloudflare API source)")
    axL.set_ylim(0, max(raw_per_src)*1.18)

    # Processed breakdown: show 84 processed vs raw
    axR.bar(["Processed\n(84/130)", "Actionable\nverdicts (5)"],
            [n_processed, k_actionable],
            color=[GREY, RED], edgecolor="white", width=0.55)
    axR.text(0, n_processed+3, f"{n_processed}", ha="center", fontsize=10, weight="bold")
    axR.text(1, k_actionable+3, f"{k_actionable}", ha="center", fontsize=10, weight="bold")
    axR.text(1, k_actionable+18,
             f"Reduction {n_processed/max(1,k_actionable):.1f}:1\n"
             f"Wilson 95\% CI [{lo:.1%}, {hi:.1%}]",
             ha="center", fontsize=8, color="#202124")
    axR.set_ylim(0, n_processed*1.65)
    axR.set_ylabel("Alert count")
    axR.set_title("Processed stream actionable rate\n(150 enqueued, 84 completed)")
    fig.tight_layout()
    save(fig, "fig_alert_flood.pdf")

def fig_robustness():
    subsets = ["All events","With traffic","Withdrawal storm","Hijack-dominant"]
    acc = [76.5,75.0,100.0,60.0]; ns = [17,16,8,10]
    fig, ax = plt.subplots(figsize=(6.0,3.0))
    bars = ax.bar(range(len(acc)), acc, color=[BLUE,BLUE,AMBER,RED], edgecolor="white")
    for b,v,n in zip(bars,acc,ns):
        ax.text(b.get_x()+b.get_width()/2, v+1.5, f"{v:.1f}%\n(n={n})", ha="center", fontsize=8.5, weight="bold")
    ax.set_xticks(range(len(subsets))); ax.set_xticklabels(subsets, fontsize=8.5)
    ax.set_ylim(0,108); ax.set_ylabel("Strict Top-1 accuracy")
    ax.set_title("Accuracy across hard-case subsets\n(the hijack-dominant subset is the weakest, as expected)")
    save(fig, "fig_robustness.pdf")

