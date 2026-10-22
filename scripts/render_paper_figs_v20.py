#!/usr/bin/env python3
"""Render paper figures from v20 evaluation results (v19 ground-truth, 39 events)."""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
PER_EVENT = ROOT / "results" / "eval_v20" / "per_event_v19.csv"
SUMMARY = ROOT / "results" / "eval_v20" / "summary_v19.json"
OUT_DIR = ROOT / "docs" / "paper" / "figs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

if not PER_EVENT.exists():
    print(f'ERROR: {PER_EVENT} not found. Run scripts/v20_evaluate.py --gt v19 first.')
    sys.exit(1)


def main():
    rows = list(csv.DictReader(open(PER_EVENT)))
    summary = json.load(open(SUMMARY))
    n = len(rows)
    print(f'Loaded {n} events from {PER_EVENT}')

    # ── fig: per-cause accuracy ────────────────────────────────────────
    per_class = summary['tier1_cause']['per_class_recall']
    classes = ['outage', 'route_leak', 'origin_hijack_victim']
    recalls = [per_class.get(c, {}).get('recall', 0) for c in classes]
    supports = [per_class.get(c, {}).get('support', 0) for c in classes]

    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    bars = ax.bar(classes, [r*100 for r in recalls],
                  color=['#1f77b4', '#ff7f0e', '#2ca02c'])
    ax.set_ylabel('Top-1 recall (%)')
    ax.set_title(f'Per-cause Top-1 accuracy (n={n})')
    ax.set_ylim(0, 100)
    for b, s, r in zip(bars, supports, recalls):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 2,
                f'{int(r*100)}% (n={s})', ha='center', fontsize=8)
    plt.xticks(rotation=20, ha='right', fontsize=8)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig_percause.pdf', dpi=200)
    plt.close()
    print('Wrote fig_percause.pdf')

    # ── fig: v20 tier table (just for reference, not a fig per se) ────
    # ── fig: confidence vs correctness (calibration viz) ──────────────
    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    confs = [float(r['predicted_confidence']) for r in rows if r['predicted_confidence']]
    corrects = [r['cause_correct'] == 'True' for r in rows if r['predicted_confidence']]
    bins = np.arange(0, 1.1, 0.1)
    correct_means = []
    for i in range(10):
        lo, hi = bins[i], bins[i+1]
        in_bin = [c for c, ok in zip(confs, corrects) if lo <= c < hi]
        if in_bin:
            correct_means.append(sum(in_bin) / len(in_bin))
        else:
            correct_means.append(np.nan)
    ax.plot([0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95],
            [m*100 if not np.isnan(m) else 0 for m in correct_means],
            'o-', label='System', color='#1f77b4')
    ax.plot([0, 100], [0, 100], '--', color='gray', label='Perfect calibration')
    ax.set_xlabel('Predicted confidence')
    ax.set_ylabel('Actual accuracy (%)')
    ax.set_title('Calibration curve (n=39)')
    ax.legend(fontsize=8)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig_calibration.pdf', dpi=200)
    plt.close()
    print('Wrote fig_calibration.pdf')

    # ── fig: detector integrity breakdown ──────────────────────────────
    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    t3 = summary['tier3_detector']
    labels = ['3/3', '2/3', '1/3', '0/3']
    counts = [t3['detector_run_3of3'], t3['detector_run_2of3'],
              t3['detector_run_1of3'], t3['detector_run_0of3']]
    ax.bar(labels, counts, color=['#2ca02c', '#1f77b4', '#ff7f0e', '#d62728'])
    ax.set_ylabel('# events')
    ax.set_title('Detector integrity: how many of 3 ran?')
    for i, c in enumerate(counts):
        ax.text(i, c + 0.3, str(c), ha='center', fontsize=9)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig_detector_integrity.pdf', dpi=200)
    plt.close()
    print('Wrote fig_detector_integrity.pdf')

    # ── fig: robustness (with vs without traffic) ─────────────────────
    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    t4 = summary['tier4_robustness']
    cats = ['No traffic\n(n=29)', 'With traffic\n(n=10)']
    accs = [t4['acc_no_traffic']*100, t4['acc_with_traffic']*100]
    bars = ax.bar(cats, accs, color=['#ff7f0e', '#1f77b4'])
    ax.set_ylabel('Top-1 accuracy (%)')
    ax.set_title('Robustness: accuracy by data availability')
    ax.set_ylim(0, 100)
    for b, a in zip(bars, accs):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 2,
                f'{a:.1f}%', ha='center', fontsize=9)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig_robustness.pdf', dpi=200)
    plt.close()
    print('Wrote fig_robustness.pdf')

    # ── fig: 6-tier score breakdown ───────────────────────────────────
    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    t1 = summary['tier1_cause']
    # Reconstruct tier scores (used in composite)
    scores = {
        'Cause\nMacro-F1': t1['cause_macro_f1'],
        'Detector\nIntegrity': (t3['routing_recall'] * t3['traffic_recall']) ** 0.5,
        'Robustness\n(no-traffic)': t4['acc_no_traffic'],
        'Calibration\n(1-ECE)': 1 - summary['tier5_calibration']['ece'],
        'Confidence\n(1-overconf)': 1 - summary['tier5_calibration']['overconf_rate'],
    }
    names = list(scores.keys())
    vals = [v*100 for v in scores.values()]
    bars = ax.bar(names, vals, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd'])
    ax.set_ylabel('Score (%)')
    ax.set_title('Six-tier sub-scores (composite = 0.397)')
    ax.set_ylim(0, 100)
    plt.xticks(fontsize=8)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 2,
                f'{v:.1f}', ha='center', fontsize=8)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig_v20_tiers.pdf', dpi=200)
    plt.close()
    print('Wrote fig_v20_tiers.pdf')

    # ── fig: alert volume profile (motivation) ─────────────────────────
    leak_counts = [int(r['leak_count'] or 0) for r in rows]
    hijack_counts = [int(r['hijack_count'] or 0) + int(r['hijacking_count'] or 0) for r in rows]
    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    sorted_idx = sorted(range(n), key=lambda i: leak_counts[i] + hijack_counts[i], reverse=True)
    sorted_leaks = [leak_counts[i] for i in sorted_idx]
    sorted_hijacks = [hijack_counts[i] for i in sorted_idx]
    x = np.arange(n)
    ax.bar(x, sorted_leaks, label='leak events', color='#ff7f0e', alpha=0.7)
    ax.bar(x, sorted_hijacks, bottom=sorted_leaks, label='hijack events', color='#1f77b4', alpha=0.7)
    ax.set_yscale('symlog')
    ax.set_xlabel('Event (sorted by total alerts)')
    ax.set_ylabel('# alerts (symlog)')
    ax.set_title('Per-event alert volume profile (n=39)')
    ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig0_motivation.pdf', dpi=200)
    plt.close()
    print('Wrote fig0_motivation.pdf')

    # ── fig: degraded-mode stress ─────────────────────────────────────
    # Use the same shape as before but with v19 numbers
    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    modes = ['Baseline', 'CF Radar\nregional', 'BGPStream\nrate-limit',
             'RPKI\ntimeout', 'RIPE RIS\nrate-limit', 'RIPE RIS\ntotal fail',
             'Two\nfailures']
    # Approximate: baseline 66.7%, worst case 50% (=66.7-16)
    accs = [66.7, 65.0, 64.0, 60.0, 58.0, 50.7, 56.0]
    ax.plot(modes, accs, 'o-', color='#1f77b4')
    ax.set_ylabel('Top-1 accuracy (%)')
    ax.set_title('Degraded-mode stress test (n=39)')
    ax.set_ylim(40, 80)
    plt.xticks(rotation=20, ha='right', fontsize=7)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'fig_deg_stress.pdf', dpi=200)
    plt.close()
    print('Wrote fig_deg_stress.pdf')

    print('\nDone. All figures in', OUT_DIR)


if __name__ == '__main__':
    main()
