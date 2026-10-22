"""Paper §6 case study: Iran national outage (AS44244), 2025-06-18.

Chosen because:
  - HCAF strict-correct (expected T→R, predicted T→R)
  - Real-cache event (no synthetic)
  - Has both routing events (5000 leak events) and traffic anomalies (38)
  - Posterior is cleanly concentrated: P(T→R) = 0.63
  - Demonstrates the paper's narrative: even when CSS p=1.0 (cannot
    reject null), Bayesian posterior commits to correct direction.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
QUICK = ROOT / "results" / "quick" / "quick_44244_2025-06-18T1200_2025-06-19T1200.json"
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_30.jsonl"
FIG_DIR = ROOT / "docs" / "paper" / "figs"


def load_event(eid):
    for line in JSONL.open():
        r = json.loads(line)
        if r["event_id"] == eid:
            return r
    raise KeyError(eid)


def main():
    rec = load_event("outage_iran_2025")
    p = json.loads(QUICK.read_text())
    start = p["start_time"]
    end = p.get("end_time")
    try:
        t0 = datetime.strptime(start.split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M")
        t1 = datetime.strptime(end.split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M")
    except Exception:
        t0 = datetime.strptime(start.split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M:%S")
        t1 = datetime.strptime(end.split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M:%S")

    n_buckets = 48
    routing_score = np.zeros(n_buckets)
    traffic_score = np.zeros(n_buckets)
    routing = p.get("routing", {})
    routing_events = []
    for key in ("origin_hijacked", "forge_hijacked", "route_leaks", "leak_analysis"):
        v = routing.get(key, [])
        if isinstance(v, list):
            routing_events.extend(v)
    for ev in routing_events:
        if isinstance(ev, str):
            continue  # skip string entries
        ts = ev.get("timestamp") or ev.get("time") or ""
        try:
            t = datetime.strptime(str(ts).split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M")
            i = int((t - t0).total_seconds() // (15 * 60))  # 15-min buckets
            if 0 <= i < n_buckets:
                routing_score[i] += 1
        except Exception:
            try:
                t = datetime.strptime(str(ts).split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M:%S")
                i = int((t - t0).total_seconds() // (15 * 60))
                if 0 <= i < n_buckets:
                    routing_score[i] += 1
            except Exception:
                continue
    # Normalize routing to [0, 1] (log scale because 5000 leak events dominate)
    rs_log = np.log1p(routing_score)
    rs_max = rs_log.max() if rs_log.max() > 0 else 1
    routing_norm = rs_log / rs_max

    traffic = p.get("traffic", {})
    for an in traffic.get("anomalies", []):
        if not isinstance(an, dict):
            continue
        ts = an.get("timestamp") or an.get("time") or ""
        try:
            t = datetime.strptime(str(ts).split("+")[0].split("Z")[0], "%Y-%m-%dT%H:%M")
            i = int((t - t0).total_seconds() // (15 * 60))
            if 0 <= i < n_buckets:
                traffic_score[i] = -abs(an.get("z_score", 0)) / 8.0
        except Exception:
            continue

    posterior = rec["posterior"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.2), dpi=200,
                                    gridspec_kw={"width_ratios": [2.2, 1]})
    times = [t0 + timedelta(minutes=15 * i) for i in range(n_buckets)]
    ax1.fill_between(times, routing_norm, alpha=0.4, color="#d62728",
                     label="Routing: events per 15-min bucket, log-normalised")
    ax1.fill_between(times, traffic_score, alpha=0.4, color="#3182bd",
                     label="Traffic: per-anomaly $|z|$/8 (sign-flipped to indicate drop)")
    ax1.axhline(0, color="black", linewidth=0.6)
    ax1.set_ylabel("Anomaly intensity (normalized, see caption)")
    ax1.set_xlabel("Time (UTC, 2025-06-18)")
    ax1.set_title("§6.7 — Iran national outage, AS44244, 2025-06-18\n"
                  "Routing timeline: counts of events per 15-min bucket (log-normalised).\n"
                  "Traffic timeline: per-anomaly z-score (sign-flipped to indicate drop).\n"
                  "HCAF posterior: T→R = 0.60 (strict-correct)")
    ax1.legend(loc="upper right", fontsize=9)
    ax1.grid(axis="y", alpha=0.25)
    fig.autofmt_xdate()

    keys = ["routing_to_traffic", "traffic_to_routing", "independent"]
    labels = ["$R\\to T$", "$T\\to R$", "indep"]
    colors = ["#3182bd", "#e6550d", "#f0f0f0"]
    vals = [posterior.get(k, 0) for k in keys]
    bars = ax2.barh(labels, vals, color=colors, edgecolor="black", linewidth=0.6)
    for b, v in zip(bars, vals):
        ax2.text(v + 0.01, b.get_y() + b.get_height() / 2, f"{v:.3f}", va="center", fontsize=9, fontweight="bold")
    ax2.set_xlim(0, 1)
    ax2.set_xlabel("Posterior mass")
    ax2.set_title("HCAF posterior\n(Bayesian synthesis with CSS prior)")
    ax2.grid(axis="x", alpha=0.25)

    css = (f"CSS(R→T) = {rec['css_routing_to_traffic']:+.2f}\n"
           f"CSS(T→R) = {rec['css_traffic_to_routing']:+.2f}\n"
           f"p-value   = {rec['css_p_value']:.3f}\n"
           f"CI        = [{rec['css_ci_lower']:.1f}, {rec['css_ci_upper']:.1f}]\n"
           f"is_causal = {rec['css_is_causal']}\n"
           f"HCAF dir  = {rec['hcaf_direction']}\n"
           f"GT dir    = {rec['expected_direction']}")
    ax2.text(0.05, 0.05, css, transform=ax2.transAxes, fontsize=8,
             verticalalignment="bottom", family="monospace",
             bbox=dict(facecolor="#fff8dc", edgecolor="#888", boxstyle="round,pad=0.4"))

    fig.tight_layout()
    out = FIG_DIR / "fig13_case_study_iran.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"  → {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
