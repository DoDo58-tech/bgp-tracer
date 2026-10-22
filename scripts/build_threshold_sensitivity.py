"""Paper §6: abstention threshold sensitivity (the '0.34 magic number').

The bayesian_synthesize function declares 'unknown' if the dominant
posterior is below 0.34 (one-third majority). This script sweeps
threshold ∈ [0.30, 0.40, 0.50] and reports the resulting strict/
review/abstain on v11.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl"
OUT_CSV = ROOT / "results" / "eval" / "threshold_sensitivity_v36.csv"


def channels_for(rec):
    css_dir = rec.get("css_direction", "unknown")
    css_p = rec.get("css_p_value", 1.0)
    ch = {}
    strength = max(0.0, 1.0 - css_p)
    if css_dir in ("routing_to_traffic", "traffic_to_routing"):
        for name, mult in [("msbd", 3.0), ("ctpr", 2.0), ("cic", 0.5)]:
            lr = max(1.05, 1.0 + strength * mult)
            ch[name] = {
                "direction": css_dir,
                "likelihood": {
                    css_dir: lr,
                    "traffic_to_routing" if css_dir == "routing_to_traffic" else "routing_to_traffic": 1.0 / lr,
                    "independent": 1.0,
                },
            }
    g_dir = rec.get("granger_direction", "unknown")
    g_conf = rec.get("granger_confidence", 0.0)
    if g_dir in ("routing_to_traffic", "traffic_to_routing") and g_conf > 0:
        g_lr = max(1.05, 1.0 + g_conf * 1.5)
        ch["granger"] = {
            "direction": g_dir,
            "likelihood": {
                g_dir: g_lr,
                "traffic_to_routing" if g_dir == "routing_to_traffic" else "routing_to_traffic": 1.0 / g_lr,
                "independent": 1.0,
            },
        }
    t_dir = rec.get("transfer_entropy_direction", "unknown")
    t_conf = rec.get("transfer_entropy_confidence", 0.0)
    if t_dir in ("routing_to_traffic", "traffic_to_routing") and t_conf > 0.3:
        t_lr = max(1.05, 1.0 + t_conf * 1.2)
        ch["te"] = {
            "direction": t_dir,
            "likelihood": {
                t_dir: t_lr,
                "traffic_to_routing" if t_dir == "routing_to_traffic" else "routing_to_traffic": 1.0 / t_lr,
                "independent": 1.0,
            },
        }
    return ch


def synthesize_threshold(css_dir, channels, threshold, css_causal):
    prior = {"routing_to_traffic": 1.0, "traffic_to_routing": 1.0, "independent": 1.0}
    if css_dir in ("routing_to_traffic", "traffic_to_routing"):
        prior[css_dir] = 10.0 if css_causal else 4.0
    post = dict(prior)
    for name, ch in channels.items():
        lr = ch.get("likelihood", {}) or {}
        ch_dir = ch.get("direction", "unknown")
        discount = 1.0
        if css_dir in ("routing_to_traffic", "traffic_to_routing") and ch_dir in (
            "routing_to_traffic", "traffic_to_routing"
        ) and ch_dir != css_dir:
            discount = 0.4
        for k, v in lr.items():
            if k in post and v > 0:
                post[k] *= float(v) ** discount
    total = sum(post.values()) or 1.0
    norm = {k: v / total for k, v in post.items()}
    dom = max(norm, key=norm.get)
    return {"direction": dom if norm[dom] > threshold else "unknown", "posterior": norm}


def main():
    recs = [json.loads(l) for l in JSONL.open()]
    # Exclude attacker-view rows with no expected_direction.
    recs = [r for r in recs if r.get("expected_direction") in ("routing_to_traffic", "traffic_to_routing")]
    thresholds = [0.30, 0.34, 0.40, 0.45, 0.50, 0.60]
    summary = {}
    for t in thresholds:
        strict = review = abst = 0
        n = 0
        for j in recs:
            expected = j["expected_direction"]
            css_dir = j.get("css_direction", "unknown")
            css_causal = bool(j.get("css_is_causal", False))
            ch = channels_for(j)
            synth = synthesize_threshold(css_dir, ch, t, css_causal)
            pred = synth["direction"]
            n += 1
            if pred == expected:
                strict += 1
                review += 1
            elif pred == "unknown":
                abst += 1
                review += 1
        summary[t] = {
            "review": review / n * 100,
            "strict": strict / n * 100,
            "abstain": abst / n * 100,
            "n": n,
        }

    fieldnames = ["threshold", "n", "review_precision", "strict_precision", "abstain_rate"]
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for t in thresholds:
            s = summary[t]
            w.writerow({
                "threshold": t,
                "n": s["n"],
                "review_precision": round(s["review"], 1),
                "strict_precision": round(s["strict"], 1),
                "abstain_rate": round(s["abstain"], 1),
            })

    print(f"{'Threshold':<10} {'n':>3} {'review%':>8} {'strict%':>8} {'abstain%':>9}")
    print("-" * 44)
    for t in thresholds:
        s = summary[t]
        marker = " ← default" if abs(t - 0.34) < 1e-6 else ""
        print(f"{t:<10} {s['n']:>3} {s['review']:>8.1f} {s['strict']:>8.1f} {s['abstain']:>9.1f}{marker}")
    print()
    print(f"Wrote → {OUT_CSV.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
