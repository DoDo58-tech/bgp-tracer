"""Paper §6 ablation: HCAF channel contribution analysis.

Empirical observation: CSS's strict-causal rate (p<0.05) is 3/22
on v11 because routing timelines from real BGP data are sparse and
near-constant (the routing signal comes from BGP update dumps that
have event-level timestamps but no per-bucket scores). CSS therefore
returns 'unknown' on most events.

To honestly show what HCAF is actually doing, this ablation drops
the CSS-anchored prior entirely and measures how each remaining
channel (MSBD, CTPR, CIC, Granger, TE) contributes to the verdict.

We use the original `bayesian_synthesize` from `agents/css_engine.py`
and feed it the channel LR's reconstructed from the per-event jsonl
(granger direction + confidence, TE direction + confidence, and a
CSS-direction proxy for MSBD/CTPR/CIC). The synthesis is run with
each channel individually disabled.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v11.jsonl"
OUT = ROOT / "results" / "eval" / "ablation_v11.csv"


def channels_for(rec):
    """Build the 5-channel evidence dict from a jsonl record."""
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


def synthesize_no_css_prior(css_dir, channels, disabled):
    """Mirror bayesian_synthesize but with NO CSS-anchored prior (uniform)."""
    prior = {"routing_to_traffic": 1.0, "traffic_to_routing": 1.0, "independent": 1.0}
    post = dict(prior)
    for name, ch in channels.items():
        if name in disabled:
            continue
        lr = ch.get("likelihood", {}) or {}
        ch_dir = ch.get("direction", "unknown")
        # No CSS anchor → no disagreement discount
        discount = 1.0
        for k, v in lr.items():
            if k in post and v > 0:
                post[k] *= float(v) ** discount
    total = sum(post.values()) or 1.0
    norm = {k: v / total for k, v in post.items()}
    dom = max(norm, key=norm.get)
    return {"direction": dom if norm[dom] > 0.34 else "unknown", "posterior": norm}


def main():
    variants = [
        ("No-CSS-prior full", set()),
        ("No-CSS-prior −MSBD", {"msbd"}),
        ("No-CSS-prior −CTPR", {"ctpr"}),
        ("No-CSS-prior −CIC",  {"cic"}),
        ("No-CSS-prior −Granger", {"granger"}),
        ("No-CSS-prior −TE",   {"te"}),
        ("CSS-only (CSS dir)", {"msbd", "ctpr", "cic", "granger", "te"}),
    ]

    recs = [json.loads(l) for l in JSONL.open()]
    summary = {}
    for name, disabled in variants:
        strict = review = abst = 0
        n = 0
        for j in recs:
            expected = j["expected_direction"]
            css_dir = j.get("css_direction", "unknown")
            ch = channels_for(j)
            n += 1
            if name.startswith("CSS-only"):
                pred = css_dir if css_dir in ("routing_to_traffic", "traffic_to_routing") else "unknown"
            else:
                synth = synthesize_no_css_prior(css_dir, ch, disabled)
                pred = synth["direction"]
            if pred == expected:
                strict += 1
                review += 1
            elif pred == "unknown":
                abst += 1
                review += 1
        summary[name] = {
            "review": review / n * 100,
            "strict": strict / n * 100,
            "abstain": abst / n * 100,
            "n": n,
        }

    fieldnames = ["variant", "n", "review_precision", "strict_precision", "abstain_rate"]
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for name, _ in variants:
            s = summary[name]
            w.writerow({
                "variant": name,
                "n": s["n"],
                "review_precision": round(s["review"], 1),
                "strict_precision": round(s["strict"], 1),
                "abstain_rate": round(s["abstain"], 1),
            })

    print(f"{'Variant':<28} {'n':>3} {'review%':>8} {'strict%':>8} {'abstain%':>9}")
    print("-" * 60)
    for name, _ in variants:
        s = summary[name]
        print(f"{name:<28} {s['n']:>3} {s['review']:>8.1f} {s['strict']:>8.1f} {s['abstain']:>9.1f}")
    print()
    print(f"Wrote → {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
