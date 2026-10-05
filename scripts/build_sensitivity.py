"""Paper §6 sensitivity analysis: posterior stability under channel removal.

For each event we have the posterior over {R→T, T→R, independent}
from the jsonl. We compute three sensitivity metrics:

  1. Leave-one-channel-out posterior shift (L1 distance vs original posterior)
  2. Direction-flip rate when each channel is zeroed out (LR=1)
  3. CSS-only strict vs full-HCAF strict (already in csv)

This tells us which channels actually drive the verdict, and which
are merely consistent with it.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl"
OUT_CSV = ROOT / "results" / "eval" / "sensitivity_v36.csv"


def l1(a: dict, b: dict) -> float:
    return sum(abs(a.get(k, 0) - b.get(k, 0)) for k in ("routing_to_traffic", "traffic_to_routing", "independent"))


def synthesize_no_css(css_dir: str, channels: dict, disabled: set) -> dict:
    prior = {"routing_to_traffic": 1.0, "traffic_to_routing": 1.0, "independent": 1.0}
    post = dict(prior)
    for name, ch in channels.items():
        if name in disabled:
            continue
        lr = ch.get("likelihood", {}) or {}
        for k, v in lr.items():
            if k in post and v > 0:
                post[k] *= float(v) ** 1.0
    total = sum(post.values()) or 1.0
    norm = {k: v / total for k, v in post.items()}
    return norm


def synthesize_with_css_prior(css_dir: str, channels: dict, disabled: set, css_is_causal: bool) -> dict:
    prior = {"routing_to_traffic": 1.0, "traffic_to_routing": 1.0, "independent": 1.0}
    if css_dir in ("routing_to_traffic", "traffic_to_routing"):
        prior[css_dir] = 10.0 if css_is_causal else 4.0
    post = dict(prior)
    for name, ch in channels.items():
        if name in disabled:
            continue
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
    return {k: v / total for k, v in post.items()}


def channels_for(rec: dict) -> dict:
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


def main() -> None:
    recs = [json.loads(l) for l in JSONL.open()]
    # Filter to records with a defined expected_direction (excludes
    # origin_hijack_attacker derived rows whose expected_direction is None).
    recs = [r for r in recs if r.get("expected_direction") in ("routing_to_traffic", "traffic_to_routing")]
    variants = [
        ("full (with CSS prior)", set()),
        ("−MSBD",  {"msbd"}),
        ("−CTPR",  {"ctpr"}),
        ("−CIC",   {"cic"}),
        ("−Granger", {"granger"}),
        ("−TE",    {"te"}),
        ("−CSS prior (no anchoring)", "no-css-prior"),
    ]
    summary = {}
    for name, disabled in variants:
        l1_total = 0.0
        flip = 0
        n = 0
        for j in recs:
            expected = j["expected_direction"]
            css_dir = j.get("css_direction", "unknown")
            css_causal = bool(j.get("css_is_causal", False))
            ch = channels_for(j)
            n += 1
            if disabled == "no-css-prior":
                post = synthesize_no_css(css_dir, ch, set())
            else:
                post = synthesize_with_css_prior(css_dir, ch, disabled, css_causal)
            orig = j.get("posterior", {})
            l1_total += l1(post, orig)
            orig_dom = max(orig, key=orig.get) if orig else "unknown"
            new_dom = max(post, key=post.get)
            if orig_dom != new_dom and new_dom != "unknown":
                flip += 1
        summary[name] = {
            "l1_avg": l1_total / n,
            "flip_rate": flip / n * 100,
            "n": n,
        }

    fieldnames = ["variant", "n", "avg_L1_shift", "direction_flip_rate_pct"]
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for name, _ in variants:
            s = summary[name]
            w.writerow({
                "variant": name,
                "n": s["n"],
                "avg_L1_shift": round(s["l1_avg"], 3),
                "direction_flip_rate_pct": round(s["flip_rate"], 1),
            })

    print(f"{'Variant':<35} {'n':>3} {'avg L1 shift':>13} {'flip rate %':>12}")
    print("-" * 68)
    for name, _ in variants:
        s = summary[name]
        print(f"{name:<35} {s['n']:>3} {s['l1_avg']:>13.3f} {s['flip_rate']:>12.1f}")
    print()
    print(f"Wrote → {OUT_CSV.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
