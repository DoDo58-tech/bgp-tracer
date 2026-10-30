"""Operating characteristics of AEA: V2 size, end-to-end power, common-shock safety.

Three measurements, all on synthetic geometry so the truth is known:

* ``size``    -- the V2 null with no planted effect, under AR(1) noise.  This is
  the same generator the FIT pilot used, so the numbers are directly
  comparable with the published operating point.
* ``power``   -- a routing burst followed by a lagged traffic drop.  Counts how
  often the estimator commits and how often the committed direction is right.
* ``common``  -- a *simultaneous* pulse in both series.  No direction is
  identifiable, so every commitment here is an error; V1 exists to make this
  rate zero.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents._segmentation import its_p_value  # noqa: E402
from agents.edge_ownership import (  # noqa: E402
    AEA_PROTOCOL,
    R2T,
    UNKNOWN,
    attribute,
    matched_horizon,
    protocol_hash,
)

#: Geometry of the synthetic windows.  ``K`` and ``TAU`` fix the window and
#: the cause onset; the response horizon is *not* fixed here, because the
#: engine derives it from the pre-onset capacity of each window
#: (``matched_horizon``).  Fixing it externally is what previously left the
#: harness with fewer placebos than ``alpha`` could resolve.
K, TAU, MIN_SEG = 200, 110, 20


def ar1(rng: np.random.Generator, n: int, rho: float) -> np.ndarray:
    e = rng.normal(0.0, 1.0, n)
    x = np.zeros(n)
    for i in range(1, n):
        x[i] = rho * x[i - 1] + e[i]
    return x


def effect_of(x: np.ndarray, tau: int, horizon: int) -> float:
    pre = x[:tau]
    t = np.arange(tau, dtype=float)
    if np.ptp(pre) < 1e-12:
        slope, intercept = 0.0, float(pre.mean())
    else:
        slope, intercept = np.polyfit(t, pre, 1)
    pred = intercept + slope * np.arange(tau, tau + horizon, dtype=float)
    return float(np.mean(x[tau:tau + horizon] - pred))


def run_size(rho: float, trials: int, seed0: int) -> Dict[str, Any]:
    rng = np.random.default_rng(seed0)
    horizon = matched_horizon(TAU, K, MIN_SEG)
    if horizon is None:
        raise RuntimeError("the geometry cannot support a matched-horizon test")
    hits = measured = 0
    for _ in range(trials):
        x = ar1(rng, K, rho)
        x = np.log1p(np.exp(x))
        effect = effect_of(x, TAU, horizon)
        p, n_placebos = its_p_value(x, TAU, effect, horizon, MIN_SEG)
        if n_placebos == 0:
            continue
        measured += 1
        if p < AEA_PROTOCOL["alpha"]:
            hits += 1
    return {
        "rho": rho,
        "trials": trials,
        "measured": measured,
        "rejections": hits,
        "rate": round(hits / measured, 4) if measured else None,
        "horizon": horizon,
        "seed0": seed0,
    }


def run_power(lag: int, drop: float, trials: int, seed0: int,
              pulse: int = 30) -> Dict[str, Any]:
    """Plant a routing burst and a traffic drop ``lag`` buckets later."""
    rng = np.random.default_rng(seed0)
    commits = correct = 0
    reasons: Dict[str, int] = {}
    for _ in range(trials):
        r = rng.poisson(3.0, K).astype(float)
        t = rng.poisson(100.0, K).astype(float)
        r[TAU:TAU + pulse] += 3.0 * 3.0
        t[TAU + lag:TAU + lag + pulse] *= (1.0 - drop)
        v = attribute(r, t)
        reasons[v.reason] = reasons.get(v.reason, 0) + 1
        if v.direction != UNKNOWN:
            commits += 1
            if v.direction == R2T:
                correct += 1
    return {
        "lag": lag,
        "drop": drop,
        "trials": trials,
        "commits": commits,
        "correct_direction": correct,
        "commit_rate": round(commits / trials, 4) if trials else None,
        "accuracy": round(correct / commits, 4) if commits else None,
        "reasons": dict(sorted(reasons.items())),
        "seed0": seed0,
    }


def run_common_shock(trials: int, seed0: int, pulse: int = 30) -> Dict[str, Any]:
    """A pulse in both series at the same instant: no direction exists."""
    rng = np.random.default_rng(seed0)
    commits = 0
    reasons: Dict[str, int] = {}
    for _ in range(trials):
        r = rng.poisson(3.0, K).astype(float)
        t = rng.poisson(100.0, K).astype(float)
        r[TAU:TAU + pulse] += 9.0
        t[TAU:TAU + pulse] *= 1.8
        v = attribute(r, t, routing_mechanism="withdrawal")
        reasons[v.reason] = reasons.get(v.reason, 0) + 1
        if v.direction != UNKNOWN:
            commits += 1
    return {
        "trials": trials,
        "commits": commits,
        "false_commit_rate": round(commits / trials, 4) if trials else None,
        "reasons": dict(sorted(reasons.items())),
        "seed0": seed0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--power-trials", type=int, default=200)
    ap.add_argument("--out", default=str(ROOT / "results/eval/aea_calibration.json"))
    args = ap.parse_args()

    size: List[Dict[str, Any]] = [
        run_size(rho, args.trials, 200_000 + 10_000 * i)
        for i, rho in enumerate((0.0, 0.5, 0.8))
    ]
    power: List[Dict[str, Any]] = [
        run_power(lag, drop, args.power_trials, 300_000 + 10_000 * i)
        for i, (lag, drop) in enumerate(
            [(lag, drop) for lag in (2, 4, 8, 16) for drop in (0.2, 0.5, 0.8)])
    ]
    common: List[Dict[str, Any]] = [
        run_common_shock(args.power_trials, 400_000 + 10_000 * i)
        for i in range(3)
    ]

    out = {
        "estimator": "AEA",
        "protocol": AEA_PROTOCOL,
        "protocol_hash": protocol_hash(),
        "geometry": {"K": K, "tau": TAU, "min_seg": MIN_SEG,
                     "horizon": matched_horizon(TAU, K, MIN_SEG),
                     "power_regime": {"routing_rate": 3.0, "traffic_rate": 100.0,
                                      "pulse": 30, "lag": 4}},
        "size": size,
        "power_counts": power,
        "common_shock": common,
        "power_total": {
            "cells": len(power),
            "commits": sum(r["commits"] for r in power),
            "correct": sum(r["correct_direction"] for r in power),
            "trials": sum(r["trials"] for r in power),
            "accuracy_among_commits": (
                round(sum(r["correct_direction"] for r in power)
                      / sum(r["commits"] for r in power), 4)
                if sum(r["commits"] for r in power) else None),
        },
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")

    print(f"protocol {out['protocol_hash']}")
    print(f"\nV2 size (no effect; target = alpha = {AEA_PROTOCOL['alpha']})")
    for row in size:
        print(f"  rho={row['rho']:<4} rejections={row['rejections']:>3}"
              f"/{row['measured']}  rate={row['rate']}")
    print("\nend-to-end power (planted routing burst -> traffic drop)")
    for row in power:
        print(f"  lag={row['lag']:<3} drop={row['drop']:<4} "
              f"commits={row['commits']:>3}/{row['trials']}"
              f"  accuracy={row['accuracy']}")
    print("\ncommon shock (no direction identifiable; false commits must be 0)")
    for row in common:
        print(f"  seed0={row['seed0']:<8} false commits={row['commits']:>3}"
              f"/{row['trials']}  rate={row['false_commit_rate']}")
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
