"""Measure the operating characteristics of FIT's P2 test."""
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

from agents.falsification_test import (  # noqa: E402
    PROTOCOL,
    UNKNOWN,
    its_p_value,
    infer_direction,
)

#: Placebo-friendly geometry: the tested horizon is capped by the pre-baseline,
#: so K=200 at tau=110 leaves 11 matched-horizon placebos of length 60.
K, TAU, HORIZON, MIN_SEG = 200, 110, 60, 20


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


def run(rho: float, amp: float, trials: int, seed0: int) -> Dict[str, Any]:
    rng = np.random.default_rng(seed0)
    hits = measured = 0
    for _ in range(trials):
        x = ar1(rng, K, rho)
        if amp:
            x[TAU:] += amp
        x = np.log1p(np.exp(x))          # positive, like an event-count series
        effect = effect_of(x, TAU, HORIZON)
        p, n_placebos = its_p_value(x, TAU, effect, HORIZON, MIN_SEG)
        if n_placebos == 0:
            continue                     # geometry did not admit a placebo
        measured += 1
        if p < PROTOCOL["alpha"]:
            hits += 1
    return {
        "rho": rho,
        "amp": amp,
        "trials": trials,
        "measured": measured,
        "rejections": hits,
        "rate": round(hits / measured, 4) if measured else None,
        "seed0": seed0,
    }


def run_count_power(drop: float, trials: int, seed0: int,
                    pulse: int = 30, lag: int = 4) -> Dict[str, Any]:
    """Plant a routing burst and a lagged traffic drop on sparse counts."""
    rng = np.random.default_rng(seed0)
    commits = correct = 0
    for _ in range(trials):
        r = rng.poisson(3.0, K).astype(float)
        t = rng.poisson(100.0, K).astype(float)
        r[TAU:TAU + pulse] += 3.0 * 3.0
        t[TAU + lag:TAU + lag + pulse] *= (1.0 - drop)
        res = infer_direction(r, t)
        if res.direction != UNKNOWN:
            commits += 1
            if res.direction == "routing_to_traffic":
                correct += 1
    return {
        "drop": drop,
        "trials": trials,
        "commits": commits,
        "correct_direction": correct,
        "commit_rate": round(commits / trials, 4) if trials else None,
        "accuracy": round(correct / commits, 4) if commits else None,
        "seed0": seed0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--power-trials", type=int, default=200)
    ap.add_argument("--out", default=str(ROOT / "results/eval/fit_calibration.json"))
    args = ap.parse_args()

    size: List[Dict[str, Any]] = []
    for i, rho in enumerate((0.0, 0.5, 0.8)):
        size.append(run(rho, 0.0, args.trials, 200_000 + 10_000 * i))

    power: List[Dict[str, Any]] = []
    for i, drop in enumerate((0.2, 0.5, 0.8)):
        power.append(run_count_power(drop, args.power_trials,
                                     300_000 + 10_000 * i))

    out = {
        "protocol": PROTOCOL,
        "geometry": {"K": K, "tau": TAU, "horizon": HORIZON,
                     "min_seg": MIN_SEG,
                     "power_regime": {"routing_rate": 3.0,
                                      "traffic_rate": 100.0,
                                      "pulse": 30, "lag": 4}},
        "size": size,
        "power_counts": power,
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")

    print(f"{'size':<14}{'rho':>6}{'trials':>8}{'measured':>10}"
          f"{'rejects':>9}{'rate':>8}")
    print("-" * 55)
    for row in size:
        print(f"{'size':<14}{row['rho']:>6.1f}{row['trials']:>8}"
              f"{row['measured']:>10}{row['rejections']:>9}{row['rate']:>8.3f}")
    print()
    print(f"{'power (counts)':<14}{'drop':>6}{'trials':>8}{'commits':>10}"
          f"{'correct':>9}{'rate':>8}")
    print("-" * 55)
    for row in power:
        print(f"{'power (counts)':<14}{row['drop']:>6.1f}{row['trials']:>8}"
              f"{row['commits']:>10}{row['correct_direction']:>9}"
              f"{row['commit_rate']:>8.3f}")
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())