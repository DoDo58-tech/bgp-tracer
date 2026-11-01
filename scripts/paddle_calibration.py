"""Operating characteristics of PADDLE: size, end-to-end power, common-shock safety.

Three measurements, all on synthetic geometry so the truth is known:

* ``size``    -- the V2 null with no planted effect.  Two independent
  channels, neither of which moves, so every commitment is an error.
* ``power``   -- a control-plane edge followed by a lagged traffic drop.
  Counts how often the estimator commits and how often the committed
  direction is right.
* ``common``  -- a *simultaneous* move in both series.  No direction is
  identifiable, so every commitment here is an error; the precedence
  veto exists to make this rate small.

The geometry is built on the same wall-clock grid the estimator reads,
because the estimator's claim is that the two sides are measured at the
same moment against the same clock counterfactual.  A synthetic series
that ignored the clock would measure the estimator's arithmetic rather
than its method.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.control_plane import ControlPlaneSeries  # noqa: E402
from agents.paddle_attribution import (  # noqa: E402
    PADDLE_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    attribute,
    protocol_hash,
)

#: The width of one slot, in seconds.
STEP = 300
#: How many slots the event window holds.
K = 200
#: Where the cause happens, in slots.
TAU = 110
#: How many ordinary days the counterfactual is built from.
DAYS = 7
#: When the event window starts.
ORIGIN = datetime(2025, 1, 1, 0, 0)


def ar1(rng: np.random.Generator, n: int, rho: float) -> np.ndarray:
    e = rng.normal(0.0, 1.0, n)
    x = np.zeros(n)
    for i in range(1, n):
        x[i] = rho * x[i - 1] + e[i]
    return x


def build_series(
    event: np.ndarray,
    *,
    baseline: np.ndarray,
    channel: str = "own_volume",
    rng: np.random.Generator | None = None,
) -> ControlPlaneSeries:
    """A control plane carrying one instrumented channel.

    The event window and the baseline days are on the same grid, and the
    baseline is the ordinary days preceding the event.  Only the
    channel under test is instrumented, because a channel that was never
    measured is not a channel that measured zero.

    Each ordinary day is drawn separately.  A baseline that repeated
    one day exactly would make the placebo null degenerate: every
    placebo would show the same displacement, the null would have no
    spread, and the exclusivity test would have nothing to compare the
    incident against.  Real ordinary days differ from one another, and
    that difference is what the null measures.
    """
    stamps = [ORIGIN + timedelta(seconds=STEP * i) for i in range(K)]
    channels = {name: [0.0] * K for name in
                ("own_volume", "own_withdrawal", "volume",
                 "withdrawal", "origin_change", "path_change")}
    channels[channel] = [float(v) for v in event]

    buckets: Dict[datetime, Dict[str, float]] = {}
    baseline_stamps: List[datetime] = []
    day_values: List[np.ndarray] = []
    for day in range(1, DAYS + 1):
        base_day = ORIGIN - timedelta(days=day)
        if rng is None:
            values = baseline
        else:
            values = baseline * rng.uniform(0.4, 1.8, K)
        day_values.append(values)
        for i in range(K):
            stamp = base_day + timedelta(seconds=STEP * i)
            buckets[stamp] = {channel: float(values[i])}
            baseline_stamps.append(stamp)

    baseline_channels = {
        name: [0.0] * len(baseline_stamps) for name in channels
    }
    for i, stamp in enumerate(baseline_stamps):
        baseline_channels[channel][i] = float(
            day_values[i // K][i % K])

    return ControlPlaneSeries(
        stamps=stamps,
        channels=channels,
        baseline=baseline_channels,
        baseline_stamps=baseline_stamps,
        baseline_bucket_map=buckets,
        measured_channels=[channel],
    )


def build_response(values: np.ndarray, *, drop_at: int) -> List[Dict[str, Any]]:
    """The data plane: normal until ``drop_at``, then down.

    The historical mean is the level the traffic actually ran at before
    the drop, so the deviation the estimator reads is the size of the
    drop rather than the difference between the traffic level and an
    unrelated constant.
    """
    out = []
    baseline = float(np.median(values[:max(1, drop_at)])) if len(values) else 0.0
    for i in range(K):
        stamp = ORIGIN + timedelta(seconds=STEP * i)
        out.append({
            "timestamp": stamp,
            "raw_event": {
                "current_value": float(values[i]),
                "historical_mean": baseline,
            },
        })
    return out


def noisy_level(rng: np.random.Generator, n: int, level: float,
                noise: float = 0.05) -> np.ndarray:
    """A stable level with multiplicative noise.

    A count series whose every slot is an independent draw from a wide
    distribution is not a traffic series: its slot-to-slot variation
    dwarfs the drop it is supposed to carry, and no onset can be
    located in it.  Real traffic runs at a level and wobbles around it,
    so the noise is a small fraction of the level.
    """
    return level * (1.0 + rng.normal(0.0, noise, n))


def run_size(rho: float, trials: int, seed0: int) -> Dict[str, Any]:
    """No planted effect: both sides move on their own.

    The control plane carries ordinary day-to-day variation and the
    traffic carries the same variation, independently.  Neither series
    has an edge, so every commitment is a false commitment.
    """
    rng = np.random.default_rng(seed0)
    hits = measured = 0
    reasons: Dict[str, int] = {}
    for _ in range(trials):
        control = np.log1p(np.exp(ar1(rng, K, rho)))
        traffic = noisy_level(rng, K, 100.0)
        series = build_series(control, baseline=control, rng=rng)
        response = build_response(traffic, drop_at=TAU)
        verdict = attribute(series, response)
        reasons[verdict.reason] = reasons.get(verdict.reason, 0) + 1
        if verdict.direction != UNKNOWN:
            hits += 1
        measured += 1
    return {
        "rho": rho,
        "trials": trials,
        "measured": measured,
        "rejections": hits,
        "rate": round(hits / measured, 4) if measured else None,
        "reasons": dict(sorted(reasons.items())),
        "seed0": seed0,
    }


def run_power(lag: int, drop: float, trials: int, seed0: int,
              pulse: int = 30) -> Dict[str, Any]:
    """Plant a control-plane edge and a traffic drop ``lag`` slots later."""
    rng = np.random.default_rng(seed0)
    commits = correct = 0
    reasons: Dict[str, int] = {}
    for _ in range(trials):
        base = noisy_level(rng, K, 20.0)
        traffic = noisy_level(rng, K, 100.0)
        # The control plane is ordinary, then goes quiet.
        event = base.copy()
        event[TAU:TAU + pulse] *= 0.0
        traffic[TAU + lag:TAU + lag + pulse] *= (1.0 - drop)

        series = build_series(event, baseline=base, rng=rng)
        response = build_response(traffic, drop_at=TAU + lag)
        verdict = attribute(series, response)
        reasons[verdict.reason] = reasons.get(verdict.reason, 0) + 1
        if verdict.direction != UNKNOWN:
            commits += 1
            if verdict.direction == R2T:
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


def run_common(lag: int, trials: int, seed0: int,
               pulse: int = 30) -> Dict[str, Any]:
    """A *simultaneous* move in both series.

    No direction exists, so every commitment is an error.  With a zero
    lag the two sides move together and the precedence veto has nothing
    to order; with a one-slot skew the order exists but is an artefact
    of the resolution, which is the boundary of the claim.
    """
    rng = np.random.default_rng(seed0)
    commits = 0
    reasons: Dict[str, int] = {}
    for _ in range(trials):
        base = noisy_level(rng, K, 20.0)
        traffic = noisy_level(rng, K, 100.0)
        event = base.copy()
        event[TAU:TAU + pulse] *= 0.0
        traffic[TAU + lag:TAU + lag + pulse] *= 0.5

        series = build_series(event, baseline=base, rng=rng)
        response = build_response(traffic, drop_at=TAU + lag)
        verdict = attribute(series, response)
        reasons[verdict.reason] = reasons.get(verdict.reason, 0) + 1
        if verdict.direction != UNKNOWN:
            commits += 1
    return {
        "lag": lag,
        "trials": trials,
        "commits": commits,
        "false_commit_rate": round(commits / trials, 4) if trials else None,
        "reasons": dict(sorted(reasons.items())),
        "seed0": seed0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "results/eval/paddle_calibration.json"))
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--size-trials", type=int, default=400)
    args = ap.parse_args()

    size = [run_size(rho, args.size_trials, 1000 + i)
            for i, rho in enumerate((0.0, 0.5, 0.8))]

    power: List[Dict[str, Any]] = []
    for lag in (2, 4, 8, 16):
        for drop in (0.2, 0.5, 0.8):
            power.append(run_power(lag, drop, args.trials,
                                   2000 + lag * 10 + int(drop * 10)))

    common = [
        run_common(0, args.trials, 3000),
        run_common(1, args.trials, 3001),
    ]

    cells = len(power)
    commits = sum(cell["commits"] for cell in power)
    correct = sum(cell["correct_direction"] for cell in power)
    out = {
        "estimator": "PADDLE",
        "protocol": PADDLE_PROTOCOL,
        "protocol_hash": protocol_hash(),
        "geometry": {
            "K": K,
            "tau": TAU,
            "days": DAYS,
            "step_seconds": STEP,
        },
        "size": size,
        "power": power,
        "power_total": {
            "cells": cells,
            "trials": sum(cell["trials"] for cell in power),
            "commits": commits,
            "correct": correct,
            "accuracy_among_commits": round(correct / commits, 4) if commits else None,
        },
        "common": common,
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({
        "size": [{k: s[k] for k in ("rho", "rate")} for s in size],
        "power_total": out["power_total"],
        "common": [{k: c[k] for k in ("lag", "false_commit_rate")}
                   for c in common],
    }, indent=1))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
