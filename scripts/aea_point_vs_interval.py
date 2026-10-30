"""Interval ordering versus point-estimate ordering on a simultaneous shock.

The paper's central methodological claim is that reporting an onset as an
*interval* rather than as a point is what prevents a simultaneous common
shock from being ordered at all.  This script measures that claim directly.

Two orderings of the same two series are compared:

``interval``
    the shipped rule: the two onsets are reported as the sets of split
    positions the data cannot distinguish, and a direction is committed only
    when those sets are disjoint.

``point``
    the comparator: the two onsets are reported as the single BIC-optimal
    split position, and a direction is committed whenever the two points
    differ.  This is the natural heuristic, and it is what the interval rule
    is designed to replace.

Both orderings then face the same remaining vetoes (persistence,
exclusivity, provenance, mirror), so the difference between them is
attributable to the ordering alone.

The generator plants a *simultaneous* pulse in both series.  There is no
direction in such a window: a common shock drives both series, so any
committed direction is a false commitment by construction.  The measure is
therefore the false-commit rate on windows where the truth is that no
direction exists.

Three geometric regimes are used, because the rate should depend on how
hard the simultaneity is to see: the pulse is placed at exactly the same
bucket in both series, at one bucket of jitter, and at two buckets.

Writes results/eval/aea_point_vs_interval.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.edge_ownership import (  # noqa: E402
    AEA_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    anchored_test,
    matched_horizon,
    protocol_hash,
)
from agents._segmentation import onset_interval  # noqa: E402
from agents.falsification_test import (  # noqa: E402
    clean,
    detect_changes,
)

K, TAU, MIN_SEG = 200, 110, 20
PULSE = 30


def ar1(rng: np.random.Generator, n: int, rho: float) -> np.ndarray:
    e = rng.normal(0.0, 1.0, n)
    x = np.zeros(n)
    for i in range(1, n):
        x[i] = rho * x[i - 1] + e[i]
    return x


def plant(rng: np.random.Generator, jitter: int, rho: float) -> Tuple[np.ndarray, np.ndarray]:
    """A pulse in both series, the second skewed by ``jitter`` buckets.

    ``rho`` is the lag-one dependence imposed on both count series.
    """
    r = rng.poisson(3.0, K).astype(float)
    t = rng.poisson(100.0, K).astype(float)
    r += np.abs(ar1(rng, K, rho)) * 0.5
    t += np.abs(ar1(rng, K, rho)) * 0.5
    r[TAU:TAU + PULSE] += 9.0
    t[TAU + jitter:TAU + jitter + PULSE] *= 1.8
    return r, t


def order_by(
    routing: np.ndarray,
    traffic: np.ndarray,
    *,
    interval: bool,
    cfg: Dict[str, Any],
) -> Optional[Tuple[str, np.ndarray, np.ndarray, Dict[str, Any], Dict[str, Any]]]:
    """Return the ordered pair under the requested rule, or None if unordered.

    ``interval`` reports the onset as the set of admissible split positions
    and commits a direction only when the two sets are disjoint.  ``point``
    reports the single BIC-optimal position and commits whenever the two
    positions differ.
    """
    K_ = min(len(routing), len(traffic))
    r, t = routing[:K_], traffic[:K_]
    min_seg = max(2, int(round(cfg["min_segment_frac"] * K_)))
    det_r = detect_changes(r, min_seg, cfg["bic_penalty"])
    det_t = detect_changes(t, min_seg, cfg["bic_penalty"])
    if not det_r["changes"] or abs(det_r["t_onset"]) < cfg["break_t_stat"]:
        return None
    if not det_t["changes"] or abs(det_t["t_onset"]) < cfg["break_t_stat"]:
        return None

    tau_r, tau_t = int(det_r["changes"][0]), int(det_t["changes"][0])
    if interval:
        ci_r = onset_interval(r, min_seg, det_r, cfg["bic_penalty"], cfg["onset_slack"])
        ci_t = onset_interval(t, min_seg, det_t, cfg["bic_penalty"], cfg["onset_slack"])
        if ci_r is None or ci_t is None:
            return None
        if ci_r[1] < ci_t[0]:
            return R2T, r, t, det_r, det_t
        if ci_t[1] < ci_r[0]:
            return T2R, t, r, det_t, det_r
        return None

    if tau_r != tau_t:
        if tau_r < tau_t:
            return R2T, r, t, det_r, det_t
        return T2R, t, r, det_t, det_r
    return None


def run(regime: str, trials: int, seed0: int, jitter: int, rho: float) -> Dict[str, Any]:
    rng = np.random.default_rng(seed0)
    cfg = dict(AEA_PROTOCOL)
    counts = {"interval": 0, "point": 0}
    ordered = {"interval": 0, "point": 0}
    for _ in range(trials):
        r_raw, t_raw = plant(rng, jitter, rho)
        r, t = clean(r_raw), clean(t_raw)
        for rule in ("interval", "point"):
            got = order_by(r, t, interval=(rule == "interval"), cfg=cfg)
            if got is None:
                continue
            ordered[rule] += 1
            direction, cause, response, det_c, det_o = got
            res = anchored_test(cause, response, det_c, det_o, cfg,
                                side="routing" if direction == R2T else "traffic",
                                routing_scope=None, series_scope=None)
            if not res["reason"]:
                counts[rule] += 1
    return {
        "regime": regime,
        "jitter_buckets": jitter,
        "rho": rho,
        "trials": trials,
        "ordered": ordered,
        "committed": counts,
        "false_commit_rate": {
            rule: (counts[rule] / trials if trials else None) for rule in counts
        },
        "seed0": seed0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--out", default=str(ROOT / "results/eval/aea_point_vs_interval.json"))
    args = ap.parse_args()

    regimes: List[Dict[str, Any]] = []
    for regime, jitter, rho in (
        ("simultaneous_independent", 0, 0.0),
        ("simultaneous_correlated", 0, 0.8),
        ("jitter_1_independent", 1, 0.0),
        ("jitter_1_correlated", 1, 0.8),
    ):
        rows = [run(regime, args.trials, 500_000 + 10_000 * i, jitter, rho)
                for i in range(3)]
        merged = {
            "regime": regime,
            "jitter_buckets": jitter,
            "rho": rho,
            "trials": args.trials * len(rows),
            "seeds": [r["seed0"] for r in rows],
        }
        for rule in ("interval", "point"):
            ordered = sum(r["ordered"][rule] for r in rows)
            committed = sum(r["committed"][rule] for r in rows)
            merged.setdefault("ordered", {})[rule] = ordered
            merged.setdefault("committed", {})[rule] = committed
            merged.setdefault("false_commit_rate", {})[rule] = round(
                committed / merged["trials"], 4)
        regimes.append(merged)

    out = {
        "estimator": "AEA",
        "protocol": AEA_PROTOCOL,
        "protocol_hash": protocol_hash(),
        "geometry": {"K": K, "tau": TAU, "min_seg": MIN_SEG, "pulse": PULSE,
                     "horizon": matched_horizon(TAU, K, MIN_SEG)},
        "regimes": regimes,
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"protocol {out['protocol_hash']}")
    for row in regimes:
        print(f"\n[{row['regime']}] jitter={row['jitter_buckets']} "
              f"rho={row['rho']} windows={row['trials']}")
        for rule in ("interval", "point"):
            print(f"  {rule:<9} ordered={row['ordered'][rule]:>4}  "
                  f"committed={row['committed'][rule]:>4}  "
                  f"false-commit rate={row['false_commit_rate'][rule]:.4f}")
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
