"""FIT -- Falsification-based Identification Test for causal direction."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

R2T = "routing_to_traffic"
T2R = "traffic_to_routing"
UNKNOWN = "unknown"

#: Frozen decision rule.  Changing any value changes the operating point and
#: must be reported as a new protocol (the evaluator prints a hash of this dict).
PROTOCOL: Dict[str, Any] = {
    "min_buckets": 12,          # below this the series cannot support a split
    "min_segment_frac": 0.10,   # each side of a split holds >= 10% of the window
    "break_t_stat": 2.0,        # |Welch t| needed to call a break
    "bic_penalty": 1.0,         # multiplier on the BIC penalty for extra changes
    "max_placebos": 60,         # placebo onsets enumerated for the P2 null
    "min_placebos": 20,         # below this the p-value cannot reach alpha
    "alpha": 0.05,              # level of the single P2 test: P1 fixes direction
    "recovery_tol_frac": 1.0 / 12.0,
}


# Helpers
def clean(series: Sequence[float]) -> np.ndarray:
    x = np.asarray(list(series), dtype=float)
    if x.ndim != 1:
        raise ValueError("series must be one-dimensional")
    x = np.where(np.isfinite(x), x, 0.0)
    # Event counts are heavy-tailed; log1p keeps one burst from dominating the
    # variance while preserving order and zero structure.
    return np.log1p(np.clip(x, 0.0, None))


def prefix(x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    c1 = np.concatenate(([0.0], np.cumsum(x)))
    c2 = np.concatenate(([0.0], np.cumsum(x * x)))
    return c1, c2


def welch_t(x: np.ndarray, idx: np.ndarray, lo: int, hi: int) -> np.ndarray:
    """Welch t for every split in ``idx`` within the window ``x[lo:hi]``."""
    c1, c2 = prefix(x)
    n1 = idx.astype(float) - lo
    n2 = hi - idx.astype(float)
    m1 = (c1[idx] - c1[lo]) / n1
    m2 = (c1[hi] - c1[idx]) / n2
    v1 = np.maximum((c2[idx] - c2[lo]) / n1 - m1 * m1, 0.0)
    v2 = np.maximum((c2[hi] - c2[idx]) / n2 - m2 * m2, 0.0)
    # Bessel correction keeps the statistic finite for tiny segments.
    v1 *= n1 / np.maximum(n1 - 1.0, 1.0)
    v2 *= n2 / np.maximum(n2 - 1.0, 1.0)
    denom = np.sqrt(v1 / n1 + v2 / n2)
    with np.errstate(divide="ignore", invalid="ignore"):
        t = np.where(denom > 1e-12, (m2 - m1) / denom, 0.0)
    return t


def seg_sse(c1: np.ndarray, c2: np.ndarray, i: int, j: int) -> float:
    """Sum of squared deviations inside ``x[i:j]`` from its own mean."""
    n = j - i
    if n <= 0:
        return 0.0
    s = c1[j] - c1[i]
    return float(max((c2[j] - c2[i]) - s * s / n, 0.0))


def bic(sse: float, n: int, k: int) -> float:
    return n * float(np.log(max(sse, 1e-12) / n)) + k * float(np.log(n))


def detect_changes(
    x: np.ndarray,
    min_seg: int,
    bic_penalty: float = 1.0,
) -> Dict[str, Any]:
    """Piecewise-constant segmentation with 0, 1 or 2 changes, chosen by BIC.
    
    Returns a dict with ``model``, ``changes`` (0, 1 or 2 positions),
    ``means`` (one more than ``len(changes)``), ``jumps`` (at each change),
    ``t_onset`` and ``sse``."""
    K = len(x)
    c1, c2 = prefix(x)
    logK = float(np.log(K))

    best: Dict[str, Any] = {
        "model": 0,
        "changes": [],
        "means": [float(x.mean())],
        "jumps": [],
        "t_onset": 0.0,
        "sse": seg_sse(c1, c2, 0, K),
        "bic": bic(seg_sse(c1, c2, 0, K), K, 2),
    }

# M1: one change
    a_grid = np.arange(min_seg, K - min_seg + 1)
    if a_grid.size:
        sse1 = np.array([seg_sse(c1, c2, 0, int(a)) + seg_sse(c1, c2, int(a), K)
                         for a in a_grid])
        bic1 = K * np.log(np.maximum(sse1, 1e-12) / K) + 4 * logK * bic_penalty
        k = int(np.argmin(bic1))
        if bic1[k] < best["bic"]:
            a = int(a_grid[k])
            m0, m1 = float(x[:a].mean()), float(x[a:].mean())
            best.update(model=1, changes=[a], means=[m0, m1],
                        jumps=[m1 - m0], sse=float(sse1[k]),
                        bic=float(bic1[k]))

# M2: two changes (pulse)
    a_lo, a_hi = min_seg, K - 2 * min_seg
    if a_hi >= a_lo:
        for a in range(a_lo, a_hi + 1):
            b_grid = np.arange(a + min_seg, K - min_seg + 1)
            if b_grid.size == 0:
                continue
            sse_mid = (c2[b_grid] - c2[a]) - (c1[b_grid] - c1[a]) ** 2 / (b_grid - a)
            sse_tail = (c2[K] - c2[b_grid]) - (c1[K] - c1[b_grid]) ** 2 / (K - b_grid)
            sse2 = seg_sse(c1, c2, 0, a) + np.maximum(sse_mid, 0.0) + np.maximum(sse_tail, 0.0)
            bic2 = K * np.log(np.maximum(sse2, 1e-12) / K) + 6 * logK * bic_penalty
            k = int(np.argmin(bic2))
            if bic2[k] < best["bic"]:
                b = int(b_grid[k])
                m0, m1, m2 = (float(x[:a].mean()), float(x[a:b].mean()),
                              float(x[b:].mean()))
                best.update(model=2, changes=[a, b], means=[m0, m1, m2],
                            jumps=[m1 - m0, m2 - m1], sse=float(sse2[k]),
                            bic=float(bic2[k]))

    if best["changes"]:
        a = best["changes"][0]
        best["t_onset"] = float(welch_t(
            x, np.array([a]), 0, K)[0])
    return best


def its_effect(x: np.ndarray, tau: int, horizon: int, min_seg: int) -> Optional[float]:
    """Interrupted-time-series effect: post mean minus pre-trend extrapolation."""
    pre = x[:tau]
    post = x[tau:tau + horizon]
    if len(pre) < max(2 * min_seg, 3) or len(post) < min_seg:
        return None
    tt = np.arange(len(pre), dtype=float)
    # Degenerate pre-period (constant): slope 0, intercept = mean.
    if np.ptp(pre) < 1e-12:
        slope, intercept = 0.0, float(pre.mean())
    else:
        slope, intercept = np.polyfit(tt, pre, 1)
    pred = intercept + slope * np.arange(tau, tau + len(post), dtype=float)
    return float(np.mean(post - pred))


def its_p_value(
    response: np.ndarray,
    tau: int,
    effect: float,
    horizon: int,
    min_seg: int,
    max_placebos: int = 60,
    min_placebos: int = 20,
) -> Tuple[float, int]:
    """Placebo-in-time p-value for the interrupted-time-series effect.

    The p-value is the exact permutation p-value with the add-one
    correction, ``(1 + #{|e_b| >= |e|}) / (B + 1)``: the response series is
    re-estimated at every placebo onset with the same horizon and the same
    estimator, and the candidate effect is compared against that empirical
    null.  The add-one correction is required because an empirical p-value of
    exactly zero is not an attainable probability at any finite B.

    Returns ``(p, n_placebos)``; ``n_placebos == 0`` means the pre-period is too
    short to test, and the caller must abstain rather than assume."""
    n_total = len(response)
    first = 2 * min_seg
    last = tau - horizon
    if last < first or horizon < min_seg or tau + horizon > n_total:
        return 1.0, 0
    positions = list(range(first, last + 1))
    if len(positions) > max_placebos:
        step = int(np.ceil(len(positions) / max_placebos))
        positions = positions[::step]

    # Every placebo uses exactly the horizon under test.  Mixing horizons would
    null: List[float] = []
    for p_tau in positions:
        e = its_effect(response, p_tau, horizon, min_seg)
        if e is not None:
            null.append(abs(e))
    if len(null) < min_placebos:
        return 1.0, 0

    # Exact permutation test: the candidate effect is ranked against the
    # empirical null of the same estimator at the placebo onsets.  The
    # add-one correction keeps the smallest attainable p-value at 1/(B+1).
    exceedances = sum(1 for v in null if v >= abs(effect))
    p = (1.0 + exceedances) / (len(null) + 1.0)
    return min(1.0, p), len(null)


def recovery_of(det: Dict[str, Any]) -> Optional[int]:
    """Recovery edge of a detected pulse, or ``None`` for a step/flat series."""
    if det["model"] < 2:
        return None
    j0, j1 = det["jumps"]
    if j0 == 0 or np.sign(j0) == np.sign(j1):
        return None
    return int(det["changes"][1])


# Result object
@dataclass
class FITResult:
    direction: str = UNKNOWN
    reason: str = ""
    tau_routing: Optional[int] = None
    tau_traffic: Optional[int] = None
    lag: Optional[int] = None
    t_routing: float = 0.0
    t_traffic: float = 0.0
    effect: Optional[float] = None
    p_value: float = 1.0
    n_placebos: int = 0
    tests: Dict[str, Any] = field(default_factory=dict)
    protocol: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self, include_protocol: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "direction": self.direction,
            "reason": self.reason,
            "tau_routing": self.tau_routing,
            "tau_traffic": self.tau_traffic,
            "lag": self.lag,
            "t_routing": round(self.t_routing, 3),
            "t_traffic": round(self.t_traffic, 3),
            "effect": round(self.effect, 4) if self.effect is not None else None,
            "p_value": round(self.p_value, 6) if self.p_value == self.p_value else None,
            "n_placebos": self.n_placebos,
            "tests": self.tests,
        }
        if include_protocol:
            out["protocol"] = self.protocol
        return out


def infer_direction(
    routing_series: Sequence[float],
    traffic_series: Sequence[float],
    *,
    protocol: Optional[Dict[str, Any]] = None,
) -> FITResult:
    """Return the direction that survives P1-P3, or an abstention with a reason."""
    cfg = dict(PROTOCOL)
    if protocol:
        cfg.update(protocol)

    r = clean(routing_series)
    t = clean(traffic_series)
    K = int(min(len(r), len(t)))
    res = FITResult(protocol={k: cfg[k] for k in sorted(cfg)})

    if K < cfg["min_buckets"]:
        res.reason = "series_too_short"
        return res
    r, t = r[:K], t[:K]
    if np.ptp(r) < 1e-9:
        res.reason = "routing_series_flat"
        return res
    if np.ptp(t) < 1e-9:
        res.reason = "traffic_series_flat"
        return res

    min_seg = max(2, int(round(cfg["min_segment_frac"] * K)))

# P1: ordering
    det_r = detect_changes(r, min_seg, cfg["bic_penalty"])
    det_t = detect_changes(t, min_seg, cfg["bic_penalty"])
    if not det_r["changes"]:
        res.reason = "no_routing_break"
        return res
    if not det_t["changes"]:
        res.reason = "no_traffic_break"
        return res
    tau_r, tau_t = int(det_r["changes"][0]), int(det_t["changes"][0])
    res.tau_routing, res.tau_traffic = tau_r, tau_t
    res.t_routing, res.t_traffic = det_r["t_onset"], det_t["t_onset"]

    if abs(det_r["t_onset"]) < cfg["break_t_stat"]:
        res.reason = "no_routing_break"
        return res
    if abs(det_t["t_onset"]) < cfg["break_t_stat"]:
        res.reason = "no_traffic_break"
        return res

    if tau_r == tau_t:
        # Same bucket: the data cannot order the two changes, so the direction
        # is not identified.  This is the case a vote would have decided by
        # weight; FIT refuses.
        res.reason = "simultaneous_breaks"
        return res

    routing_first = tau_r < tau_t
    if routing_first:
        cause, response, det_c, det_o = r, t, det_r, det_t
    else:
        cause, response, det_c, det_o = t, r, det_t, det_r
    tau_c, tau_o = int(det_c["changes"][0]), int(det_o["changes"][0])
    res.lag = tau_o - tau_c

    # The onset comes from the cause series, not from the response's own
    pre_capacity = tau_c - 2 * min_seg
    if pre_capacity < 2 * min_seg:
        res.reason = "pre_period_too_short"
        return res
    horizon = min(K - tau_c, pre_capacity // 2)
    effect = its_effect(response, tau_c, horizon, min_seg)
    if effect is None:
        # Defensive only: with the two geometry checks above (tau_c >= 4*min_seg
        res.reason = "post_window_too_short"
        return res
    p, n_placebos = its_p_value(
        response, tau_c, effect, horizon, min_seg,
        max_placebos=int(cfg["max_placebos"]), min_placebos=int(cfg["min_placebos"]),
    )
    res.effect, res.p_value, res.n_placebos = effect, p, n_placebos
    if n_placebos == 0:
        res.reason = "pre_period_too_short"
        return res

    # Only one direction is testable: P1 already excluded the other.  Alpha is
    # therefore spent once, as pre-registered, not halved post hoc.
    if p >= cfg["alpha"]:
        res.reason = "effect_not_significant"
        res.tests["p1"] = {"tau_routing": tau_r, "tau_traffic": tau_t,
                           "lag": res.lag, "routing_first": routing_first}
        res.tests["p2"] = {"effect": round(effect, 4), "p": round(p, 4),
                           "placebos": n_placebos, "horizon": horizon}
        return res

# P3: recovery consistency
    rec_c = recovery_of(det_c)
    rec_o = recovery_of(det_o)
    tol = max(2, int(round(cfg["recovery_tol_frac"] * K)))
    p3: Dict[str, Any] = {
        "cause_recovery": rec_c,
        "response_recovery": rec_o,
        "tolerance": tol,
    }
    if rec_c is not None and rec_o is not None:
        if abs(rec_c - rec_o) > tol:
            res.reason = "recovery_misaligned"
            res.tests["p3"] = p3
            return res
        p3["verdict"] = "aligned"
    elif rec_c is not None or rec_o is not None:
        p3["verdict"] = "partial"
    else:
        p3["verdict"] = "no_recovery_information"

    res.tests["p1"] = {"tau_routing": tau_r, "tau_traffic": tau_t,
                       "lag": res.lag, "routing_first": routing_first}
    res.tests["p2"] = {"effect": round(effect, 4), "p": round(p, 4),
                       "placebos": n_placebos, "horizon": horizon}
    res.tests["p3"] = p3
    res.direction = R2T if routing_first else T2R
    res.reason = "committed"
    return res


__all__ = ["FITResult", "PROTOCOL", "infer_direction", "R2T", "T2R", "UNKNOWN"]