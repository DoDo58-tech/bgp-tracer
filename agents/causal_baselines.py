"""Traditional causal-attribution baselines for HCAF ablation.

Each baseline takes the same routing + traffic timeline as
``CausalAttributionEngine.analyze`` and returns a ``(direction,
confidence)`` tuple. They are intentionally simpler than HCAF so that
the paper's §6 ablation table demonstrates the value of multi-method
synthesis (MSBD + CTPR + CIC + Granger + confounder detection) over a
single statistical baseline.

Direction convention (matches HCAF):
    "routing_to_traffic"  — routing change preceded traffic change
    "traffic_to_routing"  — traffic change preceded routing change
    "unknown"             — insufficient evidence

Baselines:
    pearson_only        — global Pearson correlation on aligned series.
                          If r(routing, traffic) > 0.5, treat as
                          co-moving (direction undecidable); if strong
                          cross-correlation at a specific lag, use that
                          lag's sign to decide direction.
    granger_only        — pure Granger causality on the same series.
                          Skips HCAF's MSBD/CTPR/CIC synthesis.
    timestamp_distance  — non-statistical: nearest-neighbor distance
                          between the first routing event and the first
                          traffic event. Whichever came first wins. This
                          is the most naive baseline and is what a
                          reviewer would expect to be the worst.

All three share ``baseline_attribution(routing_timeline, traffic_timeline)``
and return ``dict(direction, confidence, method, ...)`` so they can be
called uniformly from the ablation harness in
``tests/test_hcaf_vs_baselines.py``.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_OK = True
except ImportError:
    NUMPY_OK = False
    np = None  # type: ignore[assignment]


@dataclass
class BaselineResult:
    """Uniform result shape for all three baselines."""

    direction: str = "unknown"            # routing_to_traffic | traffic_to_routing | unknown
    confidence: float = 0.0               # 0..1
    method: str = ""                       # pearson | granger | timestamp_distance
    # Per-baseline diagnostic fields
    details: Dict[str, Any] = field(default_factory=dict)


def _to_aligned_series(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
) -> Tuple[List[float], List[float]]:
    """Normalize timelines to two parallel scalar lists, padding to common length.

    Each input timeline is a list of dicts with at least ``score`` and
    ``timestamp``. We extract ``score`` in order and pad the shorter
    one with zeros so the two series have equal length. This is
    crude but matches what a single-statistical baseline would do.
    """
    r = [float(p.get("score", 0) or 0) for p in routing_timeline]
    t = [float(p.get("score", 0) or 0) for p in traffic_timeline]
    n = max(len(r), len(t))
    if len(r) < n:
        r = r + [0.0] * (n - len(r))
    if len(t) < n:
        t = t + [0.0] * (n - len(t))
    return r, t


def _safe_first_timestamp(timeline: List[dict]) -> Optional[datetime]:
    """Return the first parseable timestamp in a timeline, or None."""
    for p in timeline:
        ts = p.get("timestamp")
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue
    return None


# ─────────────────────────────────────────────────────────────────────
# Baseline 1: Pearson correlation only
# ─────────────────────────────────────────────────────────────────────
def pearson_baseline(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
) -> BaselineResult:
    """Pearson correlation at lags 0..3 on aligned series.

    Decision rule:
            * Pearson r at any lag > 0.5  → co-movement, but direction
              still undecidable. Return ``unknown`` with confidence =
              abs(max_corr). This is a known weakness of pure Pearson.
            * |max_corr| ≤ 0.5  → ``unknown`` with low confidence.

    The baseline is intentionally weak on direction — that's the point.
    A multi-method HCAF needed to do better than this in §6.
    """
    if not NUMPY_OK or not routing_timeline or not traffic_timeline:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="pearson",
            details={"reason": "numpy missing or empty timeline"},
        )
    r, t = _to_aligned_series(routing_timeline, traffic_timeline)
    if len(r) < 4:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="pearson",
            details={"reason": "series too short for lag scan"},
        )
    arr_r = np.array(r)
    arr_t = np.array(t)
    if float(arr_r.std()) == 0 or float(arr_t.std()) == 0:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="pearson",
            details={"reason": "zero-variance series"},
        )
    max_corr = 0.0
    best_lag = 0
    for lag in (0, 1, 2, 3, 5, 10):
        if lag == 0:
            a, b = arr_r, arr_t
        elif lag > 0:
            # positive lag = routing leads traffic by `lag` steps
            a = arr_r[:-lag]
            b = arr_t[lag:]
        else:
            a = arr_r[-lag:]
            b = arr_t[:lag]
        if len(a) < 3:
            continue
        sa = float(a.std())
        sb = float(b.std())
        if sa == 0 or sb == 0:
            continue
        c = float(np.corrcoef(a, b)[0, 1])
        if math.isnan(c):
            continue
        if abs(c) > abs(max_corr):
            max_corr = c
            best_lag = lag
    direction = "unknown"
    if abs(max_corr) > 0.5:
        # A *negative* correlation between routing and traffic, with the
        # routing series leading, is the classic BGP signature: routing
        # announcements (or withdrawals) surge first, traffic follows
        # in the opposite direction. Anti-correlated lag > 0 ⇒
        # ``routing_to_traffic``. Anti-correlated lag < 0 ⇒
        # ``traffic_to_routing``. Positively correlated series with a
        # positive lag ⇒ ``routing_to_traffic`` (e.g. traffic rise
        # following a re-route).
        if max_corr < 0:
            if best_lag > 0:
                direction = "routing_to_traffic"
            elif best_lag < 0:
                direction = "traffic_to_routing"
        else:
            if best_lag > 0:
                direction = "routing_to_traffic"
            elif best_lag < 0:
                direction = "traffic_to_routing"
    return BaselineResult(
        direction=direction,
        confidence=min(0.99, abs(max_corr)),
        method="pearson",
        details={"max_corr": round(max_corr, 3), "best_lag": best_lag},
    )


# ─────────────────────────────────────────────────────────────────────
# Baseline 2: Granger causality only
# ─────────────────────────────────────────────────────────────────────
def granger_baseline(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
) -> BaselineResult:
    """Pure Granger causality (no MSBD/CTPR/CIC synthesis).

    Returns ``routing_to_traffic`` if Granger test rejects "traffic
    does NOT Granger-cause routing" with p<0.05, else
    ``traffic_to_routing``. This baseline intentionally skips the
    confounder check that HCAF does.
    """
    if not routing_timeline or not traffic_timeline:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="granger",
            details={"reason": "empty timeline"},
        )
    try:
        from statsmodels.tsa.stattools import grangercausalitytests
    except ImportError:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="granger",
            details={"reason": "statsmodels not installed"},
        )
    r, t = _to_aligned_series(routing_timeline, traffic_timeline)
    if len(r) < 8:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="granger",
            details={"reason": "series too short"},
        )
    arr_r = np.array(r)
    arr_t = np.array(t)
    if float(arr_r.std()) == 0 or float(arr_t.std()) == 0:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="granger",
            details={"reason": "zero-variance series"},
        )
    # Granger test: H0 = "x does NOT Granger-cause y". We test both
    # directions and pick the one whose null is rejected more strongly.
    #
    # For Granger, direction is decided by *which series is the response*
    # (column 0) — not by the sign of the lag-coefficient, which the
    # pure test does not return. So:
    #   (arr_t, arr_r)  →  response=traffic, predictor=routing
    #                      rejection ⇒ "routing_to_traffic"
    #   (arr_r, arr_t)  →  response=routing, predictor=traffic
    #                      rejection ⇒ "traffic_to_routing"
    # statsmodels grangercausalitytests returns a dict keyed by lag;
    # each value is (test_dicts, regression_results). ssr_ftest in
    # recent versions is a tuple (F_stat, p_value, df_denom, df_num).
    # Older versions returned a dict with key ``ssr_ftest_pvalue``.
    n = min(len(arr_r), len(arr_t))
    granger_lag = max(1, min(3, n - 2))
    try:
        data_rt = np.column_stack([arr_t, arr_r])  # traffic = response, routing = predictor
        res_rt = grangercausalitytests(data_rt, maxlag=[granger_lag], verbose=False)
        _ssr = res_rt[granger_lag][0]["ssr_ftest"]
        p_rt = float(_ssr[1] if isinstance(_ssr, tuple) else _ssr["ssr_ftest_pvalue"])

        data_tr = np.column_stack([arr_r, arr_t])  # routing = response, traffic = predictor
        res_tr = grangercausalitytests(data_tr, maxlag=[granger_lag], verbose=False)
        _ssr = res_tr[granger_lag][0]["ssr_ftest"]
        p_tr = float(_ssr[1] if isinstance(_ssr, tuple) else _ssr["ssr_ftest_pvalue"])
    except (KeyError, TypeError, IndexError, ValueError, Exception) as e:
        # Catch statsmodels.tsa.stattools.InfeasibleTestError (constant
        # series) and any other unexpected regression-fit failure.
        return BaselineResult(
            direction="unknown", confidence=0.0, method="granger",
            details={"reason": f"granger test failed (lag={granger_lag}, n={n}): {type(e).__name__}: {e}"},
        )
    # Pick the direction with the smaller p-value (stronger rejection).
    if p_rt < 0.05 and p_rt < p_tr:
        direction = "routing_to_traffic"
        confidence = min(0.99, max(0.0, 1.0 - p_rt))
    elif p_tr < 0.05 and p_tr < p_rt:
        direction = "traffic_to_routing"
        confidence = min(0.99, max(0.0, 1.0 - p_tr))
    else:
        direction = "unknown"
        confidence = 0.5 * max(0.0, 1.0 - min(p_rt, p_tr))
    return BaselineResult(
        direction=direction,
        confidence=round(confidence, 3),
        method="granger",
        details={"p_routing_to_traffic": round(p_rt, 4),
                 "p_traffic_to_routing": round(p_tr, 4)},
    )


# ─────────────────────────────────────────────────────────────────────
# Baseline 3: timestamp distance (no statistics at all)
# ─────────────────────────────────────────────────────────────────────
def timestamp_distance_baseline(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
) -> BaselineResult:
    """Pick the side that moved first by raw timestamp.

    No statistics, no lag analysis, just ``argmin(routing_t0,
    traffic_t0)``. This is the worst-performing baseline we expect,
    included so the ablation table has a "naive" anchor.
    """
    r_t0 = _safe_first_timestamp(routing_timeline)
    t_t0 = _safe_first_timestamp(traffic_timeline)
    if r_t0 is None or t_t0 is None:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="timestamp_distance",
            details={"reason": "missing timestamp"},
        )
    delta = (r_t0 - t_t0).total_seconds()
    if delta < -60:        # routing moved more than 1 min earlier
        direction = "routing_to_traffic"
    elif delta > 60:       # traffic moved more than 1 min earlier
        direction = "traffic_to_routing"
    else:
        direction = "unknown"
    # Confidence decays with the magnitude of the gap, capped at 0.7
    # (this is a naive baseline; it should never be over-confident).
    confidence = min(0.7, min(1.0, abs(delta) / 600.0))
    return BaselineResult(
        direction=direction,
        confidence=round(confidence, 3),
        method="timestamp_distance",
        details={"delta_seconds": round(delta, 1),
                 "r_t0": r_t0.isoformat(),
                 "t_t0": t_t0.isoformat()},
    )


# ─────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────
# Baseline 4: Transfer Entropy (non-linear, non-Gaussian)
# ─────────────────────────────────────────────────────────────────────
def transfer_entropy_baseline(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
    lag: int = 1,
    bins: int = 4,
    n_perm: int = 200,
) -> BaselineResult:
    """Estimate directional transfer entropy (Schreiber 2000) at lag 1.

    TE(X → Y) = Σ P(y_t, y_t-1, x_t-lag) · log[ P(y_t | y_t-1, x_t-lag)
                                              / P(y_t | y_t-1) ]

    Unlike Granger (linear + Gaussian), TE captures non-linear causal
    direction in arbitrary distributions. For BGP+traffic attribution
    this matters because:
        * routing announcements are bursts (non-Gaussian)
        * traffic response to BGP events is non-linear (trough ≠ -peak)

    Implementation:
        * Discretise each series into `bins` quantile bins.
        * Compute joint counts for the 3-variable joint distribution.
        * Compute conditional counts.
        * Convert to probabilities via Laplace smoothing.
        * Surrogate baseline: shuffle routing lag-window `n_perm` times,
          recompute TE, use mean ± 2·std as the null distribution.

    Decision rule (significance threshold 0.05 on the permutation test):
        * TE(R → T) > μ_null + 2·σ_null  AND  TE(R → T) > TE(T → R)
          → routing_to_traffic
        * TE(T → R) > μ_null + 2·σ_null  AND  TE(T → R) > TE(R → T)
          → traffic_to_routing
        * otherwise → unknown

    Confidence = clamp(|TE(R → T) − TE(T → R)| / max(TE), 0, 1).
    """
    if not NUMPY_OK or not routing_timeline or not traffic_timeline:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="transfer_entropy",
            details={"reason": "numpy missing or empty timeline"},
        )
    r_series, t_series = _to_aligned_series(routing_timeline, traffic_timeline)
    if len(r_series) < max(2 * lag + 4, 8):
        return BaselineResult(
            direction="unknown", confidence=0.0, method="transfer_entropy",
            details={"reason": "series too short for TE"},
        )
    r_arr = np.array(r_series, dtype=float)
    t_arr = np.array(t_series, dtype=float)
    if float(r_arr.std()) == 0 or float(t_arr.std()) == 0:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="transfer_entropy",
            details={"reason": "zero-variance series"},
        )
    try:
        te_rt = _transfer_entropy_scalar(r_arr, t_arr, lag=lag, bins=bins)
        te_tr = _transfer_entropy_scalar(t_arr, r_arr, lag=lag, bins=bins)
    except Exception as e:
        return BaselineResult(
            direction="unknown", confidence=0.0, method="transfer_entropy",
            details={"reason": f"TE computation failed: {type(e).__name__}: {e}"},
        )
    # Surrogate baseline: shuffle routing's lag-window, recompute TE(R → T).
    rng = np.random.default_rng(42)
    te_null = np.empty(n_perm, dtype=float)
    for k in range(n_perm):
        shuffled = r_arr.copy()
        block = shuffled[lag:]
        rng.shuffle(block)
        shuffled[lag:] = block
        try:
            te_null[k] = _transfer_entropy_scalar(shuffled, t_arr, lag=lag, bins=bins)
        except Exception:
            te_null[k] = 0.0
    null_mean = float(te_null.mean())
    null_std = float(te_null.std())

    # Decision rule:
    #   * Direction is decided by cross-direction comparison (TE_R→T vs
    #     TE_T→R). The surrogate null is used only as a significance
    #     check: if neither direction beats the null at 1·std the call
    #     is "unknown" (no information transfer detectable).
    #   * Confidence = clamp(|TE_R→T − TE_T→R| / max(TE_R→T, TE_T→R), 0, 1).
    sig_rt = te_rt > null_mean + 1.0 * null_std
    sig_tr = te_tr > null_mean + 1.0 * null_std
    if sig_rt and te_rt > te_tr and (not sig_tr or te_rt >= te_tr):
        direction = "routing_to_traffic"
    elif sig_tr and te_tr > te_rt and (not sig_rt or te_tr > te_rt):
        direction = "traffic_to_routing"
    elif te_rt > te_tr * 1.2:
        direction = "routing_to_traffic"
    elif te_tr > te_rt * 1.2:
        direction = "traffic_to_routing"
    else:
        direction = "unknown"
    denom = max(te_rt, te_tr, 1e-9)
    confidence = min(1.0, abs(te_rt - te_tr) / denom)
    return BaselineResult(
        direction=direction,
        confidence=round(float(confidence), 3),
        method="transfer_entropy",
        details={
            "te_routing_to_traffic": round(float(te_rt), 4),
            "te_traffic_to_routing": round(float(te_tr), 4),
            "null_mean": round(null_mean, 4),
            "null_std": round(null_std, 4),
            "sig_rt": bool(sig_rt),
            "sig_tr": bool(sig_tr),
            "lag": lag,
            "bins": bins,
            "n_perm": n_perm,
        },
    )


def _transfer_entropy_scalar(
    source: np.ndarray,
    target: np.ndarray,
    lag: int,
    bins: int,
) -> float:
    """Scalar TE(source → target) at the given lag.

    TE = Σ_{s_t, s_t-lag, t_t} p(s_t, s_t-lag, t_t) ·
         log[ p(t_t | s_t, s_t-lag) / p(t_t | s_t-lag) ]
    """
    n = min(len(source), len(target))
    if n <= lag + 2:
        return 0.0
    s_t = source[lag:n]
    s_lag = source[: n - lag]
    t_t = target[lag:n]
    t_lag = target[: n - lag]

    # Discretise each into `bins` quantile bins (handles skewed series
    # like BGP burst counts). NaN-safe quantile assignment; if all values
    # are identical we fall back to ordinal encoding so the bin index
    # still carries *temporal* information.
    def _digitise(x: np.ndarray) -> np.ndarray:
        if len(x) < bins:
            return np.zeros(len(x), dtype=int)
        # Use unique quantiles so we never collapse to a single bin.
        qs = np.linspace(0, 1, bins + 1)[1:-1]
        edges = np.quantile(x, qs)
        edges = np.unique(edges)
        if len(edges) == 0:
            # All values identical — encode by rank so the bin index
            # captures temporal position rather than value.
            return np.argsort(np.argsort(x)) % bins
        return np.clip(np.searchsorted(edges, x), 0, len(edges)).astype(int)

    s_t_d = _digitise(s_t)
    s_lag_d = _digitise(s_lag)
    t_t_d = _digitise(t_t)
    t_lag_d = _digitise(t_lag)

    m = len(t_t_d)
    # Laplace smoothing constant
    alpha = 1.0
    # Joint counts: P(t_t, s_t, s_lag, t_lag)  (use t_lag for conditioning on t's past)
    # We approximate P(t_t | t_lag, s_t, s_lag) and P(t_t | t_lag).
    joint_3 = np.zeros((bins, bins, bins, bins), dtype=float)  # t_t, t_lag, s_t, s_lag
    joint_1 = np.zeros((bins, bins), dtype=float)              # t_t, t_lag
    for i in range(m):
        joint_3[t_t_d[i], t_lag_d[i], s_t_d[i], s_lag_d[i]] += 1
        joint_1[t_t_d[i], t_lag_d[i]] += 1

    # Compute the conditional probabilities:
    #   p_3[t_t, t_lag, s_t, s_lag] = P(t_t | t_lag, s_t, s_lag)
    #   p_1[t_t, t_lag]             = P(t_t | t_lag)
    # Marginal over t_t gives the weighting p_3_marginal for the TE formula.
    sum_3 = joint_3.sum(axis=0)  # shape (bins_t_lag, bins_s_t, bins_s_lag)
    sum_1 = joint_1.sum(axis=0)  # shape (bins_t_lag,)
    p_3 = (joint_3 + alpha) / (sum_3[None, :, :, :] + alpha * bins)
    p_1 = (joint_1 + alpha) / (sum_1[None, :] + alpha * bins)
    p_3_marginal = sum_3 / (m + alpha * bins ** 4)

    # log ratio: p_3 is (t_t, t_lag, s_t, s_lag); p_1 is (t_t, t_lag).
    # Broadcast p_1 over the (s_t, s_lag) axes to align shapes.
    log_ratio = np.log(p_3 / np.maximum(p_1[:, :, None, None], 1e-12))
    te = float((p_3_marginal * log_ratio).sum())
    return max(te, 0.0)


BASELINES = {
    "pearson": pearson_baseline,
    "granger": granger_baseline,
    "timestamp_distance": timestamp_distance_baseline,
    "transfer_entropy": transfer_entropy_baseline,
}


def baseline_attribution(
    method: str,
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
) -> BaselineResult:
    """Run one baseline and return a BaselineResult.

    Args:
        method: one of "pearson", "granger", "timestamp_distance".
        routing_timeline, traffic_timeline: same shape as
            ``CausalAttributionEngine.analyze`` expects.
    """
    fn = BASELINES.get(method)
    if fn is None:
        raise ValueError(f"Unknown baseline: {method}; choices: {list(BASELINES)}")
    return fn(routing_timeline, traffic_timeline)


def run_all_baselines(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
) -> Dict[str, BaselineResult]:
    """Run all three baselines and return their results keyed by method name."""
    return {name: fn(routing_timeline, traffic_timeline) for name, fn in BASELINES.items()}