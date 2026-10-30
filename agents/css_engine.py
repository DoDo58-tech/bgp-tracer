"""Causal Sufficiency Score (CSS) engine — Pearl's do-calculus approximation."""
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


# Result schema (replaces the 3-vote tuple with a single causal claim)
@dataclass
class CSSResult:
    """CSS attribution verdict."""
    direction: str = "unknown"
    css_routing_to_traffic: float = 0.0
    css_traffic_to_routing: float = 0.0
    confidence: float = 0.0
    ci_lower: float = 0.0
    ci_upper: float = 0.0
    p_value: float = 1.0
    is_causal: bool = False
    sufficiency: float = 0.0
    necessity: float = 0.0
    explanation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    method: str = "css_pns"


# Timeline utilities: turn a pre-bucketed series or a raw event log into
# two index-aligned per-bucket series on one shared clock
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%m/%d/%y %H:%M:%S",
    "%m/%d/%y %H:%M",
)


def parse_timestamp(ts: Any) -> Optional[datetime]:
    """Parse the timestamp spellings that appear in caches and live runs."""
    if isinstance(ts, datetime):
        return ts
    if not ts:
        return None
    raw = str(ts).strip().replace("Z", "")
    # ``fromisoformat`` handles fractional seconds and ``+00:00`` offsets.
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def is_prequantised(timeline: List[dict]) -> bool:
    """True when ``timeline`` is already one score per bucket on a uniform grid.
    
    Returns ``False`` when any timestamp is unparseable, because an event log
    with irregular/mixed formats must be bucketed rather than passed through."""
    if not timeline or not all(isinstance(p, dict) for p in timeline):
        return False
    if not any(p.get("timestamp") for p in timeline):
        # No timestamps at all: a bare score vector can only be a per-bucket
        # series (a raw event log is *defined* by its event timestamps, and
        # there is nothing to bucket it by).
        return True
    if any(("raw_event" in p) or ("event_type" in p) for p in timeline):
        return False
    stamps = [parse_timestamp(p.get("timestamp")) for p in timeline]
    if any(s is None for s in stamps):
        return False
    if len(set(stamps)) != len(stamps):
        return False
    if len(stamps) < 3:
        return True
    gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])]
    return (max(gaps) - min(gaps)) <= 1e-6


def bucketize_pair(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
    bucket_minutes: int = 5,
) -> Tuple[List[float], List[float]]:
    """Bucket two raw event logs onto **one shared** time grid.
    
    Returns two equal-length lists, or ``([], [])`` when neither timeline has
    a parseable timestamp."""
    events: List[Tuple[datetime, str, float]] = []
    for source, tl in (("routing", routing_timeline), ("traffic", traffic_timeline)):
        for p in tl or []:
            if not isinstance(p, dict):
                continue
            dt = parse_timestamp(p.get("timestamp"))
            if dt is None:
                continue
            sev = p.get("severity", p.get("score", p.get("z_score", 0.0)))
            try:
                sev = float(sev)
            except (TypeError, ValueError):
                sev = 0.0
            events.append((dt, source, sev))
    if not events:
        # No parseable timestamps anywhere (e.g. bare {"score": x} vectors from
        # a library caller).  There is no clock to bucket on, so fall back to
        # index alignment of the two score vectors.
        r = extract_scores(routing_timeline)
        t = extract_scores(traffic_timeline)
        n = min(len(r), len(t))
        return r[:n], t[:n]
    t0 = min(e[0] for e in events)
    t1 = max(e[0] for e in events)
    span_min = max((t1 - t0).total_seconds() / 60.0, float(bucket_minutes))
    n_buckets = max(4, min(240, int(math.ceil(span_min / bucket_minutes))))
    width_s = max((t1 - t0).total_seconds() / n_buckets, 1e-9)
    r_sum = [0.0] * n_buckets
    r_cnt = [0] * n_buckets
    t_sum = [0.0] * n_buckets
    t_cnt = [0] * n_buckets
    for dt, source, sev in events:
        idx = min(n_buckets - 1, max(0, int((dt - t0).total_seconds() / width_s)))
        if source == "routing":
            r_sum[idx] += sev
            r_cnt[idx] += 1
        else:
            t_sum[idx] += sev
            t_cnt[idx] += 1
    routing = [min(s / c, 1.0) if c else 0.0 for s, c in zip(r_sum, r_cnt)]
    traffic = [min(s / c, 1.0) if c else 0.0 for s, c in zip(t_sum, t_cnt)]
    return ([max(v, 1e-9) for v in routing], [max(v, 1e-9) for v in traffic])


def extract_scores(timeline: List[dict]) -> List[float]:
    """Extract per-bucket anomaly scores from a Phase-1 timeline."""
    out = []
    for p in timeline:
        if not isinstance(p, dict):
            out.append(0.0)
            continue
        # Chain of preferred fields (Phase-2 already-bucketed > severity > z > conf > presence)
        for key in ("score", "severity", "z_score", "confidence"):
            v = p.get(key)
            if v is not None:
                try:
                    out.append(float(v))
                    break
                except (TypeError, ValueError):
                    continue
        else:
            # No usable score field → fall back to "event present" (1.0)
            # so that an event in the timeline is treated as a 1σ
            # anomaly burst, not as a 0-bucket.
            out.append(1.0 if p.get("timestamp") else 0.0)
    return out


def align_series(
    r_scores: List[float],
    t_scores: List[float],
) -> Tuple[List[float], List[float]]:
    """Align two per-bucket series on their common window.
    
    Returns ``([], [])`` when either input is empty — callers already treat an
    empty series as "cannot estimate"."""
    n = min(len(r_scores), len(t_scores))
    if n <= 0:
        return [], []
    return list(r_scores[:n]), list(t_scores[:n])


def find_breakpoint(
    series: List[float],
    half_window: Optional[int] = None,
    min_effect: float = 0.0,
) -> int:
    """Return the index of the largest mean-shift in ``series``, or ``-1``."""
    n = len(series)
    if n < 4 or not NUMPY_OK:
        return -1
    arr = np.array(series, dtype=float)
    half = half_window or max(1, n // 4)
    if n - 2 * half < 1:
        half = max(1, (n - 1) // 2)
    pre_mean = arr[:half].mean()
    scale = float(arr.std())
    best_idx = -1
    best_effect = 0.0
    for k in range(half, n - half):
        post_mean = arr[k:].mean()
        effect = abs(float(post_mean) - float(pre_mean))
        if scale > 1e-12:
            effect /= scale
        # Strictly greater: an all-zero/constant series keeps best_idx == -1.
        if effect > best_effect:
            best_effect = effect
            best_idx = k
    return best_idx if best_effect > min_effect else -1


# Counterfactual baseline: split timeline at MSBD breakpoint
def split_at_breakpoint(
    r_scores: List[float],
    t_scores: List[float],
    breakpoint_idx: Optional[int] = None,
) -> Tuple[List[float], List[float], List[float], List[float], int]:
    """Return (r_pre, t_pre, r_post, t_post, breakpoint_idx).
    
    If ``breakpoint_idx`` is None we find the largest-mean-shift point in the
    routing series (proxy for MSBD output).  When no break is detectable the
    function returns empty windows and ``-1`` — it never falls back to a
    midpoint split, because a midpoint split invents a pre/post partition that
    the data does not support (see :func:`_find_breakpoint`)."""
    n = len(r_scores)
    if n < 4:
        return [], [], [], [], -1
    if breakpoint_idx is None or breakpoint_idx < 1 or breakpoint_idx >= n - 1:
        breakpoint_idx = find_breakpoint(r_scores)
    if breakpoint_idx < 1 or breakpoint_idx >= n:
        return [], [], [], [], -1
    pre_end = breakpoint_idx
    post_start = breakpoint_idx
    return (
        r_scores[:pre_end],
        t_scores[:pre_end],
        r_scores[post_start:],
        t_scores[post_start:],
        breakpoint_idx,
    )


# PNS estimation: difference-in-means with bootstrap CI
SCARCITY_THRESHOLD = 10


def scarcity_aware_pns(pre, post, alpha_prior=1.0, beta_prior=1.0):
    """Bayesian-shrinkage PNS for small samples, in standardised units.
    
    Returns a dict with:
    - point: shrunk standardised effect
    - ci_lower / ci_upper: Beta-posterior 95% credible interval on
    the direction-of-effect probability, mapped back onto the
    standardised-effect scale
    - p_value: Bayesian posterior probability that effect ≤ 0,
    two-sided via the symmetric-Beta reference"""
    n_pre, n_post = len(pre), len(post)
    scale = standardisation_scale(pre, post)
    if not np.isfinite(scale) or scale <= 1e-12:
        return {
            "point": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "p_value": 1.0, "sufficiency": 0.0, "necessity": 0.0,
            "estimable": False,
        }
    threshold = float(pre.mean())
    n_post_above = int((post > threshold).sum())
    # Beta posterior: Beta(α + k, β + n - k)
    alpha_post = alpha_prior + n_post_above
    beta_post = beta_prior + (n_post - n_post_above)
    # Sample from Beta to compute CI efficiently
    rng = np.random.default_rng(42)
    beta_samples = rng.beta(alpha_post, beta_post, size=2000)
    # Two-sided: exclude 0.5 symmetrically
    lo, hi = float(np.percentile(beta_samples, 2.5)), float(np.percentile(beta_samples, 97.5))
    # Convert the Beta CI (a probability-scale interval) to the standardised
    point_raw = float((post.mean() - pre.mean()) / scale)
    point_abs = abs(point_raw)
    if point_raw >= 0:
        ci_lower = (max(lo, 0.5) - 0.5) * 2.0 * point_abs
        ci_upper = (max(hi, 0.5) - 0.5) * 2.0 * point_abs
    else:
        ci_lower = -(max(hi, 0.5) - 0.5) * 2.0 * point_abs
        ci_upper = -(max(lo, 0.5) - 0.5) * 2.0 * point_abs
    # Shrinkage: alpha + beta → n_post + α + β - 2
    shrinkage = (alpha_prior + beta_prior) / (alpha_post + beta_post)
    point_shrunk = point_raw * (1.0 - shrinkage)
    # Bayesian two-sided p: P(direction is null) = 2·min(P(θ<0.5), P(θ>0.5)),
    n_draws = int(beta_samples.size)
    left = int((beta_samples < 0.5).sum())
    right = n_draws - left
    p_value = 2.0 * min(left + 1, right + 1) / (n_draws + 1)
    p_value = max(0.0, min(1.0, p_value))
    sufficiency = min(abs(point_shrunk), 5.0)
    necessity = float(n_post_above / max(n_post, 1))
    return {
        "point": point_shrunk,
        "ci_lower": float(ci_lower),
        "ci_upper": float(ci_upper),
        "p_value": p_value,
        "sufficiency": sufficiency,
        "necessity": necessity,
        "method": "scarcity_aware",
        "estimable": True,
    }


def standardisation_scale(pre, post) -> float:
    """Return a finite, scale-free denominator for a difference in means."""
    n_pre, n_post = len(pre), len(post)
    var_pre = float(pre.var(ddof=1)) if n_pre > 1 else 0.0
    var_post = float(post.var(ddof=1)) if n_post > 1 else 0.0
    denom = max(n_pre + n_post - 2, 1)
    within = ((n_pre - 1) * var_pre + (n_post - 1) * var_post) / denom
    if within > 1e-18:
        return float(np.sqrt(within))
    return float(np.concatenate([pre, post]).std())


def pns_estimate(
    pre_values: List[float],
    post_values: List[float],
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> Dict[str, float]:
    """Estimate PNS as a **standardised** pre→post mean shift.
    
    Returns:
    dict(
    point=standardised effect (Cohen's d),
    ci_lower, ci_upper (95% bootstrap CI, same unit),
    p_value (two-sided permutation p),
    sufficiency (|point|, already σ-normalised, capped at 5),
    necessity (fraction of post where the intervention is "on"),
    estimable (False when the scale is degenerate),
    )"""
    if not NUMPY_OK or len(pre_values) < 2 or len(post_values) < 2:
        return {
            "point": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "p_value": 1.0, "sufficiency": 0.0, "necessity": 0.0,
            "estimable": False,
        }
    pre = np.array(pre_values, dtype=float)
    post = np.array(post_values, dtype=float)
    scale = standardisation_scale(pre, post)
    if not np.isfinite(scale) or scale <= 1e-12:
        # Both arms are flat at the *same* value: no effect to estimate.
        return {
            "point": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "p_value": 1.0, "sufficiency": 0.0, "necessity": 0.0,
            "estimable": False,
        }
    # Scarcity-aware fallback: when both arms are tiny, the bootstrap
    # percentile CI is not trustworthy (n_bootstrap resamples from
    # essentially the same handful of points).
    if min(len(pre), len(post)) < SCARCITY_THRESHOLD:
        return scarcity_aware_pns(pre, post)
    rng = np.random.default_rng(seed)
    point = float((post.mean() - pre.mean()) / scale)
    # Bootstrap CI: resample both arms, recompute the *standardised* difference.
    # The scale is held at its observed value so the interval quantifies the
    # sampling variability of the means, not of the dispersion estimate.
    boot_diffs = np.empty(n_bootstrap, dtype=float)
    for k in range(n_bootstrap):
        b_pre = pre[rng.integers(0, len(pre), size=len(pre))]
        b_post = post[rng.integers(0, len(post), size=len(post))]
        boot_diffs[k] = float((b_post.mean() - b_pre.mean()) / scale)
    ci_lower, ci_upper = float(np.percentile(boot_diffs, 2.5)), float(np.percentile(boot_diffs, 97.5))
    # p-value: null is "no intervention" — pool pre and post values and
    # compute the difference under random reassignment. This is the
    # standard permutation-test p-value, not the bootstrap-of-mean p-value.
    pooled = np.concatenate([pre, post])
    n_pre = len(pre)
    perm_diffs = np.empty(n_bootstrap, dtype=float)
    for k in range(n_bootstrap):
        idx = rng.permutation(len(pooled))
        perm_diffs[k] = float((pooled[idx[:n_pre]].mean() - pooled[idx[n_pre:]].mean()) / scale)
    abs_point = abs(point)
    # Add-one correction: with a finite number of permutations the empirical
    p_value = float((1 + int((np.abs(perm_diffs) >= abs_point).sum())) / (n_bootstrap + 1))
    # Necessity: fraction of post values where the signal is "active"
    # (above the pre mean). In BGP context "active" means routing/traffic
    # anomaly is detected.
    threshold = float(pre.mean() + max(float(pre.std()), 1e-9))
    necessity = float((post > threshold).mean())
    sufficiency = min(abs_point, 5.0)  # already in σ units
    return {
        "point": point,
        "ci_lower": ci_lower,
        "ci_upper": ci_upper,
        "p_value": p_value,
        "sufficiency": sufficiency,
        "necessity": necessity,
        "estimable": True,
    }


# Public API: css_score()
def css_score(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
    msbd_breakpoint_idx: Optional[int] = None,
    n_bootstrap: int = 1000,
    p_threshold: float = 0.05,
    min_samples: int = 4,
) -> CSSResult:
    """Compute the Causal Sufficiency Score for routing → traffic attribution.
    
    Returns:
    CSSResult — full PNS-style attribution verdict with bootstrap CI."""
    if not NUMPY_OK or not routing_timeline or not traffic_timeline:
        return CSSResult(
            direction="unknown",
            explanation="numpy missing or empty timeline; CSS cannot estimate.",
            details={"reason": "numpy missing or empty timeline"},
        )
    # Normalise the two inputs onto ONE time grid.
    if is_prequantised(routing_timeline) and is_prequantised(traffic_timeline):
        routing_scores = extract_scores(routing_timeline)
        traffic_scores = extract_scores(traffic_timeline)
    else:
        routing_scores, traffic_scores = bucketize_pair(
            routing_timeline, traffic_timeline
        )
    r_aligned, t_aligned = align_series(routing_scores, traffic_scores)
    if len(r_aligned) < min_samples:
        return CSSResult(
            direction="unknown",
            explanation=f"aligned series length {len(r_aligned)} < {min_samples}; CSS cannot estimate.",
            details={"reason": "series too short"},
        )

    # Detect intervention point (MSBD-style break in routing series).
    r_pre, t_pre, r_post, t_post, bp_idx = split_at_breakpoint(
        r_aligned, t_aligned, msbd_breakpoint_idx,
    )
    if not r_pre or not r_post:
        return CSSResult(
            direction="unknown",
            explanation=(
                "no detectable breakpoint in the routing series; without an "
                "intervention window CSS cannot estimate PNS and abstains."
            ),
            details={"reason": "no detectable breakpoint", "breakpoint_idx": bp_idx},
        )

    # Precondition: routing series must show a non-trivial shift between
    if NUMPY_OK:
        r_pre_arr = np.array(r_pre, dtype=float)
        r_post_arr = np.array(r_post, dtype=float)
        if float(r_pre_arr.std()) == 0 and float(r_post_arr.std()) == 0:
            # Truly flat routing → no intervention observable → CSS abstains.
            return CSSResult(
                direction="unknown",
                explanation="routing series has zero variance; no observable intervention.",
                details={"reason": "flat routing series"},
            )
    # Mean-shift magnitude — first the standard mean/std route, then
    pre_mean = float(r_pre_arr.mean())
    post_mean = float(r_post_arr.mean())
    max_std = max(float(r_pre_arr.std()), float(r_post_arr.std()), 1e-9)
    shift_magnitude = abs(post_mean - pre_mean) / max_std
    pre_median = float(np.median(r_pre_arr))
    post_median = float(np.median(r_post_arr))
    median_shift = abs(post_median - pre_median)
    median_shift_present = median_shift > max(pre_median, 1e-9) * 0.5
    # Sparsity-aware shift: P99 vs P99 ratio, or active-bucket-count ratio.
    pre_p99 = float(np.percentile(r_pre_arr, 99)) if len(r_pre_arr) else 0.0
    post_p99 = float(np.percentile(r_post_arr, 99)) if len(r_post_arr) else 0.0
    p99_ratio = post_p99 / max(pre_p99, 1e-9)
    pre_active = float((r_pre_arr > 1e-6).sum()) / max(len(r_pre_arr), 1)
    post_active = float((r_post_arr > 1e-6).sum()) / max(len(r_post_arr), 1)
    active_ratio = post_active / max(pre_active, 1e-9)
    # Burst signature: any single post bucket > 5× max(pre bucket) is
    # a routing event spike (a BGP hijack/leak produces this even when
    # std is inflated by the spike itself).
    pre_max = float(r_pre_arr.max())
    post_max = float(r_post_arr.max())
    burst_signature = post_max > 5.0 * max(pre_max, 1e-9)
    # An intervention is observable if EITHER shift_magnitude ≥ 0.3,
    # OR median_shift is meaningful, OR there's a clear burst.
    has_intervention = (
        shift_magnitude >= 0.3
        or median_shift_present
        or burst_signature
        or (post_p99 > 2.0 * pre_p99 and post_p99 > 1.0)
    )
    if not has_intervention:
        return CSSResult(
            direction="unknown",
            explanation=f"routing pre/post shift ({shift_magnitude:.2f}σ) is too small to attribute; CSS abstains.",
            details={"reason": "no routing intervention",
                     "shift_magnitude": round(shift_magnitude, 3),
                     "median_shift": round(median_shift, 3),
                     "burst_signature": burst_signature,
                     "p99_ratio": round(p99_ratio, 2),
                     "active_ratio": round(active_ratio, 2)},
        )

    # Symmetric check: if traffic shows no shift either, the event is
    traffic_available = True
    if NUMPY_OK and len(t_pre) >= 2 and len(t_post) >= 2:
        t_pre_arr = np.array(t_pre, dtype=float)
        t_post_arr = np.array(t_post, dtype=float)
        t_pre_std = float(t_pre_arr.std())
        t_post_std = float(t_post_arr.std())
        # Treat near-zero std (≤ 1e-6) as zero: split_merged_timeline
        # uses max(score, 1e-9) so a flat series has std ≈ 2e-25, not
        # exactly 0. Float-equality would miss this.
        if t_pre_std < 1e-6 and t_post_std < 1e-6:
            # No traffic signal — note for downstream logic and proceed
            # with routing-only attribution. This is the common case on
            # real BGP data where traffic CSVs don't cover the event.
            traffic_available = False
        # Scarcity-aware shift: if mean/std shift < 0.3 but the
        # *median* itself moved meaningfully, treat as a traffic
        # response rather than abstaining.
        max_t_std = max(t_pre_std, t_post_std, 1e-9)
        t_shift = abs(float(t_post_arr.mean()) - float(t_pre_arr.mean())) / max_t_std
        t_pre_median = float(np.median(t_pre_arr))
        t_post_median = float(np.median(t_post_arr))
        t_median_shift = abs(t_post_median - t_pre_median)
        t_median_present = t_median_shift > max(t_pre_median, 1e-9) * 0.5
        if traffic_available and t_shift < 0.3 and not t_median_present:
            return CSSResult(
                direction="unknown",
                explanation=f"traffic pre/post shift ({t_shift:.2f}σ) is too small; CSS abstains.",
                details={"reason": "no traffic response", "traffic_shift_magnitude": round(t_shift, 3)},
            )

    # PNS(R → T): routing "active" in post, traffic response measured.
    rt = pns_estimate(t_pre, t_post, n_bootstrap=n_bootstrap, seed=11)
    # PNS(T → R): split at the *traffic* breakpoint (traffic defines the
    t_bp_idx = find_breakpoint(t_aligned)
    if t_bp_idx < 1 or t_bp_idx >= len(r_aligned):
        tr = {
            "point": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "p_value": 1.0, "sufficiency": 0.0, "necessity": 0.0,
            "estimable": False,
        }
    else:
        tr = pns_estimate(
            r_aligned[:t_bp_idx], r_aligned[t_bp_idx:],
            n_bootstrap=n_bootstrap, seed=23,
        )

    css_rt = rt["point"]
    css_tr = tr["point"]

    # Temporal precedence tiebreaker (Pearl: cause precedes effect).
    r_bp = find_breakpoint(r_aligned) if NUMPY_OK else -1
    t_bp = find_breakpoint(t_aligned) if NUMPY_OK else -1
    lead = (r_bp - t_bp) if (r_bp >= 0 and t_bp >= 0) else None

    # Compute absolute magnitudes up front so the decision branches below
    abs_css_rt = abs(css_rt)
    abs_css_tr = abs(css_tr)
    rt_est = bool(rt.get("estimable", True))
    tr_est = bool(tr.get("estimable", True))
    rt_abs_ci_pos = rt_est and (rt["ci_lower"] > 0 or rt["ci_upper"] < 0)
    tr_abs_ci_pos = tr_est and (tr["ci_lower"] > 0 or tr["ci_upper"] < 0)

    if lead is not None and lead < -1:
        # Routing clearly precedes traffic — T→R is structurally implausible.
        rt_significant = (rt["p_value"] < p_threshold and rt_abs_ci_pos)
        tr_significant = False
    elif lead is not None and lead > 1:
        # Traffic clearly precedes routing — R→T is structurally implausible.
        tr_significant = (tr["p_value"] < p_threshold and tr_abs_ci_pos)
        rt_significant = False
    else:
        # Simultaneous / ambiguous / unknown precedence — fall back to the
        # standardised magnitude comparison (now on a shared scale).
        rt_significant = (
            rt["p_value"] < p_threshold and rt_abs_ci_pos and abs_css_rt > abs_css_tr
        )
        tr_significant = (
            tr["p_value"] < p_threshold and tr_abs_ci_pos and abs_css_tr > abs_css_rt
        )

    if rt_significant and not tr_significant:
        direction = "routing_to_traffic"
        ci_lower = rt["ci_lower"]
        ci_upper = rt["ci_upper"]
        p_value = rt["p_value"]
    elif tr_significant and not rt_significant:
        direction = "traffic_to_routing"
        ci_lower = tr["ci_lower"]
        ci_upper = tr["ci_upper"]
        p_value = tr["p_value"]
    elif rt_significant and tr_significant:
        # Both directions clear their own null (possible when neither the
        if abs_css_rt >= abs_css_tr:
            direction = "routing_to_traffic"
            ci_lower, ci_upper, p_value = rt["ci_lower"], rt["ci_upper"], rt["p_value"]
        else:
            direction = "traffic_to_routing"
            ci_lower, ci_upper, p_value = tr["ci_lower"], tr["ci_upper"], tr["p_value"]
    elif abs_css_rt > 0 and abs_css_tr > 0 and abs(abs_css_rt - abs_css_tr) <= 1e-12:
        # Two non-zero but numerically identical standardised effects and
        direction = "unknown"
        ci_lower = min(rt["ci_lower"], tr["ci_lower"])
        ci_upper = max(rt["ci_upper"], tr["ci_upper"])
        p_value = max(rt["p_value"], tr["p_value"])
    else:
        # Neither direction survives its null. The previous code picked the
        direction = "unknown"
        ci_lower = min(rt["ci_lower"], tr["ci_lower"])
        ci_upper = max(rt["ci_upper"], tr["ci_upper"])
        p_value = max(rt["p_value"], tr["p_value"])

    # Confidence: derived from CI width and separation between directions.
    abs_css_rt_final = abs(css_rt)
    abs_css_tr_final = abs(css_tr)
    dominant_pt = abs_css_rt_final if direction == "routing_to_traffic" else abs_css_tr_final if direction == "traffic_to_routing" else 0.0
    alt_pt = abs_css_tr if direction == "routing_to_traffic" else abs_css_rt
    separation = dominant_pt - alt_pt
    ci_width = max(ci_upper - ci_lower, 1e-9)
    # CI not crossing zero (in the absolute-value sense) is the strongest
    rt_abs_ci_pos = rt["ci_lower"] > 0 or rt["ci_upper"] < 0
    tr_abs_ci_pos = tr["ci_lower"] > 0 or tr["ci_upper"] < 0
    dominant_abs_ci_pos = False
    if direction == "routing_to_traffic":
        dominant_abs_ci_pos = rt_abs_ci_pos
    elif direction == "traffic_to_routing":
        dominant_abs_ci_pos = tr_abs_ci_pos
    # p-value: use the dominant-direction PNS alone. When traffic is
    if direction == "routing_to_traffic":
        if traffic_available:
            p_value_combined = rt["p_value"]
        else:
            # Compute routing-series PNS as the causal evidence.
            # Use the routing breakpoint (already established as bp_idx).
            r_pns = pns_estimate(
                list(r_pre), list(r_post), n_bootstrap=n_bootstrap, seed=31,
            )
            p_value_combined = r_pns["p_value"]
    elif direction == "traffic_to_routing":
        if traffic_available:
            p_value_combined = tr["p_value"]
        else:
            r_pns = pns_estimate(
                list(r_pre), list(r_post), n_bootstrap=n_bootstrap, seed=31,
            )
            p_value_combined = r_pns["p_value"]
    else:
        p_value_combined = max(rt["p_value"], tr["p_value"]) if traffic_available else 1.0
    is_causal = bool(dominant_abs_ci_pos and (p_value_combined < p_threshold))
    confidence = min(
        1.0,
        0.5 * min(1.0, abs(separation) / max(abs(dominant_pt), 1e-9))
        + 0.5 * min(1.0, abs(dominant_pt) / max(ci_width, 1e-9)),
    )
    if direction not in ("routing_to_traffic", "traffic_to_routing"):
        confidence = 0.0

    explanation = (
        f"CSS(R→T)={css_rt:+.3f} [CI {rt['ci_lower']:+.3f},{rt['ci_upper']:+.3f}], p={rt['p_value']:.3f}; "
        f"CSS(T→R)={css_tr:+.3f} [CI {tr['ci_lower']:+.3f},{tr['ci_upper']:+.3f}], p={tr['p_value']:.3f}. "
        f"Breakpoint idx={bp_idx}. "
        f"{'CI excludes zero' if is_causal else 'CI crosses zero; direction uncertain'}."
    )

    return CSSResult(
        direction=direction,
        css_routing_to_traffic=round(css_rt, 4),
        css_traffic_to_routing=round(css_tr, 4),
        confidence=round(confidence, 3),
        ci_lower=round(ci_lower, 4),
        ci_upper=round(ci_upper, 4),
        p_value=round(p_value, 4),
        is_causal=is_causal,
        sufficiency=round(
            (tr if direction == "traffic_to_routing" else rt)["sufficiency"], 3
        ),
        necessity=round(
            (tr if direction == "traffic_to_routing" else rt)["necessity"], 3
        ),
        explanation=explanation,
        details={
            "breakpoint_idx": bp_idx,
            "n_pre": len(r_pre),
            "n_post": len(r_post),
            "pns_routing_to_traffic": rt,
            "pns_traffic_to_routing": tr,
            "separation": round(separation, 4),
            "n_bootstrap": n_bootstrap,
            "p_threshold": p_threshold,
        },
        method="css_pns",
    )


# Bayesian synthesis: combine CSS with other evidence channels
def bayesian_synthesize(
    css: CSSResult,
    evidence_channels: Dict[str, Dict[str, Any]],
    prior: Optional[Dict[str, float]] = None,
    event_type: Optional[str] = None,
    routing_withdrawal_signal: Optional[str] = None,
) -> Dict[str, Any]:
    """Bayesian synthesis of CSS with the other evidence channels.
    
    Returns a dict with ``direction`` (argmax posterior), ``posterior`` (the
    three-direction posterior mass), ``confidence`` (max posterior mass) and
    diagnostics: ``n_channels``, ``n_clusters`` and ``redundancy``
    (``n_channels / n_clusters``; > 1 means channels were duplicated)."""
    # Uniform prior: no channel — including CSS — is privileged before the
    # evidence is read.  ``event_type`` is intentionally unused (see docstring).
    _ = event_type
    base_prior = prior or {
        "routing_to_traffic": 1.0,
        "traffic_to_routing": 1.0,
        "independent": 1.0,
    }
    posteriors = {
        d: float(base_prior.get(d, 1.0))
        for d in ("routing_to_traffic", "traffic_to_routing", "independent")
    }

    # Collect the channels that actually carry a likelihood.
    channels: Dict[str, Dict[str, Any]] = {}
    for name, ch in (evidence_channels or {}).items():
        if isinstance(ch, dict) and isinstance(ch.get("likelihood"), dict):
            channels[str(name)] = ch

    # CSS enters as a channel, and only when it is statistically supported.
    # A CSS verdict with p ≥ threshold or a CI crossing zero carries no
    # directional evidence, so it gets LR = 1 (i.e. it is not added).
    if css.direction in ("routing_to_traffic", "traffic_to_routing") and css.is_causal:
        effect = (
            abs(css.css_routing_to_traffic)
            if css.direction == "routing_to_traffic"
            else abs(css.css_traffic_to_routing)
        )
        css_lr = 1.0 + min(4.0, float(effect))  # bounded: |d| ∈ [0, 5] → LR ≤ 5
        opposite = (
            "traffic_to_routing"
            if css.direction == "routing_to_traffic"
            else "routing_to_traffic"
        )
        channels["css_pns"] = {
            "direction": css.direction,
            "likelihood": {css.direction: css_lr, opposite: 1.0 / css_lr, "independent": 1.0},
        }

    # A withdrawal observed in-window is a *measured* control-plane fact (not a
    if routing_withdrawal_signal in ("routing_to_traffic", "traffic_to_routing"):
        opposite = (
            "traffic_to_routing"
            if routing_withdrawal_signal == "routing_to_traffic"
            else "routing_to_traffic"
        )
        channels["routing_withdrawal_observed"] = {
            "direction": routing_withdrawal_signal,
            "likelihood": {
                routing_withdrawal_signal: 1.5,
                opposite: 1.0 / 1.5,
                "independent": 1.0,
            },
        }

    # Pool channels by the direction they vote for.  Within a cluster the
    # contribution is the geometric mean, so N copies of the same signal count
    # as one observation rather than N independent confirmations.
    clusters: Dict[str, List[Dict[str, float]]] = {}
    for ch in channels.values():
        ch_dir = str(ch.get("direction", "unknown"))
        clusters.setdefault(ch_dir, []).append(ch["likelihood"])

    for lrs in clusters.values():
        k = len(lrs)
        for d in posteriors:
            vals = [float(lr[d]) for lr in lrs if d in lr and float(lr[d]) > 0]
            if not vals:
                continue
            if k == 1 or len(vals) == 1:
                factor = vals[0]
            else:
                factor = math.exp(sum(math.log(v) for v in vals) / len(vals))
            posteriors[d] *= factor
    total = sum(posteriors.values()) or 1.0
    norm = {k: v / total for k, v in posteriors.items()}
    dominant = max(norm, key=norm.get)
    n_channels = len(channels)
    n_clusters = len(clusters)
    # The gate lives here, on the posterior mass of the dominant hypothesis --
    try:
        from config import HCAF_MIN_POSTERIOR as _POSTERIOR_FLOOR
    except (ValueError):  # pragma: no cover - config always present in practice
        _POSTERIOR_FLOOR = 0.50
    return {
        "direction": dominant if norm[dominant] >= _POSTERIOR_FLOOR else "unknown",
        "posterior_floor": _POSTERIOR_FLOOR,
        "posterior": {k: round(v, 4) for k, v in norm.items()},
        "confidence": round(norm[dominant], 3),
        "method": "css_bayesian_synthesis",
        # Diagnostics for the honest ablation: how many channels were read and
        # how many were collapsed into a single cluster because they agreed.
        "n_channels": n_channels,
        "n_clusters": n_clusters,
        "redundancy": round(n_channels / n_clusters, 3) if n_clusters else 0.0,
        "channels": {k: ch.get("direction", "unknown") for k, ch in channels.items()},
    }