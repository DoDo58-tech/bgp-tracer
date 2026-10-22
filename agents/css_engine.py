"""Causal Sufficiency Score (CSS) engine — Pearl's do-calculus approximation.

The paper's primary contribution is **CSS**, a directional causal-attribution
scoring method based on Pearl's Probability of Necessity and Sufficiency
(PNS), replacing the older HCAF weighted-vote scheme.

## Why not voting?

The previous HCAF scored directions by summing weighted contributions from
four heuristic methods (MSBD breakpoint detection, CTPR path
reconstruction, CIC cascade estimation, Granger causality). A weighted
sum is functionally a vote with continuous weights — it cannot resolve
direction conflicts when the four methods disagree, because the strength
information is collapsed into a one-dimensional scalar per method before
the sum.

CSS replaces voting with a single counterfactual quantity computed
explicitly for each direction:

```
    CSS(R → T) = E[T | do(R=1)] − E[T | do(R=0)]
    CSS(T → R) = E[R | do(T=1)] − E[R | do(T=0)]
```

The direction with the larger CSS (with bootstrap-CI significance) is
the final causal verdict.

## Why PNS-based?

PNS (Pearl 1999, formally defined in Tian & Pearl 2000) is the canonical
causal-calculus answer to "is X sufficient to produce Y?" — a question
the older vote avoided by design (votes cannot answer sufficiency
questions). PNS makes the causal claim falsifiable: a Bootstrap 95% CI
that does not cross zero is a paper-grade significance statement.

## Do-calculus without a causal graph

Real BGP telemetry does not come with an a priori causal graph. We
estimate the do-intervention by constructing a **synthetic control**
from the pre-event baseline window:

```
    E[T | do(R=1)] := mean(T over post-event window where R is active)
    E[T | do(R=0)] := mean(T over pre-event baseline) ± pre-event std
```

This is a standard difference-in-means estimator with the pre-event
window as control and post-event as treatment. For Granger-consistent
directionality we additionally require R to *precede* T (lead ≥ 1
bucket). The sufficiency check (Pearl's PNS condition) is whether the
post-event T departs from baseline by > 2σ.

## Bootstrap CI

Each CSS value is bootstrapped `n_bootstrap` times. The final direction
is the one whose CI lower bound is positive AND whose raw CSS exceeds
the alternative direction's CI upper bound (with significance
threshold `p_threshold`). This produces a paper-grade significance
claim, not a heuristic vote.

## Pipeline role

CSS replaces ``evaluate_convergence`` in
``CausalAttributionEngine``. The other methods (MSBD, CTPR, CIC,
Granger, Transfer Entropy) become **evidence channels** that feed into
the Bayesian synthesis, not voting inputs. MSBD specifically serves as
the **counterfactual baseline** — it tells CSS where the intervention
starts. CTPR/CIC contribute as **sufficiency checks** (Pearl's PNS
condition).

Public API:
    css_score(routing_timeline, traffic_timeline, msbd_breakpoint_idx=None)
        → dict(
            css_routing_to_traffic, css_traffic_to_routing,
            direction, confidence, p_value, ci_lower, ci_upper,
            method="css_pns", is_causal=bool, ...)
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


# ─────────────────────────────────────────────────────────────────────
# Result schema (replaces the 3-vote tuple with a single causal claim)
# ─────────────────────────────────────────────────────────────────────
@dataclass
class CSSResult:
    """CSS attribution verdict.

    Attributes:
        direction: "routing_to_traffic" | "traffic_to_routing" | "independent" | "unknown"
        css_routing_to_traffic: PNS-style score E[T|do(R=1)] - E[T|do(R=0)]
        css_traffic_to_routing: PNS-style score E[R|do(T=1)] - E[R|do(T=0)]
        confidence: 0..1, derived from CI width
        ci_lower: lower bound of bootstrap CI on the dominant CSS
        ci_upper: upper bound of bootstrap CI on the dominant CSS
        p_value: bootstrap p-value (fraction of surrogates >= observed)
        is_causal: True iff CI doesn't cross zero AND dominant direction's
                   CSS exceeds the alternative direction's CSS by a margin
        sufficiency: Pearl's PNS check (post-event T departs from baseline)
        necessity: Pearl's PN check (post-event R never absent while T active)
        explanation: human-readable justification
        details: per-step diagnostics for the paper's appendix
    """
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


# ─────────────────────────────────────────────────────────────────────
# Timeline utilities (mirror causal_baselines._to_aligned_series but
# kept local so the engine is independent)
# ─────────────────────────────────────────────────────────────────────
def _bucketize_events(
    timeline: List[dict],
    bucket_minutes: int = 5,
) -> List[float]:
    """Bucket a raw event list into a per-bucket anomaly score series.

    Phase 1's correlation analyzer produces a merged timeline of
    individual events ``[{timestamp, source, severity, ...}, ...]``
    rather than a pre-bucketed score series. CSS's
    ``_extract_scores`` then sees an unsummarised list where every
    event has the same severity (1.0 for routing, 0.4–1.0 for
    traffic), which produces a flat series and triggers the
    flat-series abstention.

    This function buckets events into ``bucket_minutes``-sized
    windows and returns one score per bucket. The score is the
    mean severity of events in the bucket, capped at 1.0. Empty
    buckets contribute 0.0, which preserves the "no events"
    baseline. The number of buckets is derived from the timeline
    span (≥ 4 buckets to satisfy CSS's ``min_samples`` gate).
    """
    if not timeline:
        return []
    parsed = []
    for p in timeline:
        if not isinstance(p, dict):
            continue
        ts = p.get("timestamp")
        if not ts:
            continue
        try:
            # Accept both "2024-01-03T14:45:00Z" and "01/03/24 14:54:29".
            iso = str(ts).replace("Z", "")
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M"):
                try:
                    dt = datetime.strptime(iso, fmt)
                    break
                except ValueError:
                    continue
            else:
                continue
            sev = p.get("severity", p.get("score", p.get("z_score", 0)))
            try:
                sev = float(sev)
            except (TypeError, ValueError):
                sev = 0.0
            parsed.append((dt, sev))
        except Exception:
            continue
    if not parsed:
        return []
    parsed.sort(key=lambda x: x[0])
    t0, t1 = parsed[0][0], parsed[-1][0]
    span_min = max((t1 - t0).total_seconds() / 60.0, bucket_minutes)
    if NUMPY_OK:
        n_buckets = max(4, int(np.ceil(span_min / bucket_minutes)))
    else:
        n_buckets = max(4, -(-int(span_min) // bucket_minutes))  # ceil div without numpy
    scores = [0.0] * n_buckets
    counts = [0] * n_buckets
    for dt, sev in parsed:
        idx = min(int((dt - t0).total_seconds() / 60.0 // bucket_minutes), n_buckets - 1)
        if 0 <= idx < n_buckets:
            scores[idx] += sev
            counts[idx] += 1
    bucketed = [min(s / c, 1.0) if c else 0.0 for s, c in zip(scores, counts)]
    return bucketed


def _to_score_series(timeline: List[dict]) -> List[float]:
    """Return a per-bucket score series from either raw events or a
    pre-bucketed Phase-2 timeline.

    Detection rule: if the majority of entries are dicts with a
    ``timestamp`` field, treat the input as a raw event list and
    bucketise via :func:`_bucketize_events`. Otherwise treat it as a
    pre-bucketed Phase-2 timeline and pass through
    :func:`_extract_scores`.

    Pre-bucketed detection (preferred when both signals are available):
    if every entry has a *distinct* timestamp AND the entries are
    uniformly spaced (typical of split_merged_timeline output), they
    are already per-bucket scores — pass them through to avoid the
    "mean of severity" flattening bug that turned real pre-bucketed
    routing series into constant scores.
    """
    if not timeline:
        return []
    ts_count = sum(1 for p in timeline if isinstance(p, dict) and p.get("timestamp"))
    if ts_count < max(1, len(timeline) // 2):
        return _extract_scores(timeline)
    # Heuristic: count unique timestamps. If each entry has a distinct
    # bucket timestamp, this is a pre-bucketed Phase-2 series (one
    # entry per bucket), not a raw event log (many entries per bucket).
    distinct_ts = {p.get("timestamp") for p in timeline if isinstance(p, dict)}
    if len(distinct_ts) >= 0.9 * len(timeline):
        # All entries have distinct timestamps → pre-bucketed, pass through.
        return _extract_scores(timeline)
    return _bucketize_events(timeline)


def _extract_scores(timeline: List[dict]) -> List[float]:
    """Extract per-bucket anomaly scores from a Phase-1 timeline.

    Phase 1 produces events with the canonical field ``score`` (already
    bucketed per routing/traffic evidence channel). For backward
    compatibility with the merged-timeline shape used by
    ``correlation_analyzer.build_merged_timeline`` (which puts
    ``severity`` / ``z_score`` / ``confidence`` on each event instead of
    ``score``), we fall through a chain of plausible fields. If none of
    those fields is present we synthesise a binary presence score (1.0
    if the event is recorded, 0.0 otherwise) — this is what is required
    to get a non-zero CSS point estimator on real BGP data, where the
    raw event record carries per-event severity but the bucket-level
    score is not pre-aggregated.
    """
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


def _align_series(
    r_scores: List[float],
    t_scores: List[float],
) -> Tuple[List[float], List[float]]:
    n = max(len(r_scores), len(t_scores))
    r = list(r_scores) + [0.0] * (n - len(r_scores))
    t = list(t_scores) + [0.0] * (n - len(t_scores))
    return r, t


def _find_breakpoint(
    series: List[float],
    half_window: Optional[int] = None,
    min_effect: float = 0.0,
) -> int:
    """Return the index of the largest mean-shift in ``series``, or ``-1``.

    ``-1`` means *no detectable breakpoint*: the series is constant, all-zero,
    too short, or its best split does not move the mean by more than
    ``min_effect`` standard deviations.  Callers MUST treat ``-1`` as "there is
    no intervention window" and abstain.  Returning the midpoint instead (the
    pre-2026-10-22 behaviour) fabricated an intervention on flat series: every
    candidate split has ``diff == 0``, the first candidate ``k = half`` won the
    ``best_diff`` comparison, and both series ended up split at the same index,
    so ``lead`` was always 0 and the direction fell through to a magnitude
    comparison between two incommensurable quantities.

    The effect is normalised by the series' own standard deviation so the
    ``min_effect`` floor (when supplied by a caller) is scale-free.
    """
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


# ─────────────────────────────────────────────────────────────────────
# Counterfactual baseline: split timeline at MSBD breakpoint
# ─────────────────────────────────────────────────────────────────────
def _split_at_breakpoint(
    r_scores: List[float],
    t_scores: List[float],
    breakpoint_idx: Optional[int] = None,
) -> Tuple[List[float], List[float], List[float], List[float], int]:
    """Return (r_pre, t_pre, r_post, t_post, breakpoint_idx).

    If ``breakpoint_idx`` is None we find the largest-mean-shift point in the
    routing series (proxy for MSBD output).  When no break is detectable the
    function returns empty windows and ``-1`` — it never falls back to a
    midpoint split, because a midpoint split invents a pre/post partition that
    the data does not support (see :func:`_find_breakpoint`).
    """
    n = len(r_scores)
    if n < 4:
        return [], [], [], [], -1
    if breakpoint_idx is None or breakpoint_idx < 1 or breakpoint_idx >= n - 1:
        breakpoint_idx = _find_breakpoint(r_scores)
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


# ─────────────────────────────────────────────────────────────────────
# PNS estimation: difference-in-means with bootstrap CI
# ─────────────────────────────────────────────────────────────────────
# Scarcity threshold: below this many samples per arm, switch from
# plain bootstrap to Bayesian shrinkage + bias-corrected percentile CI.
# The threshold was derived empirically: with n<10 per arm, the bootstrap
# percentile CI is unstable (can include 0 even when the rank statistic
# is at the boundary) and the permutation-test p-value has high
# variance. Scarcity-aware PNS uses a Beta(α=1,β=1) prior on the
# direction-of-effect (symmetric Jeffrey's prior), which shrinks the
# point estimate toward 0 in proportion to the inverse sample size.
SCARCITY_THRESHOLD = 10


def _scarcity_aware_pns(pre, post, alpha_prior=1.0, beta_prior=1.0):
    """Bayesian-shrinkage PNS for small samples, in standardised units.

    Adds α-1 successes and β-1 failures to a Bernoulli model where
    each pre/post sample is "post > pre baseline". This shrinks the
    effect estimate toward the prior mean (0.5 for symmetric Jeffrey's)
    when the sample is small, and converges to the MLE when n is large.

    The point estimate and the CI are both expressed as the standardised
    mean shift (Cohen's d), so this path is directly comparable with the
    bootstrap path used for larger samples and with the opposite direction.

    Returns a dict with:
      - point: shrunk standardised effect
      - ci_lower / ci_upper: Beta-posterior 95% credible interval on
        the direction-of-effect probability, mapped back onto the
        standardised-effect scale
      - p_value: Bayesian posterior probability that effect ≤ 0,
        two-sided via the symmetric-Beta reference
    """
    n_pre, n_post = len(pre), len(post)
    scale = _standardisation_scale(pre, post)
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
    # effect scale by anchoring it at the observed |d|.  A CI that sits on 0.5
    # (no sign information) collapses to zero effect; a CI at the boundary maps
    # to the full observed effect.
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
    # Bayesian two-sided p: P(|effect| > 0 | data) lower-tail on |effect-0|
    # P(direction is null) = 2 * min(P(theta<0.5), P(theta>0.5))
    p_null = 2.0 * min(float((beta_samples < 0.5).mean()),
                      float((beta_samples > 0.5).mean()))
    p_value = max(0.0, min(1.0, 1.0 - (1.0 - p_null)))
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


def _standardisation_scale(pre, post) -> float:
    """Return a finite, scale-free denominator for a difference in means.

    Uses the within-arm pooled standard deviation (Cohen's d denominator).
    When both arms are internally constant — e.g. a clean step function — the
    pooled within-arm variance is zero and d would be infinite, so we fall back
    to the total standard deviation of the pooled sample, which is finite
    whenever the two arms differ.  Returns ``0.0`` when *both* are zero, which
    callers must treat as "effect not estimable".
    """
    n_pre, n_post = len(pre), len(post)
    var_pre = float(pre.var(ddof=1)) if n_pre > 1 else 0.0
    var_post = float(post.var(ddof=1)) if n_post > 1 else 0.0
    denom = max(n_pre + n_post - 2, 1)
    within = ((n_pre - 1) * var_pre + (n_post - 1) * var_post) / denom
    if within > 1e-18:
        return float(np.sqrt(within))
    return float(np.concatenate([pre, post]).std())


def _pns_estimate(
    pre_values: List[float],
    post_values: List[float],
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> Dict[str, float]:
    """Estimate PNS as a **standardised** pre→post mean shift.

    ``point = (mean(post) − mean(pre)) / pooled_sd`` — i.e. Cohen's d.

    Why standardised: the two CSS directions are computed on *different*
    variables (R→T measures a shift in traffic, T→R measures a shift in
    routing).  A raw difference in means therefore carries the units and the
    variance of whichever series it was computed on, and comparing
    ``|CSS(R→T)|`` with ``|CSS(T→R)|`` compared traffic-count units against
    BGP-update-count units.  Routing series are sparse spikes (std dominated by
    a single burst) while traffic series are dense, so the raw comparison was
    decided almost entirely by which series had the larger variance.  Dividing
    by each variable's own dispersion puts both directions on one ruler.

    For small samples (n<SCARCITY_THRESHOLD per arm) we fall back to
    Bayesian-shrinkage PNS (Beta-Binomial, Jeffrey's prior), also expressed in
    the standardised unit.

    Returns:
        dict(
                point=standardised effect (Cohen's d),
                ci_lower, ci_upper (95% bootstrap CI, same unit),
                p_value (two-sided permutation p),
                sufficiency (|point|, already σ-normalised, capped at 5),
                necessity (fraction of post where the intervention is "on"),
                estimable (False when the scale is degenerate),
            )
    """
    if not NUMPY_OK or len(pre_values) < 2 or len(post_values) < 2:
        return {
            "point": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "p_value": 1.0, "sufficiency": 0.0, "necessity": 0.0,
            "estimable": False,
        }
    pre = np.array(pre_values, dtype=float)
    post = np.array(post_values, dtype=float)
    scale = _standardisation_scale(pre, post)
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
        return _scarcity_aware_pns(pre, post)
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
    p_value = float((np.abs(perm_diffs) >= abs_point).mean())
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


# ─────────────────────────────────────────────────────────────────────
# Public API: css_score()
# ─────────────────────────────────────────────────────────────────────
def css_score(
    routing_timeline: List[dict],
    traffic_timeline: List[dict],
    msbd_breakpoint_idx: Optional[int] = None,
    n_bootstrap: int = 1000,
    p_threshold: float = 0.05,
    min_samples: int = 4,
) -> CSSResult:
    """Compute the Causal Sufficiency Score for routing → traffic attribution.

    Args:
        routing_timeline: list of {timestamp, score} entries.
        traffic_timeline: list of {timestamp, score} entries.
        msbd_breakpoint_idx: optional intervention-start index (from MSBD).
            If None, we find the largest-mean-shift in the routing series.
        n_bootstrap: number of bootstrap resamples for the CI.
        p_threshold: significance threshold for the bootstrap p-value.
        min_samples: minimum aligned-series length to attempt scoring.

    Returns:
        CSSResult — full PNS-style attribution verdict with bootstrap CI.
    """
    if not NUMPY_OK or not routing_timeline or not traffic_timeline:
        return CSSResult(
            direction="unknown",
            explanation="numpy missing or empty timeline; CSS cannot estimate.",
            details={"reason": "numpy missing or empty timeline"},
        )
    # Detect raw-event vs pre-bucketed timelines. If the timeline
    # entries carry a timestamp field AND there's more than one entry
    # per score repetition, it's a Phase-1 raw event list — bucketise
    # it before extracting scores. This is what fixes the
    # "point=0 on real BGP data" bug for Phase-1 callers.
    routing_scores = _to_score_series(routing_timeline)
    traffic_scores = _to_score_series(traffic_timeline)
    r_aligned, t_aligned = _align_series(routing_scores, traffic_scores)
    if len(r_aligned) < min_samples:
        return CSSResult(
            direction="unknown",
            explanation=f"aligned series length {len(r_aligned)} < {min_samples}; CSS cannot estimate.",
            details={"reason": "series too short"},
        )

    # Detect intervention point (MSBD-style break in routing series).
    r_pre, t_pre, r_post, t_post, bp_idx = _split_at_breakpoint(
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
    # pre and post. If routing is flat, there is no intervention to
    # attribute — bail to "unknown" so downstream Bayesian synthesis
    # uses the other channels instead. Threshold: post/pre mean ratio
    # OR std deviation exceeds 1.5×. This implements Pearl's
    # requirement that the "treatment" be observable.
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
    # a robustness fallback: if mean/std is dominated by outliers
    # (shift/σ < 0.3) but the *median* itself moved meaningfully
    # (median(post) ≠ median(pre)) we still consider the routing
    # series to carry an intervention signal. This is the
    # scarcity-aware branch: long-tail BGP series have
    # median(post) > median(pre) even when shift/σ is tiny because
    # std is inflated by outliers.
    #
    # FIX (real-data branch): for BGP event-time aggregations where most
    # buckets are zero and one bucket carries a 100+ event spike, std is
    # dominated by that one spike, so mean/std shift becomes artificially
    # small. We add a *sparsity-aware* shift metric: fraction of active
    # buckets (score > 0) and 90th-percentile-vs-pre ratio. Either is a
    # valid intervention indicator for BGP "bursty" event logs.
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
    # not bipartite — CSS abstains. We only run this when routing has an
    # intervention; otherwise the routing check above already returned.
    #
    # FIX (real-data branch): for BGP events we often have routing signal
    # but no traffic signal (Cloudflare Radar CSV doesn't cover the event
    # window, or the destination AS isn't in our traffic dataset). In that
    # case we cannot do a *bipartite* PNS test, but the routing-only
    # signal is still meaningful for direction attribution if routing
    # precedes traffic (lead < -1, established by routing breakpoint).
    # We therefore proceed to PNS estimation with an empty traffic series,
    # and rely on the lead-based tiebreaker in the decision logic below
    # to commit to R→T (routing precedes → R→T) rather than abstaining.
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
    #   E[T | do(R=1)] := post-traffic-mean
    #   E[T | do(R=0)] := pre-traffic-mean (synthetic control)
    # Split at the *routing* breakpoint (routing defines the intervention).
    rt = _pns_estimate(t_pre, t_post, n_bootstrap=n_bootstrap, seed=11)
    # PNS(T → R): split at the *traffic* breakpoint (traffic defines the
    # intervention). The traffic-breakpoint split is computed independently
    # so each PNS estimator uses the right pre/post window for its claim.
    # If traffic has no break, T→R is not identified: we mark it
    # non-estimable instead of slicing at an invented index.
    t_bp_idx = _find_breakpoint(t_aligned)
    if t_bp_idx < 1 or t_bp_idx >= len(r_aligned):
        tr = {
            "point": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "p_value": 1.0, "sufficiency": 0.0, "necessity": 0.0,
            "estimable": False,
        }
    else:
        tr = _pns_estimate(
            r_aligned[:t_bp_idx], r_aligned[t_bp_idx:],
            n_bootstrap=n_bootstrap, seed=23,
        )

    css_rt = rt["point"]
    css_tr = tr["point"]

    # Temporal precedence tiebreaker (Pearl: cause precedes effect).
    # If routing's intervention onset strictly precedes traffic's, we
    # *only* consider CSS(R→T) — the symmetric CSS(T→R) is structurally
    # implausible because routing's intervention window cannot begin
    # after traffic's already started. This is the standard
    # potential-outcomes identifiability constraint.
    #
    # ``lead`` is None when either series has no detectable breakpoint: we
    # cannot order two onsets when one of them was never observed.
    r_bp = _find_breakpoint(r_aligned) if NUMPY_OK else -1
    t_bp = _find_breakpoint(t_aligned) if NUMPY_OK else -1
    lead = (r_bp - t_bp) if (r_bp >= 0 and t_bp >= 0) else None

    # Compute absolute magnitudes up front so the decision branches below
    # can compare them without redefining (and shadowing) the names.
    # Both values are standardised effects (Cohen's d) on the variable they
    # describe, so the comparison is finally dimensionally valid.
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
        # precedence constraint nor the magnitude comparison can separate
        # them). Keep the larger standardised effect — a like-for-like
        # comparison now that both are Cohen's d.
        if abs_css_rt >= abs_css_tr:
            direction = "routing_to_traffic"
            ci_lower, ci_upper, p_value = rt["ci_lower"], rt["ci_upper"], rt["p_value"]
        else:
            direction = "traffic_to_routing"
            ci_lower, ci_upper, p_value = tr["ci_lower"], tr["ci_upper"], tr["p_value"]
    elif abs_css_rt > 0 and abs_css_tr > 0 and abs(abs_css_rt - abs_css_tr) <= 1e-12:
        # Exactly equal standardised effects and neither significant: the
        # data cannot order the two directions.
        direction = "independent"
        ci_lower = min(rt["ci_lower"], tr["ci_lower"])
        ci_upper = max(rt["ci_upper"], tr["ci_upper"])
        p_value = max(rt["p_value"], tr["p_value"])
    else:
        # Neither direction survives its null. The previous code picked the
        # larger |effect| as a "best guess" here, which manufactured a
        # directional verdict out of two statistically indistinguishable
        # quantities. CSS abstains instead.
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
    # signal that the *magnitude* of the dominant CSS is significantly
    # different from the null. Pearson-style bipolar CIs are fine for
    # this because PNS is signed (post − pre).
    # PNS interpretation: traffic shifted from baseline by a non-trivial
    # amount after the routing intervention (sign can be + or −, depending
    # on whether the event is a surge or a drop). Significance is therefore
    # ``CI excludes 0`` in the *two-sided* sense:
    #   ci_lower > 0  ⇒ traffic surged after routing
    #   ci_upper < 0  ⇒ traffic dropped after routing
    # Both are evidence that R → T causally affected T.
    rt_abs_ci_pos = rt["ci_lower"] > 0 or rt["ci_upper"] < 0
    tr_abs_ci_pos = tr["ci_lower"] > 0 or tr["ci_upper"] < 0
    dominant_abs_ci_pos = False
    if direction == "routing_to_traffic":
        dominant_abs_ci_pos = rt_abs_ci_pos
    elif direction == "traffic_to_routing":
        dominant_abs_ci_pos = tr_abs_ci_pos
    # p-value: use the dominant-direction PNS alone. When traffic is
    # unavailable, `rt.point` and `rt.ci` are degenerate (zero shift on
    # the traffic series), so we use the routing-series pre/post PNS as
    # the significance test — the routing intervention IS the causal
    # evidence in this branch. Pre-compute it lazily here.
    if direction == "routing_to_traffic":
        if traffic_available:
            p_value_combined = rt["p_value"]
        else:
            # Compute routing-series PNS as the causal evidence.
            # Use the routing breakpoint (already established as bp_idx).
            r_pns = _pns_estimate(
                list(r_pre), list(r_post), n_bootstrap=n_bootstrap, seed=31,
            )
            p_value_combined = r_pns["p_value"]
    elif direction == "traffic_to_routing":
        if traffic_available:
            p_value_combined = tr["p_value"]
        else:
            r_pns = _pns_estimate(
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
        sufficiency=round(rt["sufficiency"], 3),
        necessity=round(rt["necessity"], 3),
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


# ─────────────────────────────────────────────────────────────────────
# Bayesian synthesis: combine CSS with other evidence channels
# ─────────────────────────────────────────────────────────────────────
def bayesian_synthesize(
    css: CSSResult,
    evidence_channels: Dict[str, Dict[str, Any]],
    prior: Optional[Dict[str, float]] = None,
    event_type: Optional[str] = None,
    routing_withdrawal_signal: Optional[str] = None,
) -> Dict[str, Any]:
    """Bayesian synthesis of CSS with the other evidence channels.

    Each channel (CSS itself, MSBD counterfactual, CTPR sufficiency, CIC
    scope, Granger, transfer entropy) supplies a likelihood ratio:

        LR_d = P(channel_evidence | direction=d)

    and the posterior is

        P(direction=d | evidence) ∝ prior(d) · Π_clusters mean(LR_d)

    Two deliberate design changes from the previous version:

    1. **Uniform prior.**  CSS used to enter as a 10:1 (or 4:1) *prior*,
       i.e. before any channel was read.  That made the "posterior" a
       restatement of CSS's own verdict plus decoration, and it also meant
       the two directions were compared using CSS's raw (unstandardised)
       effect.  Here the prior is uniform and CSS is one channel among
       several, so the posterior reflects all the evidence and nothing is
       anchored in advance.

    2. **Correlated channels are pooled, not multiplied.**  MSBD, CTPR, CIC,
       Granger and TE all read the same two time series (and previously all
       consumed ``event_type``), so they are not independent observations.
       Multiplying five likelihood ratios treats five copies of one signal as
       five independent confirmations and drives the posterior to a spurious
       0.99.  Channels that point the same way are therefore grouped into one
       cluster and the cluster contributes the *geometric mean* of its
       members' likelihoods: repetition does not create evidence.

    ``event_type`` is accepted for API compatibility and deliberately
    ignored.  It is the ground-truth cause label; the expected direction is
    derived from the same label, so using it as a prior is label leakage
    (``route_leak`` → prior R→T → "predicted" R→T).

    ``routing_withdrawal_signal`` is likewise no longer a prior override.  It
    is folded into the channel set with a bounded likelihood, so it can be
    outweighed by contrary evidence instead of vetoing it.

    Returns a dict with ``direction`` (argmax posterior), ``posterior`` (the
    three-direction posterior mass), ``confidence`` (max posterior mass) and
    diagnostics: ``n_channels``, ``n_clusters`` and ``redundancy``
    (``n_channels / n_clusters``; > 1 means channels were duplicated).
    """
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
    # label), so it may enter as a weak channel.  It is bounded and can be
    # outweighed: an outage withdrawal is often the effect of the traffic
    # disruption rather than its cause.
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
    return {
        "direction": dominant if norm[dominant] > 0.34 else "unknown",
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