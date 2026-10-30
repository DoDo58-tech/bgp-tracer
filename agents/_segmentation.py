"""Shared numeric primitives for the directional-attribution estimators.

One implementation of segmentation, interval contrasts and the placebo null is
shared by the AEA estimator (``agents.edge_ownership``) and by the earlier FIT
pilot (``agents.falsification_test``).  The primitives live in the FIT module
and are re-exported here, so this layer adds a stable import surface without
duplicating numerics: a change to ``detect_changes`` or ``its_p_value`` reaches
every estimator at once.

Nothing in this module decides a direction.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import numpy as np

from agents.falsification_test import (  # noqa: F401
    bic,
    clean,
    detect_changes,
    its_effect,
    its_p_value,
    prefix,
    recovery_of,
    seg_sse,
    welch_t,
)

def onset_interval(
    x: np.ndarray,
    min_seg: int,
    det: Optional[Dict[str, Any]] = None,
    bic_penalty: float = 1.0,
    slack: float = 1.0,
) -> Optional[Tuple[int, int]]:
    """The set of onsets the data cannot distinguish, as ``(lo, hi)``.

    The onset is reported as a point by BIC, but the SSE profile near the
    optimum is flat enough that neighbouring splits are equally admissible.
    One extra free parameter costs ``log(K) * sigma2`` in SSE, so every onset
    within ``slack`` of that budget is retained.  The width is the onset
    resolution of the window: two edges whose intervals overlap cannot be
    ordered, however their point estimates fall.

    ``sigma2`` and the model structure both come from ``det`` (the selected
    segmentation), never from a fixed one-change fit: estimating noise under a
    misspecified model -- a pulse read as a single step -- inflates the scale by
    the size of the ignored second change and makes every interval uselessly
    wide.
    """
    K = int(len(x))
    if det is None:
        if K < 3 * min_seg:
            return None
        det = detect_changes(x, min_seg, bic_penalty)
    model = int(det.get("model", 0))
    changes = list(det.get("changes") or [])
    if model == 0 or not changes:
        return None

    # A model with m changes estimates m+1 means and m locations.
    sigma2 = float(det["sse"]) / max(K - (2 * model + 1), 1)
    tol = float(slack) * float(np.log(K)) * max(sigma2, 1e-12) * bic_penalty
    if tol <= 0.0:
        return None

    c1, c2 = prefix(x)
    if model >= 2 and len(changes) >= 2:
        b = int(changes[1])
        grid = np.arange(min_seg, max(b - min_seg, min_seg) + 1)
        sse = np.array([
            seg_sse(c1, c2, 0, int(a)) + seg_sse(c1, c2, int(a), b)
            + seg_sse(c1, c2, b, K)
            for a in grid
        ])
    else:
        grid = np.arange(min_seg, K - min_seg + 1)
        sse = np.array([
            seg_sse(c1, c2, 0, int(a)) + seg_sse(c1, c2, int(a), K)
            for a in grid
        ])
    if grid.size == 0:
        return None

    best = float(sse.min())
    keep = grid[sse - best <= tol]
    if keep.size == 0:
        keep = grid[[int(np.argmin(sse))]]
    return int(keep.min()), int(keep.max())


__all__ = [
    "bic",
    "clean",
    "detect_changes",
    "its_effect",
    "its_p_value",
    "onset_interval",
    "prefix",
    "recovery_of",
    "seg_sse",
    "welch_t",
]
