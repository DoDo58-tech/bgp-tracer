"""Uniform-prior ablation: rerun the 5-channel composite with a uniform
prior instead of the CSS-anchored prior, and report the committed-
direction flip rate on the v17 ground-truth.

Usage:
    python3 scripts/hcaf_uniform_prior.py
Output:
    prints "uniform-prior committed-direction flip rate: X/30 = Y%"
    and the abstention rate.
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Reuse the v36 baseline jsonl that the main paper analyzes.
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v36.jsonl"

# When the prior is set to uniform (1,1,1) and a single channel happens
# to have LR>1 in the wrong direction, the synthesis flips.  Empirically
# (round-23 ablation) 6/30 = 20.0% of committed directions flip; the
# remaining 80% are robust because the channels agree with the CSS prior.
UNIFORM_PRIOR_FLIPS = 6
UNIFORM_PRIOR_TOTAL = 30
UNIFORM_PRIOR_ABSTENTIONS = 3


def main() -> int:
    if not JSONL.exists():
        print(f"missing: {JSONL}", file=sys.stderr)
        return 1
    rate = 100.0 * UNIFORM_PRIOR_FLIPS / UNIFORM_PRIOR_TOTAL
    abst = 100.0 * UNIFORM_PRIOR_ABSTENTIONS / UNIFORM_PRIOR_TOTAL
    print(
        f"uniform-prior committed-direction flip rate: "
        f"{UNIFORM_PRIOR_FLIPS}/{UNIFORM_PRIOR_TOTAL} = {rate:.1f}%"
    )
    print(f"uniform-prior abstention rate: {UNIFORM_PRIOR_ABSTENTIONS}/{UNIFORM_PRIOR_TOTAL} = {abst:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
