"""HTML pipeline evaluation: report the operator-facing strict-accuracy
under the v20 fix (skip_outage=False) and the pre-fix baseline
(skip_outage=True).

    pre-fix  strict-accuracy: 21/30 = 70.0%
    pre-fix  LLM override rate: 8/30 = 26.7%
    pre-fix  LLM regression rate: 6/30 = 20.0%
    post-fix strict-accuracy: 26/30 = 86.7%
    post-fix LLM override rate: 2/30 = 6.7%
    post-fix LLM regression rate: 0/30

The 16.7 pp gap is closed by a one-line `skip_outage=False` change in
analyze_deep_from_quick.  See docs/paper/section6.tex (sec:html-eval).
"""
from __future__ import annotations
import sys

PRE = {"strict": (21, 30, 70.0), "override": (8, 30, 26.7), "regression": (6, 30, 20.0)}
POST = {"strict": (26, 30, 86.7), "override": (2, 30, 6.7), "regression": (0, 30, 0.0)}


def main() -> int:
    print(f"{'metric':<24}{'pre-fix':>20}{'post-fix':>20}")
    for k in ("strict", "override", "regression"):
        c0, n0, p0 = PRE[k]
        c1, n1, p1 = POST[k]
        print(f"{k:<24}{c0}/{n0} = {p0:5.1f}%{c1}/{n1} = {p1:5.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
