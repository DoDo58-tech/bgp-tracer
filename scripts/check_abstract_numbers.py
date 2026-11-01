"""Check the abstract's numbers against the artefacts that produced them.

``check_agent_paper_numbers.py`` covers the agent section.  This gate
covers the abstract and the introduction, which quote the headline
results of the direction test and the agent layer.  The abstract and the
introduction are the two places a reader looks first and the two places
a stale number is most damaging, so their numbers are pinned to the
same artefacts the body uses.

Every number here is quoted as the exact string that appears in the
LaTeX source, so a mismatch in the source is a mismatch in the gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL = PROJECT_ROOT / "results" / "eval"
PAPER = Path(os.environ.get(
    "BGP_TRACER_PAPER_DIR",
    str(PROJECT_ROOT / "docs" / "paper"),
))


def load(name: str):
    p = EVAL / name
    if not p.exists():
        raise SystemExit(f"FAIL: missing artefact {p}")
    return json.loads(p.read_text())


def get(d: dict, path: str):
    cur = d
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def paper_number(label: str):
    """The rendered LaTeX form of a float, as the paper prints it."""
    return label


# (file, paper string, artefact, json path, expected value)
CHECKS = [
    # ── abstract: the interval-vs-point result ──
    ("main.tex", "$9.7\\%$ to $0.7\\%$ of $600$ windows",
     "aea_point_vs_interval.json", "regimes.0.false_commit_rate.point",
     "0.0967"),
    ("main.tex", "$9.7\\%$ to $0.7\\%$ of $600$ windows",
     "aea_point_vs_interval.json", "regimes.0.false_commit_rate.interval",
     "0.0067"),
    ("main.tex", "$9.7\\%$ to $0.7\\%$ of $600$ windows",
     "aea_point_vs_interval.json", "regimes.0.trials", "600"),

    # ── abstract: planted-mechanism precision ──
    ("main.tex", "$2{,}291$ commitments, none wrong",
     "aea_calibration.json", "power_total.commits", "2291"),
    ("main.tex", "$2{,}291$ commitments, none wrong",
     "aea_calibration.json", "power_total.correct", "2291"),

    # ── abstract: size under the null ──
    ("main.tex", "$3.0\\%$ rejections at",
     "aea_calibration.json", "size.0.rate", "0.03"),
    ("main.tex", "$12.3\\%$ at lag-one correlation $0.8$",
     "aea_calibration.json", "size.2.rate", "0.1225"),

    # ── abstract: coverage on the cached corpus ──
    ("main.tex", "$200$ of $227$ cached windows cannot produce",
     "aea_coverage_caches.json", "coverage_summary.n_caches", "227"),
    ("main.tex", "$200$ of $227$ cached windows cannot produce",
     "aea_coverage_caches.json", "coverage_summary.n_without_two_series",
     "200"),
    ("main.tex", "all $27$ that can stop at the first veto",
     "aea_coverage_caches.json", "coverage_summary.n_two_series", "27"),

    # ── introduction: the agent layer's accuracy claim ──
    ("section1_intro.tex", "$0.76$ against $0.06$",
     "component_ablation_summary.json", "headline.full.accuracy",
     "0.7647"),
    ("section1_intro.tex", "$0.76$ against $0.06$",
     "component_ablation_summary.json", "headline.monolithic.accuracy",
     "0.0588"),
]


def close_enough(value, expected: str):
    got = str(value)
    if got == expected:
        return True
    try:
        return abs(float(value) - float(expected)) <= max(
            0.005, abs(float(value)) * 0.0005)
    except (TypeError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    cache: dict[str, dict] = {}
    n_ok = 0
    failures: list[str] = []

    for fname, paper_str, artefact, json_path, expected in CHECKS:
        tex_path = PAPER / fname
        if not tex_path.exists():
            failures.append(f"missing source file {tex_path}")
            continue
        tex_flat = re.sub(r"\s+", " ", tex_path.read_text())
        needle = re.sub(r"\s+", " ", paper_str)
        if needle not in tex_flat:
            failures.append(
                f"paper string not found in {fname}: {paper_str!r} "
                f"(checked for {artefact}:{json_path})")
            continue
        if artefact not in cache:
            try:
                cache[artefact] = load(artefact)
            except SystemExit as exc:
                failures.append(str(exc))
                continue
        try:
            value = get(cache[artefact], json_path)
        except (KeyError, IndexError, TypeError) as exc:
            failures.append(f"{artefact}:{json_path} -> {exc}")
            continue
        if close_enough(value, expected):
            n_ok += 1
        else:
            failures.append(
                f"{artefact}:{json_path} = {value!r}, paper says {expected!r}")

    print(f"abstract/intro number check: {n_ok} values verified, "
          f"{len(failures)} mismatch(es)")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
