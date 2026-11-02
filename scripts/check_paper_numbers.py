"""Cross-check every headline number in the paper against its artefact.

The two dedicated gates (``check_agent_paper_numbers.py`` and
``check_abstract_numbers.py``) pin the strings that appear in a table
row or an abstract sentence.  This gate is the complement: it derives
each headline number from the artefact and looks for it anywhere in
the paper, so a number that is correct in isolation but attached to the
wrong claim is still caught.

The LaTeX source is normalised before the search, so a number printed
as ``$12.3\\%`` is found by the plain string ``12.3%``.

Writes nothing; exits nonzero on a miss.
"""

from __future__ import annotations

import json
import os
import re
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL = PROJECT_ROOT / "results" / "eval"
PAPER = Path(os.environ.get(
    "BGP_TRACER_PAPER_DIR",
    str(PROJECT_ROOT / "docs" / "paper"),
))


def normalise(text: str):
    text = re.sub(r"\s+", " ", text)
    for a, b in (("\\%", "%"), ("{,}", ","), ("$", ""), ("\\", ""),
                 ("\\,", ""), ("~", " "), ("&amp;", "&")):
        text = text.replace(a, b)
    return text


def percent(value: float):
    """A percentage printed the way the paper prints it.

    ``49/400`` is exactly 12.25%, which the paper prints as 12.3%
    (round half up).  Float formatting would give 12.2%, because
    ``0.1225 * 100`` is 12.249999999999998 in binary floating point.
    """
    exact = (Decimal(str(value)) * 100).quantize(
        Decimal("0.1"), rounding=ROUND_HALF_UP)
    return f"{exact}%"


def load(name: str):
    path = EVAL / name
    if not path.exists():
        raise SystemExit(f"FAIL: missing artefact {path}")
    return json.loads(path.read_text())


def main():
    paper = normalise(" ".join(
        p.read_text() for p in sorted(PAPER.glob("*.tex"))))

    cal = load("paddle_calibration.json")
    cov = load("paddle_coverage_caches.json")["coverage_summary"]
    agent = load("gt_agent_full.json")["summary"]
    rules = load("gt_rule_only.json")["summary"]
    mono = load("gt_baseline_monolithic.json")["summary"]
    expl = load("explainability_audit.json")["summary"]
    ablation = load("component_ablation_summary.json")["summary"]
    heldout = load("heldout_validation.json")["arms"]
    baselines = load("baseline_comparison.json")["arms"]
    subsets = load("robustness_subsets.json")["subsets"]

    tests: list[tuple[str, str]] = [
        # ── the direction test ──
        ("size, rho=0", percent(cal["size"][0]["rate"])),
        ("size, rho=0.5", percent(cal["size"][1]["rate"])),
        ("size, rho=0.8", percent(cal["size"][2]["rate"])),
        ("planted commitments", f"{cal['power_total']['commits']:,}"),
        ("planted cells", str(cal["power_total"]["cells"])),
        ("simultaneous-shock false-commit rate",
         percent(cal["common"][0]["false_commit_rate"])),
        ("one-bucket-skew false-commit rate",
         percent(cal["common"][1]["false_commit_rate"])),
        ("cached windows", str(cov["n_caches"])),
        ("two-series windows", str(cov["n_two_series"])),
        ("windows without two series", str(cov["n_without_two_series"])),
        ("no traffic observations",
         f"No traffic observations & {cov['reasons']['no_traffic']}"),
        ("no declared window",
         f"No declared window & {cov['reasons']['no_window']}"),
        ("committed",
         f"Committed & {cov['n_committed']}"),

        # ── the agent layer ──
        ("agent correct",
         f"{agent['cause_accuracy_evaluable']['correct']}/"
         f"{agent['cause_accuracy_evaluable']['n']}"),
        ("monolithic correct",
         f"{mono['cause_accuracy_evaluable']['correct']}/"
         f"{mono['cause_accuracy_evaluable']['n']}"),
        ("rules correct",
         f"{rules['cause_accuracy_evaluable']['correct']}/"
         f"{rules['cause_accuracy_evaluable']['n']}"),
        ("agent outage",
         f"{agent['per_cause']['outage']['correct']}/"
         f"{agent['per_cause']['outage']['n']}"),
        ("rules outage",
         f"{rules['per_cause']['outage']['correct']}/"
         f"{rules['per_cause']['outage']['n']}"),
        ("agent hijack",
         f"{agent['per_cause']['origin_hijack_victim']['correct']}/"
         f"{agent['per_cause']['origin_hijack_victim']['n']}"),
        ("rules hijack",
         f"{rules['per_cause']['origin_hijack_victim']['correct']}/"
         f"{rules['per_cause']['origin_hijack_victim']['n']}"),
        ("agent leak",
         f"{agent['per_cause']['route_leak']['correct']}/"
         f"{agent['per_cause']['route_leak']['n']}"),
        ("rules leak",
         f"{rules['per_cause']['route_leak']['correct']}/"
         f"{rules['per_cause']['route_leak']['n']}"),
        ("agent accuracy", f"{agent['cause_accuracy_evaluable']['accuracy']:.2f}"),
        ("monolithic accuracy",
         f"{mono['cause_accuracy_evaluable']['accuracy']:.2f}"),
        ("rules accuracy", f"{rules['cause_accuracy_evaluable']['accuracy']:.2f}"),
        ("held-out agent",
         f"{heldout['corroboration_gate']['correct']}/"
         f"{heldout['corroboration_gate']['n']}"),
        ("held-out rules",
         f"{heldout['rule_only']['correct']}/{heldout['rule_only']['n']}"),
        ("explainability, agent mean",
         f"{expl['agent']['mean_score']:.3f}"),
        ("explainability, monolithic mean",
         f"{expl['monolithic']['mean_score']:.3f}"),
        ("explainability, agent Q4", f"{expl['agent']['Q4_alternative']:.2f}"),
        ("explainability, agent Q5", f"{expl['agent']['Q5_gap']:.2f}"),
        ("ablation, full",
         f"{ablation['full']['accuracy_across_runs']['mean']:.3f}"),
        ("ablation, no reasoning",
         f"{ablation['no_reasoning']['accuracy_across_runs']['mean']:.3f}"),

        # ── the system-level comparison ──
        ("pick-max top-1",
         percent(baselines["pick_max"]["top1"])),
        ("routing-only top-1",
         percent(baselines["routing_only"]["top1"])),
        ("traffic-only top-1",
         percent(baselines["traffic_only"]["top1"])),
        ("balanced accuracy, agent",
         f"{baselines['agent_full']['balanced_accuracy']:.3f}"),
        ("balanced accuracy, rules",
         f"{baselines['rule_only']['balanced_accuracy']:.3f}"),
        ("robustness, all events",
         percent(subsets["all"]["accuracy"])),
        ("robustness, with traffic",
         percent(subsets["with_traffic"]["accuracy"])),
        ("robustness, withdrawal storm",
         percent(subsets["withdrawal_storm"]["accuracy"])),
        ("robustness, hijack dominant",
         percent(subsets["hijack_dominant"]["accuracy"])),
    ]

    missing = []
    for name, needle in tests:
        if needle in paper:
            continue
        # A rate may be printed to either one or two decimals; accept
        # both, since 49/400 = 12.25% is legitimately printed 12.3% or
        # 12.25%.
        alt = None
        m = re.fullmatch(r"(\d+)\.(\d)%", needle)
        if m:
            whole, frac = m.groups()
            alt = f"{whole}.{frac}0%" if len(frac) == 1 else f"{whole}.{frac}%"
        if alt and alt in paper:
            continue
        missing.append((name, needle))

    print(f"paper/artefact cross-check: {len(tests) - len(missing)} of "
          f"{len(tests)} headline numbers found in the paper")
    for name, needle in missing:
        print(f"  MISS {name}: {needle!r} not found in the paper source")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
