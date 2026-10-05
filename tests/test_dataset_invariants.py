"""Invariants that no existing test enforces.

Three defects in this project were invisible to the 444-test suite because
they are consistency properties across files, not unit behaviour of a single
function:

  1. Three ground-truth CSVs coexisted (``v13`` 29 rows, ``v15`` 10 rows,
     ``final_public`` 10 rows). ``run_4mode_batch.py`` defaulted to ``v15``
     while ``eval_hcaf_vs_baselines.py`` defaulted to ``v13``, so a batch run
     and an evaluation run scored different event sets and the two sets of
     numbers were not comparable. Nothing asserted a single source of truth,
     and ``test_hcaf_consistency.py`` even auto-selected a version at runtime.

  2. ``build_ground_truth_v16.py`` dropped every event the routing detector
     did not flag, i.e. it selected ground truth by detector output. That is
     label leakage: the evaluated system decides its own answer set. The
     project states the opposite rule in
     ``scripts/build_final_public_dataset.py`` ("Selecting events by detector
     output would be the exact leakage the project forbids") but no test
     enforced it.

  3. The dataset build / scan scripts had no test coverage at all: 53 test
     files referenced ``scripts/`` in only 7, and none of them imported
     ``build_ground_truth_v16``, ``build_final_public_dataset``,
     ``scan_public_events`` or ``verify_ground_truth``.

Each test below fails loudly on the corresponding state.
"""
from __future__ import annotations

import ast
import csv
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
COLLECT = ROOT / "data_check" / "ground_truth_collection"
DATASET_VERSION_RE = re.compile(r"^final_(?:balanced_dataset_v\d+|public_dataset)\.csv$")


def _csv_files() -> list[Path]:
    if not COLLECT.is_dir():
        return []
    return sorted(p for p in COLLECT.glob("*.csv") if DATASET_VERSION_RE.match(p.name))


def _all_consumers() -> list[Path]:
    out = []
    for sub in ("scripts", "agents", "detectors", "llm", "utils", "tools", "tests"):
        d = ROOT / sub
        if d.is_dir():
            out.extend(d.rglob("*.py"))
    for name in ("chief_agent.py", "workflow_engine.py", "config.py"):
        p = ROOT / name
        if p.is_file():
            out.append(p)
    return out


@pytest.mark.xfail(
    strict=True,
    reason="4 dataset versions coexist; consolidation to a single canonical "
           "CSV is pending an owner decision on the inclusion policy",
)
def test_only_one_ground_truth_dataset_exists():
    """Exactly one active ground-truth CSV may exist.

    Three coexisting versions is the root cause of non-comparable evaluation
    output. Version history belongs in git, not in the working tree.

    xfail(strict=True): currently 4 datasets coexist. The marker flips to a
    hard failure the moment the condition is fixed, so the cleanup cannot be
    forgotten.
    """
    found = _csv_files()
    assert len(found) <= 1, (
        "multiple active ground-truth datasets present: "
        f"{[p.name for p in found]}. Consumers pick different ones, so batch "
        "and evaluation results are not comparable. Keep one and move the "
        "rest into git history."
    )


@pytest.mark.xfail(
    strict=True,
    reason="9 files still hardcode a stale dataset version; see "
           "UNCOMMITTED_CLASSIFICATION.md group 3",
)
def test_every_consumer_points_at_the_same_dataset():
    """No source file may hardcode a different dataset version than the rest."""
    found = _csv_files()
    if not found:
        return  # single-source rule is exercised above

    canonical = found[0].name
    offenders: dict[str, set[str]] = {}
    for path in _all_consumers():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        refs = set(re.findall(r"final_(?:balanced_dataset_v\d+|public_dataset)\.csv", text))
        stale = {r for r in refs if r != canonical}
        if stale:
            offenders[str(path.relative_to(ROOT))] = stale

    assert not offenders, (
        f"these files reference a ground-truth dataset other than "
        f"{canonical}: {offenders}. Fix the default so evaluation and batch "
        "runs score the same events."
    )


@pytest.mark.xfail(
    strict=True,
    reason="build_ground_truth_v16.py still drops events when the routing "
           "detector is silent (label leakage); the job is also being killed",
)
def test_dataset_builder_does_not_filter_by_detector_output():
    """A ground-truth builder must not drop events the detector failed to flag.

    Leakage check: a builder that reads a detector verdict and uses it as an
    inclusion criterion is selecting the answer set with the system under
    test. Detection may only be *recorded*, never used to drop a row.
    """
    builder = ROOT / "scripts" / "build_ground_truth_v16.py"
    if not builder.is_file():
        return  # builder removed

    tree = ast.parse(builder.read_text(encoding="utf-8"))
    src = builder.read_text(encoding="utf-8")

    # Any `drop(...)` call whose reason mentions the detector missed it.
    leak_reasons = ("routing_detector_silent", "detector_returned_nothing")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
        if name not in ("drop", "reject"):
            continue
        rendered = ast.dump(node)
        for reason in leak_reasons:
            if reason in rendered:
                raise AssertionError(
                    f"{builder.name} drops ground-truth events based on "
                    f"detector output ({reason}). The evaluated detector must "
                    "not decide which events count as ground truth; record "
                    "detection in a column instead."
                )

    assert "routing_detector_silent" not in src, (
        f"{builder.name} still contains the 'routing_detector_silent' drop "
        "reason, which removes an event precisely because the detector missed "
        "it. That is label leakage."
    )


def test_build_scripts_are_importable_without_side_effects():
    """The dataset build chain must import without network or LLM calls.

    ``run_4mode_batch`` is already covered by round-22; the build chain
    (``build_ground_truth_v16``, ``build_final_public_dataset``,
    ``scan_public_events``, ``verify_ground_truth``) had no coverage, which is
    how the leak-selection bug survived.
    """
    import importlib
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    for mod in ("build_ground_truth_v16", "build_final_public_dataset",
                "scan_public_events", "verify_ground_truth"):
        path = ROOT / "scripts" / f"{mod}.py"
        if not path.is_file():
            continue
        try:
            importlib.import_module(mod)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"scripts/{mod}.py failed to import: {type(exc).__name__}: {exc}"
            ) from exc


@pytest.mark.xfail(
    strict=True,
    reason="leak_cox_communications_2025 (AS22773) has no start/end time in "
           "any version on disk; recovering the APNIC timestamps is pending",
)
def test_ground_truth_rows_have_resolvable_as_and_window():
    """Every row must be runnable: an AS and a real start/end window.

    ``chief_agent.py`` and ``run_4mode_batch.py`` both skip rows they cannot
    resolve, so a row without an AS or window is a silent no-op rather than a
    scored miss.
    """
    found = _csv_files()
    if not found:
        return

    with found[0].open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return

    bad: list[str] = []
    for row in rows:
        eid = row.get("event_id", "?")
        asn = (row.get("victim_as") or row.get("leak_as")
               or row.get("attacker_as") or "").strip()
        start = (row.get("start_time_utc") or "").strip()
        end = (row.get("end_time_utc") or "").strip()
        if not asn or not start or not end:
            bad.append(f"{eid} (as={asn or '-'} start={start or '-'} end={end or '-'})")

    if os.environ.get("BGP_ALLOW_UNRUNNABLE_ROWS") == "1":
        pytest.skip(f"{len(bad)} unrunnable row(s) tolerated by env flag: {bad}")

    assert not bad, (
        f"{len(bad)} row(s) cannot be executed and would be skipped silently: "
        f"{bad}. Either supply the missing field, or move the row to the "
        "rejected-events log with a reason."
    )
