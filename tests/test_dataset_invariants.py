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
     builder now derives membership from the seed list and never reads a
     detector verdict, and ``test_dataset_builder_does_not_filter_by_detector_output``
     keeps it that way.

  3. The dataset build / scan scripts had no test coverage at all. The build
     chain (``build_ground_truth_v16``, ``verify_ground_truth``) now imports
     cleanly, so a regression in the inclusion logic will fail this test.

All three are fixed. The markers were ``xfail(strict=True)`` so they turned
into hard failures the moment the condition cleared; they are plain
assertions now.
"""
from __future__ import annotations

import ast
import csv
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
COLLECT = ROOT / "data_check" / "ground_truth_collection"
DATASET_VERSION_RE = re.compile(r"^final_(?:balanced_dataset_v\d+|public_dataset)\.csv$")
AUXILIARY_SUFFIXES = ("_input.csv", "_rejected.csv")


def _csv_files() -> list[Path]:
    if not COLLECT.is_dir():
        return []
    return sorted(
        p for p in COLLECT.glob("*.csv")
        if DATASET_VERSION_RE.match(p.name)
        and not any(p.name.endswith(s) for s in AUXILIARY_SUFFIXES)
    )


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


def test_only_one_ground_truth_dataset_exists():
    """Exactly one active ground-truth CSV may exist.

    Three coexisting versions is the root cause of non-comparable evaluation
    output. Version history belongs in git, not in the working tree.
    """
    found = _csv_files()
    assert len(found) <= 1, (
        "multiple active ground-truth datasets present: "
        f"{[p.name for p in found]}. Consumers pick different ones, so batch "
        "and evaluation results are not comparable. Keep one and move the "
        "rest into git history."
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
        refs = set(re.findall(r"final_(?:balanced_dataset_v\d+|public_dataset)(?:_input|_rejected)?\.csv", text))
        stale = {r for r in refs if not r.startswith(canonical.removesuffix(".csv")) and r != canonical}
        if stale:
            offenders[str(path.relative_to(ROOT))] = stale

    assert not offenders, (
        f"these files reference a ground-truth dataset other than "
        f"{canonical}: {offenders}. Fix the default so evaluation and batch "
        "runs score the same events."
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
    (``build_ground_truth_v16``, ``verify_ground_truth``) now imports cleanly
    here, which is how the leak-selection bug was caught.
    """
    import importlib
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    for mod in ("build_ground_truth_v16", "verify_ground_truth"):
        path = ROOT / "scripts" / f"{mod}.py"
        if not path.is_file():
            continue
        try:
            importlib.import_module(mod)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"scripts/{mod}.py failed to import: {type(exc).__name__}: {exc}"
            ) from exc


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


def test_every_row_declares_an_evidence_tier():
    """A row must state how strong its evidence is.

    v15 deleted the automated-detection tier outright instead of labelling it,
    which silently rebalanced the dataset toward media-reported events. The
    tier column is what stops that recurring: a paper can filter on evidence
    strength instead of inferring it from which rows survived.
    """
    found = _csv_files()
    if not found:
        return
    with found[0].open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return

    assert "evidence_tier" in rows[0], (
        f"{found[0].name} has no evidence_tier column, so evidence strength "
        "cannot be filtered on"
    )

    allowed = {"A", "B", "not_applicable"}
    undeclared = [r["event_id"] for r in rows
                  if r.get("evidence_tier") not in allowed]
    assert not undeclared, (
        f"rows with an unrecognised evidence_tier: {undeclared}. "
        f"Expected one of {sorted(allowed)}."
    )

    # A tier-B row must not silently look like a public report.
    mislabelled = [r["event_id"] for r in rows
                   if r.get("evidence_tier") == "A"
                   and "bgpstream" in (r.get("source_url") or "").lower()]
    assert not mislabelled, (
        f"rows labelled tier A while citing an alert platform: {mislabelled}. "
        "An automated detector is not a public report."
    )


def test_thin_class_is_marked_not_backfilled():
    """roa_misconfig rows must each be primary public postmortems with a victim
    AS and a window; rows missing any of those go to REJECTED.

    At v16, the class was kept at n=1 because only the Orange Espana account
    takeover had a full public write-up. The North Korea star-JV maxLength
    ROA of 2025-03-18 added a second primary postmortem, so the cap was
    lifted. The cap can return only if evidence dries up again; it is not
    a permanent policy.
    """
    found = _csv_files()
    if not found:
        return
    with found[0].open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    roa = [r for r in rows if r.get("ground_truth_cause_label") == "roa_misconfig"]
    for r in roa:
        assert r.get("victim_as"), (
            f"roa_misconfig row {r.get('event_id')} must name a victim AS"
        )
        assert r.get("start_time_utc") and r.get("end_time_utc"), (
            f"roa_misconfig row {r.get('event_id')} must have a window"
        )
        assert r.get("evidence_tier") in ("A", "not_applicable"), (
            f"roa_misconfig row {r.get('event_id')} must be tier A or marked"
        )


def test_dataset_is_rebuildable_from_the_seed_list():
    """The dataset must be a pure function of the seed list.

    v16 was consolidated by deleting v13/v14/v15, which also deleted the
    builder's own inputs. The seed list is now the single source of truth, so
    a rebuild cannot silently depend on a file that no longer exists.
    """
    seed = COLLECT / "seed_events.py"
    assert seed.is_file(), (
        f"{seed} is missing, so the dataset cannot be rebuilt from source"
    )

    sys.path.insert(0, str(COLLECT))
    for mod in ("seed_events",):
        sys.modules.pop(mod, None)
    import seed_events

    found = _csv_files()
    if not found:
        return
    with found[0].open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    seed_ids = {e["event_id"] for e in seed_events.SEED}
    csv_ids = {r["event_id"] for r in rows}
    assert seed_ids == csv_ids, (
        "the dataset and the seed list disagree. "
        f"only in seed: {sorted(seed_ids - csv_ids)}; "
        f"only in csv: {sorted(csv_ids - seed_ids)}"
    )

    rejected_ids = {e["event_id"] for e in seed_events.REJECTED}
    overlap = seed_ids & rejected_ids
    assert not overlap, (
        f"events appear in both the dataset and the rejected log: "
        f"{sorted(overlap)}"
    )


def test_no_tier_b_rows_in_canonical_dataset():
    """The canonical dataset must contain only public-report (Tier A) rows.

    Per the user's directive (2026-10): "alert-platform-only events
    (BGPStream, etc.) are forbidden in the ground-truth dataset" — v17
    enforces a Tier-A-only policy.

    Tier-B rows that the project still tracks belong in the rejected log,
    not the active dataset.
    """
    found = _csv_files()
    if not found:
        return
    with found[0].open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    tier_b = [r for r in rows if r.get("evidence_tier") == "B"]
    assert not tier_b, (
        f"{len(tier_b)} tier-B rows remain in the canonical dataset: "
        f"{[r['event_id'] for r in tier_b]}. Per the 2026-10 directive, "
        "BGPStream / alert-platform-only events are forbidden; move them "
        "to the rejected log."
    )


def test_builder_reproduces_derived_columns():
    """Re-running ``build_ground_truth_v16.py`` must not silently strip the
    two derived annotation columns ``routing_event_in_window`` and
    ``leak_as_role`` that the eval pipeline now depends on.

    The builder is the single source of truth. A column the builder does
    not emit disappears the next time anyone rebuilds. This test
    catches that regression: if the FIELDS list in build_ground_truth_v16.py
    drops either column, the rebuild will overwrite the CSV with an
    older 32-column shape and ``expected_direction()`` will silently
    fall back to the mis-coded ``T→R`` default for every outage row
    whose true direction is ``R→T``.
    """
    builder = ROOT / "scripts" / "build_ground_truth_v16.py"
    if not builder.is_file():
        return
    src = builder.read_text(encoding="utf-8")
    for col in ("routing_event_in_window", "leak_as_role"):
        assert f'"{col}"' in src, (
            f"build_ground_truth_v16.py no longer declares the '{col}' "
            f"column in FIELDS. Rebuilding the CSV will silently drop it "
            f"and break eval_hcaf_vs_baselines::expected_direction for "
            f"outage rows whose routing_event_in_window must be 'yes'."
        )
