"""
Regression tests for Round 18 bug fixes.

BUG-R132: the then-current human_review_report.csv had 6 rows with missing
victim_as fields, causing chief_agent.py to skip those events with a "no_asn"
reason during 4-mode batch evaluation. The 6 AS numbers were filled in from
authoritative sources (Kentik/APNIC/NANOG reports, Cloudflare postmortem,
Oracle advisory):

    hijack_crypto_campaign_2023  → AS398722  (Oracle advisory)
    hijack_uztelecom_2024        → AS28910   (Kentik)
    leak_voxility_2025           → AS3223    (Kentik)
    leak_upx_2025                → AS52863   (Kentik)
    leak_cox_2025                → AS22773   (APNIC)
    leak_reliablesite_2025       → AS23470   (NANOG ml)

REWRITTEN 2026-10-05. The original tests read
``human_review_report.csv``, which no longer exists (superseded by
``final_balanced_dataset_v13.csv``), so all four tests were erroring with
``FileNotFoundError`` and had been silently failing — they were not guarding
anything.

The underlying invariant is unchanged and is what actually matters: every event
must resolve to a usable AS number, because chief_agent.py skips events it
cannot resolve. The v10+ schema splits this across three columns by event type
(``victim_as`` for hijack/outage, ``leak_as`` for route leaks,
``attacker_as`` for attacker-view rows), and every consumer in the repo reads
them with that fallback:

    scripts/eval_hcaf_vs_baselines.py:611
    scripts/reproduce_eval.py:57
    scripts/run_4mode_batch.py:267
    tests/test_hcaf_consistency.py:155

So asserting "``victim_as`` must be non-empty for all rows" is simply the wrong
invariant: 8 of 29 v13 rows are route leaks that legitimately carry their AS in
``leak_as``. These tests now assert the real contract.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASET = (
    PROJECT_ROOT
    / "data_check/ground_truth_collection/final_balanced_dataset_v13.csv"
)


def _load_csv():
    # utf-8-sig strips a leading BOM if present (the file is written with BOM)
    with open(DATASET, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _resolve_as(row: dict) -> str:
    """The AS a consumer would actually use for this row."""
    return (
        row.get("victim_as")
        or row.get("leak_as")
        or row.get("attacker_as")
        or row.get("asn")
        or ""
    ).strip()


def test_dataset_loadable():
    """The active ground-truth dataset must exist and parse."""
    assert DATASET.exists(), f"missing ground-truth dataset: {DATASET}"
    rows = _load_csv()
    assert len(rows) >= 20, f"expected >=20 rows, got {len(rows)}"


def test_no_missing_as():
    """Every event row must resolve to a non-empty AS.

    This is the invariant BUG-R132 was actually about: chief_agent.py skips
    events it cannot resolve to an AS, silently dropping them from evaluation.
    """
    rows = _load_csv()
    missing = [r.get("event_id") for r in rows if not _resolve_as(r)]
    assert not missing, (
        f"The following events resolve to no AS in any of "
        f"victim_as/leak_as/attacker_as/asn: {missing}. "
        "chief_agent.py will skip them with 'no_asn'."
    )


def test_all_as_have_as_prefix():
    """Every resolved AS must start with 'AS' for chief_agent parsing."""
    rows = _load_csv()
    bad = []
    for r in rows:
        va = _resolve_as(r)
        if va and not va.startswith("AS"):
            bad.append((r.get("event_id"), va))
    assert not bad, f"The following events have an AS without 'AS' prefix: {bad}"


def test_bug_r132_as_values_are_correct():
    """The BUG-R132 AS numbers must be present with the right values, or
    explicitly accounted for as rejected.

    The events were renamed when the dataset was consolidated into v13, so this
    matches on the AS number itself rather than the old event_id: the point of
    the original fix was that these specific ASes carry the right values.

    Three of the six are absent from v13 because they were *deliberately*
    rejected, not lost — ``v13_rejected_events.csv`` records
    ``leak_upx_2025`` with ``v11_rejection_reason =
    "traffic_irregular_for_anomaly_detection"``. A 15-minute leak that produces
    no traffic anomaly is not detectable by this system's design, so excluding
    it from a detection benchmark is correct. Silently dropping it would be
    data loss, so this test asserts the rejection is still documented.
    """
    rows = _load_csv()
    by_as = {_resolve_as(r): r for r in rows if _resolve_as(r)}

    # Still in the dataset, and attached to the right kind of event.
    expected_present = {
        "AS3223": "leak_voxility",      # Kentik: Voxility leaker
        "AS22773": "leak_cox",          # APNIC: Cox leaker
        "AS23470": "leak_reliablesite",  # NANOG: ReliableSite leaker
    }
    for asn, id_fragment in expected_present.items():
        assert asn in by_as, (
            f"{asn} (BUG-R132 {id_fragment}) is missing from the dataset; "
            f"present ASes: {sorted(by_as)[:8]}..."
        )
        assert id_fragment in (by_as[asn].get("event_id") or ""), (
            f"{asn} should belong to a {id_fragment} event, but is attached to "
            f"{by_as[asn].get('event_id')!r}"
        )

    # Absent from v13 on purpose — the rejection must still be on record with
    # a stated reason, otherwise this is unexplained data loss.
    rejected_path = (
        PROJECT_ROOT / "data_check/ground_truth_collection/v13_rejected_events.csv"
    )
    assert rejected_path.exists(), (
        "v13_rejected_events.csv must exist so dropped events stay auditable"
    )
    with open(rejected_path, newline="", encoding="utf-8-sig") as f:
        rejected = {r.get("event_id"): r for r in csv.DictReader(f)}

    # leak_upx_2025 was deliberately excluded and the reason is on record:
    # a 15-minute leak produces no traffic anomaly, so it is undetectable by
    # this system and does not belong in a detection benchmark.
    assert "leak_upx_2025" not in by_as, (
        "leak_upx_2025 unexpectedly re-entered the dataset; update this test"
    )
    assert (rejected.get("leak_upx_2025", {}).get("v11_rejection_reason") or "").strip(), (
        "leak_upx_2025 is excluded but has no stated rejection reason"
    )

    # KNOWN GAP (found 2026-10-05, unresolved): two Tier A hijack events that
    # earlier versions of the dataset carried are present in NEITHER the
    # current dataset NOR the rejected-events log, so their disappearance
    # cannot be justified from the data on disk:
    #
    #     hijack_crypto_campaign_2023  AS398722  Oracle advisory (self-hijack)
    #     hijack_uztelecom_2024        AS28910   Kentik (self-leak)
    #
    # Both were in the old human_review_report.csv, which was deleted when the
    # dataset was consolidated into v13, and neither name nor AS appears
    # anywhere in data_check/ground_truth_collection now. This is silent
    # ground-truth loss of publicly reported events, which biases the
    # benchmark toward whatever the rebuild happened to keep.
    #
    # This assertion therefore FAILS on purpose. It is a tripwire, not a
    # regression: it records the discrepancy so it cannot be forgotten, and it
    # will start passing once the events are either restored to the dataset or
    # given a documented rejection reason. Delete or invert it only after one
    # of those two actually happens.
    for event_id, asn in (
        ("hijack_crypto_campaign_2023", "AS398722"),
        ("hijack_uztelecom_2024", "AS28910"),
    ):
        accounted_for = event_id in rejected or asn in by_as
        assert accounted_for, (
            f"GROUND-TRUTH LOSS: {event_id} ({asn}) is a publicly reported "
            "Tier A event that exists in neither the active dataset nor "
            "v13_rejected_events.csv. Either restore it or record an explicit "
            "rejection reason — silently dropping it biases the benchmark."
        )


def test_csv_parses_without_error():
    """The CSV must be readable and every row must have the same fields."""
    rows = _load_csv()
    assert rows, "dataset is empty"
    fieldnames = set(rows[0].keys())
    for i, row in enumerate(rows[1:], start=2):
        missing_fields = fieldnames - set(row.keys())
        assert not missing_fields, (
            f"Row {i} ({row.get('event_id', '?')}) is missing fields: {missing_fields}"
        )


def test_as_values_are_numeric():
    """AS numbers must be digits once the prefix is stripped.

    chief_agent.py casts to int; a non-numeric value would raise mid-batch and
    abort the remaining events.
    """
    rows = _load_csv()
    bad = []
    for r in rows:
        asn = _resolve_as(r)
        if asn and not asn.replace("AS", "").strip().isdigit():
            bad.append((r.get("event_id"), asn))
    assert not bad, f"Non-numeric AS values would crash chief_agent: {bad}"
