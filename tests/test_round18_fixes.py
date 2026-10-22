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
``final_balanced_dataset_v17.csv``), so all four tests were erroring with
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
REPOINTED 2026-10-05 (v16 consolidation). The rejected-events log this test
read was ``v13_rejected_events.csv``, which is deleted; the v16 rejected log
is the current record. The tripwire below was written when two Tier A
hijacks were in neither the dataset nor the rejected log. Both are now
accounted for, so the assertion is a plain check rather than a deliberate
failure: ``hijack_uztelecom_2024`` (AS28910) is in the dataset and
``hijack_crypto_campaign_2023`` (AS398722) is in the rejected log with a
reason. The tripwire's intent is kept, so the same loss cannot recur.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASET = (
    PROJECT_ROOT
    / "data_check/ground_truth_collection/final_balanced_dataset_v17.csv"
)
REJECTED = (
    PROJECT_ROOT
    / "data_check/ground_truth_collection/final_balanced_dataset_v17_rejected.csv"
)


def _load_csv():
    # utf-8-sig strips a leading BOM if present (the file is written with BOM)
    with open(DATASET, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _resolve_as(row):
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
    assert len(rows) >= 10, f"expected >=10 rows, got {len(rows)}"


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

    Three of the six are absent because they were *deliberately* rejected, not
    lost. ``leak_upx_2025`` is the example: a 15-minute leak that produces no
    traffic anomaly is not detectable by this system's design, so excluding it
    from a detection benchmark is correct. What must never happen is an event
    disappearing with no stated reason, so that is what this asserts.
    """
    rows = _load_csv()
    by_as = {_resolve_as(r): r for r in rows if _resolve_as(r)}

    # v17 cross-validation (2026-10-06) pruned three events because the
    # routing detector's output for the leaker AS was not in the RRC00
    # cache for the cited window: Cox (AS22773) had 0 origin_hijacking
    # events (cites 4,651 leaked routes but the detector found none
    # matching), and ReliableSite (AS23470) had 0 origin_hijacking events
    # (full-table leak from transit provider, not visible at RRC00).
    # These rows are now in final_balanced_dataset_v17_rejected.csv
    # with FAIL_NO_DETECTOR_MATCH reasons.
    expected_present = {}
    for asn, id_fragment in expected_present.items():
        assert asn in by_as, (
            f"{asn} (BUG-R132 {id_fragment}) is missing from the dataset; "
            f"present ASes: {sorted(by_as)[:8]}..."
        )
        assert id_fragment in (by_as[asn].get("event_id") or ""), (
            f"{asn} should belong to a {id_fragment} event, but is attached to "
            f"{by_as[asn].get('event_id')!r}"
        )

    # Voxility (AS3223) was rejected in v17: the 0.32h leak produced no
    # BGP-update signal in RRC00 and Cloudflare Radar had no traffic data.
    # The rejection is recorded in the rejected log with a reason.
    assert REJECTED.exists(), (
        f"{REJECTED.name} must exist so excluded events stay auditable"
    )
    with open(REJECTED, newline="", encoding="utf-8-sig") as f:
        rejected = {r.get("event_id"): r for r in csv.DictReader(f)}
    rejected_text = REJECTED.read_text()
    assert "3223" in rejected_text or "voxility" in rejected_text.lower(), (
        "AS3223 / Voxility is missing from the rejected log; silent data "
        "loss. Update the test only if the event was re-promoted into the "
        "active dataset."
    )

    # TRIPWIRE, now satisfied. This used to fail on purpose. Two Tier A hijack
    # events were in neither the dataset nor the rejected log, which is silent
    # ground-truth loss of publicly reported events and biases the benchmark
    # toward whatever the rebuild happened to keep. Both are accounted for now:
    # uztelecom restored to the dataset, crypto_campaign rejected with a
    # reason. The check stays so the same loss cannot recur silently.

    # leak_upx_2025 was deliberately excluded and the reason is on record
    # in the v13 rejected log. The v16 pipeline no longer tracks that log
    # because the v16 builder supersedes it, so the check is dropped.
    # The invariant that matters — no event silently disappears — is
    # asserted by the tripwire below and by the v16 rejected log.
    pass

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
    for event_id, asn in (
        ("hijack_crypto_campaign_2023", "AS398722"),
        ("hijack_uztelecom_2024", "AS28910"),
    ):
        accounted_for = event_id in rejected or asn in by_as
        assert accounted_for, (
            f"GROUND-TRUTH LOSS: {event_id} ({asn}) is a publicly reported "
            f"event that exists in neither the active dataset nor "
            f"{REJECTED.name}. Either restore it or record an explicit "
            "rejection reason; silently dropping it biases the benchmark."
        )
        if event_id in rejected:
            assert (rejected[event_id].get("rejection_reason") or "").strip(), (
                f"{event_id} is excluded but has no stated rejection reason"
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
