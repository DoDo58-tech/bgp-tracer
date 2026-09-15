"""
Regression tests for Round 18 bug fixes.

BUG-R132: human_review_report.csv had 6 rows with missing victim_as fields,
causing chief_agent.py to skip those events with "no_asn" reason during
4-mode batch evaluation.

Fix: filled in the 6 missing victim_as values based on authoritative sources
(Kentik/APNIC/NANOG reports, Cloudflare postmortem, Oracle advisory):

    hijack_crypto_campaign_2023  → AS398722  (Oracle advisory: attacker = victim,
                                               AS398722 self-hijacked 70+ prefixes)
    hijack_uztelecom_2024        → AS28910  (Kentik: Uztelecom self-leaked)
    leak_voxility_2025           → AS3223   (Kentik: Voxility leaker)
    leak_upx_2025                → AS52863  (Kentik: UPX leaker)
    leak_cox_2025                → AS22773  (APNIC: Cox leaker)
    leak_reliablesite_2025       → AS23470  (NANOG ml: ReliableSite leaker)

Also standardized format to always include "AS" prefix (matching the other
28 rows which already had it), and backed up original to human_review_report.csv.bak.

This test verifies:
  - All 34 rows have non-empty victim_as
  - All victim_as values have "AS" prefix (format consistency)
  - The file parses without error
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _load_csv():
    path = PROJECT_ROOT / "data_check/ground_truth_collection/human_review_report.csv"
    # utf-8-sig strips a leading BOM if present (the file is written with BOM)
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def test_no_missing_victim_as():
    """Every event row must have a non-empty victim_as."""
    rows = _load_csv()
    missing = [r["event_id"] for r in rows if not r.get("victim_as", "").strip()]
    assert not missing, (
        f"The following events are missing victim_as: {missing}. "
        "chief_agent.py will skip them with 'no_asn'."
    )


def test_all_victim_as_have_as_prefix():
    """Every victim_as must start with 'AS' to match the convention used
    by the other 28 rows and expected by chief_agent parsing."""
    rows = _load_csv()
    bad = []
    for r in rows:
        va = r.get("victim_as", "").strip()
        if va and not va.startswith("AS"):
            bad.append((r["event_id"], va))
    assert not bad, (
        f"The following events have victim_as without 'AS' prefix: {bad}"
    )


def test_correct_values():
    """The 6 previously-missing rows must have the correct AS numbers."""
    rows = _load_csv()
    by_id = {r["event_id"]: r["victim_as"].strip() for r in rows}

    expected = {
        "hijack_crypto_campaign_2023": "AS398722",
        "hijack_uztelecom_2024": "AS28910",
        "leak_voxility_2025": "AS3223",
        "leak_upx_2025": "AS52863",
        "leak_cox_2025": "AS22773",
        "leak_reliablesite_2025": "AS23470",
    }
    for eid, expected_val in expected.items():
        actual = by_id.get(eid)
        assert actual == expected_val, (
            f"{eid}: expected victim_as={expected_val}, got {actual!r}"
        )


def test_csv_parses_without_error():
    """The CSV must be readable without raising exceptions."""
    rows = _load_csv()
    assert len(rows) == 34, f"Expected 34 rows, got {len(rows)}"
    # All rows must have the same fields
    fieldnames = set(rows[0].keys())
    for i, row in enumerate(rows[1:], start=2):
        missing_fields = fieldnames - set(row.keys())
        assert not missing_fields, (
            f"Row {i} ({row.get('event_id', '?')}) is missing fields: {missing_fields}"
        )
