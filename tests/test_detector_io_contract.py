"""
Contract tests for the 2026-10-05 detector I/O audit.

Five defects were found by inspecting what the detectors actually accept and
return, rather than what they are documented to accept and return. Each of
these tests reproduces the specific silent failure; all five produce a
plausible-looking *negative* result rather than an error, which is why they
survived 454 passing tests.

1. Swapped arguments were accepted. ``detect_hijacks`` is
   ``(start_time, end_time, target_as)`` while ``analyze_leak_surface`` is
   ``(asn, start_time, end_time)``. Calling either with the ASN in a time
   slot used to run to completion and write a results file reporting zero
   alerts, i.e. a fabricated false negative.
2. No time-window validation existed anywhere in the repo, so an inverted
   window scanned nothing and reported a clean empty result.
3. The batch runner picked the AS by a fixed ``victim -> attacker -> leak``
   order, which analyses the wrong party for route leaks whenever the victim
   and the leaker differ.
4. The hijack paths hardcoded ``data_available: True`` even when zero
   announcements were scanned.
5. ``wrap()`` inferred ``data_available`` from whether anomalies were found,
   so "ran on complete data and found nothing" was indistinguishable from
   "never had data".

These are cheap: no network, no parquet scans, no LLM. They assert the
*contract*, so they fail fast when someone reintroduces one of the bugs.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from detectors.input_validation import (  # noqa: E402
    InputValidationError,
    looks_like_asn,
    looks_like_timestamp,
    parse_timestamp,
    validate_detection_request,
    validate_time_window,
)

EVENT = ("2024-10-30 13:21", "2024-10-30 13:40")


# ── 1 + 2: input validation primitives ──────────────────────────────────


class TestValidationPrimitives:
    def test_valid_request_returns_normalised_values(self):
        asn, start, end = validate_detection_request("AS24940", *EVENT)
        assert asn == "24940", "the 'AS' prefix must be stripped for downstream use"
        assert isinstance(start, datetime) and isinstance(end, datetime)

    @pytest.mark.parametrize(
        "asn",
        ["AS24940", "24940", 24940],
    )
    def test_accepted_asn_forms(self, asn):
        assert looks_like_asn(asn)

    @pytest.mark.parametrize(
        "value",
        ["", "   ", None, True, False, 0, -1, "4294967296", "AS", "notan as"],
    )
    def test_rejected_asn_forms(self, value):
        assert not looks_like_asn(value)

    def test_timestamp_rejected_in_asn_slot_names_the_swap(self):
        """The error must point at the real cause, not just 'invalid'."""
        with pytest.raises(InputValidationError) as exc:
            validate_detection_request("2024-10-30 13:21", *EVENT)
        msg = str(exc.value).lower()
        assert "timestamp" in msg and "swapped" in msg

    def test_asn_rejected_in_time_slot_names_the_swap(self):
        with pytest.raises(InputValidationError) as exc:
            validate_detection_request("49981", "2024-10-30 13:21", "49981")
        assert "swapped" in str(exc.value).lower()

    def test_inverted_window_is_rejected(self):
        with pytest.raises(InputValidationError) as exc:
            validate_time_window("2024-10-30 13:40", "2024-10-30 13:21")
        assert "before" in str(exc.value).lower()

    def test_equal_window_allowed_unless_minimum_set(self):
        start, end = validate_time_window("2024-10-30 13:21", "2024-10-30 13:21")
        assert start == end
        with pytest.raises(InputValidationError):
            validate_time_window(
                "2024-10-30 13:21", "2024-10-30 13:21", min_duration_seconds=60
            )

    def test_iso_variants_accepted(self):
        for value in [
            "2024-10-30T13:21:00",
            "2024-10-30T13:21:00Z",
            "2024-10-30T13:21",
            "2024-10-30 13:21:00",
            "2024-10-30 13:21",
        ]:
            assert looks_like_timestamp(value), value
            assert parse_timestamp(value).year == 2024

    def test_garbage_timestamp_message_lists_expected_formats(self):
        with pytest.raises(InputValidationError) as exc:
            parse_timestamp("last tuesday")
        assert "%Y-%m-%d" in str(exc.value)

    def test_input_validation_error_is_a_valueerror(self):
        """Existing `except ValueError` handlers must still catch this."""
        assert issubclass(InputValidationError, ValueError)


# ── 1: the detectors must reject rather than fabricate a negative ───────


class TestDetectorsRejectMalformedRequests:
    def test_hijack_rejects_asn_in_time_slot(self):
        from detectors.hijack.hijack_detector import detect_hijacks

        # This is the exact call that previously produced a results file with
        # an inverted window and `total_alerts: 0`.
        r = detect_hijacks("AS24940", "2024-10-30 13:40", "2024-10-30 13:21")
        assert r["success"] is False
        assert r.get("invalid_request") is True
        assert r["no_data_reason"] == "invalid_request"

    def test_hijack_rejects_inverted_window(self):
        from detectors.hijack.hijack_detector import detect_hijacks

        r = detect_hijacks("2024-10-30 13:40", "2024-10-30 13:21", "AS24940")
        assert r["success"] is False
        assert r.get("invalid_request") is True

    def test_leak_rejects_asn_in_time_slot(self):
        from detectors.leak.leak_detector import analyze_leak_surface

        r = analyze_leak_surface("2024-10-30 13:21", "2024-10-30 13:40", "49981")
        assert r["success"] is False
        assert r.get("invalid_request") is True
        assert r["no_data_reason"] == "invalid_request"

    def test_leak_rejects_inverted_window(self):
        from detectors.leak.leak_detector import analyze_leak_surface

        r = analyze_leak_surface("49981", "2024-10-30 13:40", "2024-10-30 13:21")
        assert r["success"] is False
        assert r.get("invalid_request") is True

    def test_rejection_never_reports_a_clean_negative(self):
        """A rejected request must not look like 'ran fine, found nothing'."""
        from detectors.hijack.hijack_detector import detect_hijacks

        r = detect_hijacks("2024-10-30 13:40", "2024-10-30 13:21", "AS24940")
        # Either it failed, or it had no data — never "success with zero
        # anomalies and data available".
        assert not (r["success"] and r["data_available"])
        assert r.get("anomaly_count", 0) == 0


# ── 3: the batch runner must pick the AS the event type implies ─────────


class TestTargetAsnResolution:
    def _rows(self):
        import csv

        path = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v17.csv"
        with path.open(encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    def test_leak_events_target_the_leaker(self):
        from run_4mode_batch import resolve_target_asn

        rows = [r for r in self._rows() if r["ground_truth_cause_label"] == "route_leak"]
        assert rows, "dataset should contain route-leak events"
        for r in rows:
            asn, source = resolve_target_asn(r)
            assert source == "leak_as", (
                f"{r['event_id']} resolved from {source}; a leak must be analysed "
                "at the leaking AS, otherwise it cannot be detected"
            )
            assert asn == r["leak_as"].replace("AS", "").strip()

    def test_worldstream_leak_targets_the_leaker_not_the_victim(self):
        """The concrete mis-binding found during the audit.

        victim_as=AS22773 (Cox, the party that actually suffered visible
        leak paths at RRC00) but the leaker is AS49981 (Worldstream).
        Measured against a control window the leaker's candidate volume
        rose far more than the victim's.
        """
        from run_4mode_batch import resolve_target_asn

        row = next(
            r for r in self._rows() if r["event_id"] == "leak_worldstream_ovhcloud_2024"
        )
        assert row["leak_as"] == "AS49981"
        asn, source = resolve_target_asn(row)
        assert asn == "49981"
        assert source == "leak_as"

    def test_hijack_and_outage_target_the_victim(self):
        from run_4mode_batch import resolve_target_asn

        for r in self._rows():
            label = r["ground_truth_cause_label"]
            if label in ("origin_hijack_victim", "outage"):
                asn, source = resolve_target_asn(r)
                assert source == "victim_as", r["event_id"]
                assert asn == r["victim_as"].replace("AS", "").strip()

    def test_every_dataset_row_resolves_to_some_as(self):
        from run_4mode_batch import resolve_target_asn

        for r in self._rows():
            asn, source = resolve_target_asn(r)
            assert asn, f"{r['event_id']} resolved to no AS"
            assert looks_like_asn(asn)

    def test_every_dataset_row_has_a_valid_window(self):
        for r in self._rows():
            validate_time_window(r["start_time_utc"], r["end_time_utc"])


# ── 4 + 5: the result contract must be unambiguous ─────────────────────


class TestResultContract:
    def _wrap(self, raw):
        from detectors.unified_result import DetectionType, wrap

        return wrap(DetectionType.LEAK, raw, asn="49981").to_dict()

    def test_ran_on_data_and_found_nothing_is_data_available(self):
        """The case that used to be miscounted as a miss."""
        d = self._wrap(
            {"success": True, "total_announcements": 5013770, "route_leaks": [], "anomaly_count": 0}
        )
        assert d["data_available"] is True, (
            "input volume was scanned, so this is a genuine negative, not missing data"
        )
        assert d["success"] is True

    def test_no_data_always_carries_a_reason(self):
        d = self._wrap({"success": False, "route_leaks": [], "anomaly_count": 0})
        assert d["data_available"] is False
        assert d["no_data_reason"], "data_available=False must explain itself"

    def test_anomalies_imply_data_was_available(self):
        d = self._wrap(
            {"success": True, "total_announcements": 10, "route_leaks": [{"a": 1}], "anomaly_count": 1}
        )
        assert d["data_available"] is True

    def test_findings_and_no_data_reason_are_mutually_exclusive(self):
        d = self._wrap({"success": True, "total_announcements": 5, "route_leaks": [{"a": 1}]})
        assert not d["no_data_reason"]

    def test_to_dict_always_carries_the_keys_downstream_reads(self):
        required = {
            "success",
            "data_available",
            "no_data_reason",
            "anomalies_detected",
            "anomaly_count",
            "anomalies",
            "origin_hijacked",
            "forge_hijacked",
            "route_leaks",
        }
        d = self._wrap({"success": True, "total_announcements": 1})
        assert not (required - set(d))

    def test_hijack_paths_do_not_hardcode_data_available(self):
        """Regression on the hardcoded `data_available: True`."""
        import ast

        path = ROOT / "detectors/hijack/hijack_detector.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for k, v in zip(node.keys, node.values):
                if (
                    isinstance(k, ast.Constant)
                    and k.value == "data_available"
                    and isinstance(v, ast.Constant)
                    and v.value is True
                ):
                    offenders.append(getattr(k, "lineno", "?"))
        assert not offenders, (
            f"data_available hardcoded True at lines {offenders}; it must reflect "
            "whether rows were actually scanned"
        )