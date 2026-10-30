"""Traffic detector must degrade to a no-data result when the fetch fails.

A Cloudflare Radar fetch can fail for reasons outside our control: an AS
with no published series, a truncated response, or a 5xx that survives
every retry.  That is an absence of *traffic* evidence, not a failure of
the analysis — the routing evidence must still be scored.  If the
exception escapes, ``chief_agent`` aborts the whole run and writes no
cache, which silently removes the event from every evaluation.

This is a regression test: an unguarded fetch made
``outage_cloudflare_dns_2025_07_14`` produce no cache at all.
"""

from __future__ import annotations

import pytest

from detectors.traffic.traffic_detector import CloudflareRadarAPI


@pytest.fixture
def detector():
    det = CloudflareRadarAPI.__new__(CloudflareRadarAPI)
    det._resolved_country = {}
    det.hasCredentials = True
    det.traffic_cache_dir = None
    det._cache = {}
    return det


def test_fetch_failure_returns_no_data_result(detector, monkeypatch):
    def boom(asn, windows):
        raise Exception("AS13335: shared-span fetch failed (HTTP 200 without usable timeseries)")

    monkeypatch.setattr(detector, "get_traffic_windows_shared_scale", boom)

    result = detector.detect_anomalies(
        "13335", "2025-07-14 00:00:00", "2025-07-14 02:00:00",
    )

    assert result["success"] is False
    assert result["data_available"] is False
    assert result["anomaly_count"] == 0
    assert result["traffic_signal_present"] is False
    # The contract guard requires a reason whenever data_available is False,
    # so a downstream reader can tell "provider had nothing" from "clean".
    assert result["no_data_reason"]
    assert "shared-span fetch failed" in result["error"]


def test_auth_failure_is_labelled_distinctly(detector, monkeypatch):
    def boom(asn, windows):
        raise Exception("Cloudflare Radar API token is not configured")

    monkeypatch.setattr(detector, "get_traffic_windows_shared_scale", boom)

    result = detector.detect_anomalies(
        "13335", "2025-07-14 00:00:00", "2025-07-14 02:00:00",
    )

    assert result["no_data_reason"] == "cloudflare_authentication_failed"


def test_request_failure_is_labelled_as_request_failure(detector, monkeypatch):
    def boom(asn, windows):
        raise Exception("HTTP 503 service unavailable")

    monkeypatch.setattr(detector, "get_traffic_windows_shared_scale", boom)

    result = detector.detect_anomalies(
        "13335", "2025-07-14 00:00:00", "2025-07-14 02:00:00",
    )

    assert result["no_data_reason"] == "cloudflare_request_failed"
