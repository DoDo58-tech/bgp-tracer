"""Regression tests for the ragged-baseline truncation bug (2026-10-05).

`preprocess_traffic_data` used to truncate every series to the *shortest*
historical week, taking the tail off the current window. On AS8048
(2024-08-01 08:45→09:45) the baseline weeks came back 193/193/97/193 samples
while the current window had 101, so min_len=97 cut the current series at
08:45 — discarding the whole event hour including the 09:15 trough. The
detector then reported peak_trough_drop = 9.9% and anomalies_detected = False
on a window where traffic fell 72.7% and Cloudflare's own confidenceInfo flags
a TRAFFIC_ANOMALY.

These tests pin the behaviour that was wrong, using the real numbers. They are
pure-Python (no network): the values are the ones actually observed.
"""

import numpy as np
import pytest

from detectors.traffic.preprocessing import preprocess_traffic_data


def _event_series(n=101):
    """The real AS8048 current window: calm, then a one-hour collapse.

    Index 0..96 are the calm pre-event samples (~1.95-2.20e9). The last four
    are the event hour, which contains the 09:15 trough at 6.0e8.
    """
    calm = np.linspace(1.95e9, 2.20e9, n - 4)
    event = np.array([9.90981244e8, 7.96917943e8, 6.00843029e8, 1.01210424e9])
    return np.concatenate([calm, event])


class TestRaggedBaselineKeepsEventTail:
    def test_short_baseline_no_longer_truncates_event(self):
        """A 97-sample baseline must not chop the event hour off the current window."""
        current = _event_series(101)
        # One short baseline (the 2024-07-10 week that triggered the bug) and
        # three long ones, exactly as Radar returned them.
        historical = [
            {"timestamps": [], "values": list(np.linspace(1.9e9, 2.1e9, 97))},
            {"timestamps": [], "values": list(np.linspace(1.9e9, 2.1e9, 193))},
            {"timestamps": [], "values": list(np.linspace(1.9e9, 2.1e9, 193))},
            {"timestamps": [], "values": list(np.linspace(1.9e9, 2.1e9, 193))},
        ]

        out_current, means, stds, hist_list = preprocess_traffic_data(
            current, historical
        )

        # The event tail (trough 6.00843029e8) must survive.
        assert min(out_current) < 7.0e8, (
            "event-hour trough was truncated away — the bug is back"
        )
        # Peak-to-trough on the retained series must reflect the real ~70% drop,
        # not the ~10% of the calm-only prefix.
        drop_pct = (max(out_current) - min(out_current)) / max(out_current) * 100
        assert drop_pct > 50.0, f"peak-to-trough only {drop_pct:.1f}%, expected >50%"

    def test_length_is_bounded_by_shortest_baseline(self):
        """The paired-sample bound is still honoured (statistics need equal length)."""
        current = _event_series(101)
        historical = [
            {"timestamps": [], "values": list(np.linspace(1.9e9, 2.1e9, 97))},
        ]
        out_current, means, stds, _ = preprocess_traffic_data(current, historical)
        assert len(out_current) == 97
        assert len(means) == 97
        assert len(stds) == 97

    def test_baselines_are_right_aligned_not_left(self):
        """A long baseline and a short baseline must line up on their ends.

        Left-aligning a 193-sample week against a 97-sample week compares the
        wrong hours; the tail of each week is the part contemporaneous with the
        event, so alignment must be on the end.
        """
        short = {"timestamps": [], "values": [10.0] * 97}
        long_ = {"timestamps": [], "values": [100.0] * 193}
        _, means, _, hist_list = preprocess_traffic_data(
            _event_series(101), [short, long_]
        )
        # Each baseline contributed at min_len, and their means differ, proving
        # they were realigned rather than concatenated/mispaired.
        assert all(len(h) == 97 for h in hist_list)
        assert means[-1] == pytest.approx((10.0 + 100.0) / 2)

    def test_too_short_baseline_is_interpolated_not_dropped(self):
        """A baseline shorter than min_len is resampled, not silently discarded."""
        current = _event_series(101)
        historical = [
            {"timestamps": [], "values": list(np.linspace(1.9e9, 2.1e9, 97))},
            {"timestamps": [], "values": [1.0, 2.0]},  # absurdly short
        ]
        _, means, _, hist_list = preprocess_traffic_data(current, historical)
        assert len(hist_list) == 2, "short baseline was dropped instead of resampled"
        assert len(means) == 97

    def test_no_historical_data_is_a_noop(self):
        current = _event_series(101)
        out_current, means, stds, hist = preprocess_traffic_data(current, [])
        assert list(out_current) == list(current)
        assert means.size == 0 and stds.size == 0 and hist == []


class TestTimestampAlignmentContract:
    def test_caller_keeps_matching_tail(self):
        """The detector slices timestamps to match the retained values.

        preprocess_traffic_data now keeps the *tail* of the current window, so
        the caller must slice the tail too. If it kept the head, values and
        timestamps would drift apart and every anomaly index would point at the
        wrong time.
        """
        import inspect

        from detectors.traffic import traffic_detector

        src = inspect.getsource(traffic_detector.CloudflareRadarAPI.detect_anomalies)
        assert "timestamps = timestamps[len(timestamps) - n_after:]" in src, (
            "detect_anomalies must slice the timestamp tail to match values"
        )
        # And it must not also slice the head, which would double-truncate.
        tail_slice = "timestamps = timestamps[len(timestamps) - n_after:]"
        head_slice = "timestamps = timestamps[:n_after]"
        assert tail_slice in src
        assert "timestamps = timestamps[:len(current_values)]" not in src, (
            "stale head-slice of timestamps is still present"
        )
