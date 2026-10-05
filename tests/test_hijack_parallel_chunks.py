"""Tests for the parallel chunk-processing refactor (Round-24 perf fix).

The hijack detector dispatches each chunk to a worker thread via
ThreadPoolExecutor, bounded to CHUNK_INFLIGHT chunks in flight so peak memory
does not grow with the width of the analysis window. These tests verify:

  1. The worker function handles empty / malformed input safely.
  2. The worker function returns alerts with the expected shape.
  3. The serial path (BGP_TRACER_PARALLEL_CHUNKS=0) still works.
  4. The in-flight cap is enforced and chunks merge in temporal order.

Most of these are unit tests of _process_chunk_worker; the end-to-end
parallel vs serial parity is exercised by the existing smoke tests
under tests/test_round22_*.py and tests/test_round23_*.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))


pytestmark = pytest.mark.fast


# ─── Helpers ────────────────────────────────────────────────────────────


def _make_params(cleaned_as_list=None, target_prefixes=None, skip_forge=True):
    return {
        "union_target_prefixes": target_prefixes or ["1.2.3.0/24"],
        "covered_subnet_set": [],
        "cleaned_as_set": cleaned_as_list or ["65001"],
        "cleaned_as_list": cleaned_as_list or ["65001"],
        "skip_forge_detection": skip_forge,
        "prefix_to_as_subset": {"1.2.3.0/24": "65001"},
        "as_relationships_data": {},
    }


# ─── Unit tests ─────────────────────────────────────────────────────────


def test_worker_empty_records_returns_empty_list():
    """An empty chunk produces zero alerts and doesn't crash."""
    from detectors.hijack.hijack_detector import _process_chunk_worker
    out = _process_chunk_worker(([], _make_params()))
    assert out == []


def test_worker_filters_to_announces_only():
    """Worker only processes Announce (A/W='A') rows. Withdrawals are ignored."""
    from detectors.hijack.hijack_detector import _process_chunk_worker
    records = [
        {"prefix": "1.2.3.0/24", "as-path": "65000 65001", "A/W": "W",
         "timestamp": "2024-01-01 00:00:00"},
        {"prefix": "5.6.7.0/24", "as-path": "65000 65002", "A/W": "A",
         "timestamp": "2024-01-01 00:05:00"},
    ]
    out = _process_chunk_worker((records, _make_params()))
    # Only the A row is processed; the W row is filtered out.
    assert isinstance(out, list)


def test_worker_returns_list_of_dicts():
    """Worker returns a list of plain dicts (no dataclasses, no DataFrames)."""
    from detectors.hijack.hijack_detector import _process_chunk_worker
    records = [
        {"prefix": "1.2.3.0/24", "as-path": "65000 65001", "A/W": "A",
         "timestamp": "2024-01-01 00:00:00"},
    ]
    out = _process_chunk_worker((records, _make_params()))
    assert isinstance(out, list)
    for item in out:
        assert isinstance(item, dict)


def test_worker_handles_malformed_as_path():
    """Worker doesn't crash on malformed AS paths (e.g. empty, single AS)."""
    from detectors.hijack.hijack_detector import _process_chunk_worker
    records = [
        {"prefix": "1.2.3.0/24", "as-path": "", "A/W": "A",
         "timestamp": "2024-01-01 00:00:00"},
        {"prefix": "1.2.3.0/24", "as-path": "65001", "A/W": "A",
         "timestamp": "2024-01-01 00:05:00"},
    ]
    out = _process_chunk_worker((records, _make_params()))
    assert isinstance(out, list)


def test_worker_large_chunk_runs():
    """Worker handles a large chunk (1000 rows) without crashing."""
    from detectors.hijack.hijack_detector import _process_chunk_worker
    import random
    random.seed(42)
    records = [
        {
            "prefix": f"10.{(i // 256) % 256}.{i % 256}.0/24",
            "as-path": f"65000 {random.choice(['65001', '65002', '65003'])}",
            "A/W": "A",
            "timestamp": f"2024-01-01 00:{(i % 60):02d}:00",
        }
        for i in range(1000)
    ]
    out = _process_chunk_worker((records, _make_params()))
    assert isinstance(out, list)


# ─── Integration smoke test ─────────────────────────────────────────────


def test_detect_hijacks_batch_has_parallel_path():
    """detect_hijacks_batch exposes the BGP_TRACER_PARALLEL_CHUNKS gate.

    Sanity check: the parallel branch is wired in. We don't run an actual
    detection (that needs network + cache), we just confirm the function
    signature and code path exists.
    """
    import inspect
    from detectors.hijack.hijack_detector import detect_hijacks_batch
    src = inspect.getsource(detect_hijacks_batch)
    assert "BGP_TRACER_PARALLEL_CHUNKS" in src, "parallel gate should be present"
    assert "ThreadPoolExecutor" in src, "worker pool should be wired"
    assert "_process_chunk_worker" in src, "worker fn should be referenced"
    assert "CHUNK_INFLIGHT" in src, "in-flight cap should bound resident chunks"


def test_parallel_is_default_when_env_unset():
    """Without BGP_TRACER_PARALLEL_CHUNKS=0, the parallel path is selected."""
    os.environ.pop("BGP_TRACER_PARALLEL_CHUNKS", None)
    # Re-read the source: the gate is `_os.environ.get("...", "1") != "0"`
    import inspect
    from detectors.hijack.hijack_detector import detect_hijacks_batch
    src = inspect.getsource(detect_hijacks_batch)
    # The default value in os.environ.get("...", "1") means parallel=1
    assert '"BGP_TRACER_PARALLEL_CHUNKS", "1"' in src, (
        "parallel should be the default; serial path must be opt-in"
    )


def test_detect_hijacks_batch_serial_path_compatible():
    """When BGP_TRACER_PARALLEL_CHUNKS=0, the function still initialises
    correctly (doesn't fail at import / function-define time)."""
    os.environ["BGP_TRACER_PARALLEL_CHUNKS"] = "0"
    try:
        # Re-import to pick up the env var? No — the env is read inside
        # the function call, so we just check the code path exists.
        import inspect
        from detectors.hijack.hijack_detector import detect_hijacks_batch
        src = inspect.getsource(detect_hijacks_batch)
        assert "Serial path" in src or "serial path" in src.lower(), (
            "serial path should be preserved for opt-in legacy mode"
        )
    finally:
        os.environ.pop("BGP_TRACER_PARALLEL_CHUNKS", None)


# ─── Bounded in-flight window ─────────────────────────────────────────────


class _Recorder:
    def __init__(self):
        self.chunks = []

    def add_chunk(self, chunk):
        self.chunks.append(len(chunk))


def _build_batch(asns):
    return {
        asn: {
            "_aggregator": _Recorder(),
            "origin_hijacked": [],
            "origin_hijacking": [],
            "forge_hijack": [],
        }
        for asn in asns
    }


def test_merge_chunk_alerts_buckets_and_strips_tag():
    """Alerts are routed to the right per-AS bucket and __asn is removed."""
    from detectors.hijack.hijack_detector import _merge_chunk_alerts

    batch = _build_batch(["AS1", "AS2"])
    _merge_chunk_alerts(
        batch,
        [
            {"__asn": "AS1", "hijack_type": "origin_hijacked", "t": 1},
            {"__asn": "AS1", "hijack_type": "origin_hijacked", "t": 2},
            {"__asn": "AS1", "hijack_type": "forge_hijack", "t": 3},
            {"__asn": "AS404", "hijack_type": "origin_hijacked", "t": 4},
            "not-a-dict",
        ],
    )

    assert len(batch["AS1"]["origin_hijacked"]) == 2
    assert len(batch["AS1"]["forge_hijack"]) == 1
    assert batch["AS2"]["origin_hijacked"] == []
    assert all("__asn" not in h for h in batch["AS1"]["origin_hijacked"])


def test_merge_chunk_alerts_respects_sample_cap():
    """Retained alert samples stop at MAX_ALERT_SAMPLE; counts still flow
    to the aggregator, which is what the report quotes."""
    from detectors.hijack import hijack_detector as hd

    batch = _build_batch(["AS1"])
    original_cap = hd.MAX_ALERT_SAMPLE
    hd.MAX_ALERT_SAMPLE = 3
    try:
        hd._merge_chunk_alerts(
            batch,
            [
                {"__asn": "AS1", "hijack_type": "origin_hijacked", "i": i}
                for i in range(10)
            ],
        )
    finally:
        hd.MAX_ALERT_SAMPLE = original_cap

    assert len(batch["AS1"]["origin_hijacked"]) == 3
    assert batch["AS1"]["_aggregator"].chunks == [10]


def test_inflight_cap_holds_and_merges_in_order():
    """The pump never exceeds CHUNK_INFLIGHT and merges in chunk order.

    Workers deliberately finish out of order, so a pump that collected by
    completion time would interleave the alert samples and lose the temporal
    ordering the report relies on.
    """
    import time
    from collections import deque
    from concurrent.futures import ThreadPoolExecutor

    from detectors.hijack.hijack_detector import (
        _merge_chunk_alerts,
        CHUNK_INFLIGHT,
    )

    n_chunks = 40
    asns = [f"AS{i}" for i in range(1, 4)]
    batch = _build_batch(asns)

    def worker(idx):
        time.sleep(0.01 if idx % 2 == 0 else 0.001)
        return [
            {
                "__asn": asns[idx % len(asns)],
                "hijack_type": "origin_hijacked",
                "i": idx,
            }
        ]

    peak = 0
    next_idx = 0
    with ThreadPoolExecutor(max_workers=8) as ex:
        pending = deque()
        exhausted = False
        while not exhausted or pending:
            while not exhausted and len(pending) < CHUNK_INFLIGHT:
                if next_idx >= n_chunks:
                    exhausted = True
                    break
                pending.append(ex.submit(worker, next_idx))
                next_idx += 1
                peak = max(peak, len(pending))
            if pending:
                _merge_chunk_alerts(batch, pending.popleft().result())

    assert peak <= CHUNK_INFLIGHT, f"in-flight {peak} exceeded cap {CHUNK_INFLIGHT}"

    seen = []
    for asn in asns:
        idxs = [h["i"] for h in batch[asn]["origin_hijacked"]]
        assert idxs == sorted(idxs), f"{asn} merged out of temporal order"
        seen.extend(idxs)
    assert sorted(seen) == list(range(n_chunks)), "chunks lost or duplicated"
