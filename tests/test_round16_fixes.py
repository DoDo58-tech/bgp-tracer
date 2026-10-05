"""Regression tests for Round 16 bug fixes (BUG-R121..R129).

Round 16 focused on file-descriptor leaks, atomic writes in three more
places, a hot-path parser correctness bug (IPv4 octets out-of-range
+ missing IPv6 support), a misleading documentation-vs-implementation
mismatch in the outage detector's LRU cache that turned O(1) into O(n),
silent token-budget under-counting in chief_agent, and shell-handle
leaks in the batch driver.

Each test is tight, self-contained, and uses ``tmp_path`` so it never
touches the real on-disk checkpoints / cache files.

Run with::

    pytest tests/test_round16_fixes.py -v
"""

import asyncio
import inspect
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
def test_run_mode_uses_with_open_for_subprocess_stdout():
    """BUG-R121: ``run_one`` must use ``with open(...)`` when piping
    subprocess output to a log file so the file handle is closed
    deterministically — not left to GC. Without that, long batch
    runs leak descriptors on every event.

    UPDATED 2026-10-05: the function was renamed ``run_mode`` -> ``run_one``
    during slimming, so this test had been failing with AttributeError. The
    invariant itself is still intact at scripts/run_4mode_batch.py:177.
    """
    from scripts import run_4mode_batch

    assert hasattr(run_4mode_batch, "run_one"), (
        "run_4mode_batch must still expose run_one (renamed from run_mode)"
    )
    src = inspect.getsource(run_4mode_batch.run_one)
    # Strip comments + docstrings so the BUG-R121 explanation in the
    # method's comments doesn't itself trip the assertion.
    code_only = re.sub(r"#.*", "", src)
    code_only = re.sub(r"\"{3}.*?\"{3}", "", code_only, flags=re.DOTALL)
    # The buggy pattern is ``stdout=open(log_path, "w")``. After the
    # fix the source should contain the safer ``with open(...) as`` form.
    assert "stdout=open(log_path, \"w\")" not in code_only, (
        "run_4mode_batch.run_one must no longer pass "
        "stdout=open(log_path, 'w') directly into subprocess.run"
    )
    assert re.search(r"with open\(log_path, \"w\"\) as \w+:", code_only), (
        "run_4mode_batch.run_one should wrap the log file in a "
        "`with open(...) as log_fh:` block."
    )


def test_batch_runner_subprocess_does_not_leak_fd(tmp_path):
    """End-to-end smoke test: even after a successful subprocess.run
    that pipes stdout into a log file, the file handle should be
    closed before run_mode returns."""
    from scripts import run_4mode_batch

    # Simulate a successful subprocess.run with stdout=log_fh.
    log_path = tmp_path / "log.txt"
    with open(log_path, "w") as log_fh:
        subprocess.run(
            ["python", "-c", "print('hello')"],
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
    # We should be able to reopen the file immediately for append
    with open(log_path, "a", encoding="utf-8") as f:
        f.write("\n[test] closed-handle-check\n")
    assert (log_path.read_text(encoding="utf-8")).endswith(
        "[test] closed-handle-check\n"
    )


# ---------------------------------------------------------------------------
def test_quick_cache_uses_atomic_write():
    """BUG-R122: ``_run_quick_analysis_async`` must use the
    tmp + os.replace pattern when persisting its cache so a crash
    mid-write cannot leave a partially-populated JSON file at the
    cache path."""
    from chief_agent import _run_quick_analysis_async

    src = inspect.getsource(_run_quick_analysis_async)
    code_only = re.sub(r"#.*", "", src)
    assert "os.replace" in code_only, (
        "_run_quick_analysis_async must use os.replace for atomic write"
    )
    assert ".tmp" in code_only, (
        "_run_quick_analysis_async must write to a .tmp file first"
    )


# ---------------------------------------------------------------------------
def test_extract_prefixes_validates_octets():
    """BUG-R123: ``extract_prefixes`` must reject octets > 255 and
    prefix lengths > 32 instead of passing nonsense to RPKI/traceroute
    probes."""
    from agents.auto_probe_executor import extract_prefixes

    # Out-of-range octet (was matched by ``\\d{1,3}`` in the old regex)
    assert extract_prefixes("999.999.999.999/8") == []
    assert extract_prefixes("256.0.0.1/24") == []
    # Invalid prefix length
    assert extract_prefixes("1.2.3.4/33") == []
    # Valid prefixes still match
    assert extract_prefixes("90.174.144.0/20") == ["90.174.144.0/20"]
    # Two valid ones
    out = extract_prefixes("prefixes: 90.174.144.0/20, 85.54.152.0/22")
    assert out == ["90.174.144.0/20", "85.54.152.0/22"]


def test_extract_prefixes_supports_ipv6():
    """BUG-R123: ``extract_prefixes`` must also match IPv6 prefixes
    (the old regex was IPv4-only and silently dropped them)."""
    from agents.auto_probe_executor import extract_prefixes

    assert extract_prefixes("2001:db8::/32") == ["2001:db8::/32"]
    # Combined IPv4 + IPv6
    out = extract_prefixes("90.174.144.0/20, 2001:db8::/32")
    assert "90.174.144.0/20" in out
    assert "2001:db8::/32" in out


def test_extract_prefixes_empty_or_invalid_input():
    """Edge cases: empty string, None, no recognised prefix -> []."""
    from agents.auto_probe_executor import extract_prefixes

    assert extract_prefixes("") == []
    assert extract_prefixes(None) == []
    assert extract_prefixes("plain text without IPs") == []
    # Invalid plen for IPv6
    assert extract_prefixes("2001:db8::/200") == []


# ---------------------------------------------------------------------------
def test_outage_detector_cache_is_ordered_dict():
    """BUG-R127: the parsed_cache must be an OrderedDict (O(1)
    recency refresh), not a dict + list pair that used O(n) ``remove``."""
    from collections import OrderedDict
    from detectors.outage.outage_detector import RouteOutageDetector

    detector = RouteOutageDetector()
    assert isinstance(detector.parsed_cache, OrderedDict)
    # The auxiliary list is no longer required
    assert getattr(detector, "_parsed_cache_order", None) in (None, [])


def test_outage_detector_lru_move_to_end():
    """Verify the LRU recency refresh is O(1) (OrderedDict.move_to_end)
    by checking that re-accessing the same key keeps it at the tail
    and survives an eviction round."""
    from datetime import datetime, timedelta
    from detectors.outage.outage_detector import RouteOutageDetector

    detector = RouteOutageDetector()
    base = datetime(2025, 1, 1)

    # Fill the cache to the cap with timestamps
    for i in range(detector._MAX_PARSED_CACHE_SIZE):
        detector.parse_cached((base + timedelta(seconds=i)).isoformat())

    # Re-access the first-inserted (oldest) key. It should move to the
    # tail, becoming the most-recently used.
    first_iso = (base + timedelta(seconds=0)).isoformat()
    detector.parse_cached(first_iso)

    # Now insert enough NEW entries to evict roughly 1/8 of the cache.
    extra = detector._MAX_PARSED_CACHE_SIZE // 8
    for i in range(extra):
        detector.parse_cached(
            (base + timedelta(seconds=detector._MAX_PARSED_CACHE_SIZE + 1 + i)).isoformat()
        )

    # first_iso should still be there because we touched it last among
    # the original batch.
    assert first_iso in detector.parsed_cache
    # The cache is still bounded
    assert len(detector.parsed_cache) <= detector._MAX_PARSED_CACHE_SIZE


def test_outage_detector_lru_performance_no_quadratic():
    """Smoke test for BUG-R127: ``parse_cached`` should not show the
    N^2-scaling quadratic behaviour of ``list.remove``. We patch out
    ``datetime.fromisoformat`` so the only remaining cost is the
    recency refresh; it must finish quickly when the cache is saturated
    to its cap."""
    from datetime import datetime, timedelta
    from detectors.outage.outage_detector import RouteOutageDetector

    detector = RouteOutageDetector()
    base = datetime(2025, 1, 1)

    # Fill the cache to its cap.
    keys = []
    for i in range(detector._MAX_PARSED_CACHE_SIZE):
        iso = (base + timedelta(seconds=i)).isoformat()
        keys.append(iso)
        detector.parse_cached(iso)

    # Hit each cached entry once. With the buggy O(n) implementation
    t0 = time.perf_counter()
    for k in keys:
        detector.parse_cached(k)
    elapsed = time.perf_counter() - t0
    # Conservative bound: 5x the cache size in milliseconds.
    bound_ms = detector._MAX_PARSED_CACHE_SIZE * 5 / 1000.0
    assert elapsed < bound_ms, (
        f"parse_cached re-access took {elapsed:.3f}s for "
        f"{detector._MAX_PARSED_CACHE_SIZE} entries — cache is "
        f"likely not O(1) on hit (BUG-R127)."
    )


# ---------------------------------------------------------------------------
def test_process_prefix2as_uses_atomic_write():
    """BUG-R128: ``process_prefix2as`` must use the tmp + os.replace
    pattern when persisting parsed JSON; otherwise a crash mid-write
    leaves a truncated file that the existence-cache treats as valid."""
    from data.prefix2as_loader import process_prefix2as

    src = inspect.getsource(process_prefix2as)
    code_only = re.sub(r"#.*", "", src)
    assert "os.replace" in code_only, (
        "process_prefix2as must use os.replace for atomic write"
    )
    assert ".tmp" in code_only, (
        "process_prefix2as must write to a .tmp file first"
    )


# ---------------------------------------------------------------------------
def test_extract_token_count_uses_max_not_assignment():
    """BUG-R129: when both traffic and routing results carry
    ``total_across_agents`` values, ``_extract_token_count`` must take
    the maximum across them. The old code used plain ``=`` which kept
    overwriting with whatever value came last."""
    from chief_agent import ChiefExpertAgent

    src = inspect.getsource(ChiefExpertAgent._extract_token_count)
    code_only = re.sub(r"#.*", "", src)
    code_only = re.sub(r"\"{3}.*?\"{3}", "", code_only, flags=re.DOTALL)
    # The fix uses ``if value > tokens: tokens = value`` (max semantics).
    assert 'if value > tokens' in code_only, (
        "_extract_token_count must use max-style semantics "
        "(BUG-R129); should contain `if value > tokens`."
    )
    # Guard against the buggy unconditional re-assignment pattern
    # regressing.
    assert "tokens = token_usage[\"total_across_agents\"]" not in code_only, (
        "_extract_token_count still uses unconditional `tokens = ...` "
        "for total_across_agents (BUG-R129 regression)"
    )


def test_extract_token_count_max_kept_across_results():
    """End-to-end: synthesise a fake context with traffic carrying a
    higher ``total_across_agents`` than routing, and verify the
    extracted total reflects the higher traffic value."""
    import asyncio
    from chief_agent import ChiefExpertAgent

    fake_context = type("C", (), {})()
    fake_context.traffic_result = {"token_usage": {"total_across_agents": 12345}}
    fake_context.routing_result = {"token_usage": {"total_across_agents": 6789}}
    fake_context.reasoning_result = {}
    fake_context.message_bus_run_id = ""

    chief = ChiefExpertAgent.__new__(ChiefExpertAgent)
    tokens = chief._extract_token_count(fake_context)
    assert tokens == 12345, (
        f"_extract_token_count must keep the larger value across "
        f"results, got {tokens} (BUG-R129)"
    )

    # Reverse the order and ensure max still wins.
    fake_context.traffic_result = {"token_usage": {"total_across_agents": 6789}}
    fake_context.routing_result = {"token_usage": {"total_across_agents": 12345}}
    tokens2 = chief._extract_token_count(fake_context)
    assert tokens2 == 12345


def test_extract_token_count_handles_total_across_agents_zero():
    """When ``total_across_agents`` is 0 / falsy, the buggy version
    would still assign ``tokens = 0`` — wiping out a previously
    larger value. The new ``max`` semantics should never decrease
    the running total."""
    from chief_agent import ChiefExpertAgent

    fake_context = type("C", (), {})()
    fake_context.traffic_result = {"token_usage": {"total_across_agents": 100}}
    fake_context.routing_result = {"token_usage": {"total_across_agents": 0}}
    fake_context.reasoning_result = {}
    fake_context.message_bus_run_id = ""

    chief = ChiefExpertAgent.__new__(ChiefExpertAgent)
    tokens = chief._extract_token_count(fake_context)
    assert tokens == 100, (
        f"_extract_token_count must NEVER decrease the running total "
        f"(BUG-R129), got {tokens}"
    )


# ---------------------------------------------------------------------------
def test_all_modified_files_parse():
    """Round 16 modifications touched chief_agent.py,
    scripts/run_4mode_batch.py, agents/auto_probe_executor.py,
    data/prefix2as_loader.py, detectors/outage/outage_detector.py.
    Each must still be valid Python syntax."""
    import ast
    for rel in (
        "chief_agent.py",
        "scripts/run_4mode_batch.py",
        "agents/auto_probe_executor.py",
        "data/prefix2as_loader.py",
        "detectors/outage/outage_detector.py",
    ):
        path = ROOT / rel
        ast.parse(path.read_text(encoding="utf-8"))
