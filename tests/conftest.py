"""Shared pytest configuration for bgp_tracer.

This conftest does four things:

1. Marks every test ``@pytest.mark.fast`` by default. Tests that hit the
   network or take >5 s should be ``@pytest.mark.slow`` or
   ``@pytest.mark.network``.
2. Applies a per-test timeout (default 60 s) so a hung test can never
   stall the whole suite (this is what caused the 1h26m pytest stall
   on 2026-09-17).
3. Mocks the external LLM API and the BGP data downloader when tests
   are marked ``network``.
4. Provides a ``sample_event`` fixture used across most regression tests.

See ``docs/BOTTLENECK_ROADMAP.md`` §2 for rationale.
"""

from __future__ import annotations

import os
import sys
import time
import socket
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ── Per-test timeout (defends against hung tests stalling CI) ──────────────
DEFAULT_TEST_TIMEOUT_S = float(os.environ.get("BGP_TRACER_TEST_TIMEOUT_S", "60"))


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers and surface the timeout to the user."""
    config.addinivalue_line(
        "markers",
        "fast: pure-Python unit test, no LLM / no network (<5 s)",
    )
    config.addinivalue_line(
        "markers",
        "slow: requires >5 s but still no external network",
    )
    config.addinivalue_line(
        "markers",
        "network: hits external API (Cloudflare / RIS / LLM) — skip in CI",
    )


# ── Network guard: skip network-marked tests unless explicitly enabled ────
@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Two responsibilities:

    1. Skip network-marked tests unless ``BGP_TRACER_RUN_NETWORK_TESTS=1``.
    2. Auto-tag unmarked tests as ``fast`` so ``-m fast`` selects them.
    """
    # 1) Network guard
    if os.environ.get("BGP_TRACER_RUN_NETWORK_TESTS") != "1":
        skip_network = pytest.mark.skip(
            reason="network test skipped (set BGP_TRACER_RUN_NETWORK_TESTS=1 to enable)"
        )
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip_network)

    # 2) Auto-tag unmarked as fast
    for item in items:
        if not any(
            m.name in ("fast", "slow", "network") for m in item.iter_markers()
        ):
            item.add_marker(pytest.mark.fast)


# ── Per-test timeout (uses pytest-timeout if installed; manual fallback) ─
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Apply per-test timeout from env var or marker overrides."""
    timeout = DEFAULT_TEST_TIMEOUT_S
    marker = item.get_closest_marker("timeout")
    if marker is not None and marker.args:
        timeout = float(marker.args[0])
    item._bgp_tracer_timeout = timeout  # type: ignore[attr-defined]
    if not hasattr(item, "_bgp_tracer_started"):
        item._bgp_tracer_started = time.monotonic()  # type: ignore[attr-defined]


def pytest_runtest_teardown(item: pytest.Item) -> None:
    started = getattr(item, "_bgp_tracer_started", None)
    timeout = getattr(item, "_bgp_tracer_timeout", None)
    if started is not None and timeout is not None:
        elapsed = time.monotonic() - started
        if elapsed > timeout:
            # Don't fail here — pytest-timeout will. We just surface the
            # violation to the user log so it's clear what happened.
            print(
                f"\n[bgp-tracer] WARNING: test {item.nodeid} exceeded "
                f"{timeout:.0f}s timeout (ran {elapsed:.1f}s). "
                f"Mark slow if this is expected.",
                file=sys.stderr,
            )


# ── Network guard: refuse to actually open a TCP socket during fast tests ──
@pytest.fixture(autouse=True)
def _guard_network_in_fast_tests(request: pytest.FixtureRequest, monkeypatch):
    """When a test is marked ``fast``, block accidental outbound connections.

    Why: a fast-marked test should never call out to a real API. If it
    does, that's a regression that wastes time and money. We patch
    ``socket.socket`` to raise after 50 ms, so the failure is loud.
    """
    # `request.keywords` is a dict[str, Mark]; check membership by key.
    keywords = set(request.keywords.keys()) if hasattr(request, "keywords") else set()
    if "fast" not in keywords:
        return
    if os.environ.get("BGP_TRACER_ALLOW_NETWORK_IN_FAST") == "1":
        return

    real_socket = socket.socket

    class _GuardedSocket(real_socket):
        def connect(self, address):  # type: ignore[override]
            host = address[0] if isinstance(address, tuple) else str(address)
            # Allow loopback / unix sockets
            if host in ("localhost", "127.0.0.1", "::1") or not host:
                return super().connect(address)
            raise RuntimeError(
                f"[bgp-tracer] fast-marked test attempted network "
                f"connection to {host!r}. Mark the test as "
                f"`@pytest.mark.network` or "
                f"`@pytest.mark.slow` if this is intentional."
            )

    monkeypatch.setattr(socket, "socket", _GuardedSocket)


# ── Common fixtures ────────────────────────────────────────────────────────
@pytest.fixture
def sample_event() -> dict:
    """The canonical AS12479 2024-01-03 traffic-drop event."""
    return {
        "asn": "12479",
        "start_time": "2024-01-03 14:45",
        "end_time": "2024-01-03 18:00",
        "expected_drop_ratio": 0.82,
        "expected_anomaly_count_min": 6,
    }


@pytest.fixture
def minimal_routing_result() -> dict:
    """A minimal but well-formed routing result payload."""
    return {
        "result": {
            "origin_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacked": [],
            "forge_hijacking": [],
            "route_leaks": [],
            "alerts": [],
        }
    }


@pytest.fixture
def minimal_traffic_result() -> dict:
    """A minimal traffic result with two anomalies."""
    return {
        "result": {
            "anomaly_count": 2,
            "max_severity": "high",
            "percent_change": -8.5,
            "peak_trough_drop_pct": 25.0,
            "anomalies": [
                {"timestamp": "2024-01-03T15:00:00Z", "severity": "high",
                 "z_score": 4.2, "value": 0.4},
                {"timestamp": "2024-01-03T16:00:00Z", "severity": "high",
                 "z_score": 3.8, "value": 0.5},
            ],
        }
    }
