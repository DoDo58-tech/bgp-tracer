"""The scope veto has to be able to fire.

The provenance check compares the entity set the routing edge is about
with the entity set the traffic series measured.  When the two are
built on different kinds of entity -- a prefix on one side and a
network on the other -- their intersection is empty however the
incident went, so the veto suspends on every window and never refuses
anything.  A veto that cannot fire is not a veto.

These tests pin that the two sides meet where they can, and stay
apart where they should.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.paddle_runtime import collect_scope  # noqa: E402


def routing_edge(**fields):
    return {"event_type": "leak", "raw_event": fields}


def traffic_point(**fields):
    return {"timestamp": "2025-01-15 01:30:00", "raw_event": fields}


def test_a_leak_about_another_network_does_not_cover_the_measured_one():
    routing = [routing_edge(affected_prefixes=["2c0f:f860::/32"],
                             claimed_as="99999")]
    traffic = [traffic_point(z_score=-3.0)]

    routing_scope, traffic_scope = collect_scope(
        routing, traffic, {}, {"asn": "27653"})

    assert routing_scope and traffic_scope
    assert not set(routing_scope) & set(traffic_scope)


def test_a_leak_about_the_measured_network_covers_it():
    routing = [routing_edge(affected_prefixes=["2c0f:f860::/32"],
                             claimed_as="27653", victim_as="27653")]
    traffic = [traffic_point(z_score=-3.0)]

    routing_scope, traffic_scope = collect_scope(
        routing, traffic, {}, {"asn": "27653"})

    assert set(routing_scope) & set(traffic_scope)


def test_a_hijack_meets_the_traffic_series_at_the_victim():
    routing = [routing_edge(prefix="68.106.64.0/24",
                             victim_as="22773", origin_as="54845",
                             legitimate_origins=["22773"])]
    traffic = [traffic_point(z_score=-3.0)]

    routing_scope, traffic_scope = collect_scope(
        routing, traffic, {}, {"asn": "22773"})

    assert set(routing_scope) & set(traffic_scope)


def test_a_prefix_and_a_network_are_not_the_same_entity():
    """The two kinds must not be conflated into one comparable set.

    A prefix and a network are different things, so comparing them
    directly would either always overlap or never overlap by accident
    of the strings.
    """
    routing = [routing_edge(prefix="68.106.64.0/24")]
    traffic = [traffic_point()]

    routing_scope, traffic_scope = collect_scope(
        routing, traffic, {}, {"asn": "22773"})

    assert "prefix:68.106.64.0/24" in routing_scope
    assert "asn:22773" in traffic_scope
    assert "asn:22773" not in routing_scope


def test_an_unknown_scope_suspends_rather_than_fails():
    routing_scope, traffic_scope = collect_scope(
        [routing_edge()], [traffic_point()], {}, {})

    assert routing_scope is None
    assert traffic_scope is None


def test_the_context_contributes_its_affected_prefixes():
    routing_scope, _ = collect_scope(
        [], [], {"affected_prefixes": ["10.0.0.0/8"]}, {"asn": "1"})

    assert "prefix:10.0.0.0/8" in routing_scope
