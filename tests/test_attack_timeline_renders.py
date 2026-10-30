"""The Attack Timeline section must render on both code paths.

``render_attack_timeline`` had two paths: a primary path that reads a
merged correlation timeline, and a fallback path that synthesises rows
from raw routing/traffic results.  The fallback path called ``ts(ev)``
while the helper it intended to call was named ``format_ts`` — and on
the primary path a local variable named ``ts`` shadowed the name
entirely, so the call raised ``UnboundLocalError: cannot access local
variable 'ts'``.

Because the report agent catches that failure and renders a
deterministic fallback page, the bug was invisible in the pipeline:
every analysis still produced a verdict, but the Attack Timeline —
the section that shows *when* each signal landed — was silently
replaced by generic fallback text.  On the ground-truth run this
affected every single event.
"""

from __future__ import annotations

from agents.report_agent import render_attack_timeline


def routing_fixture():
    return {
        "origin_hijacked": [
            {
                "prefix": "1.1.1.0/24",
                "origin_as": "64496",
                "timestamp": "2024-08-01 09:00:00",
            }
        ],
        "origin_hijacking": [],
    }


def traffic_fixture():
    return {
        "timeline": [
            {
                "timestamp": "2024-08-01 09:05:00",
                "type": "traffic_anomaly",
                "z_score": -4.2,
            }
        ]
    }


def test_fallback_path_renders_without_unbound_local_error():
    html = render_attack_timeline(
        routing_norm=routing_fixture(),
        traffic_norm=traffic_fixture(),
        correlation_norm={},
        target_as="AS64496",
    )

    assert "1.1.1.0/24" in html
    assert "traffic_anomaly" in html
    assert "Attack Timeline" in html


def test_primary_path_renders_merged_timeline():
    html = render_attack_timeline(
        routing_norm={},
        traffic_norm={},
        correlation_norm={
            "timeline": [
                {
                    "timestamp": "2024-08-01 09:00:00",
                    "source": "routing",
                    "type": "origin_hijacked",
                    "prefix": "8.8.8.0/24",
                    "origin_as": "64497",
                    "severity": "high",
                }
            ]
        },
        target_as="AS64496",
    )

    assert "8.8.8.0/24" in html
    assert "origin_hijacked" in html


def test_empty_inputs_render_explicit_empty_state():
    html = render_attack_timeline(
        routing_norm={},
        traffic_norm={},
        correlation_norm={},
        target_as="AS64496",
    )

    assert "Attack Timeline" in html
    assert "No timestamped events" in html
