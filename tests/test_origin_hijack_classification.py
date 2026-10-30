"""Tests for the origin-hijack classification.

Three snapshot states have to be kept apart:

  exact-owned     the snapshot names the target as an origin of the exact
                  prefix the announcement carries
  exact-other     the snapshot names a different origin for the exact
                  prefix
  unknown         the snapshot does not cover the exact prefix

Collapsing the last two into "foreign" is what produced the mass false
positives: every announcement of a more-specific prefix inside the
target's block was read as a hijack of the target's space.

A second distinction matters for a transit provider: when the target AS
appears in the AS path immediately before the origin AS, the origin is a
customer of the target announcing its own more-specific prefix inside the
target's allocation.  That is ordinary origination, not hijacking.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import polars as pl  # noqa: E402

from detectors.hijack.hijack_detector_core import detect_origin_hijacks  # noqa: E402


def build(announcements, prefix_to_as):
    return pl.DataFrame({
        "as-path": [a["path"] for a in announcements],
        "prefix": [a["prefix"] for a in announcements],
        "timestamp": [a.get("timestamp", "2025-01-01 00:00:00") for a in announcements],
    })


def alerts_of(announcements, prefix_to_as, target="812"):
    df = build(announcements, prefix_to_as)
    result = detect_origin_hijacks(df, prefix_to_as, target_as=target)
    return result


def test_exact_owned_prefix_announced_by_other_is_victim_hijack():
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 200 12021"}],
        {"10.0.0.0/24": ["812"]},
    )
    kinds = {a["hijack_type"] for a in alerts}
    assert kinds == {"origin_hijacked"}, alerts


def test_unknown_prefix_announced_by_unrelated_as_is_victim_hijack():
    """An AS unrelated to the target originating inside the target's block."""
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 200 12021"}],
        {"10.0.0.0/16": ["812"]},
    )
    kinds = {a["hijack_type"] for a in alerts}
    assert kinds == {"origin_hijacked"}, alerts


def test_customer_announcement_inside_target_block_is_not_a_hijack():
    """The target is the direct predecessor of the origin: a customer."""
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 812 12021"}],
        {"10.0.0.0/16": ["812"]},
    )
    assert alerts == [], alerts


def test_target_as_transit_is_not_a_hijack():
    """The target is in the path but not the direct predecessor."""
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "812 900 12021"}],
        {"10.0.0.0/16": ["812"]},
    )
    assert alerts == [], alerts


def test_exact_prefix_owned_by_another_as_is_not_a_victim_hijack():
    """The exact prefix belongs to somebody else, so the target is not the victim."""
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 200 12021"}],
        {"10.0.0.0/24": ["9999"]},
    )
    assert alerts == [], alerts


def test_target_announcing_a_foreign_exact_prefix_is_attacker():
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 200 812"}],
        {"10.0.0.0/24": ["9999"]},
    )
    kinds = {a["hijack_type"] for a in alerts}
    assert kinds == {"origin_hijacking"}, alerts


def test_target_announcing_an_uncovered_prefix_is_not_an_attacker():
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 200 812"}],
        {"10.0.0.0/16": ["9999"]},
    )
    assert alerts == [], alerts


def test_target_originating_its_own_exact_prefix_is_not_a_hijack():
    alerts = alerts_of(
        [{"prefix": "10.0.0.0/24", "path": "100 200 812"}],
        {"10.0.0.0/24": ["812"]},
    )
    assert alerts == [], alerts


def test_v4_mapped_prefixes_are_handled():
    """IPv6 prefixes follow the same rules."""
    alerts = alerts_of(
        [{"prefix": "2001:db8::/48", "path": "100 200 12021"}],
        {"2001:db8::/32": ["812"]},
    )
    kinds = {a["hijack_type"] for a in alerts}
    assert kinds == {"origin_hijacked"}, alerts
