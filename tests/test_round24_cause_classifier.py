"""Regression tests for the deterministic cause classifier (BUG-R140/142).

Symptom this pins down: the AS12479 / Orange España event — a documented
ROA-tampering hijack — was verdicted "BGP Reachability Outage" in the
operator-facing report even though the detectors had found 500
origin-hijacked and 500 origin-hijacking events. Three defects combined:

  1. `origin_hijacking` was treated as "hostile attacker" when *any* entry
     named a victim. On AS12479 two of 500 entries name AS210158, which
     demoted the cause to origin_hijack_attacker (0.90) and let the weak
     outage signal (0.95) win.
  2. A weak outage score (0.30) outranked a 1000-event hijack signal,
     even though a hijack itself causes the announcement drop.
  3. The correlation confidence bonus was applied to `candidates[0]`
     (first branch appended) *before* sorting, so it could land on a
     losing cause.

BUG-R142 (2026-09-29): when origin_hijacked and origin_hijacking are
both large and roughly equal (the Orange symmetric pattern), the
"AS is attacker" interpretation is wrong — a hostile hijacker would
not simultaneously be a victim of equal magnitude. The symmetric
pattern is the signature of RPKI/ROA tampering, so the cause must be
`roa_misconfig` rather than `origin_hijack_attacker`. The existing
`symmetric_rpki_gap` already suppressed the victim branch; BUG-R142
extends it to also suppress the hostile-attacker branch.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.report_agent import compute_top_cause  # noqa: E402


def _routing(oh, oi, leaks, *, victim_entries=0, outage_score=0.0, outage_suspected=False):
    """Build a normalized routing dict. `victim_entries` of the oi
    origin_hijacking alerts carry a recorded legitimate origin."""
    hijacking = [{} for _ in range(oi - victim_entries)]
    hijacking += [{"victim_as": "210158", "expected_origin": "210158"}
                  for _ in range(victim_entries)]
    return {
        "origin_hijacked": [{} for _ in range(oh)],
        "origin_hijacking": hijacking,
        "forge_hijacked": [],
        "forge_hijacking": [],
        "route_leaks": [{} for _ in range(leaks)],
        "outage_score": outage_score,
        "outage_suspected": outage_suspected,
    }


_TRAFFIC = {"anomaly_count": 12, "peak_trough_drop_pct": 81.7, "percent_change": -3.47}
_CORR = {"temporal_proximity": "strong", "confidence": 0.8, "delta_ts": []}

_HIJACK_CAUSES = {"roa_misconfig", "origin_hijack_victim", "origin_hijack_attacker"}


def test_orange_stray_victim_entries_do_not_flip_cause():
    """Two stray victim entries among 500 must not demote the ROA-gap
    cause — that demotion is what let outage_score 0.30 win."""
    top = compute_top_cause(
        _routing(500, 500, 5000, victim_entries=2, outage_score=0.30, outage_suspected=True),
        _TRAFFIC, _CORR, target_as="12479",
    )
    assert top["cause"] in _HIJACK_CAUSES, (
        f"AS12479 is a documented hijack; got {top['cause']} ({top['confidence']})"
    )
    assert top["cause"] != "outage", (
        "a weak outage score must not outrank a 1000-event hijack signal"
    )


def test_stray_victim_share_is_noise_below_threshold():
    """A small share of victim-recording alerts is detector noise."""
    for n in (0, 1, 5, 20):
        top = compute_top_cause(
            _routing(500, 500, 5000, victim_entries=n), _TRAFFIC, _CORR,
            target_as="12479",
        )
        assert top["cause"] == "roa_misconfig", (
            f"{n}/500 victim entries should stay ROA-gap, got {top['cause']}"
        )


def test_orange_symmetric_pattern_is_roa_misconfig():
    """BUG-R142 2026-09-29: AS12479 / Orange España shows 500 origin_hijacked
    + 500 origin_hijacking + 188 of the latter with expected_origin=210158
    (37.6% share). Even though this share trips the hostile-attacker threshold
    (>=20%), the symmetric pattern (the AS is both victim AND attacker in
    equal measure) is the signature of ROA tampering, not a malicious hijack.
    The cause must be `roa_misconfig`, not `origin_hijack_attacker`."""
    top = compute_top_cause(
        _routing(500, 500, 5000, victim_entries=188),
        _TRAFFIC, _CORR, target_as="12479",
    )
    assert top["cause"] == "roa_misconfig", (
        f"Orange-style symmetric 500/500 pattern with 188/500 expected_origin "
        f"should classify as ROA misconfig (RPKI tampering), got {top['cause']} "
        f"({top['confidence']})"
    )
    # roa_misconfig must also outrank the route_leak candidate, which would
    # otherwise dominate on raw count (5000 leaks vs 500 hijacks = 10x).
    roa = next((c for c in top["ranked"] if c["cause"] == "roa_misconfig"), None)
    leak = next((c for c in top["ranked"] if c["cause"] == "route_leak"), None)
    assert roa is not None and leak is not None, (
        f"Both roa_misconfig and route_leak should be candidates, got {top['ranked']}"
    )
    assert roa["confidence"] > leak["confidence"], (
        f"roa_misconfig ({roa['confidence']}) must outrank route_leak "
        f"({leak['confidence']}) for Orange-style ROA tampering"
    )


def test_hostile_attacker_without_symmetric_pattern_still_flagged():
    """BUG-R142 2026-09-29: when the symmetric_rpki_gap does NOT hold — i.e.
    the AS is the attacker but NOT simultaneously a victim of equal magnitude —
    the hostile-attacker interpretation still applies. This separates a true
    hostile hijack (one-sided) from an ROA-tampering event (symmetric).

    No leaks here, so this isolates the symmetric check from leak-dominance
    rules. The 500/500 attack/victim split below would have been symmetric,
    so we use an asymmetric split: 10 hijacks vs 500 victims. The AS is
    overwhelmingly the victim with only a tiny attacker signal — not the
    symmetric pattern we want to flag as ROA misconfig."""
    # 10 attacker-side events (all with expected_origin != target_as) + 0
    # victim-side events — not symmetric, the hostile_attacker threshold
    # should fire and select origin_hijack_attacker.
    top = compute_top_cause(
        _routing(0, 10, 0, victim_entries=10), _TRAFFIC, _CORR,
        target_as="12479",
    )
    assert top["cause"] == "origin_hijack_attacker", (
        f"10/10 attacker entries with no symmetric victim pattern should flag "
        f"hostile attacker, got {top['cause']}"
    )


def test_strong_outage_still_wins_when_score_is_high():
    """The outage demotion must only apply to *weak* scores — a genuine
    outage event has to keep its verdict."""
    top = compute_top_cause(
        _routing(0, 0, 0, outage_score=0.75, outage_suspected=True),
        {"anomaly_count": 90, "peak_trough_drop_pct": 97.0, "percent_change": -97.0},
        _CORR, target_as="44244",
    )
    assert top["cause"] == "outage", f"expected outage, got {top['cause']}"


def test_weak_outage_does_not_beat_hijack():
    top = compute_top_cause(
        _routing(500, 500, 0, outage_score=0.30, outage_suspected=True),
        _TRAFFIC, _CORR, target_as="12479",
    )
    assert top["cause"] != "outage"
    assert top["cause"] in _HIJACK_CAUSES


def test_upx_leak_still_wins_over_hijack_signal():
    """Bugs R136/R139 classified UPX (5000 leaks + 500 self-hijacks) as a
    Route Leak. UPX is a one-sided leak event — its hijacks come from the
    leak itself, not from a symmetric attacker pattern. Use 500 leaks with
    a small attacker-side signal (no symmetric victim pattern)."""
    top = compute_top_cause(
        # 254 victim-of-self hijacks (UPX real signature per ground truth) +
        # 0 attacker-side (UPX is the leak source, not the attacker) +
        # 5000 leaks. Not symmetric → route_leak should win.
        _routing(254, 0, 5000, victim_entries=0, outage_score=0.30, outage_suspected=True),
        {"anomaly_count": 26, "peak_trough_drop_pct": 10.9, "percent_change": -1.0},
        _CORR, target_as="52863",
    )
    assert top["cause"] == "route_leak", f"expected route_leak, got {top['cause']}"


def test_ranked_is_sorted_by_confidence():
    """The correlation bonus must be applied to the winner, then the list
    re-sorted — so ranked[0] is always the top-confidence candidate."""
    top = compute_top_cause(
        _routing(500, 500, 5000, victim_entries=0), _TRAFFIC, _CORR,
        target_as="12479",
    )
    confs = [e["confidence"] for e in top["ranked"]]
    assert confs == sorted(confs, reverse=True), f"ranked not sorted: {confs}"
    assert top["ranked"][0]["cause"] == top["cause"]
