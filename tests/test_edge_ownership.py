"""AEA must refuse what it cannot identify, and commit what it can.

The estimator is a veto chain, so most of these tests pin down *refusals*: the
geometries where a score-based method would still emit a direction.  The one
positive case plants a routing edge before a traffic drop and requires the
commitment.
"""

from __future__ import annotations

import numpy as np

from agents.edge_ownership import (
    AEA_PROTOCOL,
    REASONS,
    R2T,
    T2R,
    UNKNOWN,
    attribute,
    protocol_hash,
)


def make_pair(lag: int = 4, n: int = 200, tau: int = 90, seed: int = 7):
    """Routing steps up at ``tau``; traffic drops at ``tau + lag``.

    The window is long enough to supply the placebos the exact permutation
    test needs: with ``n = 200`` and ``tau = 90`` the engine's matched
    horizon is 42 buckets, which leaves 31 placebo onsets and therefore a
    smallest attainable p-value of 1/32, comfortably below alpha.
    """
    rng = np.random.default_rng(seed)
    r = np.concatenate([np.ones(K)
                        for K in (tau, n - tau)]).astype(float)
    r[tau:] = 6.0
    r = r + rng.uniform(0.0, 0.10, n)
    t = np.full(n, 10.0)
    t[tau + lag:] = 4.0
    t = t + rng.uniform(0.0, 0.30, n)
    return r, t


def test_short_series_abstains():
    v = attribute([1.0, 2.0, 3.0], [1.0, 2.0, 3.0])
    assert v.direction == UNKNOWN
    assert v.reason == "series_too_short"


def test_flat_response_abstains():
    v = attribute([1.0] * 60 + [5.0] * 60, [3.0] * 120)
    assert v.direction == UNKNOWN
    assert v.reason == "traffic_series_flat"


def test_no_routing_edge_abstains():
    rng = np.random.default_rng(1)
    r = 1.0 + rng.uniform(0.0, 1.0, 120)
    r[60:] += 0.05           # a step smaller than the noise: no detectable edge
    v = attribute(r, np.concatenate([np.full(60, 10.0), np.full(60, 4.0)]))
    assert v.direction == UNKNOWN
    assert v.reason == "no_routing_edge"


def test_simultaneous_edges_abstain():
    n, tau = 120, 60
    r = np.concatenate([np.full(tau, 1.0), np.full(n - tau, 6.0)])
    t = np.concatenate([np.full(tau, 10.0), np.full(n - tau, 4.0)])
    v = attribute(r, t)
    assert v.direction == UNKNOWN
    assert v.reason == "inadmissible_precedence"
    assert v.vetoes["V1"] == "fail"


def test_planted_routing_to_traffic_commits():
    r, t = make_pair()
    v = attribute(r, t)
    assert v.reason == "committed", v.as_dict()
    assert v.direction == R2T
    assert v.vetoes["V2"] == "pass"
    assert v.p_value < AEA_PROTOCOL["alpha"]
    # No reversion inside the window: V4 is suspended, not failed.
    assert v.vetoes["V4"] == "suspend"


def test_unknown_scope_suspends_provenance_without_refuting():
    r, t = make_pair()
    v = attribute(r, t)
    assert v.vetoes["V3"] == "suspend"
    assert v.direction == R2T


def test_disjoint_scope_vetoes_the_claim():
    r, t = make_pair()
    v = attribute(r, t, routing_scope=["64500"], series_scope=["15169"])
    assert v.direction == UNKNOWN
    assert v.reason == "provenance_disjoint"
    assert v.vetoes["V3"] == "fail"


def test_shared_scope_passes_provenance():
    r, t = make_pair()
    v = attribute(r, t, routing_scope=["64500", "15169"],
                  series_scope=["15169", "3356"])
    assert v.vetoes["V3"] == "pass"
    assert v.tests["provenance"]["shared"] == 1


def test_swapping_the_series_never_reproduces_the_same_direction():
    r, t = make_pair()
    forward = attribute(r, t)
    backward = attribute(t, r)
    assert forward.direction == R2T
    assert backward.direction != R2T
    # Without an annotation the reverse claim is not made at all.
    assert backward.reason == "mechanism_unknown"


def test_reaction_mechanism_permits_a_traffic_to_routing_claim():
    r, t = make_pair()
    v = attribute(t, r, routing_mechanism="withdrawal")
    assert v.reason == "committed", v.as_dict()
    assert v.direction == T2R


def test_origin_change_is_not_treated_as_a_reaction():
    r, t = make_pair()
    v = attribute(t, r, routing_mechanism="origin_change")
    assert v.direction == UNKNOWN
    assert v.reason == "reactive_incompatible"


def test_no_commit_below_the_alpha_floor():
    r, t = make_pair()
    v = attribute(r, t, protocol={"alpha": 0.0})
    assert v.direction == UNKNOWN
    assert v.reason == "not_exclusive"
    assert v.vetoes["V2"] == "fail"


def test_verdicts_are_deterministic_and_protocol_identified():
    r, t = make_pair()
    a = attribute(r, t).as_dict()
    b = attribute(r, t).as_dict()
    assert a == b
    assert a["protocol_hash"] == protocol_hash()
    assert protocol_hash() != protocol_hash(dict(AEA_PROTOCOL, alpha=0.01))


def test_every_reason_has_a_name():
    r, t = make_pair()
    observed = {
        attribute(r, t).reason,
        attribute(t, r).reason,
        attribute(t, r, routing_mechanism="origin_change").reason,
        attribute(r, t, routing_scope=["a"], series_scope=["b"]).reason,
        attribute([1.0] * 120, [1.0] * 120).reason,
        attribute([1.0, 2.0], [1.0, 2.0]).reason,
    }
    assert observed <= set(REASONS)
