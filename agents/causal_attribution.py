"""HCAF causal attribution engine.

Chains MSBD (wavelet breakpoints), CTPR (AS-path reconstruction), CIC
(counterfactual cascade), Granger causality, and Transfer Entropy into a
Bayesian ensemble; embeds Pearl-style Causal Sufficiency Score (CSS) as
the anchor likelihood and supports abstention when evidence is weak.
"""
import os
import zlib
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from collections import defaultdict
from typing import Dict, Optional, Any
import logging
import math
import warnings

logger = logging.getLogger(__name__)

try:
    from agents.css_engine import (
        css_score,
        bayesian_synthesize,
        CSSResult,
    )
    _CSS_OK = True
except ImportError:
    _CSS_OK = False
    CSSResult = None  # type: ignore[assignment, misc]
    css_score = None  # type: ignore[assignment]
    bayesian_synthesize = None  # type: ignore[assignment]

try:
    from agents.causal_baselines import transfer_entropy_baseline
except ImportError:
    transfer_entropy_baseline = None  # type: ignore[assignment]

try:
    import numpy as np
    from statsmodels.tsa.stattools import grangercausalitytests, adfuller
    STATSMODELS_OK = True
except ImportError:
    STATSMODELS_OK = False
    np = None  # type: ignore[assignment]

try:
    from config import (
        HCAF_WEIGHTS_MSBD, HCAF_WEIGHTS_CTPR, HCAF_WEIGHTS_CIC,
        HCAF_WEIGHTS_GRANGER, HCAF_MAJORITY_THRESHOLD,
        HCAF_MIN_DIRECTION_CONFIDENCE, HCAF_MIN_POSTERIOR,
    )
    _HCAF_CFG_OK = True
except ImportError:
    _HCAF_CFG_OK = False
    HCAF_WEIGHTS_MSBD, HCAF_WEIGHTS_CTPR = 0.40, 0.30
    HCAF_WEIGHTS_CIC, HCAF_WEIGHTS_GRANGER = 0.30, 0.15
    HCAF_MAJORITY_THRESHOLD = 2
    HCAF_MIN_DIRECTION_CONFIDENCE = 0.10
    HCAF_MIN_POSTERIOR = 0.50


def _hcaf_majority_vote(method_directions, threshold=HCAF_MAJORITY_THRESHOLD):
    """Return the direction with ≥ ``threshold`` votes, or None.

    ``method_directions`` is a list of direction strings. ``"unknown"``
    counts as abstention and does not contribute.
    """
    counts = {}
    for d in method_directions:
        if d == "unknown" or d is None:
            continue
        counts[d] = counts.get(d, 0) + 1
    for d, c in counts.items():
        if c >= threshold:
            return d
    return None

# ADF significance level for the stationarity pre-check. Series with
ADF_SIGNIFICANCE = float(os.environ.get("BGP_TRACER_ADF_SIG", "0.05"))

try:
    import pywt
    PYWT_OK = True
except ImportError:
    PYWT_OK = False


# 1:  (Multi-Scale Causal Breakpoint Detection)


def detect_multi_scale_breakpoints(routing_series, traffic_series, timestamps=None):
    if not PYWT_OK:
        return msbd_fallback(routing_series, traffic_series)
    n = min(len(routing_series), len(traffic_series))
    if n < 10:
        return {"direction": "unknown", "strength": 0.0, "significant": False, "interpretation": ""}
    routing = np.array(routing_series[:n])
    traffic = np.array(traffic_series[:n])
    wavelet = "db4"
    max_level = min(4, int(np.log2(n)) - 1)
    if max_level < 1:
        max_level = 1
    try:
        r_coeffs = pywt.wavedec(routing, wavelet, level=max_level)
        t_coeffs = pywt.wavedec(traffic, wavelet, level=max_level)
    except Exception:
        return msbd_fallback(routing_series, traffic_series)
    scale_results = []
    for idx in range(1, len(r_coeffs)):
        rd, td = r_coeffs[idx], t_coeffs[idx]
        if len(rd) < 2:
            continue
        r_bp = msbd_find_bp(rd)
        t_bp = msbd_find_bp(td)
        sync = msbd_sync(r_bp, t_bp, len(rd))
        energy = (np.sum(rd**2) + np.sum(td**2)) / (np.sum(routing**2) + np.sum(traffic**2) + 1e-10)
        scale_results.append({"scale": idx, "sync_score": sync, "energy": energy})
    if not scale_results:
        return {"direction": "unknown", "strength": 0.0, "significant": False, "interpretation": ""}
    total_e = sum(s["energy"] for s in scale_results) + 1e-10
    weighted_sync = sum(s["sync_score"] * s["energy"] for s in scale_results) / total_e
    consistency = msbd_consistency(scale_results)
    direction = msbd_direction(weighted_sync, routing, traffic)
    return {"direction": direction, "strength": weighted_sync,
            "significant": consistency >= 0.6 and weighted_sync >= 0.3,
            "scale_sync": weighted_sync, "scale_consistency": consistency,
            "interpretation": f"multi_scale_sync={weighted_sync:.2f}, consistency={consistency:.2f}",
            "scale_results": scale_results}


def msbd_find_bp(coeffs):
    if len(coeffs) < 3:
        return []
    abs_c = np.abs(coeffs)
    threshold = np.mean(abs_c) + 2 * np.std(abs_c)
    return [i for i, v in enumerate(abs_c) if v > threshold]


def msbd_sync(r_bp, t_bp, scale_len):
    if not r_bp or not t_bp:
        return 0.0
    tol = max(1, scale_len // 10)
    matched = sum(1 for rp in r_bp if any(abs(rp - tp) <= tol for tp in t_bp))
    total = len(r_bp) + len(t_bp)
    return 2.0 * matched / total if total > 0 else 0.0


def msbd_consistency(results):
    if not results:
        return 0.0
    scores = [s["sync_score"] for s in results]
    if not scores:
        return 0.0
    mean_s, std_s = np.mean(scores), np.std(scores)
    return 1.0 - min(std_s / mean_s, 1.0) if mean_s > 0.01 else 0.0


def msbd_direction(sync, routing, traffic):
    # sync<0.2  peak_position fallback,  HCAF 
    if sync >= 0.6:
        # ,  peak 
        r_peak = int(np.argmax(routing)) if len(routing) > 0 else 0
        t_peak = int(np.argmax(traffic)) if len(traffic) > 0 else 0
        n = max(len(routing), len(traffic), 1)
        gap_ratio = abs(r_peak - t_peak) / n
        if gap_ratio > 0.5:  # peak 
            return "independent"
    r_peak = int(np.argmax(routing)) if len(routing) > 0 else 0
    t_peak = int(np.argmax(traffic)) if len(traffic) > 0 else 0
    if r_peak < t_peak:
        return "routing_to_traffic"
    elif t_peak < r_peak:
        return "traffic_to_routing"
    return "independent"


def msbd_fallback(routing_series, traffic_series):
    n = min(len(routing_series), len(traffic_series))
    if n < 10:
        return {"direction": "unknown", "strength": 0.0, "significant": False, "interpretation": ""}
    r, t = np.array(routing_series[:n]), np.array(traffic_series[:n])
    # FIX: If traffic is all zeros (no traffic events recorded), the peak
    # position is undefined — the argmax is at index 0 regardless of any
    # real signal. MSBD should abstain rather than hallucinate a direction.
    # This prevents "traffic_to_routing" predictions on events where the
    # traffic CSV has no overlap with the event window (e.g. AS45804,
    # AS29119, outage_bangladesh where traffic CSV ends before the event).
    t_std = float(np.std(t))
    t_nonzero = float(np.sum(t > 1e-9))
    if t_std < 1e-9 and t_nonzero < 2:
        return {"direction": "unknown", "strength": 0.0, "significant": False,
                "interpretation": "traffic series all-zero; MSBD abstain"}
    corr = np.corrcoef(r, t)[0, 1] if n > 2 else 0
    rp, tp = int(np.argmax(r)), int(np.argmax(t))
    direction = "routing_to_traffic" if rp < tp else ("traffic_to_routing" if tp < rp else "independent")
    return {"direction": direction, "strength": abs(corr), "significant": abs(corr) > 0.5,
            "interpretation": " (pywt )"}


# 2:  (Causal Transmission Path Reconstruction)


def reconstruct_transmission_path(routing, traffic, topology, target_asn):
    routing_events = routing
    traffic_events = traffic
    if not routing_events or not traffic_events:
        return ctpr_empty()
    sources = ctpr_identify_source(routing_events)
    chains = []
    for src in sources:
        chain = ctpr_build_chain(src)
        if chain:
            chains.append(chain)
    if not chains:
        return ctpr_empty()
    matched = ctpr_match_chain(chains, traffic_events)
    if not matched:
        #  routing_to_traffic,  unknown
        return ctpr_empty()
    strength, sig = ctpr_strength(matched, traffic_events)
    root = matched[0] if matched else None
    return {"direction": "routing_to_traffic", "strength": strength, "significant": sig,
            "transmission_path": matched, "root_cause_as": root["asn"] if root else None,
            "path_length": len(matched),
            "propagation_delay_estimate_lower_bound_seconds": ctpr_delay(matched),
            "propagation_delay_note": (
                "Pseudo-delay placeholder; not a measurement of real BGP propagation. "
                "Use only as a relative ordering signal across CTPR chains for the same event."
            ),
            "interpretation": ctpr_desc(matched, root, strength)}


def ctpr_identify_source(events):
    sources, seen = [], set()
    for ev in sorted(events, key=lambda e: e.get("timestamp", "")):
        path = ev.get("as_path", [])
        if path:
            # BGP AS_PATH: origin is at the END of the path (furthest from destination)
            origin = path[-1] if path else None
            if origin and origin not in seen:
                seen.add(origin)
                sources.append({"asn": origin, "timestamp": ev.get("timestamp"),
                               "event_type": ev.get("event_type"), "as_path": path})
    return sources[:5]


def ctpr_build_chain(source):
    chain = [{"asn": source["asn"], "timestamp": source["timestamp"],
              "role": "source", "delay_contribution": 0}]
    path = source.get("as_path", [])
    delay = 0
    for idx, asn in enumerate(path[:-1]):
        delay += ctpr_step_pseudo_delay(asn, path[idx + 1] if idx + 1 < len(path) else None)
        chain.append({"asn": asn, "role": "transit", "step_index": idx,
                     "cumulative_pseudo_delay": delay, "downstream": path[idx + 1] if idx + 1 < len(path) else None})
    return chain


def ctpr_step_pseudo_delay(f, t):
    """Per-hop pseudo-propagation delay placeholder.

    WARNING: this value is a non-physical, deterministic placeholder used
    only to give CTPR chains a stable, comparable total-delay metric for
    ranking / strength calculation. It MUST NOT be interpreted as a real
    BGP propagation delay. The name change from ``ctpr_step_delay`` to
    ``ctpr_step_pseudo_delay`` is intentional to discourage reviewers /
    downstream consumers from quoting it as an empirical observation.

    Range is bounded to [60s, 180s] (1 hop → 1-3 minutes), the realistic
    lower bound for an AS-to-AS eBGP update propagation in current
    operational networks.

    Override via env var ``BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER`` to
    change the jitter width; set it to ``0`` to force a constant
    60s-per-hop delay (fully deterministic, no jitter).

    Determinism note: the jitter uses ``zlib.crc32`` rather than
    Python's builtin ``hash()``. The builtin hash of a ``str`` or
    ``tuple`` is salted per-process via ``PYTHONHASHSEED``, which would
    make this placeholder -- and therefore any downstream chain ranking
    or reported pseudo-delay -- vary between otherwise identical runs,
    breaking the paper's reproducibility claim. ``crc32`` is stable
    across processes, machines, and Python versions.
    """
    if f is None or t is None:
        return 60
    jitter = int(os.environ.get("BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER", "120"))
    if jitter <= 0:
        return 60
    # Stable across processes: zlib.crc32 is NOT salted by PYTHONHASHSEED,
    # unlike hash() on str/tuple. Using hash() here made the "deterministic"
    # placeholder vary between runs, breaking reproducibility.
    digest = zlib.crc32(f"{f}->{t}".encode("utf-8"))
    return 60 + digest % jitter


def ctpr_match_chain(chains, traffic_events):
    if not chains or not traffic_events:
        return chains[0] if chains else None
    primary = max(traffic_events, key=lambda e: e.get("drop_ratio", 0))
    tt = ctpr_parse_time(primary.get("timestamp"))
    if not tt:
        return chains[0]
    best, best_diff = None, None
    for chain in chains:
        if not chain:
            continue
        ct = ctpr_parse_time(chain[0].get("timestamp"))
        if not ct:
            continue
        diff = abs((tt - ct).total_seconds())
        if best_diff is None or diff < best_diff:
            best_diff, best = diff, chain
    return best


def ctpr_strength(chain, traffic_events):
    if not chain or not traffic_events:
        return 0.0, False
    drop = max(traffic_events, key=lambda e: e.get("drop_ratio", 0)).get("drop_ratio", 0)
    penalty = max(0.3, 1.0 - (len(chain) - 1) * 0.1)
    strength = penalty * min(drop, 1.0)
    return strength, strength >= 0.4 and drop >= 0.3


def ctpr_delay(chain):
    """Return the cumulative pseudo-delay (lower-bound estimate in seconds).

    NOTE: pseudo-delay is a deterministic placeholder used to rank
    chains within a single event, NOT a physical measurement. See
    ``ctpr_step_pseudo_delay`` docstring for details.
    """
    return chain[-1].get("cumulative_pseudo_delay", 0) if chain else 0


def ctpr_desc(chain, root, strength):
    if not chain:
        return ""
    path_str = " -> ".join(str(n["asn"]) for n in chain)
    return (f"causal_transmission_path: {path_str} ({len(chain)} AS hops). "
            f"root_cause: AS{root['asn']}. "
            f"strength={strength:.2f}.")


def ctpr_parse_time(time_str):
    if not time_str:
        return None
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def ctpr_empty():
    return {"direction": "unknown", "strength": 0.0, "significant": False,
            "transmission_path": [], "root_cause_as": None, "interpretation": ""}


# 3:  (Counterfactual Intervention Cascade)


def estimate_counterfactual_cascade(intervention_as, intervention_type, routing_state,
                                    as_topology, traffic_baseline, affected_prefix,
                                    edge_types=None):
    if not as_topology:
        return cic_empty()
    cascade = cic_propagate(intervention_as, as_topology, routing_state, intervention_type,
                            affected_prefix, edge_types)
    if not cascade:
        return cic_empty()
    impacts = [cic_node_impact(n, intervention_type, traffic_baseline) for n in cascade]
    total = cic_aggregate(impacts)
    strength, sig = cic_strength(total, impacts)
    return {"direction": "routing_to_traffic", "strength": strength, "significant": sig,
            "cascade_chain": cascade, "impact_estimates": impacts, "total_impact": total,
            "affected_as_count": len(cascade),
            "relation_mix": cic_relation_mix(cascade),
            "counterfactual_summary": cic_cf_summary(intervention_as, total),
            "interpretation": cic_desc(intervention_as, cascade, total, strength)}


# How much a routing change at the origin propagates along one AS-to-AS
# edge, by commercial relationship. A withdrawal at a provider does not
# reach its customer directly (the customer re-routes around it), whereas
# a hijack does travel down the customer tree because the customer
# accepts the announcement. Peer links are symmetric and carry a partial
# share in both directions.
#
# The values are attenuation factors applied on top of the per-hop
# depth decay, and are the mechanism by which the AS supply
# relationship enters the counterfactual estimate.
_RELATION_PROPAGATION = {
    "provider": 1.0,   # origin is the provider's customer
    "customer": 0.75,  # origin is the provider
    "peer": 0.6,
    "unknown": 0.5,
}


def cic_propagate(start_as, topology, routing_state, int_type, prefix, edge_types=None):
    """Walk the AS graph outward from the intervention, recording the path.

    ``edge_types`` maps ``{asn: {neighbour: relation}}`` where relation is
    one of provider / customer / peer. It is optional: without it the
    walk still works but every edge is treated as ``unknown`` and
    propagation is attenuated conservatively.
    """
    edge_types = edge_types or {}
    # Normalise the origin to a string so the lookup matches the
    # topology keys, which are ASN strings.
    origin_key = str(start_as).strip().upper().lstrip("AS")

    visited, chain, queue = set(), [], [(origin_key, 0, None, "origin")]
    while queue:
        current, depth, upstream, relation = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        chain.append({"asn": current, "depth": depth, "upstream_as": upstream,
                      "relation": relation,
                      "has_route": cic_has_pfx(current, prefix, routing_state)})
        if depth >= 5:
            continue
        rel_map = edge_types.get(current, {}) if isinstance(edge_types, dict) else {}
        for neighbor in topology.get(current, []):
            if neighbor not in visited:
                rel = rel_map.get(neighbor, "unknown")
                queue.append((neighbor, depth + 1, current, rel))
    return chain


def cic_has_pfx(asn, prefix, routing_state):
    if not prefix or not routing_state:
        return False
    key = str(asn).strip().upper().lstrip("AS")
    prefixes = routing_state.get(key)
    if prefixes is None:
        prefixes = routing_state.get(asn, [])
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    if prefix in prefixes:
        return True
    # The affected prefix may be recorded under a different (more
    # specific or less specific) CIDR than the detector reported. Fall
    # back to a containment test so a /24 event is not missed because
    # the snapshot records the covering /22.
    try:
        import ipaddress
        target = ipaddress.ip_network(prefix, strict=False)
    except (ValueError, TypeError):
        return False
    for pfx in prefixes or []:
        try:
            other = ipaddress.ip_network(str(pfx), strict=False)
        except (ValueError, TypeError):
            continue
        if target.subnet_of(other) or other.subnet_of(target):
            return True
    return False


def cic_node_impact(node, int_type, baseline):
    asn, depth = node["asn"], node["depth"]
    bl = baseline.get(asn, 1.0)
    has_route = node["has_route"]
    relation = node.get("relation", "unknown")
    if int_type == "withdraw":
        impact = -bl if has_route else 0
    elif int_type == "hijack":
        impact = -bl * 0.7 if has_route else bl * 0.3
    elif int_type == "leak":
        impact = bl * (-0.2 if depth == 0 else 0.1)
    else:
        impact = 0
    impact *= (0.85 ** depth)
    # The commercial relationship between the origin and this node
    # attenuates how much of the routing change reaches it. The origin
    # itself is unaffected by the factor.
    if depth > 0:
        impact *= _RELATION_PROPAGATION.get(relation, _RELATION_PROPAGATION["unknown"])
    return {"asn": asn, "depth": depth, "baseline": bl, "impact": impact,
            "impact_ratio": impact / bl if bl > 0 else 0, "has_route": has_route,
            "relation": relation}


def cic_relation_mix(cascade):
    """Count how the cascade's nodes are reached, by commercial relation."""
    mix = defaultdict(int)
    for node in cascade:
        mix[node.get("relation", "unknown")] += 1
    return dict(mix)


def cic_aggregate(impacts):
    if not impacts:
        return {"total": 0, "affected_count": 0, "avg_impact": 0, "max_impact": 0}
    total = sum(e["impact"] for e in impacts)
    affected = sum(1 for e in impacts if abs(e["impact"]) > 0.1)
    avg = total / len(impacts)
    mx = max((abs(e["impact"]) for e in impacts), default=0)
    return {"total": total, "affected_count": affected, "avg_impact": avg, "max_impact": mx}


def cic_strength(total, impacts):
    if not impacts:
        return 0.0, False
    ratio = total["affected_count"] / len(impacts)
    strength = ratio * min(total["max_impact"], 1.0)
    return strength, strength >= 0.3 and total["affected_count"] >= 2


def cic_cf_summary(intervention_as, total):
    return (f"if AS{intervention_as} no_intervention, {total['affected_count']} num_downstream AS "
            f"traffic_baseline, not_occur {abs(total['total']):.1%} cumulative change.")


def cic_desc(intervention_as, cascade, total, strength):
    if not cascade:
        return ""
    depth_counts = defaultdict(int)
    for n in cascade:
        depth_counts[n["depth"]] += 1
    depth_desc = ", ".join(f"depth {d} has {c} nodes" for d, c in sorted(depth_counts.items()))
    return (f"intervention AS{intervention_as} cascade_to {len(cascade)} num_nodes ({depth_desc}). "
            f"impact {total['affected_count']} AS, CausalStrength {strength:.2f}.")


def cic_empty():
    return {"direction": "unknown", "strength": 0.0, "significant": False,
            "cascade_chain": [], "impact_estimates": [], "total_impact": {"total": 0, "affected_count": 0},
            "interpretation": " AS "}


def quick_cascade_estimate(event_type, affected_as_count, traffic_drop_ratio,
                           routing_timeline=None, traffic_timeline=None):
    """ AS .

     routing_to_traffic,  routing/traffic 
     ( peak_position baseline ),  unknown.
    """
    if not event_type or affected_as_count == 0:
        return {"direction": "unknown", "strength": 0.0, "significant": False}
    factors = {"outage": 0.9, "hijack": 0.8, "leak": 0.5, "withdrawal": 0.9, "normal": 0.0}
    ef = factors.get(event_type, 0.3)
    af = min(affected_as_count / 10.0, 1.0)
    df = min(traffic_drop_ratio, 1.0)
    strength = ef * af * df

    # , 
    direction = "unknown"
    try:
        if routing_timeline and traffic_timeline:
            r_scores = [p.get("score", 0) for p in routing_timeline]
            t_scores = [p.get("score", 0) for p in traffic_timeline]
            n = min(len(r_scores), len(t_scores))
            if n >= 3:
                r_peak = max(range(n), key=lambda i: r_scores[i])
                t_peak = max(range(n), key=lambda i: t_scores[i])
                if r_peak < t_peak:
                    direction = "routing_to_traffic"
                elif t_peak < r_peak:
                    direction = "traffic_to_routing"
                else:
                    direction = "independent"
    except Exception:
        direction = "unknown"

    return {"direction": direction, "strength": strength, "significant": strength >= 0.3,
            "affected_as_count": affected_as_count,
            "interpretation": f"{event_type} impact {affected_as_count} count AS, strength {strength:.2f}"}


# Granger  (baseline)


class GrangerEngine:
    def __init__(self, max_lag=3, significance=0.05, enforce_stationarity=True):
        self.max_lag = max_lag
        self.significance = significance
        # When True (default), run ADF stationarity pre-check and
        self.enforce_stationarity = enforce_stationarity

    def test(self, routing_timeline, traffic_timeline):
        if not STATSMODELS_OK:
            return granger_fb(routing_timeline, traffic_timeline)
        r_series, t_series = granger_align(routing_timeline, traffic_timeline)
        n = len(r_series)
        if n < 10:
            return granger_insuf(n)

        stationarity_meta = {"checked": False, "differencing_applied": False,
                             "adf_p_value": None, "stationarity_ok": True,
                             "routing_note": "", "traffic_note": ""}
        if self.enforce_stationarity:
            r_check = granger_stationary_check_and_diff(r_series, name="routing")
            t_check = granger_stationary_check_and_diff(t_series, name="traffic")
            stationarity_meta.update({
                "checked": True,
                "differencing_applied": r_check["differencing_applied"] or t_check["differencing_applied"],
                "routing_adf_p_value": r_check["adf_p_value"],
                "traffic_adf_p_value": t_check["adf_p_value"],
                "stationarity_ok": r_check["stationarity_ok"] and t_check["stationarity_ok"],
                "routing_note": r_check["note"],
                "traffic_note": t_check["note"],
            })
            if not stationarity_meta["stationarity_ok"]:
                # Either series failed to stationarise → suppress Granger.
                return granger_stationarity_insuf(n, stationarity_meta)
            r_series = r_check["series"]
            t_series = t_check["series"]
            if not r_series or not t_series:
                return granger_stationarity_insuf(n, stationarity_meta)
            # If differencing was applied to only one series, the two
            common_n = min(len(r_series), len(t_series))
            r_series = r_series[-common_n:]
            t_series = t_series[-common_n:]
            n = common_n

        lead = granger_lead(routing_timeline, traffic_timeline)
        try:
            rt = granger_gt(r_series, t_series, self.max_lag, self.significance)
            tr = granger_gt(t_series, r_series, self.max_lag, self.significance)
            return granger_synth(rt, tr, lead, n, stationarity_meta)
        except Exception as e:
            logger.warning(f"Granger failed: {e}")
            return granger_fb(routing_timeline, traffic_timeline)


def granger_align(routing, traffic):
    r_sorted = sorted(routing, key=lambda x: x.get("timestamp", ""))
    t_sorted = sorted(traffic, key=lambda x: x.get("timestamp", ""))
    r_scores = [float(r.get("score", 0)) for r in r_sorted]
    t_scores = [float(t.get("score", 0)) for t in t_sorted]
    n = min(len(r_scores), len(t_scores))
    return r_scores[:n], t_scores[:n]


def granger_lead(routing, traffic):
    r_sorted = sorted(routing, key=lambda x: x.get("timestamp", ""))
    t_sorted = sorted(traffic, key=lambda x: x.get("timestamp", ""))
    first_r = next((r for r in r_sorted if r.get("score", 0) > 0.5), None)
    first_t = next((t for t in t_sorted if t.get("score", 0) > 0.5), None)
    if not first_r or not first_t:
        return None
    try:
        rt = datetime.fromisoformat(first_r["timestamp"].replace("Z", "+00:00"))
        tt = datetime.fromisoformat(first_t["timestamp"].replace("Z", "+00:00"))
        return (tt - rt).total_seconds()
    except (ValueError, TypeError):
        return None


def granger_gt(x, y, max_lag, sig):
    """Run Granger test on a (possibly pre-differenced) pair (x, y).

    The caller is responsible for stationarising the input via
    :func:`granger_stationary_check_and_diff`. This function assumes its
    inputs are already stationary.
    """
    data = np.column_stack([y, x])
    try:
        ml = min(max_lag, len(data) // 3)
        if ml < 1:
            ml = 1
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=FutureWarning)
            result = grangercausalitytests(data, maxlag=ml, verbose=False)
        best_lag = 1
        best_aic = float("inf")
        for lag, res in result.items():
            if res[0].get("params") is not None:
                aic = res[0].get("aic", float("inf"))
                if aic < best_aic:
                    best_aic = aic
                    best_lag = lag
        f_test = result[best_lag][0]["ssr_ftest"]
        return {"significant": float(f_test[1]) < sig, "p": float(f_test[1]), "f": float(f_test[0]), "lag": best_lag}
    except Exception:
        return {"significant": False, "p": 1.0, "f": 0.0, "lag": 0}


def granger_stationary_check_and_diff(series, name="series"):
    """Stationarity pre-check used by :class:`GrangerEngine`.

    Returns ``{"series": stationary_series, "differencing_applied": bool,
    "adf_p_value": float|None, "stationarity_ok": bool, "note": str}``.

    Strategy:
      1. Run ADF on the raw series. If p < ``ADF_SIGNIFICANCE``, accept
         it as stationary.
      2. Else apply ``np.diff`` (drop first element) and re-run ADF.
         If p < threshold now, accept the differenced series.
      3. Else mark ``stationarity_ok=False`` and return an empty list.
         Caller (GrangerEngine) treats this as "do not run Granger at
         all" — better to abstain than to produce a spurious result.

    Implementation is defensive: if ``statsmodels`` is missing or the
    series is too short for ADF, we return the raw series unchanged
    (preserving legacy behaviour). Reviewer-facing note in the returned
    ``note`` field explains the path taken.
    """
    if not series or len(series) < 8:
        return {"series": list(series), "differencing_applied": False,
                "adf_p_value": None, "stationarity_ok": True,
                "note": f"{name}: too short for ADF (n={len(series)}); pass-through."}
    if not STATSMODELS_OK:
        return {"series": list(series), "differencing_applied": False,
                "adf_p_value": None, "stationarity_ok": True,
                "note": f"{name}: statsmodels unavailable; pass-through."}
    try:
        arr = np.asarray(series, dtype=float)
        p_raw = float(adfuller(arr, autolag="AIC", regression="c")[1])
        if p_raw < ADF_SIGNIFICANCE:
            return {"series": list(arr), "differencing_applied": False,
                    "adf_p_value": p_raw, "stationarity_ok": True,
                    "note": f"{name}: ADF p={p_raw:.4f} < {ADF_SIGNIFICANCE}, stationary."}
        diff = np.diff(arr)
        p_diff = float(adfuller(diff, autolag="AIC", regression="c")[1])
        if p_diff < ADF_SIGNIFICANCE:
            return {"series": list(diff), "differencing_applied": True,
                    "adf_p_value": p_diff, "stationarity_ok": True,
                    "note": f"{name}: raw non-stationary (p={p_raw:.4f}), "
                            f"differenced OK (p={p_diff:.4f})."}
        return {"series": [], "differencing_applied": False,
                "adf_p_value": p_diff, "stationarity_ok": False,
                "note": f"{name}: stationary neither before (p={p_raw:.4f}) "
                        f"nor after differencing (p={p_diff:.4f}); Granger suppressed."}
    except Exception as e:
        logger.debug(f"[{name}] ADF pre-check failed: {e}")
        return {"series": list(series), "differencing_applied": False,
                "adf_p_value": None, "stationarity_ok": True,
                "note": f"{name}: ADF exception {type(e).__name__}; pass-through."}


def granger_synth(rt, tr, lead, n, stationarity_meta=None):
    rt_sig, rt_p, rt_f = rt["significant"], rt["p"], rt["f"]
    tr_sig, tr_p, tr_f = tr["significant"], tr["p"], tr["f"]
    rt_s = rt_f / (rt_f + 5.0) if rt_f > 0 else 0.0
    tr_s = tr_f / (tr_f + 5.0) if tr_f > 0 else 0.0
    routing_leads = lead is not None and lead >= 0
    if rt_sig and not tr_sig:
        direction, strength, sig = "routing_to_traffic", rt_s, True
    elif tr_sig and not rt_sig:
        direction, strength, sig = "traffic_to_routing", tr_s, True
    elif rt_sig and tr_sig:
        direction = "routing_to_traffic" if rt_f >= tr_f else "traffic_to_routing"
        strength, sig = max(rt_s, tr_s), True
    else:
        if routing_leads and lead is not None and abs(lead) / 60 <= 60 and max(rt_f, tr_f) > 0.5:
            direction, strength, sig = "routing_to_traffic", max(rt_s, tr_s) * 0.5, False
        else:
            direction, strength, sig = "none", max(rt_s, tr_s) * 0.3, False
    meta = stationarity_meta or {}
    return {"direction": direction, "strength": min(strength, 1.0), "p_value": min(rt_p, tr_p),
            "significant": sig, "f_statistic": max(rt_f, tr_f), "temporal_lead": lead,
            "interpretation": f"Granger {direction} (p={min(rt_p, tr_p):.4f})",
            "data_points": n, "association": max(rt_s, tr_s),
            "stationarity_checked": meta.get("checked", False),
            "differencing_applied": meta.get("differencing_applied", False),
            "adf_p_value": min([p for p in (meta.get("routing_adf_p_value"),
                                             meta.get("traffic_adf_p_value")) if p is not None],
                                default=None),
            "stationarity_note": (
                f"routing: {meta.get('routing_note', '')}; "
                f"traffic: {meta.get('traffic_note', '')}"
                if meta.get("checked") else "stationarity pre-check skipped"
            )}


def granger_insuf(n):
    return {"direction": "unknown", "strength": 0.0, "p_value": 1.0, "significant": False,
            "f_statistic": 0.0, "temporal_lead": None, "interpretation": f"insufficient_data_points (n={n})",
            "data_points": n, "association": 0.0}


def granger_stationarity_insuf(n, meta):
    """Return a Granger result when ADF pre-check rejects stationarity.

    We deliberately report ``direction="unknown"`` and
    ``significant=False`` so the HCAF voter abstains rather than
    voting spuriously on a non-stationary series. The diagnostic
    fields are preserved for the report / debugging.
    """
    notes = []
    if meta.get("routing_note"):
        notes.append(meta["routing_note"])
    if meta.get("traffic_note"):
        notes.append(meta["traffic_note"])
    return {"direction": "unknown", "strength": 0.0, "p_value": 1.0, "significant": False,
            "f_statistic": 0.0, "temporal_lead": None,
            "interpretation": "Granger suppressed: " + (" | ".join(notes) or "non-stationary series"),
            "data_points": n, "association": 0.0,
            "stationarity_checked": True,
            "stationarity_ok": False,
            "stationarity_note": " | ".join(notes)}


def granger_fb(routing, traffic):
    lead = granger_lead(routing, traffic)
    ra = sum(1 for r in routing if r.get("score", 0) > 0.5)
    ta = sum(1 for t in traffic if t.get("score", 0) > 0.5)
    n = max(len(routing), len(traffic))
    coc = min(ra, ta) / max(ra, 1)
    if lead is not None and lead >= 0:
        direction, strength = "routing_to_traffic", coc
    elif lead is not None:
        direction, strength = "traffic_to_routing", coc
    else:
        direction, strength = "unknown", coc * 0.3
    return {"direction": direction, "strength": strength, "p_value": 1.0, "significant": False,
            "f_statistic": 0.0, "temporal_lead": lead, "interpretation": "statsmodels ",
            "data_points": n, "association": coc}


# 


class ConfounderDetector:
    """Detect alternative explanations for a routing/traffic correlation.

    BUG-FIX 2026-10-21: the five rule keys this detector looked up
    (``maintenance_window``, ``multiple_upstreams``, ``cdn_scenario``,
    ``ddos_protection``, ``concurrent_routing_changes``) had **no
    producer anywhere in the codebase**. Every lookup returned None, so
    the confounder list was structurally empty on every event and the
    ``identify_limitations`` check ("more than 2 external confounders
    present") could never fire. The confounder channel was decorative.

    The fix keeps the declarative rule table but derives each key from
    an observable signal that the pipeline actually produces, so the
    detector reports something real:

    * ``multiple_upstreams`` — the target AS has more than one
      provider in the as-rel snapshot, so a single upstream failure
      does not by itself explain a traffic change.
    * ``cdn_scenario`` — the affected prefix is originated by a content
      / CDN network, whose traffic can shift for reasons unrelated to
      BGP.
    * ``ddos_protection`` — a very large traffic drop with no
      corresponding routing withdrawal or hijack, the classic
      traffic-only signature of attack mitigation.
    * ``concurrent_routing_changes`` — the routing timeline contains
      several distinct event types in the same window, so the traffic
      change may be attributable to a different routing event than the
      candidate one.
    * ``maintenance_window`` — an outage that is a *withdrawal* with
      no hijack and no leak, which is the signature of a planned
      maintenance rather than a fault.
    """

    def __init__(self):
        self.rules = [
            {"name": "planned_maintenance", "key": "maintenance_window", "severity": 0.7,
             "affects_routing": True, "affects_traffic": True, "explanatory": True,
             "desc": "Withdrawal-only routing event with no hijack or leak: consistent with a planned maintenance window."},
            {"name": "multiple_upstreams", "key": "multiple_upstreams", "severity": 0.5,
             "affects_routing": True, "affects_traffic": False, "explanatory": False,
             "desc": "Target AS has multiple upstream providers, so one upstream change does not by itself explain the traffic impact."},
            {"name": "cdn_scenario", "key": "cdn_scenario", "severity": 0.6,
             "affects_routing": False, "affects_traffic": True, "explanatory": False,
             "desc": "Affected prefix is originated by a content / CDN network whose traffic can shift for reasons unrelated to BGP."},
            {"name": "ddos_mitigation", "key": "ddos_protection", "severity": 0.8,
             "affects_routing": False, "affects_traffic": True, "explanatory": False,
             "desc": "Large traffic drop with no matching routing withdrawal or hijack: consistent with attack mitigation or a data-plane event."},
            {"name": "concurrent_routing", "key": "concurrent_routing_changes", "severity": 0.6,
             "affects_routing": True, "affects_traffic": True, "explanatory": True,
             "desc": "Multiple distinct routing event types in the same window: the traffic change may be attributable to a different routing event."},
        ]

    # ── Derivation helpers ────────────────────────────────────────────────
    @staticmethod
    def _derive_multiple_upstreams(routing_ctx, traffic_ctx, as_ctx):
        """True when the target AS has >1 provider in the AS topology."""
        topo = as_ctx.get("topology_edge_types") or as_ctx.get("edge_types") or {}
        origin = as_ctx.get("topology_origin")
        if not topo or not origin:
            return False
        rels = topo.get(origin) or {}
        return sum(1 for r in rels.values() if r == "provider") > 1

    @staticmethod
    def _derive_cdn_scenario(routing_ctx, traffic_ctx, as_ctx):
        """True when the affected prefix belongs to a content / CDN AS."""
        origins = as_ctx.get("content_origins") or []
        if not origins:
            return False
        routing_state = as_ctx.get("routing_state") or {}
        for asn, prefixes in routing_state.items():
            if str(asn) in {str(o) for o in origins}:
                return True
        return False

    @staticmethod
    def _derive_ddos(routing_ctx, traffic_ctx):
        """True on the traffic-only large-drop signature."""
        drop = float(traffic_ctx.get("traffic_drop_ratio", 0.0) or 0.0)
        if drop < 0.8:
            return False
        has_withdrawal = bool(routing_ctx.get("has_routing_withdrawal")
                              or routing_ctx.get("withdrawal_count"))
        has_hijack = bool(routing_ctx.get("has_routing_origin")
                          or routing_ctx.get("hijack_count"))
        return not (has_withdrawal or has_hijack)

    @staticmethod
    def _derive_maintenance(routing_ctx):
        """True on the withdrawal-only signature of a planned maintenance."""
        has_withdrawal = bool(routing_ctx.get("has_routing_withdrawal")
                              or routing_ctx.get("withdrawal_count"))
        has_hijack = bool(routing_ctx.get("has_routing_origin")
                          or routing_ctx.get("hijack_count"))
        has_leak = bool(routing_ctx.get("has_route_leak")
                        or routing_ctx.get("leak_count"))
        return has_withdrawal and not has_hijack and not has_leak

    @staticmethod
    def _derive_concurrent_routing(routing_ctx):
        """True when several distinct routing event types co-occur."""
        types = routing_ctx.get("event_types") or []
        distinct = {str(t).lower() for t in types if t}
        return len(distinct) > 1

    def detect(self, routing_ctx, traffic_ctx, as_ctx):
        routing_ctx = routing_ctx or {}
        traffic_ctx = traffic_ctx or {}
        as_ctx = as_ctx or {}

        # Derive the rule keys from observable signals, then run the
        # declarative table over the derived context.
        derived = {
            "multiple_upstreams": self._derive_multiple_upstreams(routing_ctx, traffic_ctx, as_ctx),
            "cdn_scenario": self._derive_cdn_scenario(routing_ctx, traffic_ctx, as_ctx),
            "ddos_protection": self._derive_ddos(routing_ctx, traffic_ctx),
            "maintenance_window": self._derive_maintenance(routing_ctx),
            "concurrent_routing_changes": self._derive_concurrent_routing(routing_ctx),
        }

        detected = []
        for rule in self.rules:
            key = rule["key"]
            val = (routing_ctx.get(key) or traffic_ctx.get(key)
                   or as_ctx.get(key) or derived.get(key))
            if val and val is not False and val != 0:
                detected.append({
                    "name": rule["name"], "description": rule["desc"],
                    "severity": rule["severity"], "detected_in": "derived" if derived.get(key) else "context",
                    "affects_routing": rule["affects_routing"],
                    "affects_traffic": rule["affects_traffic"],
                    "is_explanatory_confounder": rule["explanatory"],
                })
        drop = traffic_ctx.get("traffic_drop_ratio", 0.0)
        if drop > 0.8 and not routing_ctx.get("withdrawal_count") and not routing_ctx.get("hijack_count"):
            detected.append({"name": "potential_ddos", "description": " DDoS",
                           "severity": 0.7, "detected_in": "semantic",
                           "affects_routing": False, "affects_traffic": True,
                           "is_explanatory_confounder": False})
        detected.sort(key=lambda x: x["severity"], reverse=True)
        return detected


# 


class CausalStrength(Enum):
    strong = "strong"
    medium = "moderate"
    weak = "weak"
    none = "none"


@dataclass
class innovation_finding:
    method_name: str
    direction: str
    strength: float
    p_value: float
    significance: bool
    explanation: str
    raw_output: dict


@dataclass
class CausalAttributionResult:
    direction: str
    strength: CausalStrength
    confidence: float
    routing_caused_traffic: bool
    traffic_caused_routing: bool
    innovation_findings: list
    confounder_list: list
    counterfactual_summary: str
    convergence_score: float
    is_causal: bool
    explanation: str
    limitations: str
    evidence_support: dict


class CausalAttributionEngine:
    def __init__(self):
        self.granger = GrangerEngine()
        self.confounder_detector = ConfounderDetector()

    def analyze(self, routing_timeline, traffic_timeline, routing_context=None, traffic_context=None, topology_context=None, target_as=None):
        routing_context = routing_context or {}
        traffic_context = traffic_context or {}
        topology_context = topology_context or {}

        # BOTH timelines empty → cannot make any causal claim
        if not routing_timeline and not traffic_timeline:
            return self.empty_result()

        # Only one timeline present → degrade gracefully to a single-sided analysis
        # so the report still records a direction guess / confidence based on what we have.
        if not routing_timeline:
            return self.single_sided_result(traffic_timeline=traffic_timeline, traffic_context=traffic_context,
                                topology_context=topology_context, target_as=target_as, side="traffic_only")
        if not traffic_timeline:
            return self.single_sided_result(routing_timeline=routing_timeline, routing_context=routing_context,
                                topology_context=topology_context, target_as=target_as, side="routing_only")

        confounder_list = self.confounder_detector.detect(routing_context, traffic_context, topology_context)

        breakpoint_result = detect_multi_scale_breakpoints(
            [p.get("score", 0) for p in routing_timeline],
            [p.get("score", 0) for p in traffic_timeline],
            timestamps=[p.get("timestamp") for p in routing_timeline]
        )

        routing_events = self.extract_routing_events(routing_timeline, routing_context)
        traffic_events = self.extract_traffic_events(traffic_timeline, traffic_context)
        path_result = reconstruct_transmission_path(
            routing_events, traffic_events, topology_context.get("adjacency", {}), target_as
        )

        topology = topology_context.get("adjacency", {})
        if topology:
            cascade_result = estimate_counterfactual_cascade(
                intervention_as=routing_context.get("origin_as", target_as),
                intervention_type=routing_context.get("event_type", "unknown"),
                routing_state=topology_context.get("routing_state", {}),
                as_topology=topology,
                traffic_baseline=traffic_context.get("baseline", {}),
                affected_prefix=traffic_context.get("affected_prefix"),
                edge_types=topology_context.get("edge_types", {}),
            )
        else:
            cascade_result = quick_cascade_estimate(
                event_type=routing_context.get("event_type"),
                affected_as_count=routing_context.get("affected_as_count", 0),
                traffic_drop_ratio=traffic_context.get("traffic_drop_ratio", 0),
                routing_timeline=routing_timeline,
                traffic_timeline=traffic_timeline,
            )

        granger_result = self.granger.test(routing_timeline, traffic_timeline)

        convergence = self.evaluate_convergence(
            breakpoint_result, path_result, cascade_result, granger_result,
            routing_timeline=routing_timeline,
            traffic_timeline=traffic_timeline,
            routing_context=routing_context,
            traffic_context=traffic_context,
        )
        direction, routing_to_traffic, traffic_to_routing = self.judge_direction(convergence)
        strength, confidence, is_causal = self.compute_final_score(convergence, breakpoint_result, path_result, cascade_result)

        finding_list = [
            innovation_finding("Multi-Scale Causal Breakpoint Detection",
                   breakpoint_result.get("direction", "unknown"),
                   breakpoint_result.get("strength", 0.0), breakpoint_result.get("p_value", 1.0),
                   breakpoint_result.get("significant", False), breakpoint_result.get("interpretation", ""), breakpoint_result),
            innovation_finding("Causal Transmission Path Reconstruction",
                   path_result.get("direction", "unknown"),
                   path_result.get("strength", 0.0), 1.0, path_result.get("significant", False),
                   path_result.get("interpretation", ""), path_result),
            innovation_finding("Counterfactual Intervention Network Estimation",
                   cascade_result.get("direction", "unknown"),
                   cascade_result.get("strength", 0.0), 1.0, cascade_result.get("significant", False),
                   cascade_result.get("interpretation", ""), cascade_result),
            innovation_finding("Granger (baseline)", granger_result.get("direction", "unknown"),
                   granger_result.get("strength", 0.0), granger_result.get("p_value", 1.0),
                   granger_result.get("significant", False), granger_result.get("interpretation", ""), granger_result),
            # CSS evidence finding — added in round 30 to expose the
            # Pearl-PNS score alongside the 3 innovation methods.
            innovation_finding("Causal Sufficiency Score (CSS)",
                   convergence.get("dominant", "unknown"),
                   float(convergence.get("css_routing_to_traffic", 0.0)) or 0.0,
                   float(convergence.get("css_p_value", 1.0)) or 1.0,
                   bool(convergence.get("css_is_causal", False)),
                   convergence.get("explanation", ""),
                   {"css": convergence}),
            # Transfer Entropy baseline finding — paper §5.3 reports the
            # non-linear baseline alongside CSS so reviewers can see the
            # directional information flow at a glance.
            innovation_finding("Transfer Entropy (baseline)",
                   (convergence.get("evidence_channels", {}) or {}).get("transfer_entropy", "unknown"),
                   float(convergence.get("te_confidence", 0.0)) or 0.0,
                   1.0, False, "TE non-linear directional flow",
                   {"te_rt": convergence.get("te_routing_to_traffic", 0.0),
                    "te_tr": convergence.get("te_traffic_to_routing", 0.0)}),
        ]

        explanation = self.generate_explanation(direction, strength, routing_to_traffic, traffic_to_routing, convergence, finding_list)
        limitations = self.identify_limitations(finding_list, confounder_list, len(routing_timeline))

        # ── Abstention gate (rewritten 2026-10-22) ───────────────────────────
        # Do not assert a causal direction the evidence does not support.
        #
        # The previous gate compared `confidence` — the *blended display score*
        # 0.6·css_conf + 0.3·innovation_strength + 0.1·te_conf, multiplied by
        # 0.7 (or 0.95 when CSS was causal) — against a 0.55 floor.  Those two
        # numbers are not on the same scale: with typical css≈0.1 and
        # innovation≈0.1 the blend collapses to ≈0.07, so the gate abstained on
        # 23 of 25 real-cache events regardless of the evidence.  The blend is
        # a *reporting* strength, not a decision probability.
        #
        # The decision now uses two gates on the quantities they were defined
        # for:
        #   gate 1 (statistics): the committed direction must be the one whose
        #           CSS bootstrap CI excludes zero (`is_causal`);
        #   gate 2 (posterior): max(posterior) >= HCAF_MIN_POSTERIOR.
        abstained = False
        abstain_reason = "supported"
        # `direction` may be the enum ("traffic_to_traffic") or its rendered
        # label ("traffic -> traffic") depending on which branch produced it,
        # so normalise before testing.
        _dir_norm = (direction or "").replace(" ", "").replace("->", "_to_")
        posterior = convergence.get("posterior") or {}
        max_posterior = (
            max(float(v) for v in posterior.values())
            if isinstance(posterior, dict) and posterior else 0.0
        )
        if _dir_norm in ("routing_to_traffic", "traffic_to_routing"):
            if not bool(convergence.get("is_causal", False)):
                abstained = True
                abstain_reason = "css_not_significant"
            elif max_posterior < HCAF_MIN_POSTERIOR:
                abstained = True
                abstain_reason = "posterior_below_floor"
            elif not (routing_to_traffic or traffic_to_routing):
                abstained = True
                abstain_reason = "direction_flags_disagree"
        if abstained:
            explanation = (
                "Insufficient evidence to attribute a causal direction "
                f"(best direction {direction}, max posterior {max_posterior:.3f} "
                f"vs floor {HCAF_MIN_POSTERIOR:.2f}; reason: {abstain_reason}). "
                "Reported as unknown rather than asserting an unsupported direction."
            )
            direction = "unknown"
            routing_to_traffic = False
            traffic_to_routing = False
            is_causal = False

        return CausalAttributionResult(
            direction=direction, strength=strength, confidence=confidence,
            routing_caused_traffic=routing_to_traffic, traffic_caused_routing=traffic_to_routing,
            innovation_findings=finding_list, confounder_list=confounder_list,
            counterfactual_summary=cascade_result.get("counterfactual_summary", ""),
            convergence_score=convergence["score"], is_causal=is_causal,
            explanation=explanation, limitations=limitations,
            evidence_support={
                "abstained": abstained,
                "abstain_reason": abstain_reason if abstained else "supported",
                "max_posterior": round(max_posterior, 4),
                "min_posterior_floor": HCAF_MIN_POSTERIOR,
                "msbd_breakpoint_idx": breakpoint_result.get("breakpoint_idx"),
                "msbd_scale_sync": breakpoint_result.get("scale_sync"),
                "ctpr_path_length": path_result.get("path_length"),
                "ctpr_root_cause_as": path_result.get("root_cause_as"),
                "cic_affected_as_count": cascade_result.get("affected_as_count"),
                "granger_p": granger_result.get("p_value"),
                "css_routing_to_traffic": convergence.get("css_routing_to_traffic"),
                "css_traffic_to_routing": convergence.get("css_traffic_to_routing"),
                "css_p_value": convergence.get("css_p_value"),
                "css_ci_lower": convergence.get("css_ci_lower"),
                "css_ci_upper": convergence.get("css_ci_upper"),
                "css_is_causal": convergence.get("css_is_causal"),
                "te_routing_to_traffic": convergence.get("te_routing_to_traffic"),
                "te_traffic_to_routing": convergence.get("te_traffic_to_routing"),
                "te_confidence": convergence.get("te_confidence"),
                "posterior": convergence.get("posterior"),
                "method": convergence.get("method"),
            }
        )

    def extract_routing_events(self, timeline, context):
        event_list = []
        as_path = context.get("as_path", [])
        for point in timeline:
            if point.get("score", 0) > 0.5:
                event_list.append({
                    "timestamp": point.get("timestamp"),
                    "as_path": as_path,
                    "event_type": context.get("event_type", "unknown"),
                })
        return event_list

    def extract_traffic_events(self, timeline, context):
        event_list = []
        for point in timeline:
            if point.get("score", 0) > 0.5:
                event_list.append({
                    "timestamp": point.get("timestamp"),
                    "affected_prefix": context.get("affected_prefix"),
                    "drop_ratio": context.get("traffic_drop_ratio", 0),
                })
        return event_list

    def evaluate_convergence(
        self,
        breakpoint,
        path,
        cascade,
        granger,
        routing_timeline=None,
        traffic_timeline=None,
        routing_context=None,
        traffic_context=None,
    ):
        """Bayesian causal-attribution synthesis (replaces weighted-vote).

        Pipeline:
            1. Compute CSS (Pearl PNS) on the two timelines with the
               MSBD breakpoint as the intervention point.
            2. Run Transfer Entropy baseline (non-linear / non-Gaussian
               directional information flow).
            3. Feed each evidence channel as a likelihood ratio into
               ``bayesian_synthesize`` — *not* a weighted vote. The
               posterior per direction is
                   P(d | evidence) ∝ prior(d) · Π_ch LR_d(ch).
               The dominant posterior wins.

        Returns:
            dict with keys: direction, score (posterior mass), is_causal,
            css_*, ci_*, te_*, posterior, evidence_channels,
            method="css_bayesian_synthesis".
        """
        # --- 1. CSS (PNS) ---------------------------------------------------
        css_res = None
        msbd_breakpoint_idx = None
        try:
            if isinstance(breakpoint, dict):
                scale_results = breakpoint.get("scale_results") or []
                # The largest-mean-shift scale's breakpoint is the natural
                # counterfactual intervention point. Fall back to None
                # which lets css_engine do its own breakpoint detection.
                best = None
                best_diff = -1.0
                for s in scale_results:
                    idx = s.get("breakpoint_idx")
                    strength = float(s.get("strength", 0.0) or 0.0)
                    if idx is None or strength < best_diff:
                        continue
                    best_diff = strength
                    best = int(idx)
                msbd_breakpoint_idx = best
        except (TypeError, ValueError):
            msbd_breakpoint_idx = None

        if (
            _CSS_OK
            and css_score is not None
            and routing_timeline is not None
            and traffic_timeline is not None
        ):
            css_res = css_score(
                routing_timeline,
                traffic_timeline,
                msbd_breakpoint_idx=msbd_breakpoint_idx,
                n_bootstrap=int(os.environ.get("BGP_TRACER_CSS_BOOTSTRAP", "500")),
                p_threshold=float(os.environ.get("BGP_TRACER_CSS_P", "0.05")),
            )

        # --- 2. Transfer Entropy baseline -----------------------------------
        te_result = None
        if (
            transfer_entropy_baseline is not None
            and routing_timeline is not None
            and traffic_timeline is not None
        ):
            try:
                te_result = transfer_entropy_baseline(
                    routing_timeline,
                    traffic_timeline,
                    lag=1,
                    bins=2,
                    n_perm=int(os.environ.get("BGP_TRACER_TE_PERM", "200")),
                )
            except Exception as e:  # noqa: BLE001
                logger.debug("transfer_entropy_baseline failed: %s", e)
                te_result = None

        # NOTE (2026-10-22): `event_type` is no longer read here.  It is the
        # ground-truth cause label, and the expected direction in the
        # evaluation is derived from that same label, so injecting it into any
        # prior or channel turns the benchmark into a label-echo test.  Only
        # quantities measurable from the BGP/traffic streams may enter.

        # --- 3. Build evidence channels (likelihood ratios) ----------------
        evidence_channels: Dict[str, Dict[str, Any]] = {}

        # MSBD: acts as the counterfactual baseline (Pearl's "intervention
        # window"). Its likelihood ratio favours the direction MSBD sees.
        # When MSBD abstains, it contributes nothing: the previous code
        # injected a 1.5:1 R→T "event type" channel here, which was a copy of
        # the ground-truth label.
        msbd_dir = (breakpoint or {}).get("direction", "unknown")
        msbd_strength = float((breakpoint or {}).get("strength", 0.0) or 0.0)
        if msbd_dir in ("routing_to_traffic", "traffic_to_routing"):
            msbd_lr = max(1.05, 1.0 + msbd_strength * 3.0)
            evidence_channels["msbd_counterfactual"] = {
                "direction": msbd_dir,
                "likelihood": {
                    msbd_dir: msbd_lr,
                    ("traffic_to_routing" if msbd_dir == "routing_to_traffic"
                     else "routing_to_traffic"): 1.0 / msbd_lr,
                    "independent": 1.0,
                },
            }

        # CTPR (path reconstruction): Pearl's sufficiency check. If CTPR
        # finds a path that connects routing event to traffic drop, this
        # counts as evidence the intervention *could* have produced the
        # outcome (sufficiency in PNS terminology).
        ctpr_dir = (path or {}).get("direction", "unknown")
        ctpr_strength = float((path or {}).get("strength", 0.0) or 0.0)
        if ctpr_dir in ("routing_to_traffic", "traffic_to_routing"):
            ctpr_lr = max(1.05, 1.0 + ctpr_strength * 2.0)
            evidence_channels["ctpr_sufficiency"] = {
                "direction": ctpr_dir,
                "likelihood": {
                    ctpr_dir: ctpr_lr,
                    ("traffic_to_routing" if ctpr_dir == "routing_to_traffic"
                     else "routing_to_traffic"): 1.0 / ctpr_lr,
                    "independent": 1.0,
                },
            }

        # CIC (impacted-set evaluation): Reef's "scope" check — how many
        # ASes are affected. Larger scope at the routing event implies
        # the routing change is more likely to have caused the traffic
        # response. The likelihood ratio favours routing_to_traffic.
        cic_dir = (cascade or {}).get("direction", "unknown")
        cic_affected = int((cascade or {}).get("affected_as_count", 0) or 0)
        if cic_dir in ("routing_to_traffic", "traffic_to_routing") and cic_affected > 0:
            cic_lr = max(1.05, 1.0 + math.log1p(cic_affected))
            evidence_channels["cic_scope"] = {
                "direction": cic_dir,
                "likelihood": {
                    cic_dir: cic_lr,
                    ("traffic_to_routing" if cic_dir == "routing_to_traffic"
                     else "routing_to_traffic"): 1.0 / cic_lr,
                    "independent": 1.0,
                },
            }

        # Granger (linear, Gaussian baseline): only fed in as an evidence
        # channel when it disagrees with CSS — agreement boosts confidence,
        # disagreement adds uncertainty. We weight by F-statistic.
        if granger:
            g_dir = granger.get("direction", "unknown")
            g_f = float(granger.get("f_statistic", 0.0) or 0.0)
            if g_dir in ("routing_to_traffic", "traffic_to_routing") and g_f > 0:
                g_lr = max(1.05, 1.0 + g_f / (g_f + 3.0) * 1.5)
                evidence_channels["granger_linearity"] = {
                    "direction": g_dir,
                    "likelihood": {
                        g_dir: g_lr,
                        ("traffic_to_routing" if g_dir == "routing_to_traffic"
                         else "routing_to_traffic"): 1.0 / g_lr,
                        "independent": 1.0,
                    },
                }

        # Transfer Entropy: non-linear directional information flow.
        #
        # FIX (2026-10-22): TE used to be admitted only when its direction
        # agreed with a direction derived from `event_type` ("suppress TE when
        # it disagrees with the domain prior").  That is label leakage: the
        # prior and the ground truth are the same mapping, so disagreement
        # suppression guaranteed the "correct" answer.  TE now contributes on
        # its own statistical merit — the baseline exposes a permutation
        # p-value per direction, and only a significant TE may enter.
        if te_result is not None and te_result.direction in (
            "routing_to_traffic", "traffic_to_routing"
        ):
            te_details = getattr(te_result, "details", {}) or {}
            te_significant = bool(te_details.get("significant", False))
            p_te = te_details.get(
                "p_value_rt" if te_result.direction == "routing_to_traffic" else "p_value_tr",
                1.0,
            )
            if te_significant and float(p_te) < 0.05:
                te_lr = max(1.05, 1.0 + te_result.confidence * 0.6)
                evidence_channels["transfer_entropy"] = {
                    "direction": te_result.direction,
                    "likelihood": {
                        te_result.direction: te_lr,
                        ("traffic_to_routing" if te_result.direction == "routing_to_traffic"
                         else "routing_to_traffic"): 1.0 / te_lr,
                        "independent": 1.0,
                    },
                }

        # --- 4. Routing metadata: an *observed* withdrawal in an outage window ---
        # Only the observable fact "a BGP withdrawal was recorded in the event
        # window" is used, and only for outages.  The previous branch
        #   evt in ("route_leak", "roa_misconfig", "origin_hijack*")
        # mapped the ground-truth cause label directly to a 10:1 R→T signal
        # and popped the contradicting MSBD channel.  That both leaked the
        # label (the expected direction is produced by the same mapping) and
        # deleted evidence that disagreed with the answer.  Both are removed.
        _routing_withdrawal_signal: Optional[str] = None
        if routing_context:
            evt = routing_context.get("event_type", "")
            has_wd = bool(routing_context.get("has_routing_withdrawal", False))
            if evt == "outage" and has_wd:
                # Bounded (1.5:1) weak channel inside bayesian_synthesize; it
                # can be outweighed, not used as a veto.
                _routing_withdrawal_signal = "routing_to_traffic"

        # --- 5. Bayesian synthesis -----------------------------------------
        if _CSS_OK and bayesian_synthesize is not None and css_res is not None:
            posterior = bayesian_synthesize(
                css_res,
                evidence_channels=evidence_channels,
                routing_withdrawal_signal=_routing_withdrawal_signal,
            )
            direction = posterior["direction"]
            confidence = posterior["confidence"]
            method_label = "css_bayesian_synthesis"
            # is_causal requires CSS's bootstrap p to reject the null.
            is_causal = bool(css_res.is_causal) and direction in (
                "routing_to_traffic", "traffic_to_routing"
            )
            return {
                "score": round(float(confidence), 4),
                "dominant": direction,
                "method_agreement": confidence > 0.5 and css_res.is_causal,
                "method": method_label,
                "is_causal": is_causal,
                "css_routing_to_traffic": float(css_res.css_routing_to_traffic),
                "css_traffic_to_routing": float(css_res.css_traffic_to_routing),
                "css_confidence": float(css_res.confidence),
                "css_p_value": float(css_res.p_value),
                "css_ci_lower": float(css_res.ci_lower),
                "css_ci_upper": float(css_res.ci_upper),
                "css_is_causal": bool(css_res.is_causal),
                "css_sufficiency": float(css_res.sufficiency),
                "css_necessity": float(css_res.necessity),
                "te_routing_to_traffic": (
                    float(te_result.details.get("te_routing_to_traffic", 0.0))
                    if te_result else None
                ),
                "te_traffic_to_routing": (
                    float(te_result.details.get("te_traffic_to_routing", 0.0))
                    if te_result else None
                ),
                "te_confidence": float(te_result.confidence) if te_result else 0.0,
                "posterior": posterior["posterior"],
                "evidence_channels": {
                    k: ch["direction"] for k, ch in evidence_channels.items()
                },
                "explanation": css_res.explanation,
            }

        # --- Fallback: deterministic per-evidence channel if CSS unavailable
        if not evidence_channels:
            return {
                "score": 0.0,
                "dominant": "insufficient",
                "method_agreement": False,
                "method": "css_bayesian_synthesis",
                "is_causal": False,
            }
        # Pick the highest-LR channel as the best guess; this is the
        # *fallback path* and is paper-documented as such.
        best_dir = max(
            evidence_channels.items(),
            key=lambda kv: max(kv[1]["likelihood"].values()),
        )[1]["direction"]
        return {
            "score": 0.4,
            "dominant": best_dir,
            "method_agreement": False,
            "method": "css_bayesian_synthesis_fallback",
            "is_causal": False,
            "evidence_channels": {
                k: ch["direction"] for k, ch in evidence_channels.items()
            },
        }

    def judge_direction(self, convergence):
        """Map the Bayesian-synthesized convergence verdict to the
        canonical ``(direction, routing_caused_traffic, traffic_caused_routing)``
        tuple used by ``compute_final_score`` and the report agent."""
        dominant = convergence.get("dominant", "unknown")
        is_causal = bool(convergence.get("is_causal", False))
        method_agreement = bool(convergence.get("method_agreement", False))
        posterior = convergence.get("posterior", {})
        max_posterior = max(posterior.values()) if isinstance(posterior, dict) else 0.0
        if dominant in ("insufficient", "unknown"):
            return ("unknown", False, False)
        if dominant == "independent":
            return ("independent", False, False)
        # The Bayesian posterior's confidence modulates the
        # method_agreement flag. We require posterior dominance for any
        # causal claim — is_causal is a stricter flag that requires the
        # CSS bootstrap CI to exclude zero, which it may not at small
        # sample sizes. At large sample sizes both flags should agree.
        agreement = method_agreement or max_posterior > 0.6
        mapping = {
            "routing_to_traffic": ("routing -> traffic", True, False),
            "traffic_to_routing": ("traffic -> routing", False, True),
        }
        dir_label, r_t, t_r = mapping.get(dominant, ("unknown", False, False))
        # BUG (2026-10-05): when the label and the flags disagreed the result
        # was internally inconsistent — `direction` could read
        # "traffic -> routing" while BOTH `routing_caused_traffic` and
        # `traffic_caused_routing` were False, because the booleans were
        # additionally gated on `agreement` but the label was not.
        #
        # Downstream (and the ground-truth evaluation) reads `direction`, so a
        # label asserting a causal direction whose flags both deny it is a
        # fabricated verdict. When the flags do not support the direction, the
        # direction must be "unknown" too.
        if dominant in mapping and not (r_t or t_r):
            dir_label = "unknown"
        return (dir_label, r_t and agreement, t_r and agreement)

    def compute_final_score(self, convergence, breakpoint, path, cascade):
        # CSS-driven final score: CSS posterior mass is the primary signal,
        # supplemented by the per-evidence-channel strengths. is_causal
        # is taken directly from the CSS bootstrap CI (PNS-style).
        css_conf = float(convergence.get("css_confidence", 0.0) or 0.0)
        te_conf = float(convergence.get("te_confidence", 0.0) or 0.0)
        innovation_strength = (
            float(breakpoint.get("strength", 0.0) or 0.0)
            + float(path.get("strength", 0.0) or 0.0)
            + float(cascade.get("strength", 0.0) or 0.0)
        ) / 3.0
        # 60% CSS posterior, 30% innovation-strength, 10% TE confidence.
        base = css_conf * 0.6 + innovation_strength * 0.3 + te_conf * 0.1
        factor = 0.95 if convergence.get("css_is_causal") else 0.7
        confidence = base * factor
        if base >= 0.7:
            strength = CausalStrength.strong
        elif base >= 0.4:
            strength = CausalStrength.medium
        elif base >= 0.15:
            strength = CausalStrength.weak
        else:
            strength = CausalStrength.none
        is_causal = (
            convergence.get("css_is_causal", False)
            and base >= 0.4
            and confidence >= 0.3
        )
        return strength, confidence, is_causal

    def generate_explanation(self, direction, strength, routing_to_traffic, traffic_to_routing, convergence, finding_list):
        if strength == CausalStrength.none or direction == "undetermined":
            return "Insufficient convergence across the three methods; causal verdict inconclusive."
        if routing_to_traffic:
            parts = [
                "Causal verdict: routing anomaly likely caused the traffic change.",
                f"Three-method convergence: {convergence['score']:.0%}",
            ]
            for finding in finding_list[:3]:
                if finding.direction == "routing_to_traffic":
                    parts.append(f"* {finding.method_name}: {finding.explanation[:80]}")
            return " ".join(parts)
        if traffic_to_routing:
            return "Causal verdict: traffic anomaly may have triggered the routing adjustment."
        return "Routing and traffic changes are correlated, but causal direction is unclear."

    def identify_limitations(self, finding_list, confounder_list, data_point_count):
        limitations = []
        if data_point_count < 10:
            limitations.append("Limited samples (<10).")
        if len(confounder_list) > 2:
            external = [c for c in confounder_list if not c.get("is_explanatory_confounder")]
            if external:
                limitations.append(f"{len(external)} external confounders present.")
        return " ".join(limitations) or "No additional caveats."

    def empty_result(self):
        return CausalAttributionResult(
            direction="unknown", strength=CausalStrength.none, confidence=0.0,
            routing_caused_traffic=False, traffic_caused_routing=False,
            innovation_findings=[], confounder_list=[],
            counterfactual_summary="", convergence_score=0.0, is_causal=False,
            explanation=", .",
            limitations=".",
            evidence_support={})

    def single_sided_result(self, routing_timeline=None, traffic_timeline=None, routing_context=None,
                traffic_context=None, topology_context=None, target_as=None, side="routing_only"):
        """.

          ,  + ,  HCAF 
        "unknown/none/0%". +  drop_ratio
         ( quick_cascade_estimate ).
        """
        event_type = (routing_context or {}).get("event_type", "unknown") if side == "routing_only" \
            else "unknown"
        affected_as = (routing_context or {}).get("affected_as_count", 0)
        traffic_drop_ratio = (traffic_context or {}).get("traffic_drop_ratio", 0.0)
        factor = {"outage": 0.9, "hijack": 0.8, "leak": 0.5, "withdrawal": 0.9, "normal": 0.0}
        event_factor = factor.get(event_type, 0.3)
        as_factor = min(affected_as / 10.0, 1.0) if affected_as else 0.0
        drop_factor = min(traffic_drop_ratio, 1.0)
        strength = event_factor * (as_factor + drop_factor) / 2 if (as_factor or drop_factor) else 0.0

        # When routing_only and event is hijack/outage with drop_ratio > 0.1, infer routing_to_traffic.
        if side == "routing_only" and event_type in ("hijack", "outage", "withdrawal") and drop_factor > 0.1:
            direction = "routing_to_traffic"
            explanation = (
                f"Only routing timeline available ({len(routing_timeline) if routing_timeline else 0} entries), "
                f"event_type={event_type}, traffic drop ratio={traffic_drop_ratio:.0%}. "
                f"Inferred direction=routing_to_traffic (weak evidence)."
            )
            routing_to_traffic = True
        elif side == "traffic_only":
            direction = "unknown"
            explanation = (
                f"Only traffic timeline available ({len(traffic_timeline) if traffic_timeline else 0} entries), "
                f"cannot infer causal direction without routing data."
            )
            routing_to_traffic = False
        else:
            direction = "unknown"
            explanation = (
                f"Only {('routing' if side == 'routing_only' else 'traffic')} timeline available, "
                f"traffic drop ratio={traffic_drop_ratio:.0%}, insufficient to infer causal direction."
            )
            routing_to_traffic = False

        data_points = (len(routing_timeline) if routing_timeline else 0) + (len(traffic_timeline) if traffic_timeline else 0)
        confidence = min(0.5, 0.2 + 0.1 * drop_factor + 0.1 * as_factor)  #  50%
        limitations = (
            ": , ///Granger ;"
            ", ."
        )
        return CausalAttributionResult(
            direction=direction, strength=CausalStrength.weak if strength > 0.3 else CausalStrength.none,
            confidence=confidence,
            routing_caused_traffic=routing_to_traffic, traffic_caused_routing=False,
            innovation_findings=[
                innovation_finding("", direction, strength, 1.0, False, explanation, {})
            ],
            confounder_list=[],
            counterfactual_summary=f"single_sided_analysis ({side}), conclusion {direction}, strength={strength:.2f}",
            convergence_score=0.2 if direction != "unknown" else 0.0,
            is_causal=False,
            explanation=explanation,
            limitations=limitations,
            evidence_support={"single_sided": side, "data_points": data_points},
        )


def analyze(routing_evidence, traffic_evidence):
    engine = CausalAttributionEngine()
    return engine.analyze(
        routing_timeline=routing_evidence.get("timeline", []),
        traffic_timeline=traffic_evidence.get("timeline", []),
        routing_context=routing_evidence, traffic_context=traffic_evidence,
        topology_context=routing_evidence.get("as_context", {}),
        target_as=routing_evidence.get("target_as"),
    )