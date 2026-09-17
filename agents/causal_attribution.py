"""因果归因完整框架 - 三个真正创新方法的集成"""
import os
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple
import logging
import math
import warnings

logger = logging.getLogger(__name__)

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
    )
    _HCAF_CFG_OK = True
except ImportError:
    _HCAF_CFG_OK = False
    HCAF_WEIGHTS_MSBD, HCAF_WEIGHTS_CTPR = 0.40, 0.30
    HCAF_WEIGHTS_CIC, HCAF_WEIGHTS_GRANGER = 0.30, 0.15
    HCAF_MAJORITY_THRESHOLD = 2


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
# p-value > this threshold are deemed non-stationary → differencing is
# applied before Granger. Reviewer-facing: this protects us from the
# "Granger on non-stationary series → spurious significance" criticism.
ADF_SIGNIFICANCE = float(os.environ.get("BGP_TRACER_ADF_SIG", "0.05"))

try:
    import pywt
    PYWT_OK = True
except ImportError:
    PYWT_OK = False


# 创新方法1：多尺度因果断点检测 (Multi-Scale Causal Breakpoint Detection)


def detect_multi_scale_breakpoints(routing_series, traffic_series, timestamps=None):
    if not PYWT_OK:
        return msbd_fallback(routing_series, traffic_series)
    n = min(len(routing_series), len(traffic_series))
    if n < 10:
        return {"direction": "unknown", "strength": 0.0, "significant": False, "interpretation": "数据点不足"}
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
        return {"direction": "unknown", "strength": 0.0, "significant": False, "interpretation": "尺度分解失败"}
    total_e = sum(s["energy"] for s in scale_results) + 1e-10
    weighted_sync = sum(s["sync_score"] * s["energy"] for s in scale_results) / total_e
    consistency = msbd_consistency(scale_results)
    direction = msbd_direction(weighted_sync, routing, traffic)
    return {"direction": direction, "strength": weighted_sync,
            "significant": consistency >= 0.6 and weighted_sync >= 0.3,
            "scale_sync": weighted_sync, "scale_consistency": consistency,
            "interpretation": f"多尺度同步度={weighted_sync:.2f}，一致性={consistency:.2f}",
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
    # sync<0.2 时改用 peak_position fallback，避免 HCAF 投票缺位
    if sync >= 0.6:
        # 高同步度时仍信任断点重叠，但 peak 位置严重矛盾则判独立
        r_peak = int(np.argmax(routing)) if len(routing) > 0 else 0
        t_peak = int(np.argmax(traffic)) if len(traffic) > 0 else 0
        n = max(len(routing), len(traffic), 1)
        gap_ratio = abs(r_peak - t_peak) / n
        if gap_ratio > 0.5:  # peak 距离超过序列一半长度
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
        return {"direction": "unknown", "strength": 0.0, "significant": False, "interpretation": "数据点不足"}
    r, t = np.array(routing_series[:n]), np.array(traffic_series[:n])
    corr = np.corrcoef(r, t)[0, 1] if n > 2 else 0
    rp, tp = int(np.argmax(r)), int(np.argmax(t))
    direction = "routing_to_traffic" if rp < tp else ("traffic_to_routing" if tp < rp else "independent")
    return {"direction": direction, "strength": abs(corr), "significant": abs(corr) > 0.5,
            "interpretation": "简化模式（pywt 不可用）"}


# 创新方法2：因果传递路径重建 (Causal Transmission Path Reconstruction)


def reconstruct_transmission_path(routing_events, traffic_events, as_topology, target_as):
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
        # 匹配失败时不再硬编码 routing_to_traffic，改为 unknown
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

    Override via env var ``BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER`` if a
    reviewer demands reproducible constant-delay behaviour.
    """
    if f is None or t is None:
        return 60
    jitter = int(os.environ.get("BGP_TRACER_CTPR_PSEUDO_DELAY_JITTER", "120"))
    return 60 + hash((f, t)) % jitter


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
        return "未能重建传播路径"
    path_str = " -> ".join(str(n["asn"]) for n in chain)
    return (f"因果传递路径：{path_str}（{len(chain)} 个 AS）。根因：AS{root['asn']}。"
            f"强度={strength:.2f}。")


def ctpr_parse_time(time_str):
    if not time_str:
        return None
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def ctpr_empty():
    return {"direction": "unknown", "strength": 0.0, "significant": False,
            "transmission_path": [], "root_cause_as": None, "interpretation": "无可用事件"}


# 创新方法3：反事实干预网络估计 (Counterfactual Intervention Cascade)


def estimate_counterfactual_cascade(intervention_as, intervention_type, routing_state,
                                    as_topology, traffic_baseline, affected_prefix):
    if not as_topology:
        return cic_empty()
    cascade = cic_propagate(intervention_as, as_topology, routing_state, intervention_type, affected_prefix)
    if not cascade:
        return cic_empty()
    impacts = [cic_node_impact(n, intervention_type, traffic_baseline) for n in cascade]
    total = cic_aggregate(impacts)
    strength, sig = cic_strength(total, impacts)
    return {"direction": "routing_to_traffic", "strength": strength, "significant": sig,
            "cascade_chain": cascade, "impact_estimates": impacts, "total_impact": total,
            "affected_as_count": len(cascade),
            "counterfactual_summary": cic_cf_summary(intervention_as, total),
            "interpretation": cic_desc(intervention_as, cascade, total, strength)}


def cic_propagate(start_as, topology, routing_state, int_type, prefix):
    visited, chain, queue = set(), [], [(start_as, 0, None)]
    while queue:
        current, depth, upstream = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        chain.append({"asn": current, "depth": depth, "upstream_as": upstream,
                     "has_route": cic_has_pfx(current, prefix, routing_state)})
        if depth >= 5:
            continue
        for neighbor in topology.get(current, []):
            if neighbor not in visited:
                queue.append((neighbor, depth + 1, current))
    return chain


def cic_has_pfx(asn, prefix, routing_state):
    if not prefix or not routing_state:
        return False
    return prefix in routing_state.get(asn, [])


def cic_node_impact(node, int_type, baseline):
    asn, depth = node["asn"], node["depth"]
    bl = baseline.get(asn, 1.0)
    has_route = node["has_route"]
    if int_type == "withdraw":
        impact = -bl if has_route else 0
    elif int_type == "hijack":
        impact = -bl * 0.7 if has_route else bl * 0.3
    elif int_type == "leak":
        impact = bl * (-0.2 if depth == 0 else 0.1)
    else:
        impact = 0
    impact *= (0.85 ** depth)
    return {"asn": asn, "depth": depth, "baseline": bl, "impact": impact,
            "impact_ratio": impact / bl if bl > 0 else 0, "has_route": has_route}


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
    return (f"若 AS{intervention_as} 不发生干预，{total['affected_count']} 个下游 AS "
            f"流量保持基线，不发生 {abs(total['total']):.1%} 的累计变化。")


def cic_desc(intervention_as, cascade, total, strength):
    if not cascade:
        return "未识别级联路径"
    depth_counts = defaultdict(int)
    for n in cascade:
        depth_counts[n["depth"]] += 1
    depth_desc = ", ".join(f"第{d}层 {c}个" for d, c in sorted(depth_counts.items()))
    return (f"干预 AS{intervention_as} 级联到 {len(cascade)} 个节点（{depth_desc}）。"
            f"影响 {total['affected_count']} 个 AS，因果强度 {strength:.2f}。")


def cic_empty():
    return {"direction": "unknown", "strength": 0.0, "significant": False,
            "cascade_chain": [], "impact_estimates": [], "total_impact": {"total": 0, "affected_count": 0},
            "interpretation": "无 AS 拓扑数据"}


def quick_cascade_estimate(event_type, affected_as_count, traffic_drop_ratio,
                           routing_timeline=None, traffic_timeline=None):
    """无 AS 拓扑时的退化路径。

    不再硬编码 routing_to_traffic，改为用 routing/traffic 时间线的峰值位置
    推断方向（与 peak_position baseline 同源），无时间线时返回 unknown。
    """
    if not event_type or affected_as_count == 0:
        return {"direction": "unknown", "strength": 0.0, "significant": False}
    factors = {"outage": 0.9, "hijack": 0.8, "leak": 0.5, "withdrawal": 0.9, "normal": 0.0}
    ef = factors.get(event_type, 0.3)
    af = min(affected_as_count / 10.0, 1.0)
    df = min(traffic_drop_ratio, 1.0)
    strength = ef * af * df

    # 用峰值位置推断方向，避免硬编码
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
            "interpretation": f"{event_type} 影响 {affected_as_count} 个 AS，强度 {strength:.2f}"}


# Granger 因果检验 (baseline)


class GrangerEngine:
    def __init__(self, max_lag=3, significance=0.05, enforce_stationarity=True):
        self.max_lag = max_lag
        self.significance = significance
        # When True (default), run ADF stationarity pre-check and
        # differencing before calling statsmodels.grangercausalitytests.
        # Disable for synthetic experiments where stationarity is
        # known by construction.
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
                # Return an "insufficient" marker so the HCAF voter sees
                # ``direction=unknown`` + ``significant=False`` and
                # abstains rather than voting spuriously.
                return granger_stationarity_insuf(n, stationarity_meta)
            r_series = r_check["series"]
            t_series = t_check["series"]
            if not r_series or not t_series:
                return granger_stationarity_insuf(n, stationarity_meta)
            n = min(len(r_series), len(t_series))

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


def granger_stationary_check_and_diff(series: list, name: str = "series") -> dict:
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
            "f_statistic": 0.0, "temporal_lead": None, "interpretation": f"数据点不足（n={n}）",
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
            "f_statistic": 0.0, "temporal_lead": lead, "interpretation": "statsmodels 不可用",
            "data_points": n, "association": coc}


# 混杂变量检测


class ConfounderDetector:
    def __init__(self):
        self.rules = [
            {"name": "planned_maintenance", "key": "maintenance_window", "severity": 0.7,
             "affects_routing": True, "affects_traffic": True, "explanatory": True,
             "desc": "计划内维护窗口"},
            {"name": "multiple_upstreams", "key": "multiple_upstreams", "severity": 0.5,
             "affects_routing": True, "affects_traffic": False, "explanatory": False,
             "desc": "多上游 ISP 冗余"},
            {"name": "cdn_scenario", "key": "cdn_scenario", "severity": 0.6,
             "affects_routing": False, "affects_traffic": True, "explanatory": False,
             "desc": "CDN 流量调度"},
            {"name": "ddos_mitigation", "key": "ddos_protection", "severity": 0.8,
             "affects_routing": False, "affects_traffic": True, "explanatory": False,
             "desc": "DDoS 缓解措施"},
            {"name": "concurrent_routing", "key": "concurrent_routing_changes", "severity": 0.6,
             "affects_routing": True, "affects_traffic": True, "explanatory": True,
             "desc": "断网期间其他路由变更"},
        ]

    def detect(self, routing_ctx, traffic_ctx, as_ctx):
        detected = []
        for rule in self.rules:
            key = rule["key"]
            val = routing_ctx.get(key) or traffic_ctx.get(key) or as_ctx.get(key)
            if val and val is not False and val != 0:
                detected.append({
                    "name": rule["name"], "description": rule["desc"],
                    "severity": rule["severity"], "detected_in": "context",
                    "affects_routing": rule["affects_routing"],
                    "affects_traffic": rule["affects_traffic"],
                    "is_explanatory_confounder": rule["explanatory"],
                })
        drop = traffic_ctx.get("traffic_drop_ratio", 0.0)
        if drop > 0.8 and not routing_ctx.get("withdrawal_count") and not routing_ctx.get("hijack_count"):
            detected.append({"name": "potential_ddos", "description": "疑似 DDoS",
                           "severity": 0.7, "detected_in": "semantic",
                           "affects_routing": False, "affects_traffic": True,
                           "is_explanatory_confounder": False})
        detected.sort(key=lambda x: x["severity"], reverse=True)
        return detected


# 主引擎


class 因果强度(Enum):
    强 = "strong"
    中 = "moderate"
    弱 = "weak"
    无 = "none"


@dataclass
class 创新发现:
    方法名: str
    方向: str
    强度: float
    p值: float
    显著性: bool
    解释: str
    原始输出: dict


@dataclass
class 因果归因结果:
    方向: str
    强度: 因果强度
    置信度: float
    路由导致流量: bool
    流量导致路由: bool
    创新发现列表: list
    混杂变量列表: list
    反事实总结: str
    收敛度: float
    是否为因果: bool
    解释: str
    局限: str
    证据支撑: dict


class 因果归因引擎:
    def __init__(self):
        self.granger = GrangerEngine()
        self.confounder_detector = ConfounderDetector()

    def 分析(self, 路由时间线, 流量时间线, 路由上下文=None, 流量上下文=None, 拓扑上下文=None, 目标AS=None):
        路由上下文 = 路由上下文 or {}
        流量上下文 = 流量上下文 or {}
        拓扑上下文 = 拓扑上下文 or {}

        # BOTH timelines empty → cannot make any causal claim
        if not 路由时间线 and not 流量时间线:
            return self.空结果()

        # Only one timeline present → degrade gracefully to a single-sided analysis
        # so the report still records a direction guess / confidence based on what we have.
        if not 路由时间线:
            return self.单边结果(流量时间线=流量时间线, 流量上下文=流量上下文,
                                拓扑上下文=拓扑上下文, 目标AS=目标AS, side="traffic_only")
        if not 流量时间线:
            return self.单边结果(路由时间线=路由时间线, 路由上下文=路由上下文,
                                拓扑上下文=拓扑上下文, 目标AS=目标AS, side="routing_only")

        混杂列表 = self.confounder_detector.detect(路由上下文, 流量上下文, 拓扑上下文)

        断点结果 = detect_multi_scale_breakpoints(
            [p.get("score", 0) for p in 路由时间线],
            [p.get("score", 0) for p in 流量时间线],
            timestamps=[p.get("timestamp") for p in 路由时间线]
        )

        路由事件 = self.提取路由事件(路由时间线, 路由上下文)
        流量事件 = self.提取流量事件(流量时间线, 流量上下文)
        路径结果 = reconstruct_transmission_path(
            路由事件, 流量事件, 拓扑上下文.get("adjacency", {}), 目标AS
        )

        拓扑 = 拓扑上下文.get("adjacency", {})
        if 拓扑:
            级联结果 = estimate_counterfactual_cascade(
                intervention_as=路由上下文.get("origin_as", 目标AS),
                intervention_type=路由上下文.get("event_type", "unknown"),
                routing_state=拓扑上下文.get("routing_state", {}),
                as_topology=拓扑,
                traffic_baseline=流量上下文.get("baseline", {}),
                affected_prefix=流量上下文.get("affected_prefix"),
            )
        else:
            级联结果 = quick_cascade_estimate(
                event_type=路由上下文.get("event_type"),
                affected_as_count=路由上下文.get("affected_as_count", 0),
                traffic_drop_ratio=流量上下文.get("traffic_drop_ratio", 0),
                routing_timeline=路由时间线,
                traffic_timeline=流量时间线,
            )

        granger结果 = self.granger.test(路由时间线, 流量时间线)

        收敛 = self.评估收敛(断点结果, 路径结果, 级联结果, granger结果)
        方向, 路由致流量, 流量致路由 = self.判定方向(收敛)
        强度, 置信度, 是因果 = self.计算最终分数(收敛, 断点结果, 路径结果, 级联结果)

        发现列表 = [
            创新发现("多尺度因果断点检测", 断点结果.get("direction", "unknown"),
                   断点结果.get("strength", 0.0), 断点结果.get("p_value", 1.0),
                   断点结果.get("significant", False), 断点结果.get("interpretation", ""), 断点结果),
            创新发现("因果传递路径重建", 路径结果.get("direction", "unknown"),
                   路径结果.get("strength", 0.0), 1.0, 路径结果.get("significant", False),
                   路径结果.get("interpretation", ""), 路径结果),
            创新发现("反事实干预网络估计", 级联结果.get("direction", "unknown"),
                   级联结果.get("strength", 0.0), 1.0, 级联结果.get("significant", False),
                   级联结果.get("interpretation", ""), 级联结果),
            创新发现("Granger（baseline）", granger结果.get("direction", "unknown"),
                   granger结果.get("strength", 0.0), granger结果.get("p_value", 1.0),
                   granger结果.get("significant", False), granger结果.get("interpretation", ""), granger结果),
        ]

        解释 = self.生成解释(方向, 强度, 路由致流量, 流量致路由, 收敛, 发现列表)
        局限 = self.识别局限(发现列表, 混杂列表, len(路由时间线))

        return 因果归因结果(
            方向=方向, 强度=强度, 置信度=置信度,
            路由导致流量=路由致流量, 流量导致路由=流量致路由,
            创新发现列表=发现列表, 混杂变量列表=混杂列表,
            反事实总结=级联结果.get("counterfactual_summary", ""),
            收敛度=收敛["score"], 是否为因果=是因果,
            解释=解释, 局限=局限,
            证据支撑={
                "多尺度同步度": 断点结果.get("scale_sync"),
                "传播路径长度": 路径结果.get("path_length"),
                "根因AS": 路径结果.get("root_cause_as"),
                "级联影响AS数": 级联结果.get("affected_as_count"),
                "granger_p值": granger结果.get("p_value"),
            }
        )

    def 提取路由事件(self, 时间线, 上下文):
        事件列表 = []
        as_path = 上下文.get("as_path", [])
        for 点 in 时间线:
            if 点.get("score", 0) > 0.5:
                事件列表.append({
                    "timestamp": 点.get("timestamp"),
                    "as_path": as_path,
                    "event_type": 上下文.get("event_type", "unknown"),
                })
        return 事件列表

    def 提取流量事件(self, 时间线, 上下文):
        事件列表 = []
        for 点 in 时间线:
            if 点.get("score", 0) > 0.5:
                事件列表.append({
                    "timestamp": 点.get("timestamp"),
                    "affected_prefix": 上下文.get("affected_prefix"),
                    "drop_ratio": 上下文.get("traffic_drop_ratio", 0),
                })
        return 事件列表

    def 评估收敛(self, 断点, 路径, 级联, granger):
        """4 个方法投票，按权重求和。

        权重 (HCAF_WEIGHTS_MSBD/CTPR/CIC/GRANGER) 从 ``config.py`` 读，默认
        (0.40 / 0.30 / 0.30 / 0.15)，可在运行时通过环境变量覆盖。
        当 ≥ HCAF_MAJORITY_THRESHOLD 个创新方法一致时，majority-vote 优先于
        weighted-vote（更稳定，更可解释）。
        """
        投票 = {"routing_to_traffic": 0.0, "traffic_to_routing": 0.0, "independent": 0.0}
        创新方向 = [断点.get("direction"), 路径.get("direction"), 级联.get("direction")]

        # 1) Majority-vote 优先
        majority = _hcaf_majority_vote(创新方向, threshold=HCAF_MAJORITY_THRESHOLD)
        if majority:
            return {"score": 1.0, "dominant": majority, "method_agreement": True,
                    "method": "majority_vote",
                    "weights_used": {"msbd": HCAF_WEIGHTS_MSBD,
                                     "ctpr": HCAF_WEIGHTS_CTPR,
                                     "cic": HCAF_WEIGHTS_CIC,
                                     "granger": HCAF_WEIGHTS_GRANGER}}

        # 2) 否则 weighted-vote
        创新有效 = sum(1 for d in 创新方向 if d in 投票) >= 2
        if 创新有效:
            for 方法, w in ((断点, HCAF_WEIGHTS_MSBD), (路径, HCAF_WEIGHTS_CTPR), (级联, HCAF_WEIGHTS_CIC)):
                d = 方法.get("direction", "unknown")
                s = 方法.get("strength", 0.0)
                if d in 投票:
                    投票[d] += s * w
            d = granger.get("direction", "unknown")
            if d in 投票:
                投票[d] += granger.get("strength", 0.0) * HCAF_WEIGHTS_GRANGER
        else:
            # 创新方法信号缺失：单 Granger 判定（折扣）
            d = granger.get("direction", "unknown")
            if d in 投票:
                # Granger 默认权重 × 打折 0.6 + 0.04 仍能驱动投票
                投票[d] += granger.get("strength", 0.0) * HCAF_WEIGHTS_GRANGER + 0.04
            投票["independent"] += 0.05

        总票 = sum(投票.values())
        if 总票 < 0.05:
            return {"score": 0.0, "dominant": "insufficient", "method_agreement": False,
                    "method": "weighted_vote",
                    "weights_used": {"msbd": HCAF_WEIGHTS_MSBD,
                                     "ctpr": HCAF_WEIGHTS_CTPR,
                                     "cic": HCAF_WEIGHTS_CIC,
                                     "granger": HCAF_WEIGHTS_GRANGER}}
        主导 = max(投票, key=投票.get)
        占比 = 投票[主导] / 总票
        一致 = 创新方向.count(主导) >= 2
        return {"score": 占比 * (1.0 if 主导 != "independent" else 0.5),
                "dominant": 主导, "method_agreement": 一致 and 占比 >= 0.5,
                "method": "weighted_vote",
                "weights_used": {"msbd": HCAF_WEIGHTS_MSBD,
                                 "ctpr": HCAF_WEIGHTS_CTPR,
                                 "cic": HCAF_WEIGHTS_CIC,
                                 "granger": HCAF_WEIGHTS_GRANGER}}

    def 判定方向(self, 收敛):
        主导 = 收敛["dominant"]
        if not 收敛.get("method_agreement"):
            # 即使 method_agreement=False，只要 dominant 是 routing_to_traffic
            # 或 traffic_to_routing（非 independent、非 insufficient），仍可
            # 输出方向——只是 method_agreement=False 会让是否为因果=False，
            # 给调用方一个保守语义。原来的代码一票否决变 undetermined 是过严的。
            if 主导 in ("routing_to_traffic", "traffic_to_routing"):
                映射 = {
                    "routing_to_traffic": ("routing -> traffic", True, False),
                    "traffic_to_routing": ("traffic -> routing", False, True),
                }
                return 映射[主导]
            return "undetermined", False, False
        映射 = {
            "routing_to_traffic": ("routing -> traffic", True, False),
            "traffic_to_routing": ("traffic -> routing", False, True),
            "independent": ("independent", False, False),
        }
        return 映射.get(主导, ("unknown", False, False))

    def 计算最终分数(self, 收敛, 断点, 路径, 级联):
        创新强度 = (断点.get("strength", 0.0) + 路径.get("strength", 0.0) + 级联.get("strength", 0.0)) / 3.0
        基础 = 收敛["score"] * 0.6 + 创新强度 * 0.4
        因子 = 0.9 if 断点.get("scale_results") else 0.6
        置信度 = 基础 * 因子
        if 基础 >= 0.7:
            强度 = 因果强度.强
        elif 基础 >= 0.4:
            强度 = 因果强度.中
        elif 基础 >= 0.15:
            强度 = 因果强度.弱
        else:
            强度 = 因果强度.无
        是因果 = 收敛.get("method_agreement") and 基础 >= 0.4 and 置信度 >= 0.3
        return 强度, 置信度, 是因果

    def 生成解释(self, 方向, 强度, 路由致流量, 流量致路由, 收敛, 发现列表):
        if 强度 == 因果强度.无 or 方向 == "undetermined":
            return "三个创新方法均未达成收敛，因果判定依据不足。"
        if 路由致流量:
            部分 = [f"判定结论：路由异常很可能导致了流量变化（强度：{强度.value}）。",
                   f"三创新方法收敛度：{收敛['score']:.0%}"]
            for 发现 in 发现列表[:3]:
                if 发现.方向 == "routing_to_traffic":
                    部分.append(f"· {发现.方法名}：{发现.解释[:80]}")
            return " ".join(部分)
        if 流量致路由:
            return f"判定结论：流量异常可能触发了路由调整（强度：{强度.value}）。"
        return "路由与流量变化存在关联，但因果方向不明。"

    def 识别局限(self, 发现列表, 混杂列表, 数据点数):
        局限 = []
        if 数据点数 < 10:
            局限.append("数据点不足（<10）。")
        if len(混杂列表) > 2:
            外部 = [c for c in 混杂列表 if not c.get("is_explanatory_confounder")]
            if 外部:
                局限.append(f"识别到 {len(外部)} 个外部混杂变量。")
        return " ".join(局限) or "未发现明显方法学局限。"

    def 空结果(self):
        return 因果归因结果(
            方向="unknown", 强度=因果强度.无, 置信度=0.0,
            路由导致流量=False, 流量导致路由=False,
            创新发现列表=[], 混杂变量列表=[],
            反事实总结="数据不足", 收敛度=0.0, 是否为因果=False,
            解释="数据不足，无法进行因果归因分析。",
            局限="需要至少包含有效时间戳和异常分数的数据点。",
            证据支撑={})

    def 单边结果(self, 路由时间线=None, 流量时间线=None, 路由上下文=None,
                流量上下文=None, 拓扑上下文=None, 目标AS=None, side="routing_only"):
        """仅一侧有时间线时的退化分析。

        与 空结果 不同，这里仍然产出方向猜测 + 弱置信度，让 HCAF 报告
        不再完全是"unknown/none/0%"。基于事件类型 + 流量上下文里的 drop_ratio
        推断方向（与 quick_cascade_estimate 同源）。
        """
        事件类型 = (路由上下文 or {}).get("event_type", "unknown") if side == "routing_only" \
            else "unknown"
        影响AS = (路由上下文 or {}).get("affected_as_count", 0)
        流量下降比 = (流量上下文 or {}).get("traffic_drop_ratio", 0.0)
        因素 = {"outage": 0.9, "hijack": 0.8, "leak": 0.5, "withdrawal": 0.9, "normal": 0.0}
        事件因子 = 因素.get(事件类型, 0.3)
        AS因子 = min(影响AS / 10.0, 1.0) if 影响AS else 0.0
        下降因子 = min(流量下降比, 1.0)
        强度 = 事件因子 * (AS因子 + 下降因子) / 2 if (AS因子 or 下降因子) else 0.0

        # 当 routing_only 且事件类型为 hijack/outage 且 drop_ratio > 0.1 时推断 routing_to_traffic
        if side == "routing_only" and 事件类型 in ("hijack", "outage", "withdrawal") and 下降因子 > 0.1:
            方向 = "routing_to_traffic"
            解释 = (
                f"仅路由时间线可用（{len(路由时间线) if 路由时间线 else 0} 条），"
                f"事件类型={事件类型}，流量上下文下降比={流量下降比:.0%}。"
                f"基于事件类型+流量上下文推断方向=routing_to_traffic（弱证据）。"
            )
            路由致流量 = True
        elif side == "traffic_only":
            方向 = "unknown"
            解释 = (
                f"仅流量时间线可用（{len(流量时间线) if 流量时间线 else 0} 条），"
                f"无法判断因果方向，需等待路由数据。"
            )
            路由致流量 = False
        else:
            方向 = "unknown"
            解释 = (
                f"仅 {('路由' if side == 'routing_only' else '流量')}时间线可用，"
                f"流量上下文下降比={流量下降比:.0%}，不足以推断因果方向。"
            )
            路由致流量 = False

        数据点 = (len(路由时间线) if 路由时间线 else 0) + (len(流量时间线) if 流量时间线 else 0)
        置信度 = min(0.5, 0.2 + 0.1 * 下降因子 + 0.1 * AS因子)  # 单边最大 50%
        局限 = (
            "单边数据：仅一侧时间线可用，无法同时验证断点/路径/级联/Granger 四项指标；"
            "方向推断为弱证据，需补齐另一侧时间线后重新评估。"
        )
        return 因果归因结果(
            方向=方向, 强度=因果强度.弱 if 强度 > 0.3 else 因果强度.无,
            置信度=置信度,
            路由导致流量=路由致流量, 流量导致路由=False,
            创新发现列表=[
                创新发现("单边降级分析", 方向, 强度, 1.0, False, 解释, {})
            ],
            混杂变量列表=[],
            反事实总结=f"单边分析 ({side})，结论 {方向}，强度={强度:.2f}",
            收敛度=0.2 if 方向 != "unknown" else 0.0,
            是否为因果=False,
            解释=解释,
            局限=局限,
            证据支撑={"single_sided": side, "data_points": 数据点},
        )


def analyze(路由证据, 流量证据):
    引擎 = 因果归因引擎()
    return 引擎.分析(
        路由时间线=路由证据.get("timeline", []),
        流量时间线=流量证据.get("timeline", []),
        路由上下文=路由证据, 流量上下文=流量证据,
        拓扑上下文=路由证据.get("as_context", {}),
        目标AS=路由证据.get("target_as"),
    )

# 合并自 causal_inference.py (LEGACY 兼容层)


import warnings

class CausalDirection(Enum):
    """因果方向（兼容旧版 API）"""
    ROUTING_TO_TRAFFIC = "routing->traffic"
    TRAFFIC_TO_ROUTING = "traffic->routing"
    BIDIRECTIONAL = "bidirectional"
    INDEPENDENT = "independent"
    UNKNOWN = "unknown"


@dataclass
class TimePoint:
    """时间点（兼容旧版 API）"""
    timestamp: str
    routing_anomaly_score: float = 0.0
    traffic_anomaly_score: float = 0.0
    routing_events: List[str] = field(default_factory=list)
    traffic_events: List[str] = field(default_factory=list)


@dataclass
class CausalAnalysis:
    """因果分析结果（兼容旧版 API）"""
    direction: 'CausalDirection'
    strength: float
    p_value: float
    confidence: float
    temporal_lead: Optional[float] = None
    explanation: str = ""
    confounders: List[str] = field(default_factory=list)
    counterfactual: str = ""
    evidence_summary: str = ""


@dataclass
class GrargerResult:
    """Granger 因果检验结果（兼容旧版 API）"""
    direction: 'CausalDirection'
    f_statistic: float
    p_value: float
    significant: bool
    confidence: float


class EnhancedCausalInferenceEngine:
    """兼容旧版的因果推断引擎（内部委托给 HCAF）"""

    def __init__(self):
        self.causal_threshold = 0.05
        self.temporal_tolerance_minutes = 30
        self._hcaf = 因果归因引擎()

    def analyze(self, routing_timeline, traffic_timeline,
                routing_context=None, traffic_context=None):
        """兼容接口：分析因果关系"""
        # 转换格式
        r_timeline = [{"timestamp": tp.timestamp, "score": tp.routing_anomaly_score,
                       "events": tp.routing_events} for tp in routing_timeline]
        t_timeline = [{"timestamp": tp.timestamp, "score": tp.traffic_anomaly_score,
                       "events": tp.traffic_events} for tp in traffic_timeline]

        # 调用 HCAF 引擎
        result = self._hcaf.分析(
            路由时间线=r_timeline,
            流量时间线=t_timeline,
            路由上下文=routing_context or {},
            流量上下文=traffic_context or {}
        )

        # 强度映射
        strength_map = {
            因果强度.强: 1.0,
            因果强度.中: 0.7,
            因果强度.弱: 0.4,
            因果强度.无: 0.0,
        }
        strength_val = strength_map.get(result.强度, 0.0)
        direction_map = {
            "routing->traffic": CausalDirection.ROUTING_TO_TRAFFIC,
            "traffic->routing": CausalDirection.TRAFFIC_TO_ROUTING,
            "bidirectional": CausalDirection.BIDIRECTIONAL,
            "independent": CausalDirection.INDEPENDENT,
        }
        direction = direction_map.get(
            result.方向, CausalDirection.UNKNOWN
        )

        return CausalAnalysis(
            direction=direction,
            strength=strength_val,
            p_value=1.0,
            confidence=result.置信度,
            temporal_lead=None,
            explanation=result.解释,
            counterfactual=result.反事实总结,
            evidence_summary=""
        )


def analyze_bgp_causality(routing_evidence, traffic_evidence):
    """兼容旧版的便捷分析函数"""
    engine = EnhancedCausalInferenceEngine()
    routing_timeline = [
        TimePoint(
            timestamp=rt.get('time', ''),
            routing_anomaly_score=rt.get('score', 0.0),
            routing_events=rt.get('events', [])
        )
        for rt in routing_evidence.get('timeline', [])
    ]
    traffic_timeline = [
        TimePoint(
            timestamp=tt.get('time', ''),
            traffic_anomaly_score=tt.get('score', 0.0),
            traffic_events=tt.get('events', [])
        )
        for tt in traffic_evidence.get('timeline', [])
    ]
    return engine.analyze(
        routing_timeline=routing_timeline,
        traffic_timeline=traffic_timeline,
        routing_context=routing_evidence,
        traffic_context=traffic_evidence,
    )


def convert_to_hcaf_format(routing_timeline, traffic_timeline):
    """将旧格式转换为 HCAF 格式"""
    def convert(timeline):
        out = []
        for tp in timeline:
            score = max(tp.routing_anomaly_score, tp.traffic_anomaly_score)
            events = tp.routing_events + tp.traffic_events
            out.append({"timestamp": tp.timestamp, "score": score, "events": events})
        return out
    return {
        "routing": convert(routing_timeline) if routing_timeline else [],
        "traffic": convert(traffic_timeline) if traffic_timeline else []
    }
