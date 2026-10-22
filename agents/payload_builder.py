"""
Unified Payload Builder for LLM Calls
=====================================

Resolves a structural defect across the agent system: every LLM call site
had its own ad-hoc size-limiting logic (or none at all), which produced
two failures:

  1. Payload explosion — routing results with 500 events carried full
     ``as_path`` lists into 3-5 reasoning prompts, often 200KB+ each,
     blowing past the LLM context window.

  2. Silent fallback — when the model couldn't process the prompt, each
     site had its own rule-based fallback that quietly overrode the LLM
     decision without telling anyone.

This module is the single source of truth for:

  - **Section-aware slimming**: each section (traffic / routing / correlation /
    reasoning / report) has explicit keep/drop lists for fields and a max
    item count per list type.

  - **Hard token cap**: a final guardrail that recursively shrinks lists
    until the JSON-serialized payload fits inside the budget.

  - **Token estimation**: a coarse estimator that lets callers warn the
    caller before sending the prompt, and lets ``TokenBudget`` attribute
    real tokens to the right agent.

  - **Per-section context budgets**: different stages of the workflow have
    different risk profiles — reasoning can use 60K tokens, reports 50K,
    specialist validation 30K, classification 5K, calibration 8K.

Design decisions:

  - **Allow-list > deny-list**: each section declares what it keeps.
    Adding a new field to the system that shouldn't go to LLM is
    automatically excluded (no need to remember to add it to a deny list).

  - **Estimate before send**: every helper returns ``(payload, est_tokens)``
    so a caller can decide whether to skip the call or fall back to
    deterministic.  The function never silently drops to "is_valid=True".

  - **No new dependencies**: uses only stdlib ``json``.

Public API:

  - :func:`slim_section`     — section-aware slim with default budget
  - :func:`cap_payload`      — hard byte cap with shrinking fallback
  - :func:`estimate_tokens`  — coarse token estimate
  - :func:`estimate_bytes`   — coarse byte estimate
  - :func:`record_llm_call`  — record actual usage in TokenBudget
  - :class:`PayloadBudget`   — pre-built budgets for each stage
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from utils.logger import logger


# Constants & defaults
_CHARS_PER_TOKEN = 0.4


def _safe_int_env(key, default):
    """Read integer env var with a safe fallback (non-numeric → default).

    Bug fix 2026-10-13: a previous version called ``int(env_value)``
    directly, which raised ``ValueError`` at import time when the user
    set the variable to a non-numeric value such as ``"150kb"``.
    """
    raw = os.environ.get(key, "")
    if not raw:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


# Default budget tier sizes — in *bytes* (JSON-serialized form).
_DEFAULT_BUDGETS = {
    "reasoning": _safe_int_env("PAYLOAD_BUDGET_REASONING_KB", 150) * 1024,
    "report":    _safe_int_env("PAYLOAD_BUDGET_REPORT_KB", 100) * 1024,
    "specialist":_safe_int_env("PAYLOAD_BUDGET_SPECIALIST_KB", 60) * 1024,
    "classify":  _safe_int_env("PAYLOAD_BUDGET_CLASSIFY_KB", 15) * 1024,
    "calibrate": _safe_int_env("PAYLOAD_BUDGET_CALIBRATE_KB", 20) * 1024,
}


class PayloadBudget:
    """Budget presets for each LLM call site.  Use these instead of
    magic numbers at the call site."""

    REASONING  = _DEFAULT_BUDGETS["reasoning"]
    REPORT     = _DEFAULT_BUDGETS["report"]
    SPECIALIST = _DEFAULT_BUDGETS["specialist"]
    CLASSIFY   = _DEFAULT_BUDGETS["classify"]
    CALIBRATE  = _DEFAULT_BUDGETS["calibrate"]


# Section-aware slim profiles
_TRAFFIC_KEEP = {
    # Wrapper key (chief_agent.envelope / workflow passes {result: traffic_agent_output})
    "result",
    # Top-level scalar metrics used by CDJ / reports / correlation analysis
    "anomaly_count", "anomalies_detected", "data_available",
    "success", "summary", "as_info", "periodicity_analysis",
    "z_score_distribution", "direction_breakdown", "peak_anomalies",
    "total_anomaly_count", "analysis_period", "anomalies",
    "extended_anomalies", "extended_windows",
    # Window / statistics
    "traffic_anomaly_window", "anomaly_window",
    "statistics", "stats",
    "percent_change", "current_avg", "historical_avg",
    "peak_trough_drop_pct", "peak_value", "trough_value",
    "multi_scale_analysis",
    "consecutive_anomaly_windows", "expanded_windows",
    "expanded_boundaries",
    # CDJ / report scalar fields (from ground_truth_dataset columns)
    "traffic_score", "traffic_percent_change", "traffic_affected_users",
    "traffic_signal_strength", "traffic_detected",
    # Visualization
    "plot_path", "traffic_plot_path",
    # Victim attribution
    "victim_asns",
    # Cloudflare-specific
    "outage_period_anomalies", "outage_period_start", "outage_period_end",
}
_TRAFFIC_LIST_LIMITS = {
    "anomalies": 20,
    "peak_anomalies": 10,
    "extended_anomalies": 10,
}

# NOTE on format compatibility:
_ROUTING_KEEP = {
    # Wrapper key
    "result",
    # Top-level fields (live format)
    "asn", "success", "data_available", "skipped", "skip_reason",
    "total_prefix_hijacks", "forge_path_hijacks", "total_route_leaks",
    "outage_suspected", "as_rel_file", "prefix2as_file",
    "asorg_file", "summary", "hijacks", "leaks",
    "origin_hijacked", "forge_hijacked",
    "origin_hijacking", "forge_hijacking",
    "route_leaks", "outages",
    # BUG-R141 2026-09-29: the live routing payload produced by
    # routing_impl.run_routing_agent_async() carries its leak data under
    # ``leak_analysis`` (and the outage block under ``outage_analysis``).
    # Neither was allow-listed, so both were stripped before the report was
    # rendered — the detector had already found the leaks, the report showed
    # zero. Also keep the scalar counts so a truncated list still reports the
    # true total.
    "leak_analysis", "outage_analysis", "leak_count", "outage_score",
    "mitm_alerts", "routing_status", "llm_insights", "impact_scope",
    "analysis_timestamp", "no_data_reason", "anomalies_detected",
    "anomaly_count",
    # Annotation format containers
    "hijack", "leak", "outage",
    "event_role_type", "role", "analysis_period",
    # CDJ / report scalar fields
    "route_score", "route_anomaly_count", "route_prefix_count",
    "route_propagation_tier", "route_propagation_label", "route_detected",
}
_ROUTING_LIST_LIMITS = {
    # Live format lists
    "origin_hijacked": 40,
    "forge_hijacked": 10,
    "origin_hijacking": 20,
    "forge_hijacking": 10,
    "route_leaks": 40,
    "outages": 10,
    # Annotation format lists (nested under hijack/leak/outage) — keys
    "indicators": 10,         # routing.outage.indicators
    "event_features": 5,    # routing.outage.event_features
}

_CORRELATION_KEEP = {
    "summary", "delta_ts", "delta_t_events", "delta_t_score",
    "temporal_alignment", "cross_validation",
    "hypotheses", "correlation_level", "correlation_confidence",
    "joint_tier", "joint_score", "hcaf_attribution",
    # Round-26: keep the inner correlation dict too — it carries
    # ``signals.temporal_proximity`` and ``confidence`` which downstream
    # renderers (Correlation Confidence gauge, TCA, Executive Summary
    # verdict) read. Without it the gauge collapses to the "none / 0.10"
    # fallback and the TCA strength shows "0.00" while the level says
    # "strong", producing the contradictory output the reviewer flagged.
    "correlation",
}
_CORRELATION_LIST_LIMITS = {
    "delta_ts": 20,
    "delta_t_events": 20,
    "hypotheses": 10,
}

_REASONING_KEEP = {
    "rounds_performed", "incident_classification",
    "severity_assessment", "traffic_correlation",
    "integrated_findings", "recommendations",
    "confidence_assessment", "evidence_summary",
    "reasoning_trace", "calibration",
    "integrated_analysis", "hypothesis_analysis",
    "probe_results", "structured_facts", "retrieved_context",
    # Surface traffic/routing correlation data so report sees it
    "traffic", "routing",
    "traffic_result", "routing_result",
    "victim_traffic_results", "prefix_traffic_results",
    "victim_asns", "correlation_score_result",
    "as_path_delta_result", "as_relationships_result",
    "probe_reachability_result", "roa_validation_result",
    "threat_intel_result",
}
_REASONING_LIST_LIMITS = {
    "probe_results": 3,
    "structured_facts": 5,
    "retrieved_context": 3,
    "evidence_summary": 5,
}

# Keys to ALWAYS drop from nested event dicts (per-event keys that are
_EVENT_DENY_KEYS = frozenset({
    "as_paths",                           # full list of paths (large), dropped
    # "as_path" intentionally kept: routing_agent.prepare_routing_payload
    # already truncates to ~10 ASes, so it is compact and informative
    "raw_announcements", "raw_output", "raw_observations",
    "raw_score_breakdown", "raw_features", "feature_breakdown", "noise",
    "historical_periods", "values", "timestamps",
    "daily_correlations", "weekly_correlations",
    "scales", "data_points", "plot_path",
    "traffic_result", "routing_result",   # chief_agent envelope duplicates
    "evidence_summary",
})

_SECTION_PROFILES = {
    "traffic":     (_TRAFFIC_KEEP, _TRAFFIC_LIST_LIMITS),
    "routing":     (_ROUTING_KEEP, _ROUTING_LIST_LIMITS),
    "correlation": (_CORRELATION_KEEP, _CORRELATION_LIST_LIMITS),
    "reasoning":   (_REASONING_KEEP, _REASONING_LIST_LIMITS),
}


# Estimators

def estimate_bytes(obj):
    """Coarse byte estimate for a JSON-serialisable object."""
    try:
        return len(json.dumps(obj, ensure_ascii=False, default=str))
    except Exception:
        try:
            return len(repr(obj))
        except Exception:
            return 0


def estimate_tokens(obj):
    """Coarse token estimate.

    Uses len(json.dumps()) * 0.35 (≈3 bytes per token for compact JSON,
    which over-estimates slightly for code-heavy text).  Always returns
    a positive int; returns 0 only for None.
    """
    if obj is None:
        return 0
    nbytes = estimate_bytes(obj)
    return max(1, int(nbytes * 0.35))


# Generic recursive slim

def slim_generic(
    obj: Any,
    max_list_items: int = 10,
    drop_keys: frozenset = _EVENT_DENY_KEYS,
    _depth: int = 0,
    _max_depth: int = 30,
) -> Any:
    """Recursive slim: drop deny-listed keys, truncate lists to ``max_list_items``,
    drop top-level keys past index 100 to prevent pathological inputs."""
    if _depth > _max_depth:
        return None
    if isinstance(obj, dict):
        out = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= 100:
                break  # don't iterate beyond 100 top-level keys
            if k in drop_keys:
                continue
            # Truncate very long as_path strings (they are informative but verbose)
            if k == "as_path" and isinstance(v, str) and len(v) > 200:
                v = v[:200] + " ... [truncated]"
            out[k] = slim_generic(v, max_list_items, drop_keys, _depth + 1, _max_depth)
        return out
    if isinstance(obj, list):
        return [
            slim_generic(v, max_list_items, drop_keys, _depth + 1, _max_depth)
            for v in obj[:max_list_items]
        ]
    return obj


# Section-aware slim

def slim_section(
    section: str,
    data: Any,
    max_list_items: Optional[int] = None,
) -> Any:
    """Section-aware slimming.

    Args:
        section: one of ``"traffic"``, ``"routing"``, ``"correlation"``,
            ``"reasoning"``, or any other name (falls back to generic slim).
        data: the raw section data.
        max_list_items: override the per-section default.

    Returns:
        A slimmed copy of ``data`` suitable for an LLM prompt.  The
        original is not mutated.
    """
    profile = _SECTION_PROFILES.get(section)
    if profile is None:
        return slim_generic(data, max_list_items or 10)

    keep_top, list_limits = profile
    default_limit = max_list_items or 10

    # Step 1: drop top-level keys not in keep list (allow-list)
    if isinstance(data, dict):
        out = {k: v for k, v in data.items() if k in keep_top}
    else:
        out = data

    # Step 2: recursively apply per-list-name max-item counts AND strip
    # event-level deny keys (``as_path``, ``values``, etc.) at any depth.
    out = slim_with_limits(out, list_limits, default_limit)
    return out


def slim_with_limits(
    obj: Any,
    list_limits: dict,
    default_limit: int,
    _parent_key: str = "",
    _depth: int = 0,
    _max_depth: int = 30,
) -> Any:
    """Recursive slim that:
      1. Uses per-list-name max-item counts from ``list_limits``.
      2. Strips ``_EVENT_DENY_KEYS`` at every depth.
      3. Falls back to ``default_limit`` for lists without an entry.

    The parent key is forwarded to the list child so a list named
    ``"anomalies"`` looks up ``list_limits["anomalies"]``, not
    ``list_limits["_current"]``.
    """
    if _depth > _max_depth:
        return None
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _EVENT_DENY_KEYS:
                continue
            out[k] = slim_with_limits(
                v, list_limits, default_limit,
                _parent_key=k, _depth=_depth + 1, _max_depth=_max_depth,
            )
        return out
    if isinstance(obj, list):
        limit = list_limits.get(_parent_key, default_limit)
        return [
            slim_with_limits(
                v, list_limits, default_limit,
                _parent_key=_parent_key, _depth=_depth + 1, _max_depth=_max_depth,
            )
            for v in obj[:limit]
        ]
    return obj


def apply_section_limits(obj, list_limits, default_limit):
    """Apply per-list-name max-item counts while recursively stripping deny keys.

    Deprecated: kept for backwards compatibility.  New code should call
    :func:`slim_with_limits` which integrates deny-key stripping.
    """
    return slim_with_limits(obj, list_limits, default_limit)


# Hard byte cap

def cap_payload(data: Any, max_bytes: int = PayloadBudget.REPORT) -> tuple[Any, dict]:
    """Cap a (already-slimmed) payload to ``max_bytes`` bytes.

    Recursively halves list sizes until the JSON-serialised form fits.
    As a last resort, drops optional top-level sections.

    Returns ``(capped_data, cap_meta)`` where ``cap_meta`` records:
        - original_bytes
        - final_bytes
        - dropped_sections
        - lists_truncated (counter)
    """
    info = {
        "original_bytes": estimate_bytes(data),
        "max_bytes": max_bytes,
        "lists_truncated": 0,
        "dropped_sections": [],
    }

    if info["original_bytes"] <= max_bytes:
        info["final_bytes"] = info["original_bytes"]
        return data, info

    # Pass 1: halve all lists repeatedly (up to 20 iterations).
    current = data
    for _ in range(20):
        if estimate_bytes(current) <= max_bytes:
            break
        current, truncated = halve_lists(current)
        info["lists_truncated"] += truncated
        if truncated == 0:
            break  # no more lists to shrink

    info["final_bytes"] = estimate_bytes(current)
    if info["final_bytes"] <= max_bytes:
        return current, info

    # Pass 2: drop optional sections.
    _OPTIONAL_SECTIONS = (
        "victim_traffic_results", "prefix_traffic_results",
        "as_path_delta_result", "as_relationships_result",
        "probe_reachability_result", "law_analysis",
        "retrieved_context", "evidence_board",
        "hcaf_attribution", "calibration", "bayesian_result",
        "joint_evidence_cards", "auxiliary_enrichment",
        "probe_results", "structured_facts",
    )
    if isinstance(current, dict):
        for k in _OPTIONAL_SECTIONS:
            if k in current and estimate_bytes(current) > max_bytes:
                current[k] = {"trimmed": "size_limit_reached"}
                info["dropped_sections"].append(k)
                if estimate_bytes(current) <= max_bytes:
                    break

    info["final_bytes"] = estimate_bytes(current)
    if info["final_bytes"] > max_bytes:
        logger.warning(
            f"[PayloadBuilder] Could not fit payload into {max_bytes} bytes "
            f"({info['final_bytes']} bytes final). Consider raising the cap."
        )
    return current, info


def halve_lists(obj: Any, counter: list[int] = None) -> tuple[Any, int]:
    """Halve every list in the structure.  Returns (new_obj, n_lists_halved)."""
    if counter is None:
        counter = [0]
    if isinstance(obj, dict):
        return {k: halve_lists(v, counter)[0] for k, v in obj.items()}, counter[0]
    if isinstance(obj, list):
        n = len(obj)
        if n > 4:
            keep = max(1, n // 2)
            counter[0] += 1
            new_obj = obj[:keep]
        else:
            new_obj = obj
        return [halve_lists(v, counter)[0] for v in new_obj], counter[0]
    return obj, counter[0]


# Combined helper: slim + cap

def build_payload(
    section: str,
    data: Any,
    max_bytes: int = PayloadBudget.REPORT,
    max_list_items: Optional[int] = None,
) -> tuple[Any, dict]:
    """Slim a section then cap it to ``max_bytes``.  Returns (payload, meta).

    ``meta`` contains:
        - section
        - max_bytes
        - pre_slim_bytes
        - pre_cap_bytes
        - final_bytes
        - est_tokens          (coarse estimate)
        - lists_truncated
        - dropped_sections
    """
    pre_slim = estimate_bytes(data)
    slimmed = slim_section(section, data, max_list_items=max_list_items)
    pre_cap = estimate_bytes(slimmed)
    capped, cap_meta = cap_payload(slimmed, max_bytes=max_bytes)

    meta = {
        "section": section,
        "max_bytes": max_bytes,
        "pre_slim_bytes": pre_slim,
        "pre_cap_bytes": pre_cap,
        "final_bytes": cap_meta["final_bytes"],
        "est_tokens": estimate_tokens(capped),
        "lists_truncated": cap_meta["lists_truncated"],
        "dropped_sections": cap_meta["dropped_sections"],
    }
    return capped, meta


# =============================================================================
# Token budget recording helper

def record_llm_call(
    run_id: str,
    agent: str,
    prompt: Any,
    response: Any,
    *,
    prompt_text_override: Optional[str] = None,
) -> None:
    """Record an LLM call's actual token usage into TokenBudget.

    Tries to read ``response.usage.prompt_tokens`` /
    ``response.usage.completion_tokens`` (OpenAI-compatible format).  If
    the upstream does not return usage info, falls back to the estimator.

    Args:
        run_id: workflow run identifier (matches ``TokenBudget.get_instance``).
        agent: short name of the calling agent (e.g. ``"TrafficExpert"``).
        prompt: the prompt object (str or dict).
        response: the LLM response object (must have ``.usage`` for
            accurate counting; otherwise estimated).
        prompt_text_override: explicit text to use for token estimation
            (use when the prompt object is a complex structure).
    """
    try:
        from agents.token_budget import TokenBudget
        tb = TokenBudget.get_instance(run_id)
    except ImportError:
        # Module genuinely absent — caller opted out of budget tracking.
        return
    except Exception as e:
        # Concrete error inside TokenBudget (bad run_id, init failure,
        logger.warning(
            "[record_llm_call] TokenBudget unavailable, skipping record: %s",
            e,
        )
        return

    prompt_text = prompt_text_override
    if prompt_text is None:
        if isinstance(prompt, str):
            prompt_text = prompt
        else:
            try:
                prompt_text = json.dumps(prompt, ensure_ascii=False, default=str)
            except Exception:
                prompt_text = str(prompt)

    # Extract real usage if available
    pt, ct = 0, 0
    try:
        usage = getattr(response, "usage", None)
        if usage is not None:
            pt = getattr(usage, "prompt_tokens", 0) or 0
            ct = getattr(usage, "completion_tokens", 0) or 0
    except Exception:
        pass

    # Fall back to estimator if upstream didn't return usage
    if pt == 0:
        pt = estimate_tokens(prompt_text)

    tb.add(agent, pt, ct)


# =============================================================================
# Convenience: stringify for prompt

def to_json_for_prompt(obj, *, ensure_ascii=False, indent=2):
    """JSON-serialise a payload for inclusion in an LLM prompt."""
    try:
        return json.dumps(obj, indent=indent, ensure_ascii=ensure_ascii, default=str)
    except Exception as exc:
        logger.warning(f"[PayloadBuilder] JSON serialise failed: {exc}; using repr")
        return repr(obj)
