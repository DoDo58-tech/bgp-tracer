from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Optional

from agents.core import Agent, AgentState, TaskResult
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REPORT
from config import (
    MODEL, API_KEY, BASE_URL,
    REPORT_LLM_TIMEOUT_S as _CONFIG_REPORT_LLM_TIMEOUT_S,
    REPORT_MAX_TOKENS as _CONFIG_REPORT_MAX_TOKENS,
    REPORT_REQUIRE_LLM as _CONFIG_REPORT_REQUIRE_LLM,
)
from utils.logger import logger

_REQUIRED_COT_MARKERS = (
    "OBSERVE",
    "INFER",
    "LINK",
    "CONCLUDE",
    "CITE",
    "Counterfactual Analysis",
    "[source: field_name]",
)


def _validate_cot_prompt(prompt: str) -> None:
    """
    Sanity-check that a prompt includes the mandatory CoT scaffolding.

    Called inside `_render_report_prompt` so that any future call site that
    forgets to use the unified prompt will fail loudly at runtime — this is
    what enforces "all report paths must require CoT".
    """
    missing = [m for m in _REQUIRED_COT_MARKERS if m not in prompt]
    if missing:
        raise RuntimeError(
            "Report prompt is missing required CoT markers: "
            f"{missing}. Always build report prompts via `_render_report_prompt()`."
        )


def _render_report_prompt(data_json: str) -> str:
    """
    Build the LLM prompt for HTML report generation.

    Single entry point — every report code path MUST call this. Internally
    appends the structured data to `_UNIFIED_COT_PROMPT` and validates that
    the resulting prompt still contains every mandatory CoT marker. A previous
    version of this file had two divergent prompts (one rich, one minimal);
    the minimal one dropped the counterfactual / citation requirements and
    caused silent CoT regressions for the standalone report path.
    """
    prompt = (_UNIFIED_COT_PROMPT
              + "\\n\\n== OUTPUT CONSTRAINT ==\\n"
              + "Return one compact, complete HTML document within the output-token limit. "
              + "Prioritize visible data tables and numeric values from the JSON over long prose. "
              + "Keep each section concise while including the required headings, traffic values, "
              + "routing prefixes, counts, timeline, limitations, recommendations, and "
              + "Counterfactual Analysis. Close every opened HTML tag before responding."
              + "\\n\\n== RAW ANALYSIS DATA ==\\n" + data_json)
    _validate_cot_prompt(prompt)
    return prompt

_UNIFIED_COT_PROMPT = """You are a BGP routing security analyst writing a rigorous incident report.
Generate a complete, self-contained HTML report from the structured analysis data below.

== HARD RULE: USE ONLY THE FIELDS FROM THE JSON PAYLOAD ==
Every concrete fact you write (AS number, ASN, organization name, country, prefix,
timestamp, count, severity, plot path) MUST come from the JSON payload at the end
of this prompt. DO NOT hallucinate or substitute with values from another AS or
another event.

Specifically:
- The "Target AS" header MUST be exactly the value of `target_as` in the payload
  (which is the AS the user originally queried — e.g. 44244). It MUST NOT be the
  ASN of any attacker, victim, or other AS that appears in the routing data.
- The analysis window MUST be exactly `user_analysis_window` from the payload.
- All numerical counts MUST come from the corresponding `*_count` fields.
- If a field is missing or empty, render it as "(no data)" or "N/A" — never invent.
- The Traffic Anomaly Window label MUST use the `traffic_anomaly_window` field;
  when that field is null/empty, render it as "(no traffic anomaly window detected)".

These rules are mandatory. Violating them produces factually wrong incident reports.

== DUAL-WINDOW ARCHITECTURE ==
Routing analysis ran over the USER'S ORIGINAL TIME WINDOW (user_analysis_window).
Traffic anomaly window is a SEPARATE signal. Routing events can precede traffic effects by 0.5-8 hours.

== CRITICAL: REASONING BEFORE CONCLUSION (Chain-of-Thought) ==
For EVERY conclusion you write, you MUST follow this EXACT structure:
  1. OBSERVE: cite the specific data point (e.g., "The routing detector found {count} origin hijack events at {time}")
  2. INFER: explain what this implies (e.g., "This means AS{target_as} was a victim of prefix hijacking")
  3. LINK: describe the observed temporal/logical relationship without asserting that it is causal
  4. CONCLUDE: state the finding as an observed association or an uncertainty, using the evidence-chain verdict
  5. CITE: explicitly reference the data source (e.g., "This aligns with correlation_analysis.delta_ts[0]")

Do NOT state a conclusion without first showing the reasoning chain.
Do NOT use language stronger than the correlation_confidence warrants.

== CRITICAL: COUNTERFACTUAL REASONING (REQUIRED) ==
You MUST include counterfactual reasoning for EVERY major conclusion. Ask:
"If the traffic drop had a different cause, what would be different?"

Include a "Counterfactual Analysis" section with:
- Alternative hypotheses: What else could explain the traffic change?
  * If NOT this hijack: Would traffic still drop? (e.g., "A DDoS attack could explain traffic drop independent of routing")
  * If NOT this outage: Would routing still be stable? (e.g., "Scheduled maintenance at the ISP could explain withdrawal without traffic impact")
- Evidence that WOULD distinguish alternatives:
  * What data would confirm this hijack is the cause?
  * What data would show a different cause?
- Confidence adjustment based on counterfactual:
  * If alternative causes are plausible, downgrade confidence

Format your counterfactual analysis as:
<div class="counterfactual">
  <h3>Counterfactual Analysis</h3>
  <p><strong>Alternative 1:</strong> [alternative explanation]</p>
  <p><strong>Evidence for:</strong> [what supports it] <cite>[citation]</cite></p>
  <p><strong>Evidence against:</strong> [what refutes it] <cite>[citation]</cite></p>
  <p><strong>Distinguishing data needed:</strong> [what would prove it]</p>
  <p><strong>Confidence adjustment:</strong> [how this affects your confidence]</p>
</div>

Do NOT skip the counterfactual section. Every report MUST have it.

== EVIDENCE CITATION RULES ==
- Every factual claim MUST cite a specific field from the data
- Format: [source: field_name] e.g., [correlation_analysis: correlation_level]
- Do NOT say "the data shows" without specifying which field
- For timestamps: always cite the specific timestamp from the timeline or delta_ts
- For counts: always cite the specific count from routing_event_count or traffic_event_count

== OBSERVATIONAL ASSOCIATION LANGUAGE ==
The available BGP and traffic observations can establish co-occurrence and association, not causation.
- When `causal_analysis.claim_tier` is `causal_hypothesis_supported`, use: "Independent external verification, mechanism evidence, and documented alternative-cause checks support a causal hypothesis; this is not causal proof." Cite the source field for every required evidence class.
- When `causal_analysis.claim_tier` is `strong_observational_association`, use: "The routing and traffic observations are temporally and semantically associated; additional evidence is needed to establish causation." Include `causal_evidence_gaps` and `causal_falsification_actions`.
- When association is false or timestamps are unavailable, use: "The available observations do not establish an association."
- A correlation score, temporal match, semantic match, Granger-like statistic, news item, or historical case alone MUST NOT satisfy any causal-claim requirement.
- Treat `evidence_chain.verdict` and `validation_notes` as binding constraints. State missing data explicitly.
- Never state or imply that a routing event caused, proved, confirmed, or directly produced a traffic change.

== ASSOCIATION INTERPRETATION ==
Use `correlation_analysis.correlation.signals` only to summarize observed signals.
Do not invent a correlation level or upgrade evidence based on threat intelligence or historical cases.
A temporal match is supportive context only; it does not resolve alternative explanations.

== THREAT INTELLIGENCE (use when available) ==
The `threat_intel_result` field contains:
  - attacker_asn, risk_score (0-100), threat_level (LOW/MEDIUM/HIGH/CRITICAL)
  - historical_hijack_count: how many hijack events this AS has been involved in
  - threat_signals: list of signals (e.g., "known hijacker", "transit AS", "newly observed")
When threat_level is HIGH or CRITICAL:
  → Upgrade the incident severity narrative
  → Mention the attacker AS's historical behaviour in root cause
  → Recommend immediate action (contact abuse, RPKI validation, IRT coordination)

== HISTORICAL CASE CONTEXT (use when available) ==
The `retrieved_context` field contains similar historical incidents:
  - Each entry: {case_id, asn, score, summary, match_reasons}
  - Use these to calibrate your confidence: if a similar historical case
    was classified L1 with the same ΔT range, weight your assessment upward.
  - If the historical case was ultimately determined to be a false positive,
    note this in the "Gaps & Limitations" section.
  - Cite historical cases by case_id in the narrative when relevant.

== REQUIRED HTML STRUCTURE ==
1. <style>: body { font-family: sans-serif; margin: 24px; line-height: 1.6; }
2. Header: AS number, user_analysis_window, traffic_anomaly_window
3. "Joint Evidence Assessment" section:
   - State the `evidence_chain.verdict` verbatim and whether data is complete
   - **Three-card joint-evidence verdict (C1/C2/C3 tier)**: Render the `joint_tier`
     and `joint_evidence_cards` as a paper-ready visualization:

     When `joint_tier` is available, add this HTML block immediately after the
     evidence-chain verdict paragraph (replace placeholders with actual data):

```html
<div class="three-card-tier">
  <h3>Three-Card Joint Evidence Tier</h3>
  <div class="tier-badge tier-{tier_lower}">
    <span class="tier-label">Tier: {joint_tier}</span>
    <span class="tier-score">avg score: {joint_score}</span>
  </div>
  <div class="evidence-cards">
    <!-- Card 1: Temporal Alignment -->
    <div class="evidence-card temporal">
      <h4>Card 1: Temporal Alignment</h4>
      <div class="card-score">{temporal_card.score}</div>
      <div class="card-details">
        <p>Matched pairs: {temporal_card.details.matched_count}</p>
        <p>Reason: {temporal_card.details.reason}</p>
      </div>
      <div class="card-status">{AVAILABLE|UNAVAILABLE}</div>
    </div>
    <!-- Card 2: Blast Radius -->
    <div class="evidence-card blast-radius">
      <h4>Card 2: Blast Radius (Prefix + Victim Traffic)</h4>
      <div class="card-score">{blast_card.score}</div>
      <div class="card-details">
        <p>Prefixes attacked: {blast_card.details.prefixes_attacked}</p>
        <p>Attacker ASNs: {blast_card.details.attacker_asns}</p>
        <p>Victim anomalies: {blast_card.details.victim_anomalies}</p>
      </div>
      <div class="card-status">{AVAILABLE|UNAVAILABLE}</div>
    </div>
    <!-- Card 3: Falsification Tree -->
    <div class="evidence-card falsification">
      <h4>Card 3: Falsification Tree</h4>
      <div class="card-score">{falsification_card.score}</div>
      <div class="card-details">
        <p>Excluded alternatives: {falsification_card.details.excluded_categories}</p>
        <p>Unexcluded alternatives: {falsification_card.details.not_excluded_categories}</p>
      </div>
      <div class="card-status">{AVAILABLE|UNAVAILABLE}</div>
    </div>
  </div>
  <style>
    .three-card-tier { border: 1px solid #ddd; padding: 16px; margin: 16px 0; border-radius: 8px; }
    .tier-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; font-size: 1.1em; }
    .tier-c3 { background: #28a745; color: white; }   /* green: strongest */
    .tier-c2 { background: #fd7e14; color: white; }   /* orange: moderate */
    .tier-c1 { background: #6c757d; color: white; }   /* gray: weak */
    .tier-insufficient { background: #dc3545; color: white; } /* red: insufficient */
    .tier-empty { background: #e9ecef; color: #333; }
    .evidence-cards { display: flex; gap: 12px; margin-top: 12px; flex-wrap: wrap; }
    .evidence-card { flex: 1; min-width: 180px; border: 1px solid #dee2e6; border-radius: 6px; padding: 12px; }
    .evidence-card.temporal { border-top: 4px solid #007bff; }
    .evidence-card.blast-radius { border-top: 4px solid #17a2b8; }
    .evidence-card.falsification { border-top: 4px solid #6f42c1; }
    .card-score { font-size: 1.6em; font-weight: bold; text-align: center; margin: 8px 0; }
    .card-status { margin-top: 8px; font-size: 0.85em; font-style: italic; color: #6c757d; }
    .card-status.unavailable { color: #dc3545; }
  </style>
  <p class="tier-rationale">{joint_rationale or 'Evidence-based assessment.'}</p>
</div>
```

     Tier color coding: C3 = green (strongest), C2 = orange (moderate), C1 = gray (weak),
     INSUFFICIENT = red (insufficient data). Use `joint_evidence_cards` to fill per-card
     scores and details; if a card's `available` is False, show the `reason` from `details`.
   - Use only observational-association language
4. "Signal Summary" section:
   - Table of key signal indicators (routing_event_count, traffic_event_count, temporal_proximity, etc.)
   - Visual indicators (✓/✗) for each signal
5. "Detailed Reasoning Chain" section:
   - OBSERVE → INFER → LINK → CONCLUDE → CITE, ending with an observational association or uncertainty
6. "Counterfactual Analysis" section (REQUIRED - DO NOT OMIT):
   - Alternative explanations for the observed events
   - Evidence supporting and refuting each alternative
   - What data would distinguish between alternatives
   - How counterfactual reasoning affects your confidence
7. "Correlation Analysis" section:
   - Pre-computed signal indicators (for reference)
   - **ΔT Table Explanation**: ΔT = 流量异常发生时间 - 最早路由异常发生时间。ΔT为正表示流量异常发生在路由异常之后（如ΔT=0.48h表示流量异常在路由异常后0.48小时出现）。ΔT为负表示流量异常先于路由异常出现。
   - **ΔT Table Format**: Display each delta_ts entry with columns: [Earliest Routing Event], [Traffic Anomaly Time], [ΔT (hours)], [Severity]. Add a note explaining what ΔT represents.
   - Refutable Hypotheses section
8. "Merged Event Timeline": chronological table of correlation_analysis.timeline
9. "Traffic Analysis": anomaly list + Chart.js visualization if traffic_plot_embedded
10. "Routing Security": hijack/leak/outage tables
11. "Gaps & Limitations": what cannot be determined
12. "Operational Recommendation": calibrated action based on YOUR determined level
13. "Auto-Probe Findings" section (REQUIRED when `auto_probe_findings` is non-empty):
   - Surface the actual results from `auto_probe_findings[]`. Each finding has
     {action, target, success, summary, execution_time_s}. Render them in a
     table with columns [Status (✅/⚠️), Probe, Target, Result Summary, Time].
   - Use the natural-language `summary` field directly — the agent has
     already collected the data; do not invent your own.
   - After the table, add a short paragraph that ties the probe results to
     the hypotheses: "Based on auto-probe findings, hypothesis X is now
     strengthened / weakened because ..."
   - This section replaces — not duplicates — the "Recommended Next Steps
     (Probing)" lists inside each hypothesis card. Operators no longer need
     to manually run the probes; results are already here.
   - If `auto_probe_findings` is empty, skip this section entirely.

== HARD RULE: TRAFFIC PLOT / CHART EMBEDDING ==
- DO NOT emit any `<img src="...">` whose `src` is an absolute filesystem
  path, a relative path, or a URL pointing to a plot artifact. Such paths
  only work on the host that generated the report; they render as broken
  images anywhere else.
- The chart is injected automatically as an embedded base64 `<img>` AFTER
  your response (just before `</body>`). If `traffic_plot_embedded == true`
  in the JSON payload, you may reference "the chart below" in narrative
  text — do not try to embed it yourself.
- In the Traffic Analysis section, do NOT include an `<img>` tag or the
  text "Chart path: ..." or "(Chart path: ...)" — those get stripped out.
  Instead, just write a placeholder note like "📊 Traffic plot is embedded
  at the end of this report" and let the injection step handle the image.
- If `traffic_plot_embedded == false`, render a textual chart summary using
  `traffic.percent_change`, `traffic.current_avg`, `traffic.historical_avg`,
  and `traffic.baseline_method` instead of an `<img>` tag.

== HARD RULE: HANDLING SOFT / VISIBLE-ONLY TRAFFIC DROPS ==
The detector can return `anomalies_detected=false` and `anomaly_count=0`
even when the traffic plot shows a clear drop inside the analysis window.
This happens when the strict consecutive-point filter clears an otherwise
real cluster. When this occurs, the payload still contains authoritative
soft evidence:
  * `traffic.percent_change` (signed): average comparison vs historical
  * `traffic.peak_trough_drop_pct` (signed): drop from PEAK to TROUGH
    *within the analysis window*. This is the actual drop visible in the
    chart and is typically MUCH HIGHER than `percent_change` (which is
    averaged). For normalized data (0-1 range), it's a fraction; for raw
    percentage data, it's a percentage value.
  * `traffic.expanded_windows[]` and `traffic.expanded_boundaries`:
    the cluster start/end the detector *did* flag
  * `traffic_anomaly_window` (top-level): the same cluster window
    surfaced for the report
  * `correlation_analysis.signals.traffic_percent_change` and
    `correlation_analysis.signals.traffic_cluster_window`: surfaced here
  * `correlation_analysis.signals.traffic_peak_trough_drop_pct`: same as
    above, exposed in the signals block
You MUST:
  (a) Render the Traffic Anomaly Window label from `traffic_anomaly_window`
      when non-empty, even if `anomaly_count == 0`.
  (b) Treat the cluster window as a real anomaly for the purposes of the
      Three-Card Tier (Card 1 Temporal Alignment), the ΔT table, and the
      "Traffic signal" badge in Signal Summary.
  (c) In "Traffic Analysis", report `peak_trough_drop_pct` as the primary
      drop metric (the actual visible drop) AND `percent_change` (the
      averaged comparison). Do NOT claim "no traffic anomaly detected"
      when the cluster window / peak_trough_drop_pct clearly indicate a drop.
  (d) Use `correlation_analysis.signals.traffic_max_severity` (which is
      pre-computed from peak_trough_drop_pct) to populate the three-card tier
      scores when individual anomalies are absent.

== REFUTABLE HYPOTHESES SECTION FORMAT ==
Render the hypotheses from correlation_analysis.hypotheses as a structured card for each.
Each hypothesis card MUST include these sub-sections:

For each hypothesis:
(a) Rank badge: show "Hypothesis [id]" with causal_type color coding:
    - routing_causes_traffic: red border (#dc3545)
    - independent_coincidence: gray border (#6c757d)
    - timing_gap: orange border (#fd7e14)
    - insufficient_data: gray border (#6c757d)

(b) Statement: the hypothesis in plain language, including ΔT and relevant counts

(c) Evidence List: each item with a citation reference to correlation_analysis fields
   Format: • [evidence text] <cite>[field_ref]</cite>

(d) Key Assumptions: each as a collapsible or inline list with risk level badge
   Format: • [assumption text] <span class="risk-high/medium">risk: high/medium</span>

(e) How to Refute: each as a structured item
   Format: • <strong>Test:</strong> [test description]
           <em>If wrong:</em> [expected result if hypothesis is wrong]
           <em>Data needed:</em> [what data would confirm/refute]

(f) Probing Recommendations: actionable next steps as a numbered list
   Format: • <strong>[action_name]</strong> — target: [target]
           method: [how to execute]

Example structure:
<div class="hypothesis-card routing-causes-traffic">
  <h3>Hypothesis A (highest confidence) — Routing → Traffic</h3>
  <p><strong>Statement:</strong> [hypothesis statement with ΔT and counts]</p>
  <h4>Supporting Evidence</h4>
  <ul>
    <li>[evidence text] <cite>[citation]</cite></li>
  </ul>
  <h4>Key Assumptions</h4>
  <ul>
    <li>[assumption text] <span class="risk-high">risk: high</span></li>
  </ul>
  <h4>How to Refute This Hypothesis</h4>
  <ul>
    <li><strong>Test:</strong> [test]
       <br><em>If wrong:</em> [expected if wrong]
       <br><em>Data needed:</em> [data needed]</li>
  </ul>
  <h4>Recommended Next Steps (Probing)</h4>
  <ol>
    <li><strong>[action]</strong> — target: [target], method: [how]</li>
  </ol>
</div>

== OUTPUT ==
Return ONLY the complete HTML file, nothing before or after it.
"""


def _safe_read_sync(bb, section: str, key: str, default=None):
    """Synchronous safe blackboard read for use in sync context."""
    try:
        sections = getattr(bb, "_sections", None)
        if sections is None:
            return default
        section_data = sections.get(section, {})
        if key is None:
            return section_data if section_data is not None else default
        val = section_data.get(key, default) if isinstance(section_data, dict) else default
        return val if val is not None else default
    except Exception:
        return default

async def _safe_read(bb, section: str, key: str, default=None):
    """Safe blackboard read: returns default if section/key is missing or None."""
    try:
        val = await bb.read(section, key, default)
        return val if val is not None else default
    except Exception:
        return default


def _json_serial(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dict__"):
        return str(obj)
    return str(obj)


# Fields that must NEVER enter the LLM payload — they explode token count
# without adding information value for report synthesis.
_PAYLOAD_DENY_FIELDS = frozenset({
    # Traffic periodicity — 4 weeks × hourly = ~672 entries of timestamp/value
    # pairs. The LLM only needs the *summary* (periodicity_confidence,
    # use_periodicity, etc.), not the raw series.
    "timestamps",
    "historical_periods",
    "values",
    "daily_correlations",
    "weekly_correlations",
    # Routing raw dumps — every hijack event already has prefix/as_path; the
    # full per-event AS path string is duplicated across hundreds of events.
    "raw_announcements",
    "raw_output",
    "raw_observations",
    "as_paths",
    "as_path",
    # Multi-scale analysis — 5 scales × ~5 fields = small, but each has a
    # nested "details" object the LLM doesn't need.
    "scales",
    # Reasoning internals — full causal_correlation_scorer output, raw
    # counterfactual JSON, etc. The LLM gets the pre-computed summary fields
    # from the workflow engine; passing the raw scorer payload blows the
    # budget.
    "raw_score_breakdown",
    "raw_features",
    "feature_breakdown",
    "noise",
    # Result containers — chief_agent nests traffic_result+routing_result
    # inside the chief_expert_analysis envelope. Strip the duplicates so the
    # payload isn't 3× the necessary size.
    "traffic_result",
    "routing_result",
    "evidence_summary",
    # Plotting metadata — LLM doesn't need the raw path string
    "plot_path",
    "data_points",
})


def _estimate_size(obj: Any) -> int:
    """Rough byte size for size-bounding decisions (not exact JSON length)."""
    try:
        import json as _json
        return len(_json.dumps(obj, default=str))
    except Exception:
        return 0


_MAX_PAYLOAD_BYTES = 200_000  # ~50K tokens; well below Kimi's 128K limit


def _trim_to_size(data: Any, max_bytes: int = _MAX_PAYLOAD_BYTES) -> Any:
    """Trim a (slimmed) payload down to a hard byte cap.

    Recursively drops the longest lists first until the JSON-serialized form
    fits inside ``max_bytes``. Used as a final guardrail before the LLM call
    so a noisy event (thousands of routing events, multi-week traffic
    history) never explodes the prompt.
    """
    if _estimate_size(data) <= max_bytes:
        return data

    def _shrink_lists(obj: Any, lists_seen: list) -> Any:
        """Replace the longest lists with shorter versions until size fits."""
        if isinstance(obj, dict):
            return {k: _shrink_lists(v, lists_seen) for k, v in obj.items()}
        if isinstance(obj, list):
            lists_seen.append(obj)
            return [_shrink_lists(v, lists_seen) for v in obj]
        return obj

    # First pass: halve all lists repeatedly until the payload fits.
    shrunk = data
    for _ in range(20):
        lists = []
        _shrink_lists(shrunk, lists)
        if not lists:
            break
        for lst in lists:
            if len(lst) > 3:
                # Keep first/last, drop middle. Preserves timeline edges
                # which is what the LLM needs for narrative coherence.
                keep = max(1, len(lst) // 4)
                lst[:] = lst[:keep] + lst[-keep:]
        if _estimate_size(shrunk) <= max_bytes:
            return shrunk

    # Last resort: drop entire top-level sections that aren't critical for
    # the report narrative.
    if isinstance(shrunk, dict):
        for k in list(shrunk.keys()):
            if k in {
                "victim_traffic_results",
                "prefix_traffic_results",
                "as_path_delta_result",
                "as_relationships_result",
                "probe_reachability_result",
                "law_analysis",
                "retrieved_context",
                "evidence_board",
                "hcaf_attribution",
                "calibration",
                "bayesian_result",
                "joint_evidence_cards",
            }:
                shrunk[k] = {"trimmed": "size_limit_reached"}
                if _estimate_size(shrunk) <= max_bytes:
                    return shrunk

    # last resort: hard truncate if still over limit
    final_size = _estimate_size(shrunk)
    if final_size > max_bytes:
        import json as _json
        try:
            # 尝试截断 JSON 字符串
            json_str = _json.dumps(shrunk, ensure_ascii=False, default=str)
            if len(json_str) > max_bytes:
                # 在 JSON 字符串中间截断，添加警告标记
                half = max_bytes // 2
                warning_marker = (
                    f', "__PAYLOAD_TRUNCATED_WARNING__": '
                    f'"Payload exceeded {max_bytes} bytes limit ({final_size} bytes). '
                    f'Some data was truncated. See original data source for complete information."'
                )
                # 尝试在合适的位置插入警告
                truncated = json_str[:half] + warning_marker + json_str[-half:]
                shrunk = _json.loads(truncated) if len(truncated) <= max_bytes * 1.1 else shrunk
        except Exception:
            pass  # 截断失败，保持原样

        from utils.logger import logger
        logger.warning(
            f"[ReportAgent] Payload still exceeds {max_bytes} bytes after all trim strategies "
            f"(size={final_size}). LLM call may receive incomplete data."
        )

    return shrunk


def _slim(data: Any, limit: int = 10, _depth: int = 0) -> Any:
    """Recursively truncate long lists/dicts for the LLM prompt.

    Drops any field whose name is in `_PAYLOAD_DENY_FIELDS` — those fields
    consume tokens without informing the report (raw timestamps, periodic
    history, full AS paths, raw tool output, etc.).
    """
    if _depth > 50:
        return None
    if isinstance(data, dict):
        return {
            k: _slim(v, limit, _depth + 1)
            for k, v in list(data.items())[:50]
            if k not in _PAYLOAD_DENY_FIELDS
        }
    if isinstance(data, list):
        return [_slim(v, limit, _depth + 1) for v in data[:limit]]
    return data


class TemporalEvent:
    """A timestamped anomaly event from either traffic or routing detection."""
    def __init__(
        self,
        timestamp: datetime,
        source: Literal["traffic", "routing"],
        event_type: str,
        severity: float,
        details: dict,
        asn: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.source = source  # "traffic" or "routing"
        self.event_type = event_type  # e.g., "traffic_drop", "origin_hijack", "route_leak"
        self.severity = severity  # 0-1, z-score normalized
        self.details = details
        self.asn = asn  # relevant AS for routing events


def _parse_time(ts: Any) -> Optional[datetime]:
    """Parse a timestamp string to datetime, trying multiple formats."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    ts_str = str(ts).replace("Z", "+00:00").rstrip("Z")
    
    # Try strptime with various formats - use FULL format string, not truncated
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S%z",
        # American date format: 10/30/24 13:20:11 (used in annotation_package route_check.json)
        "%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M",
        # Also try full string with full format (not truncated)
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
        # European date format: 03/01/2024 14:46:25
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
        # Short formats
        "%Y-%m-%d", "%d-%m-%Y",
        # With timezone
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z",
    ]:
        try:
            # Use full format string to parse full timestamp (not truncated)
            return datetime.strptime(ts_str, fmt)
        except (ValueError, IndexError):
            # If full parse fails, try with truncated timestamp if needed
            pass
    
    # Try truncated timestamps with truncated formats
    for fmt in [
        "%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M",
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
    ]:
        truncated = ts_str[:19]
        try:
            return datetime.strptime(truncated, fmt)
        except (ValueError, IndexError):
            pass
    
    # Try ISO format
    try:
        return datetime.fromisoformat(ts_str[:19])
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        pass
    
    # Last resort: try to extract date/time with regex
    import re
    # Match patterns like "Jan 3, 2024" or "January 03, 2024"
    month_names = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12
    }
    match = re.match(r'(\w+)\s+(\d+),?\s+(\d+)', ts_str)
    if match:
        month_str, day, year = match.groups()
        month_str = month_str.lower()[:3]
        if month_str in month_names:
            try:
                return datetime(int(year), month_names[month_str], int(day))
            except ValueError:
                pass
    
    return None


def _extract_traffic_events(
    traffic_raw: dict,
    traffic_anomaly_window: Optional[dict] = None,
) -> list[TemporalEvent]:
    """Extract traffic anomaly events with timestamps.

    Handles multiple formats:
    1. Direct format: {"anomalies": [...]}
    2. Nested format: {"result": {"anomalies": [...]}}
    3. Annotation_package format: {"extended_anomalies": [...]}

    Fallback (when the filtered anomaly list is empty):
    - Build synthetic events from `expanded_windows` /
      `expanded_boundaries` / `traffic_anomaly_window` so that
      correlation features (ΔT, three-card tier, traffic_max_severity)
      are still populated and the report can reflect the *visible*
      traffic drop visible in the chart, even when the strict
      consecutive-anomaly filter cleared the per-point list.
    """
    events: list[TemporalEvent] = []

    # Normalize traffic_raw to handle multiple formats
    tr = traffic_raw
    if isinstance(tr, dict):
        # Check if wrapped in "result" key (blackboard format)
        if "result" in tr and isinstance(tr["result"], dict):
            tr = tr["result"]

    # Try multiple anomaly keys
    anomalies = tr.get("anomalies", []) or []
    if not anomalies:
        anomalies = tr.get("extended_anomalies", []) or []
    if not anomalies:
        anomalies = tr.get("peak_anomalies", []) or []

    pct_change_raw = tr.get("percent_change") if isinstance(tr, dict) else None
    try:
        pct_change_val = float(pct_change_raw) if pct_change_raw is not None else 0.0
    except (TypeError, ValueError):
        pct_change_val = 0.0

    for a in anomalies:
        ts = _parse_time(a.get("timestamp") or a.get("time"))
        if ts is None:
            continue

        direction = a.get("direction", "unknown")
        current_val = a.get("current_value") or a.get("value", 0)
        z_score = abs(float(a.get("z_score") or 0))
        mean_val = a.get("mean") or 0.001
        pct_change = abs(float(a.get("pct_change") or 0))

        # Normalize severity to [0, 1]
        severity = min(1.0, z_score / 5.0)

        events.append(TemporalEvent(
            timestamp=ts,
            source="traffic",
            event_type=f"traffic_{direction}",
            severity=severity,
            details={
                "value": current_val,
                "mean": mean_val,
                "z_score": z_score,
                "pct_change": pct_change,
                "direction": direction,
            },
        ))

    if events:
        return sorted(events, key=lambda e: e.timestamp)

    # ── Fallback: synthesize events from cluster windows ─────────────────────
    # The detector's `filter_consecutive_anomalies(min_consecutive=2)` can wipe
    # out a single-point drop, but the cluster window / expanded boundaries
    # still pin the *time range* where traffic looked anomalous.  Surface that
    # as a synthetic event so downstream correlation features have something
    # to work with (ΔT, three-card tier, severity).
    
    # Get peak-to-trough drop for severity calculation (more accurate than
    # the average-based percent_change).
    peak_trough_drop_pct = 0.0
    try:
        peak_trough_drop_pct = float(tr.get("peak_trough_drop_pct") or 0)
    except (TypeError, ValueError):
        peak_trough_drop_pct = 0.0
    
    window_candidates: list[dict] = []
    for key in ("expanded_windows", "consecutive_anomaly_windows"):
        wins = tr.get(key) or []
        if isinstance(wins, list):
            window_candidates.extend([w for w in wins if isinstance(w, dict)])

    if traffic_anomaly_window and isinstance(traffic_anomaly_window, dict):
        window_candidates.append(traffic_anomaly_window)

    expanded_boundaries = tr.get("expanded_boundaries")
    if isinstance(expanded_boundaries, dict):
        window_candidates.append(expanded_boundaries)

    for w in window_candidates:
        start_ts = _parse_time(w.get("start") or w.get("expanded_start") or w.get("detected_start"))
        end_ts = _parse_time(w.get("end") or w.get("expanded_end") or w.get("detected_end"))
        if not start_ts or not end_ts:
            continue
        if start_ts == end_ts:
            end_ts = start_ts

        anomaly_count = int(w.get("anomaly_count", w.get("indices_len", 0)) or 0)

        # Derive severity from peak_trough_drop_pct (more accurate than
        # the average-based percent_change). Use peak_trough_drop_pct if
        # available, otherwise fall back to percent_change.
        if peak_trough_drop_pct > 0:
            # For normalized data (values 0-1), the drop is a fraction
            # For percentage data (values 0-100), convert to fraction
            if peak_trough_drop_pct > 10:  # Likely percentage data
                severity = min(1.0, peak_trough_drop_pct / 100.0)
            else:  # Likely normalized data (0-1 range)
                severity = min(1.0, peak_trough_drop_pct)
        else:
            # Fallback to percent_change (less accurate)
            severity = min(1.0, abs(pct_change_val) / 50.0)  # 50% drop -> max
        # If the cluster itself had at least 1 anomaly point, ensure non-zero
        severity = max(severity, 0.4 if anomaly_count > 0 else 0.0)

        midpoint = start_ts + (end_ts - start_ts) / 2
        events.append(TemporalEvent(
            timestamp=midpoint,
            source="traffic",
            event_type="traffic_cluster_anomaly",
            severity=severity,
            details={
                "synthesized_from": "expanded_window",
                "start": start_ts.isoformat(),
                "end": end_ts.isoformat(),
                "duration_minutes": round((end_ts - start_ts).total_seconds() / 60.0, 2),
                "cluster_anomaly_count": anomaly_count,
                "pct_change": pct_change_val,
                "peak_trough_drop_pct": peak_trough_drop_pct,
                "current_avg": tr.get("current_avg"),
                "historical_avg": tr.get("historical_avg"),
                "baseline_method": tr.get("baseline_method"),
            },
        ))

    # Deduplicate synthetic events by midpoint timestamp (multiple window
    # candidates can produce identical entries).
    seen_midpoints = set()
    deduped = []
    for ev in sorted(events, key=lambda e: e.timestamp):
        mp = ev.timestamp.isoformat()
        if mp in seen_midpoints:
            continue
        seen_midpoints.add(mp)
        deduped.append(ev)

    return deduped


def _load_routing_events_from_saved_json(target_as: str) -> Optional[list[TemporalEvent]]:
    """
    Load routing events from the most recent saved hijack alerts JSON.
    This is a fallback when the blackboard data has been cleared.
    """
    if not target_as:
        return None
    try:
        json_dir = Path(__file__).resolve().parent.parent / "results" / "json"
        if not json_dir.exists():
            return None
        files = sorted(json_dir.glob(f"hijack_alerts_AS{target_as}_*.json"), key=lambda p: p.stat().st_mtime)
        if not files:
            return None
        latest = files[-1]
        data = json.loads(latest.read_text(encoding="utf-8"))
        alerts = data.get("alerts", {})
        events = []
        for h in (alerts.get("origin_hijacks") or []):
            if not isinstance(h, dict):
                continue
            ts = _parse_time(h.get("timestamp") or h.get("first_seen") or h.get("time"))
            if ts is None:
                continue
            hijack_type = h.get("hijack_type") or h.get("type") or ""
            if "hijacked" in hijack_type or "victim" in hijack_type.lower():
                event_type = "origin_hijacked"
                role = "victim"
            else:
                event_type = "origin_hijacking"
                role = "attacker"
            events.append(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type=event_type,
                severity=1.0,
                details={
                    "prefix": h.get("prefix"),
                    "hijacker_as": h.get("hijacker_as") or "",
                    "victim_as": h.get("victim_as") or h.get("target_as") or "",
                    "role": role,
                    "as_path": h.get("as_path"),
                },
                asn=h.get("victim_as") or h.get("target_as"),
            ))
        for h in (alerts.get("mitm_hijacks") or []):
            if not isinstance(h, dict):
                continue
            ts = _parse_time(h.get("timestamp") or h.get("time"))
            if ts is None:
                continue
            events.append(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type="mitm_hijack",
                severity=1.0,
                details={"prefix": h.get("prefix"), "hijacker_as": h.get("hijacker_as")},
            ))
        events.sort(key=lambda e: e.timestamp)
        if events:
            logger.info(f"Loaded {len(events)} routing events from saved JSON: {latest.name}")
        return events
    except Exception as exc:
        logger.warning(f"Failed to load routing events from saved JSON: {exc}")
        return None


def _extract_routing_events(routing_result: dict, target_as: str = "") -> list[TemporalEvent]:
    """
    Extract routing anomaly events with timestamps.
    Handles multiple formats:
    1. Direct format (from _prepare_routing_payload): top-level keys like origin_hijacked, origin_hijacking
    2. Nested alerts format (from saved JSON): alerts.origin_hijacks
    3. annotation_package format: {"hijack": {"origin_hijacked": [...]}}
    Uses a seen set to deduplicate events that appear in both formats.
    Falls back to loading from saved JSON if blackboard data is empty.
    """
    events = []

    # The report must only use evidence collected for this run. Loading a prior
    # run's saved JSON would contaminate an empty result with stale alerts.
    # Callers should report the missing routing evidence instead.
    seen = set()

    def _add(event: TemporalEvent):
        key = (str(event.timestamp), event.event_type, str(event.details.get("prefix", "")))
        if key not in seen:
            seen.add(key)
            events.append(event)

    # Normalize routing_result to handle multiple formats:
    # 1. If there's a "result" key, unwrap it (blackboard format)
    # 2. If there's a "hijack" key, use it as the primary section (annotation_package format)
    # 3. Otherwise use the data directly (flat format from _prepare_routing_payload)
    rr = routing_result
    if isinstance(rr, dict):
        # Check if wrapped in "result" key (blackboard format)
        if "result" in rr and isinstance(rr["result"], dict):
            rr = rr["result"]
        # If we still don't have the event keys, check for annotation_package nested format
        hijack_section = rr.get("hijack") or {}
        leak_section = rr.get("leak") or {}
        # For annotation_package format, merge the nested data into flat format for easier processing
        if hijack_section or leak_section:
            # Create a flat view that prefers top-level keys but falls back to nested
            rr = dict(rr)  # Make a copy to avoid mutating original
            for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
                if key not in rr or not rr.get(key):
                    rr[key] = hijack_section.get(key)
            for key in ["route_leaks"]:
                if key not in rr or not rr.get(key):
                    rr[key] = leak_section.get(key)
        # Origin hijacked (victim role) — merged rr ensures annotation_package fallback
        for h in (rr.get("origin_hijacked") or []):
            ts = _parse_time(h.get("timestamp") or h.get("first_seen") or h.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type="origin_hijacked",
                severity=1.0,
                details={
                    "prefix": h.get("prefix"),
                    "hijacker_as": h.get("hijacker_as") or h.get("asn"),
                    "role": "victim",
                },
                asn=h.get("victim_as") or h.get("target_as") or h.get("asn"),
            ))

        # Origin hijacking (attacker role)
        for h in (rr.get("origin_hijacking") or []):
            ts = _parse_time(h.get("timestamp") or h.get("first_seen") or h.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
            timestamp=ts,
            source="routing",
            event_type="origin_hijacking",
            severity=1.0,
            details={
                "prefix": h.get("prefix"),
            "claimed_as": h.get("claimed_as") or h.get("asn"),
            "role": "attacker",
                },
            asn=h.get("asn"),
            ))

            # Forge hijacked (victim)
        for h in (rr.get("forge_hijacked") or []):
            ts = _parse_time(h.get("timestamp") or h.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
            timestamp=ts,
            source="routing",
            event_type="forge_hijacked",
            severity=1.0,
                details={"prefix": h.get("prefix"), "hijacker_as": h.get("hijacker_as")},
            asn=h.get("asn"),
            ))

            # Forge hijacking (attacker)
        for h in (rr.get("forge_hijacking") or []):
            ts = _parse_time(h.get("timestamp") or h.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
            timestamp=ts,
            source="routing",
            event_type="forge_hijacking",
            severity=1.0,
                details={"prefix": h.get("prefix"), "claimed_as": h.get("claimed_as") or h.get("asn")},
            asn=h.get("asn"),
            ))

            # Route leaks
        for lk in (rr.get("route_leaks") or []):
            ts = _parse_time(lk.get("timestamp") or lk.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
            timestamp=ts,
            source="routing",
            event_type="route_leak",
            severity=0.8,
                details={"prefix": lk.get("prefix"), "leaked_by": lk.get("leaked_by")},
            ))

    # ---- Format 2b: annotation_package nested {hijack:{}, leak:{}, outage:{}} ----
    # Live flat format and alerts format above miss this format used by
    # annotation_package route_check.json. Without this fallback,
    # annotation_package-driven runs would silently drop hijack events.
    hijack_section = routing_result.get("hijack") or {}
    if isinstance(hijack_section, dict):
        for key, ev_type, role, hijacker_field, claimed_field, victim_field in (
            ("origin_hijacked", "origin_hijacked", "victim", "hijacker_as", None, "victim_as"),
            ("origin_hijacking", "origin_hijacking", "attacker", "hijacker_as", "claimed_as", None),
            ("forge_hijacked", "forge_hijacked", "victim", "hijacker_as", None, "victim_as"),
            ("forge_hijacking", "forge_hijacking", "attacker", "hijacker_as", "claimed_as", None),
        ):
            for h in (hijack_section.get(key) or []):
                if not isinstance(h, dict):
                    continue
                ts = _parse_time(h.get("timestamp") or h.get("first_seen") or h.get("time"))
                if ts is None:
                    continue
                details = {"prefix": h.get("prefix"), "role": role}
                if hijacker_field:
                    details["hijacker_as"] = h.get(hijacker_field) or h.get("asn")
                if claimed_field:
                    details["claimed_as"] = h.get(claimed_field) or h.get("asn")
                if victim_field:
                    details["victim_as"] = h.get(victim_field) or h.get("target_as") or h.get("asn")
                _add(TemporalEvent(
                    timestamp=ts,
                    source="routing",
                    event_type=ev_type,
                    severity=1.0,
                    details=details,
                    asn=h.get("victim_as") or h.get("asn"),
                ))
        # annotation_package: leaks under leak.route_leaks
        for lk in ((routing_result.get("leak") or {}).get("route_leaks") or []):
            if not isinstance(lk, dict):
                continue
            ts = _parse_time(lk.get("timestamp") or lk.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type="route_leak",
                severity=0.8,
                details={"prefix": lk.get("prefix"), "leaked_by": lk.get("leaked_by")},
            ))
        # annotation_package: outages under outage.outages (or outage.is_outage_suspected)
        outage_section = routing_result.get("outage") or {}
        if isinstance(outage_section, dict):
            for oe in (outage_section.get("outages") or []):
                if not isinstance(oe, dict):
                    continue
                ts = _parse_time(oe.get("timestamp") or oe.get("time"))
                if ts is None:
                    continue
                _add(TemporalEvent(
                    timestamp=ts,
                    source="routing",
                    event_type="outage",
                    severity=0.9,
                    details={"prefix": oe.get("prefix"), "asn": oe.get("asn") or oe.get("affected_as")},
                ))

    # ---- Format 2: Nested alerts dict (saved per-batch JSON) ----
    alerts = routing_result.get("alerts", {})
    if isinstance(alerts, dict):
        for h in (alerts.get("origin_hijacks") or []):
            if not isinstance(h, dict):
                continue
            ts = _parse_time(h.get("timestamp") or h.get("first_seen") or h.get("time"))
            if ts is None:
                continue
            hijack_type = h.get("hijack_type") or h.get("type") or ""
            is_victim = "hijacked" in hijack_type or "victim" in hijack_type.lower()
            if is_victim:
                event_type = "origin_hijacked"
                role = "victim"
                hijacker_as = h.get("hijacker_as") or ""
                victim_as = h.get("victim_as") or h.get("target_as") or ""
            else:
                event_type = "origin_hijacking"
                role = "attacker"
                hijacker_as = h.get("hijacker_as") or ""
                victim_as = h.get("victim_as") or ""
            _add(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type=event_type,
                severity=1.0,
                details={
                    "prefix": h.get("prefix"),
                    "hijacker_as": hijacker_as,
                    "victim_as": victim_as,
                    "role": role,
                    "as_path": h.get("as_path"),
                },
                asn=victim_as,
            ))

        for h in (alerts.get("mitm_hijacks") or []):
            if not isinstance(h, dict):
                continue
            ts = _parse_time(h.get("timestamp") or h.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type="mitm_hijack",
                severity=1.0,
                details={"prefix": h.get("prefix"), "hijacker_as": h.get("hijacker_as")},
            ))

        for lk in (alerts.get("route_leaks") or []):
            if not isinstance(lk, dict):
                continue
            ts = _parse_time(lk.get("timestamp") or lk.get("time"))
            if ts is None:
                continue
            _add(TemporalEvent(
                timestamp=ts,
                source="routing",
                event_type="route_leak",
                severity=0.8,
                details={"prefix": lk.get("prefix"), "leaked_by": lk.get("leaked_by")},
            ))

    return sorted(events, key=lambda e: e.timestamp)


def _compute_delta_t(
    traffic_events: list[TemporalEvent],
    routing_events: list[TemporalEvent],
    traffic_anomaly_window: Optional[dict] = None,
) -> list[dict]:
    """
    Compute temporal offset (ΔT) between each traffic event and the earliest routing event.
    ΔT = traffic_event_time - earliest_routing_event_time
    
    If no traffic events are present but a cluster window is available,
    synthesize a single entry using the cluster midpoint.
    """
    if not routing_events:
        return []
    earliest_routing = min(e.timestamp for e in routing_events)

    results = []
    for te in traffic_events:
        # Handle timezone-aware vs naive datetime comparison
        te_ts = te.timestamp
        er_ts = earliest_routing
        
        # If one is timezone-aware and the other is naive, make both naive (assume UTC)
        if te_ts.tzinfo is not None and er_ts.tzinfo is None:
            # traffic has timezone, routing doesn't - assume routing is UTC
            er_ts = er_ts.replace(tzinfo=te_ts.tzinfo)
        elif te_ts.tzinfo is None and er_ts.tzinfo is not None:
            # routing has timezone, traffic doesn't - assume traffic is UTC
            te_ts = te_ts.replace(tzinfo=er_ts.tzinfo)
        
        delta = te_ts - er_ts
        delta_hours = delta.total_seconds() / 3600
        results.append({
            "traffic_ts": te.timestamp.isoformat(),
            "traffic_type": te.event_type,
            "earliest_routing_ts": earliest_routing.isoformat(),
            "delta_hours": round(delta_hours, 2),
            "traffic_severity": te.severity,
            "direction": te.details.get("direction", "unknown"),
        })
    
    # Fallback: synthesize a ΔT entry from cluster window if we have one but
    # no individual traffic events. This way the report's ΔT table is never
    # empty when there *is* a visible-but-soft cluster.
    if not results and traffic_anomaly_window:
        try:
            cluster_start = traffic_anomaly_window.get("start") or traffic_anomaly_window.get("detected_start")
            cluster_end = traffic_anomaly_window.get("end") or traffic_anomaly_window.get("detected_end")
            cs = datetime.fromisoformat(str(cluster_start).replace("Z", "+00:00")).replace(tzinfo=None)
            ce = datetime.fromisoformat(str(cluster_end).replace("Z", "+00:00")).replace(tzinfo=None)
            
            # Use cluster midpoint as the traffic anchor
            midpoint = cs + (ce - cs) / 2
            delta = midpoint - earliest_routing.replace(tzinfo=None)
            delta_hours = delta.total_seconds() / 3600
            results.append({
                "traffic_ts": midpoint.isoformat(),
                "traffic_type": "traffic_cluster_anomaly",
                "earliest_routing_ts": earliest_routing.isoformat(),
                "delta_hours": round(delta_hours, 2),
                "traffic_severity": 0.4,  # placeholder; real severity from signals
                "direction": "drop",
                "synthesized_from_cluster_window": True,
            })
        except Exception:
            pass
    
    return results


def _assign_correlation_level(
    traffic_events: list[TemporalEvent],
    routing_events: list[TemporalEvent],
    delta_ts: list[dict],
    traffic_anomaly_window: Optional[dict] = None,
    traffic_raw: Optional[dict] = None,
) -> dict:
    """
    Pre-compute correlation signals for LLM to reason about.

    NOTE: This function provides SIGNAL INDICATORS only.
    The actual L1-L5 classification should be determined by the LLM
    based on ALL available evidence (routing_events, traffic_events,
    delta_ts, threat_intel, hypotheses, historical_context).

    This allows the LLM to:
    - Consider the TYPE of event (hijack vs leak vs outage)
    - Weigh the quality vs quantity of signals
    - Factor in external context (threat intel, news, historical cases)

    Returns signal indicators that LLM uses for reasoning:
    - routing_signal_present: bool
    - traffic_signal_present: bool
    - temporal_proximity: str ("strong"/"moderate"/"weak"/"none")
    - signal_counts: dict

    Optional arguments:
    - traffic_anomaly_window: a cluster {start,end} that the detector
      flagged even when the strict anomaly list is empty.  When present
      we surface a non-zero severity and a meaningful `confidence`.
    - traffic_raw: the original traffic dict, used to pull `percent_change`
      when computing fallback severity.
    """
    routing_count = len(routing_events)
    traffic_count = len(traffic_events)
    traffic_max_severity = max((e.severity for e in traffic_events), default=0)

    # ── Fallback severity when no individual anomalies but the chart ────────
    # shows a clear drop.  Use the detector's `peak_trough_drop_pct` (peak-to-trough
    # drop within the window) to derive a meaningful traffic_max_severity.
    # This better reflects what's visible in the chart than the average-based percent_change.
    pct_change = 0.0
    peak_trough_drop_pct = 0.0
    trough_drop_from_peak = 0.0
    peak_value = 0.0
    trough_value = 0.0
    
    if traffic_raw and isinstance(traffic_raw, dict):
        # Try to get peak-to-trough drop first (more accurate for visible drops)
        peak_trough_drop_pct = float(traffic_raw.get("peak_trough_drop_pct") or 0)
        trough_drop_from_peak = float(traffic_raw.get("trough_drop_from_peak") or 0)
        peak_value = float(traffic_raw.get("peak_value") or 0)
        trough_value = float(traffic_raw.get("trough_value") or 0)
        
        # Also get the traditional percent_change
        try:
            pct_change = float(traffic_raw.get("percent_change") or 0)
        except (TypeError, ValueError):
            pct_change = 0.0
            
        # Try wrapped result
        if pct_change == 0 and peak_trough_drop_pct == 0:
            inner = traffic_raw.get("result") if isinstance(traffic_raw, dict) else None
            if isinstance(inner, dict):
                peak_trough_drop_pct = float(inner.get("peak_trough_drop_pct") or 0)
                trough_drop_from_peak = float(inner.get("trough_drop_from_peak") or 0)
                peak_value = float(inner.get("peak_value") or 0)
                trough_value = float(inner.get("trough_value") or 0)
                try:
                    pct_change = float(inner.get("percent_change") or 0)
                except (TypeError, ValueError):
                    pct_change = 0.0

    if traffic_count == 0 and traffic_anomaly_window:
        # Synthetic cluster-only signal — derive severity from peak_trough_drop_pct.
        # Use peak-to-trough drop percentage for more accurate severity.
        # For normalized data (0-1 range), a 50% drop from peak = 0.5 severity
        # For raw percentage data, scale appropriately
        if peak_trough_drop_pct > 0:
            # For normalized data (values ~0-1), the drop is already a fraction
            # For percentage data (values ~0-100), convert to fraction
            if peak_trough_drop_pct > 10:  # Likely percentage data
                pct_severity = min(1.0, peak_trough_drop_pct / 100.0)
            else:  # Likely normalized data (0-1 range)
                pct_severity = min(1.0, peak_trough_drop_pct)
        else:
            # Fallback to traditional percent_change (less accurate)
            pct_severity = min(1.0, abs(pct_change) / 50.0)  # 50% drop -> max
        traffic_max_severity = max(traffic_max_severity, pct_severity)

    # Build signal indicators for LLM reasoning
    # Treat a non-empty cluster window as "traffic signal present" so the
    # downstream correlation level can resolve to something other than "none".
    has_cluster_signal = bool(traffic_anomaly_window) and bool(
        (traffic_anomaly_window.get("start") or traffic_anomaly_window.get("detected_start"))
        and (traffic_anomaly_window.get("end") or traffic_anomaly_window.get("detected_end"))
    )

    signals = {
        "routing_signal_present": routing_count > 0,
        "routing_event_count": routing_count,
        "traffic_signal_present": traffic_count > 0 or has_cluster_signal,
        "traffic_event_count": traffic_count,
        "traffic_max_severity": traffic_max_severity,
        "delta_ts_available": len(delta_ts) > 0,
        "delta_ts_count": len(delta_ts),
        "traffic_percent_change": pct_change,
        "traffic_peak_trough_drop_pct": peak_trough_drop_pct,
        "traffic_trough_drop_from_peak": trough_drop_from_peak,
        "traffic_peak_value": peak_value,
        "traffic_trough_value": trough_value,
        "traffic_cluster_window": traffic_anomaly_window,
    }

    # Compute temporal proximity signal
    if delta_ts:
        min_delta = min(abs(d["delta_hours"]) for d in delta_ts)
        if min_delta <= 8:
            signals["temporal_proximity"] = "strong" if min_delta <= 2 else "moderate"
        elif min_delta <= 24:
            signals["temporal_proximity"] = "weak"
        else:
            signals["temporal_proximity"] = "none"
    elif has_cluster_signal and routing_count > 0:
        # No per-event ΔT computed (because no individual anomaly), but a
        # cluster window exists and routing events were detected.  Use the
        # gap between the routing event start and the cluster midpoint.
        try:
            from datetime import datetime as _dt
            cluster_start = traffic_anomaly_window.get("start") or traffic_anomaly_window.get("detected_start")
            cluster_end = traffic_anomaly_window.get("end") or traffic_anomaly_window.get("detected_end")
            cs = _dt.fromisoformat(str(cluster_start).replace("Z", "+00:00"))
            ce = _dt.fromisoformat(str(cluster_end).replace("Z", "+00:00"))
            earliest_routing = min((e.timestamp for e in routing_events), default=None)
            if earliest_routing is not None:
                midpoint = cs + (ce - cs) / 2
                delta_hours = (midpoint - earliest_routing).total_seconds() / 3600
                if delta_hours <= 8:
                    signals["temporal_proximity"] = "strong" if delta_hours <= 2 else "moderate"
                elif delta_hours <= 24:
                    signals["temporal_proximity"] = "weak"
                else:
                    signals["temporal_proximity"] = "none"
        except Exception:
            signals["temporal_proximity"] = "none"
    else:
        signals["temporal_proximity"] = "none"

    # For hijack events: even 1-2 routing events can be significant
    hijack_events = [e for e in routing_events if "hijack" in e.event_type]
    leak_events = [e for e in routing_events if "leak" in e.event_type]
    signals["hijack_events_count"] = len(hijack_events)
    signals["leak_events_count"] = len(leak_events)

    # Confidence calibration:
    # When we have explicit individual traffic events with timestamps + a ΔT
    # entry, confidence rises to 0.8.  When only a cluster window (no per-event
    # timestamps) is available, confidence is 0.6 — there *is* evidence, but
    # we cannot align it point-for-point with routing events.  Default 0.5 only
    # applies when no traffic data of any kind exists.
    if delta_ts and traffic_count > 0:
        confidence = 0.8
    elif has_cluster_signal and routing_count > 0:
        confidence = 0.6
    elif has_cluster_signal or traffic_count > 0:
        confidence = 0.55
    else:
        confidence = 0.5

    # Return signal indicators (LLM will determine final level)
    return {
        "level": "SIGNALS_PRECOMPUTED",  # Flag: LLM should determine level
        "label": "Signal Indicators Provided",
        "signals": signals,
        "delta_ts_summary": [
            {"earliest_routing": d.get("earliest_routing_ts"),
             "traffic_ts": d.get("traffic_ts"),
             "delta_hours": d.get("delta_hours")}
            for d in delta_ts[:5]
        ] if delta_ts else [],
        "reasoning": (
            f"Routing signal: {routing_count} events ({len(hijack_events)} hijacks, {len(leak_events)} leaks). "
            f"Traffic signal: {traffic_count} events, max severity={traffic_max_severity:.2f}, "
            f"percent_change={pct_change:.2f}%, cluster_window={'yes' if has_cluster_signal else 'no'}. "
            f"Temporal proximity: {signals['temporal_proximity']}. "
            f"These are observational signals and do not establish causation."
        ),
        "confidence": confidence,
    }


def _build_merged_timeline(
    traffic_events: list[TemporalEvent],
    routing_events: list[TemporalEvent],
) -> list[dict]:
    """Build a merged chronological timeline of all events."""
    all_events = []
    for e in traffic_events:
        all_events.append({
            "timestamp": e.timestamp.isoformat(),
            "source": "traffic",
            "type": e.event_type,
            "severity": e.severity,
            "details": e.details,
        })
    for e in routing_events:
        all_events.append({
            "timestamp": e.timestamp.isoformat(),
            "source": "routing",
            "type": e.event_type,
            "severity": e.severity,
            "details": e.details,
        })
    all_events.sort(key=lambda x: x["timestamp"])
    return all_events


def _cross_validate_correlation(
    correlation: dict,
    correlation_score_result: dict | None,
) -> dict:
    """
    Cross-validate correlation signals with quantitative correlation score.

    The Python function summarizes observed routing and traffic signals together
    with the quantitative association score. It does not convert those signals
    into causal evidence or delegate a causal determination to the LLM.

    This function provides:
    - verdict: an observational-only status for the report
    - score_context: quantitative association data for evidence citation
    - signal_summary: condensed observed signal indicators
    """
    score_total: int | None = None
    level_from_score: str | None = None
    avg_delta_hours: float | None = None

    if correlation_score_result and isinstance(correlation_score_result, dict):
        score_total = correlation_score_result.get("total_score")
        level_from_score = correlation_score_result.get("correlation_level", "NONE")
        avg_delta_hours = correlation_score_result.get("avg_delta_hours")

    # Keep the computed score as evidence context; it is not causal proof.
    signals = correlation.get("signals", {})
    routing_count = signals.get("routing_event_count", 0)
    traffic_count = signals.get("traffic_event_count", 0)
    temporal_proximity = signals.get("temporal_proximity", "none")

    # Provide score-based context for LLM to consider
    score_context = {
        "total_score": score_total,
        "level_from_score": level_from_score,
        "avg_delta_hours": avg_delta_hours,
        "score_explanation": _explain_score(level_from_score, score_total) if score_total else None,
    }

    # Signal summary for LLM
    signal_summary = {
        "routing_events": routing_count,
        "traffic_events": traffic_count,
        "temporal_proximity": temporal_proximity,
        "hijack_events": signals.get("hijack_events_count", 0),
        "leak_events": signals.get("leak_events_count", 0),
    }

    return {
        "verdict": "OBSERVATIONAL_ONLY",
        "reconciled_level": "OBSERVATIONAL_ONLY",
        "reconciled_label": "Association evidence only; causation is unproven",
        "reconciliation": (
            f"Signals: {routing_count} routing events, {traffic_count} traffic events, "
            f"temporal proximity: {temporal_proximity}; quantitative association score: "
            f"{level_from_score} ({score_total}/100 if available). "
            f"These observations must not be presented as causal proof."
        ),
        "conflicts": [],
        "level_from_score": level_from_score,
        "level_from_deltaT": "OBSERVATIONAL_ONLY",
        "avg_delta_hours": avg_delta_hours,
        "score_context": score_context,
        "signal_summary": signal_summary,
    }


def _explain_score(level: str | None, score: int | None) -> str:
    """Explain an association score without turning it into a causal claim."""
    if level == "EXCEPTIONAL":
        return f"EXCEPTIONAL ({score}/100): Strong observed alignment across available dimensions; causation remains unproven."
    elif level == "STRONG":
        return f"STRONG ({score}/100): Multiple dimensions support an observed association; causation remains unproven."
    elif level == "MODERATE":
        return f"MODERATE ({score}/100): Some dimensions support an observed association; more evidence is needed."
    elif level == "WEAK":
        return f"WEAK ({score}/100): Limited evidence of association."
    elif level == "NONE":
        return f"NONE ({score}/100): No association was established from the available data."
    return f"Unknown score level: {level} ({score})"


def _generate_refutable_hypotheses(
    correlation: dict,
    routing_events: list[TemporalEvent],
    traffic_events: list[TemporalEvent],
    delta_ts: list[dict],
    target_as: str,
) -> list[dict]:
    """
    Generate 2-4 ranked refutable hypotheses with rich evidence chains.
    Each hypothesis includes: id, statement, evidence[], key_assumptions[],
    how_to_refute[], probing_recommendations[], causal_mechanism.

    The structure is inspired by scientific peer review:
    - Every claim is tied to specific data points
    - Every assumption is stated explicitly
    - Every hypothesis has a clear path to disproof
    - Probing recommendations guide next investigation steps

    NOTE: The correlation level is now LLM-determined based on signals.
    This function generates hypotheses based on actual signal indicators,
    not hardcoded correlation levels.
    """
    hypotheses = []
    
    # Get signal indicators from correlation dict
    signals = correlation.get("signals", {})
    routing_count = signals.get("routing_event_count", len(routing_events))
    traffic_count = signals.get("traffic_event_count", len(traffic_events))
    traffic_max_severity = signals.get("traffic_max_severity", 0)
    temporal_proximity = signals.get("temporal_proximity", "none")
    
    # Fallback to direct counting if signals not available
    if routing_count == 0:
        routing_count = len(routing_events)
    if traffic_count == 0:
        traffic_count = len(traffic_events)
    
    routing_signal_present = signals.get("routing_signal_present", routing_count > 0)
    traffic_signal_present = signals.get("traffic_signal_present", traffic_count > 0)

    # ---- Compute rich event context ----
    victim_events = [e for e in routing_events if e.event_type in ("origin_hijacked", "forge_hijacked")]
    attacker_events = [e for e in routing_events if e.event_type in ("origin_hijacking", "forge_hijacking")]
    leak_events = [e for e in routing_events if e.event_type == "route_leak"]

    victim_count = len(victim_events)
    attacker_count = len(attacker_events)
    victim_prefixes = list({e.details.get("prefix") for e in victim_events if e.details.get("prefix")})
    attacker_prefixes = list({e.details.get("prefix") for e in attacker_events if e.details.get("prefix")})
    victim_hijackers = list({str(e.details.get("hijacker_as")) for e in victim_events if e.details.get("hijacker_as")})
    attacker_hijacked_as = list({str(e.details.get("victim_as")) for e in attacker_events if e.details.get("victim_as")})

    # Compute traffic directions from events
    traffic_directions = [e.details.get("direction") for e in traffic_events if e.details.get("direction")]
    if not traffic_directions:
        # Fallback: infer from event types
        traffic_directions = ["drop" if "drop" in str(e.event_type).lower() else "mixed" for e in traffic_events]
    traffic_drop_count = sum(1 for d in traffic_directions if "below" in str(d).lower() or "drop" in str(d).lower())
    traffic_rise_count = sum(1 for d in traffic_directions if "above" in str(d).lower() or "rise" in str(d).lower())
    traffic_dominant_direction = "drop" if traffic_drop_count > traffic_rise_count else ("rise" if traffic_rise_count > traffic_drop_count else "mixed")
    traffic_max_z = max((e.details.get("z_score", 0) for e in traffic_events), default=0)

    earliest_routing_ts = min((e.timestamp for e in routing_events), default=None)
    earliest_traffic_ts = min((e.timestamp for e in traffic_events), default=None)
    earliest_delta = delta_ts[0] if delta_ts else None
    earliest_delta_h = earliest_delta.get("delta_hours", 0) if earliest_delta else 0

    # ---- Helper: build evidence items with data references ----
    def ev(text, citation_key=""):
        item = {"text": text}
        if citation_key:
            item["citation"] = citation_key
        return item

    # ===================== GENERATE HYPOTHESES BASED ON SIGNALS ====================
    # LLM will use these hypotheses plus all evidence to determine final level
    # Hypotheses are generated based on signal presence, not hardcoded levels

    # Common probing steps
    common_probing = []
    if victim_count > 0 and victim_prefixes:
        common_probing.append({
            "action": "check_victim_traffic",
            "target": f"victim ASes: {', '.join(victim_hijackers[:5])}",
            "reason": "Confirm whether victim ASes experienced traffic drops during the hijack window",
            "method": "Query traffic baseline for victim ASes during the anomaly window",
        })
    if victim_prefixes:
        common_probing.append({
            "action": "bgp_path_analysis",
            "target": f"prefixes: {', '.join(victim_prefixes[:3])}",
            "reason": "Verify the hijacked prefix was globally reachable via the illegitimate origin",
            "method": "Query RIPE RIS / RouteViews collector for AS path of affected prefix",
        })
    common_probing.append({
        "action": "traceroute_probing",
        "target": f"target AS{target_as}",
        "reason": "Confirm actual traffic routing path during the anomaly window",
        "method": "Use traceroute to affected destinations during anomaly window",
    })

    # Determine which hypotheses to generate based on signals
    has_routing = routing_signal_present and routing_count > 0
    has_traffic = traffic_signal_present and traffic_count > 0
    has_temporal = temporal_proximity in ("strong", "moderate")
    has_hijack = victim_count > 0 or attacker_count > 0
    has_leak = len(leak_events) > 0

    # Case 1: Strong signals on both sides
    if has_routing and has_traffic and has_temporal:
        # This is the strongest case: routing + traffic + temporal alignment
        probing_steps = list(common_probing)
        if traffic_dominant_direction == "drop":
            probing_steps.append({
                "action": "prefix_specific_traffic",
                "target": f"prefixes: {', '.join(victim_prefixes[:3] if victim_prefixes else attacker_prefixes[:3])}",
                "reason": "Confirm traffic drop is specific to hijacked prefixes, not a general outage",
                "method": "Request prefix-level traffic breakdown from Cloudflare Radar",
            })
        
        hypotheses.append({
            "id": "A",
            "rank": "A (highest confidence)",
            "causal_type": "observational_association",
            "statement": (
                f"{victim_count if victim_count > 0 else routing_count} routing anomaly event(s) "
                f"{'detected starting at ' + (earliest_routing_ts.isoformat() if earliest_routing_ts else '?') + '. ' if routing_count > 0 else ''}"
                f"Traffic anomalies {'(dropped' if traffic_dominant_direction == 'drop' else '(changed'} "
                f"{f'approximately {earliest_delta_h:.1f}h later' if earliest_delta_h else 'around the same time'} "
                f"(ΔT={earliest_delta_h:.1f}h), "
                f"{'within the configured temporal-association range' if 0.5 <= earliest_delta_h <= 8 else 'but temporal proximity is weak'}. "
                f"The signals support an observational association that requires further verification."
            ),
            "evidence": [
                ev(f"{routing_count} routing anomaly event(s) detected", "correlation.signals.routing_event_count"),
                ev(f"{traffic_count} traffic anomaly event(s) detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic max severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
                ev(f"Temporal proximity: {temporal_proximity}", "correlation.signals.temporal_proximity"),
                ev(f"ΔT = {earliest_delta_h:.1f}h", "delta_ts[0].delta_hours") if delta_ts else ev("No ΔT data available", ""),
            ],
            "key_assumptions": [
                {
                    "text": "The temporal proximity is consistent with routing anomalies affecting traffic.",
                    "risk": "medium",
                },
                {
                    "text": "The signal strength (routing={routing_count}, traffic={traffic_count}, severity={traffic_max_severity:.2f}) is sufficient for correlation.",
                    "risk": "medium",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Check if ΔT is consistent across multiple events",
                    "expected_if_wrong": "ΔT varies significantly, suggesting independent causes",
                    "data_needed": "All traffic and routing anomaly timestamps",
                },
            ],
            "probing_recommendations": probing_steps,
            "confidence_base": 0.7,
        })

        # Hypothesis B: Coincidental (alternative)
        hypotheses.append({
            "id": "B",
            "rank": "B (alternative)",
            "causal_type": "independent_coincidence",
            "statement": (
                f"The {routing_count} routing anomalies and {traffic_count} traffic anomalies "
                f"occurred simultaneously but independently. "
                f"AS{target_as}'s traffic drop had a separate cause "
                f"(e.g., upstream link failure, maintenance, instrumentation issue)."
            ),
            "evidence": [
                ev(f"{routing_count} routing events, {traffic_count} traffic events detected", "signals"),
                ev(f"Traffic dominant direction: {traffic_dominant_direction}", "traffic_events[*].direction"),
            ],
            "key_assumptions": [
                {
                    "text": "The traffic drop has an independent cause unrelated to routing.",
                    "risk": "medium",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Check if traffic drop is specific to routing-affected prefixes",
                    "expected_if_wrong": "Traffic drop is specific to routing-affected prefixes",
                    "data_needed": "Prefix-level traffic breakdown",
                },
            ],
            "probing_recommendations": [
                {
                    "action": "check_independent_cause",
                    "target": f"AS{target_as}",
                    "reason": "Rule out independent causes",
                    "method": "Check AS network status, upstream provider status, maintenance windows",
                },
            ],
            "confidence_base": 0.3,
        })

    # Case 2: Routing signal present, weak/no traffic signal
    elif has_routing and not has_traffic:
        probing_steps = list(common_probing)
        probing_steps.append({
            "action": "collect_traffic_data",
            "target": f"AS{target_as}",
            "reason": "Verify traffic impact with additional data sources",
            "method": "Query Cloudflare Radar for AS{target_as} traffic baseline",
        })

        hypotheses.append({
            "id": "A",
            "rank": "A (routing signal present, traffic unclear)",
            "causal_type": "routing_signal_no_traffic",
            "statement": (
                f"Routing anomalies ({routing_count} events) were detected "
                f"{'at ' + (earliest_routing_ts.isoformat() if earliest_routing_ts else '?') if earliest_routing_ts else ''}. "
                f"However, no significant traffic anomalies were detected in the analysis window. "
                f"The routing anomalies may have been resolved quickly, had minimal traffic impact, "
                f"or affected prefixes with low traffic volume."
            ),
            "evidence": [
                ev(f"{routing_count} routing anomaly event(s) detected", "correlation.signals.routing_event_count"),
                ev(f"{traffic_count} traffic anomaly events detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
            ],
            "key_assumptions": [
                {
                    "text": "The routing anomalies did not significantly affect traffic, or the traffic data resolution is too coarse.",
                    "risk": "high",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Verify with victim traffic analysis",
                    "expected_if_wrong": "Victim ASes show traffic drops",
                    "data_needed": "Prefix-level traffic data for affected ASes",
                },
            ],
            "probing_recommendations": probing_steps,
            "confidence_base": 0.5,
        })

    # Case 3: Traffic signal present, weak/no routing signal
    elif has_traffic and not has_routing:
        hypotheses.append({
            "id": "A",
            "rank": "A (traffic signal present, routing unclear)",
            "causal_type": "traffic_signal_no_routing",
            "statement": (
                f"Traffic anomalies ({traffic_count} events) were detected, "
                f"but no routing anomalies were found in the analysis window. "
                f"The traffic drop may be caused by factors other than BGP routing "
                f"(e.g., upstream link failure, DDoS attack, application-level issues)."
            ),
            "evidence": [
                ev(f"{traffic_count} traffic anomaly event(s) detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
                ev(f"0 routing anomalies detected", "correlation.signals.routing_event_count"),
            ],
            "key_assumptions": [
                {
                    "text": "The routing data coverage is sufficient to detect BGP-related anomalies.",
                    "risk": "high",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Check routing data time window and coverage",
                    "expected_if_wrong": "Routing data shows anomalies in expanded window",
                    "data_needed": "Expanded routing analysis window",
                },
            ],
            "probing_recommendations": [
                {
                    "action": "expand_routing_analysis",
                    "target": f"AS{target_as}",
                    "reason": "Verify routing with expanded time window",
                    "method": "Re-run routing analysis with wider time range",
                },
            ],
            "confidence_base": 0.4,
        })

    # Case 4: Neither signal present - truly insufficient data
    else:
        hypotheses.append({
            "id": "A",
            "rank": "A (insufficient evidence)",
            "causal_type": "insufficient_data",
            "statement": (
                f"Neither routing signal (0 events) nor traffic signal "
                f"(0 events, severity={traffic_max_severity:.2f}) is strong enough to establish a correlation. "
                f"The analysis window may not cover the actual event, "
                f"the event may have been brief, or the data sources may not have coverage."
            ),
            "evidence": [
                ev(f"0 routing anomalies detected", "correlation.signals.routing_event_count"),
                ev(f"0 traffic anomalies detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
            ],
            "key_assumptions": [
                {
                    "text": "The analysis window covers the actual event.",
                    "risk": "high",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Verify time window with ground truth",
                    "expected_if_wrong": "Event occurred outside the analysis window",
                    "data_needed": "Ground truth event timing",
                },
            ],
            "probing_recommendations": [
                {
                    "action": "expand_analysis_window",
                    "target": "Analysis parameters",
                    "reason": "Consider expanding time window or using different data sources",
                    "method": "Re-run with expanded window, or verify with alternative data sources",
                },
            ],
            "confidence_base": 0.2,
        })
        # Hypothesis A: Victim hypothesis (most supported)
        probing_steps = []
        if victim_count > 0 and victim_prefixes:
            probing_steps.append({
                "action": "check_victim_traffic",
                "target": f"victim ASes: {', '.join(victim_hijackers[:5])}",
                "reason": "Confirm whether victim ASes experienced traffic drops during the hijack window",
                "method": "Query traffic baseline for victim ASes during {earliest_routing_ts} to {earliest_traffic_ts}",
            })
        if victim_prefixes:
            probing_steps.append({
                "action": "bgp_path_analysis",
                "target": f"prefixes: {', '.join(victim_prefixes[:3])}",
                "reason": "Verify the hijacked prefix was globally reachable via the illegitimate origin",
                "method": "Query RIPE RIS / RouteViews collector for AS path of affected prefix",
            })
        probing_steps.append({
            "action": "traceroute_probing",
            "target": f"target AS{target_as}",
            "reason": "Confirm actual traffic routing path includes the hijacked prefix",
            "method": "Use traceroute to affected destinations during anomaly window",
        })
        if traffic_dominant_direction == "drop":
            probing_steps.append({
                "action": "prefix_specific_traffic",
                "target": f"prefixes: {', '.join(victim_prefixes[:3] if victim_prefixes else attacker_prefixes[:3])}",
                "reason": "Confirm traffic drop is specific to hijacked prefixes, not a general outage",
                "method": "Request prefix-level traffic breakdown from Cloudflare Radar",
            })

        hypotheses.append({
            "id": "A",
            "rank": "A (highest confidence)",
            "causal_type": "observational_association",
            "statement": (
                f"AS{target_as} was a victim of {victim_count} origin-hijack events starting at "
                f"{earliest_routing_ts.isoformat() if earliest_routing_ts else '?'}. "
                f"Traffic anomalies {('dropped' if traffic_dominant_direction == 'drop' else 'changed')} "
                f"approximately {earliest_delta_h:.1f}h later (ΔT={earliest_delta_h:.1f}h, within the configured temporal-association range), "
                f"which is consistent with, but does not prove, traffic redirection through the hijacked prefix."
            ),
            "evidence": [
                ev(f"{routing_count} routing anomaly events detected in analysis window", "routing_event_count"),
                ev(f"Traffic anomaly z-score: {traffic_max_z:.2f}", "traffic_events[0].z_score"),
                ev(f"Traffic dominant direction: {traffic_dominant_direction} ({traffic_drop_count} drop / {traffic_rise_count} rise)", "traffic_events[*].direction"),
                ev(f"ΔT = {earliest_delta_h:.1f}h (within the configured temporal-association range)", "delta_ts[0].delta_hours"),
                ev(f"Routing events timestamp: {earliest_routing_ts.isoformat() if earliest_routing_ts else '?'}", "timeline[0]"),
                ev(f"Traffic events timestamp: {earliest_traffic_ts.isoformat() if earliest_traffic_ts else '?'}", "delta_ts[0].traffic_ts"),
                ev(f"Hijacked prefixes: {', '.join(victim_prefixes[:3])}{'...' if len(victim_prefixes) > 3 else ''}", "timeline[*].prefix"),
                ev(f"Attacking ASes: {', '.join(victim_hijackers[:3])}{'...' if len(victim_hijackers) > 3 else ''}", "timeline[*].hijacker_as"),
            ],
            "key_assumptions": [
                {
                    "text": "The hijacked prefixes carried non-trivial traffic for AS{target_as} during the anomaly window.",
                    "test": "Check prefix-level traffic data for AS{target_as}'s prefixes during {earliest_routing_ts}",
                    "risk": "high",
                },
                {
                    "text": "The illegitimate origin AS won BGP route selection over the legitimate origin, causing traffic redirection.",
                    "test": "Query BGP collector data for AS path changes during the hijack window",
                    "risk": "medium",
                },
                {
                    "text": "The traffic drop is a direct consequence of traffic being routed to the wrong AS, not a coincidental outage.",
                    "test": "Check for correlated infrastructure events at AS{target_as}",
                    "risk": "medium",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Check if traffic drop was specific to hijacked prefixes or affected all traffic",
                    "expected_if_wrong": "Traffic drop affected non-hijacked prefixes equally",
                    "data_needed": "Prefix-level traffic breakdown for AS{target_as}",
                },
                {
                    "test": "Check if the hijacked prefixes were globally reachable via the illegitimate origin",
                    "expected_if_wrong": "Hijacked prefixes only appeared in local collector, not globally visible",
                    "data_needed": "Multiple BGP collector data (RouteViews, RIPE RIS) for affected prefix",
                },
                {
                    "test": "Check if ΔT is consistent across multiple traffic anomalies",
                    "expected_if_wrong": "ΔT varies significantly (>4h) across events, suggesting independent causes",
                    "data_needed": "All traffic anomaly timestamps vs. routing event timestamps",
                },
            ],
            "probing_recommendations": probing_steps,
            "confidence_base": correlation.get("confidence", 0.8),
        })

        # Hypothesis B: Coincidental (alternative)
        probing_steps_b = [
            {
                "action": "check_independent_cause",
                "target": f"AS{target_as}",
                "reason": "Rule out independent causes (upstream outage, maintenance, hardware failure)",
                "method": "Check AS{target_as} network status, upstream provider status, maintenance windows",
            },
            {
                "action": "check_prefix_specificity",
                "target": f"prefixes: {', '.join(victim_prefixes[:2]) if victim_prefixes else 'N/A'}",
                "reason": "If traffic drop is prefix-specific, hijack is more likely; if general, it's likely independent",
                "method": "Compare traffic baseline for hijacked vs. non-hijacked prefixes",
            },
            {
                "action": "check_attacker_traffic",
                "target": f"attacking ASes: {', '.join(victim_hijackers[:3])}",
                "reason": "Attackers may also lose traffic during a hijack if they are peered with the victim",
                "method": "Check traffic baseline for attacker ASes during hijack window",
            },
        ]

        hypotheses.append({
            "id": "B",
            "rank": "B (alternative)",
            "causal_type": "independent_coincidence",
            "statement": (
                f"The {routing_count} routing anomalies and {traffic_count} traffic anomalies occurred "
                f"simultaneously but independently. AS{target_as}'s traffic drop had a separate cause "
                f"(e.g., upstream link failure, maintenance, instrumentation issue) and the routing "
                f"anomalies are unrelated events."
            ),
            "evidence": [
                ev(f"AS{target_as} also acted as an attacker in {attacker_count} events — attackers may have independent issues", "attacker_count"),
                ev(f"Multiple traffic anomaly clusters with different ΔT values", "delta_ts[*].delta_hours"),
                ev(f"Traffic direction: {traffic_dominant_direction} — does not clearly match victim impact pattern", "traffic_events[*].direction"),
            ],
            "key_assumptions": [
                {
                    "text": "The traffic drop is NOT specifically routed over the hijacked prefixes.",
                    "test": "Compare traffic for hijacked vs. non-hijacked prefixes",
                    "risk": "high",
                },
                {
                    "text": "No causal mechanism exists between BGP routing change and traffic change.",
                    "test": "Check for alternative causes (upstream, maintenance, hardware)",
                    "risk": "medium",
                },
            ],
            "how_to_refute": [
                {
                    "test": "Show traffic dropped ONLY for prefixes involved in hijack events",
                    "expected_if_wrong": "Traffic dropped equally across all prefixes",
                    "data_needed": "Prefix-level traffic breakdown",
                },
                {
                    "test": "Show BGP withdrawal/announcement pattern consistent with traffic impact",
                    "expected_if_wrong": "No BGP path change detected during traffic anomaly window",
                    "data_needed": "BGP collector data for AS{target_as}",
                },
            ],
            "probing_recommendations": probing_steps_b,
            "confidence_base": 0.2,
        })

    return hypotheses


def _build_victim_verification(victim_traffic_results: dict, victim_asns: list) -> list:
    """
    Build victim verification summary from pre-fetched victim traffic results.

    Each entry contains: asn, traffic_anomalous, anomaly_count, details.
    This is used by the report LLM to produce a Victim Verification section.
    """
    if not victim_asns or not victim_traffic_results:
        return []

    verification = []
    for asn in victim_asns:
        traffic_data = victim_traffic_results.get(str(asn)) or {}
        anomalies = traffic_data.get("anomalies_detected", False)
        count = traffic_data.get("anomaly_count", 0)
        anomaly_list = traffic_data.get("anomalies", [])[:5]  # cap at 5 details

        verification.append({
            "asn": str(asn),
            "traffic_anomalous": bool(anomalies),
            "anomaly_count": count,
            "anomalies": anomaly_list,
        })
    return verification


def analyze_temporal_correlation(
    traffic_raw: dict,
    routing_result: dict,
    target_as: str,
    victim_traffic_results: Optional[dict] = None,
    victim_asns: Optional[list] = None,
    prefix_traffic_results: Optional[dict] = None,
    correlation_score_result: Optional[dict] = None,
    traffic_anomaly_window: Optional[dict] = None,
) -> dict:
    """
    Pre-compute all temporal features for correlation analysis.
    This is the architecture-layer enhancement (Step 2).
    Returns a structured dict ready for the LLM prompt.

    victim_traffic_results: dict of {asn -> traffic_result} for ASes discovered
        from routing events (e.g. victims of a hijack).
    victim_asns: ordered list of victim AS numbers.
    correlation_score_result: output of compute_traffic_routing_correlation_score;
        used for cross-validation with ΔT-based correlation level.
    traffic_anomaly_window: optional pre-extracted traffic anomaly window
        (cluster start/end).  When present, even an empty `anomalies` list
        will yield a synthetic traffic event so ΔT and three-card tiers can
        be populated from the visible-but-soft cluster.
    """
    traffic_events = _extract_traffic_events(traffic_raw or {}, traffic_anomaly_window)
    routing_events = _extract_routing_events(routing_result or {}, target_as=target_as) or []
    delta_ts = _compute_delta_t(traffic_events, routing_events, traffic_anomaly_window)
    correlation = _assign_correlation_level(
        traffic_events, routing_events, delta_ts,
        traffic_anomaly_window=traffic_anomaly_window,
        traffic_raw=traffic_raw,
    )

    # ── Cross-validate ΔT-based level with quantitative score ────────────────
    cross_validation = _cross_validate_correlation(correlation, correlation_score_result)

    timeline = _build_merged_timeline(traffic_events, routing_events)
    hypotheses = _generate_refutable_hypotheses(
        correlation, routing_events, traffic_events, delta_ts, target_as
    )

    return {
        "summary": {
            "routing_event_count": len(routing_events),
            "traffic_event_count": len(traffic_events),
            "correlation_level": correlation["level"],
            "correlation_label": correlation["label"],
            "correlation_confidence": correlation["confidence"],
        },
        "correlation": correlation,
        "cross_validation": cross_validation,
        "delta_ts": delta_ts,
        "timeline": timeline[:50],  # Cap at 50 events
        "hypotheses": hypotheses,
        "routing_events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "type": e.event_type,
                "severity": e.severity,
                **e.details,
            }
            for e in routing_events[:20]  # Cap at 20
        ],
        "traffic_events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "type": e.event_type,
                "severity": e.severity,
                **e.details,
            }
            for e in traffic_events
        ],
        "victim_verification": _build_victim_verification(victim_traffic_results or {}, victim_asns or []),
        "prefix_traffic_results": prefix_traffic_results or {},
    }


def _extract_plot_path(traffic_result: Optional[dict], traffic_raw: dict, reasoning_result: Optional[dict]) -> Optional[str]:
    """Best-effort extraction of traffic plot path from all available payloads."""
    candidates: list[Any] = []

    def _collect(d: Optional[dict], _depth: int = 0):
        if _depth > 50 or not isinstance(d, dict):
            return
        candidates.extend([
            d.get("plot_path"),
            d.get("traffic_plot_path"),
        ])
        inner = d.get("result", d)
        if isinstance(inner, dict) and inner is not d:
            _collect(inner, _depth + 1)
        evidence = d.get("evidence_summary") or {}
        if isinstance(evidence, dict):
            traffic_data = evidence.get("traffic_data") or {}
            if isinstance(traffic_data, dict):
                _collect(traffic_data, _depth + 1)

    _collect(traffic_result)
    _collect(traffic_raw)
    _collect(reasoning_result)

    for item in candidates:
        candidate = str(item or "").strip()
        if candidate:
            return candidate
    return None


def _extract_traffic_anomaly_window(traffic: dict) -> Optional[dict]:
    """Extract anomaly windows from traffic analysis results.

    Looks first at the strict anomaly list and falls back to the soft
    cluster windows (`expanded_windows`, `expanded_boundaries`) so the
    report header can still show a non-empty "Traffic Anomaly Window"
    when only a soft drop is visible in the chart.
    """
    anomalies = traffic.get("anomalies", []) or []

    if anomalies:
        timestamps = []
        for a in anomalies:
            ts = a.get("timestamp") or a.get("time")
            if ts:
                p = _parse_time(ts)
                if p:
                    timestamps.append(p)

        if timestamps:
            return {
                "start": min(timestamps).isoformat(),
                "end": max(timestamps).isoformat(),
                "anomaly_count": len(anomalies),
            }

    # ── Soft fallback: expanded_windows / expanded_boundaries ─────────────
    wins = traffic.get("expanded_windows") or traffic.get("consecutive_anomaly_windows") or []
    if isinstance(wins, list) and wins:
        first = next((w for w in wins if isinstance(w, dict)), None)
        if first:
            start = first.get("start") or first.get("expanded_start")
            end = first.get("end") or first.get("expanded_end")
            if start and end:
                return {
                    "start": str(start),
                    "end": str(end),
                    "anomaly_count": int(first.get("anomaly_count", 0) or 0),
                    "soft": True,
                }

    eb = traffic.get("expanded_boundaries")
    if isinstance(eb, dict):
        start = eb.get("expanded_start") or eb.get("start")
        end = eb.get("expanded_end") or eb.get("end")
        if start and end:
            return {"start": str(start), "end": str(end), "soft": True}

    return None


def _embed_file_as_base64(path_str: Optional[str]) -> Optional[str]:
    if not path_str:
        return None
    try:
        path = Path(path_str)
        if path.exists() and path.is_file():
            return base64.b64encode(path.read_bytes()).decode("utf-8")
    except Exception as exc:
        logger.warning(f"Failed to embed traffic plot {path_str}: {exc}")
    return None


def _strip_path_based_traffic_images(html: str) -> str:
    """Remove `<img>` tags whose `src` points at the on-disk traffic plot.

    The LLM occasionally emits
        <img src="/data/bgp_tracer/.../traffic_plots/ASxxx_*.png">
    when it sees `traffic_plot_path` in the payload.  Those tags render as
    broken images anywhere outside the host that produced the report.  We
    strip them here so only the base64 copy injected by
    `_inject_traffic_plot` survives in the final HTML.

    Only path-based refs are removed; embedded base64 data URLs are kept
    (and protected by the `data:image/png;base64,` guard below).
    """
    if not html:
        return html

    # Strip <img src="/abs/path/...png" ... /> (with or without quotes, with
    # or without self-closing slash).  The full tag including the closing
    # `>` must be consumed so we don't leave dangling `alt="..."` text.
    pattern = re.compile(
        r'<img\b[^>]*?\bsrc\s*=\s*(?:"[^"]*traffic_plots[^"]*"|\'[^\']*traffic_plots[^\']*\'|[^\s>]+traffic_plots[^\s>]*)[^>]*?>',
        re.IGNORECASE,
    )
    cleaned = pattern.sub("", html)

    # Tidy any orphan whitespace left where the <img> used to be.
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n[ \t]+\n", "\n\n", cleaned)

    # Also strip the caption paragraph the LLM writes under the broken image.
    cleaned = re.sub(
        r"<p[^>]*>\s*\(Chart path:[^)]*\)\s*</p>",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    # Also strip paragraphs that begin with "Chart path:" but not in parens.
    cleaned = re.sub(
        r"<p[^>]*>\s*Chart path:[^<]*</p>",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    # Strip the chart-frame section if it just shows a broken image placeholder.
    cleaned = re.sub(
        r'<div class="chart-frame">\s*🔽\s*<strong>Traffic plot is embedded below this report</strong>.*?</div>',
        '<div class="chart-frame">📊 Traffic plot is embedded at the end of this report.</div>',
        cleaned,
        flags=re.DOTALL | re.IGNORECASE,
    )
    return cleaned


def _inject_traffic_plot(html: str, traffic_plot_base64: Optional[str]) -> str:
    """Ensure final HTML always includes the traffic plot when available.

    Two responsibilities:
      1. Strip any path-based `<img src="...traffic_plots/...">` references
         the LLM may have emitted (they're broken on other hosts).
      2. Inject exactly ONE working base64 copy of the chart just before
         `</body>` so the file is portable.
    """
    if not html:
        return html

    # Always strip path-based refs first, regardless of whether we have a
    # base64 copy.  This avoids the "two imgs, one broken" pathology.
    html = _strip_path_based_traffic_images(html)

    if not traffic_plot_base64:
        return html
    if "data:image/png;base64," in html:
        return html

    section = (
        '<div class="card">'
        '<h2>Traffic Visualization</h2>'
        '<p>Embedded directly from the generated traffic plot artifact.</p>'
        f'<img src="data:image/png;base64,{traffic_plot_base64}" '
        'alt="Traffic Analysis" style="max-width:100%; border-radius:8px; border:1px solid #ddd;" />'
        '</div>'
    )

    if "</body>" in html:
        return html.replace("</body>", section + "</body>", 1)
    return html + section


class ReportAgent(Agent):
    """
    LLM-driven report generator with pre-computed temporal correlation analysis.
    """

    name = "ReportAgent"

    def __init__(self, bb):
        super().__init__(bb)
        self.llm = None

    # ── P4: Fallback gate ─────────────────────────────────────────────────
    # When REPORT_REQUIRE_LLM=1 is set, the deterministic HTML fallback is
    # DISABLED for LLM failures (timeout / empty / exception).  Instead the
    # agent returns success=False with a structured error so the calling
    # orchestrator can retry or escalate.  This prevents silent degradation
    # of report quality from masking validation_count=0 / low-confidence cases.
    #
    # Default behaviour (env var unset / 0) preserves the legacy deterministic
    # fallback so offline / unit-test runs still get a report.
    @staticmethod
    def _should_use_fallback() -> bool:
        # Honour env var override at runtime, but prefer the imported config
        # value so offline / unit-test runs still get a deterministic report.
        runtime_flag = os.environ.get("REPORT_REQUIRE_LLM", "0").strip()
        if runtime_flag in ("1", "true", "yes"):
            return False
        return not _CONFIG_REPORT_REQUIRE_LLM

    def _report_fallback_disabled(self, reason: str) -> TaskResult:
        """Return a structured failure when REPORT_REQUIRE_LLM=1 is set."""
        from utils.logger import logger
        logger.error(
            f"[ReportAgent] Fallback disabled by REPORT_REQUIRE_LLM=1; "
            f"returning failure instead of fallback HTML. reason: {reason}"
        )
        self.state = AgentState.ERROR
        return TaskResult(
            success=False,
            error=f"llm_failed_fallback_disabled: {reason}",
            agent=self.name,
        )

    async def start(self):
        self.state = AgentState.IDLE
        self.llm, _ = setup_llm_settings(
            model=MODEL,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=DEFAULT_TEMP_REPORT,
            timeout=600.0,
            max_retries=3,
        )

    async def step(self) -> TaskResult:
        # Read all sections first so they're always available for fallback rendering.
        # Using safe defaults ensures the fallback path never throws a NameError
        # due to missing variables (Bug Fix: 'traffic_result' is not defined).
        traffic: dict = await self.bb.read_section("traffic") or {}
        routing: dict = await self.bb.read_section("routing") or {}
        reasoning: dict = await self.bb.read_section("reasoning") or {}
        config: dict = await self.bb.read_section("config") or {}

        asn = config.get("asn")
        start_time = config.get("start_time")
        end_time = config.get("end_time")

        # Honor a process-wide "skip LLM-driven report" switch. Useful in
        # offline runs or when the upstream LLM is unreachable — we still
        # emit a deterministic HTML report so downstream tools have something
        # to read. Activated by env var BGP_TRACER_DISABLE_LLM_REPORT=1.
        # Note: this branch runs even when asn is missing — we fall back to
        # the placeholder so we still produce *some* report (better than
        # an empty error).
        if os.environ.get("BGP_TRACER_DISABLE_LLM_REPORT", "").strip() in ("1", "true", "yes"):
            self.log("LLM report disabled via BGP_TRACER_DISABLE_LLM_REPORT — using fallback.")
            fallback_html = self._render_fallback_html(
                asn=str(asn) if asn else "unknown",
                start_time=str(start_time) if start_time else "",
                end_time=str(end_time) if end_time else "",
                traffic_result=traffic,
                routing_result=await self.bb.read_section("routing"),
                reasoning_result=reasoning,
            )
            await self.bb.write("report", "html", fallback_html)
            await self.bb.write("report", "success", True)
            await self.bb.write("report", "used_fallback", True)
            self.state = AgentState.DONE
            return TaskResult(success=True, data={"html": fallback_html}, agent=self.name)

        if not asn:
            return TaskResult(success=False, error="Missing asn in blackboard", agent=self.name)

        self.state = AgentState.WORKING
        self.log(f"Generating LLM-driven report for AS{asn} {start_time}->{end_time}")

        try:
            traffic_result_norm = _normalize(traffic)
            routing_result_norm = _normalize(routing)
            reasoning_result_norm = _normalize(reasoning)
            traffic_raw = traffic or {}
            traffic_plot_path = _extract_plot_path(traffic_result_norm, traffic_raw, reasoning_result_norm)
            traffic_plot_base64 = _embed_file_as_base64(traffic_plot_path)

            traffic_anomaly_window = await _safe_read(self.bb, "traffic", "anomaly_window") or \
                _extract_traffic_anomaly_window(traffic)

            # Step 2 Enhancement: Pre-compute temporal correlation features
            # Unwrap result wrappers so the correlation engine gets clean data
            routing_unwrapped = routing_result_norm.get("result", routing_result_norm)
            traffic_unwrapped = traffic_result_norm.get("result", traffic_result_norm)
            # Pull the quantitative correlation score and victim traffic (from reason_and_classify)
            corr_score_result = reasoning_result_norm.get("correlation_score_result", {})
            prefix_traffic_results = reasoning_result_norm.get("prefix_traffic_results", {})
            # victim_asns: try reasoning_result first, fallback to blackboard
            victim_asns = (reasoning_result_norm.get("victim_asns") or []) or \
                (await _safe_read(self.bb, "routing", "victim_asns") or [])
            # victim_traffic_results: try reasoning_result first, fallback to blackboard
            victim_traffic_results = (reasoning_result_norm.get("victim_traffic_results") or {}) or \
                (await _safe_read(self.bb, "routing", "victim_traffic_results") or {})
            # threat_intel_result: try reasoning_result first, fallback to blackboard
            threat_intel_result = (reasoning_result_norm.get("threat_intel_result") or {}) or \
                (await _safe_read(self.bb, "routing", "threat_intel_result") or {})
            # Merge threat_intel into reasoning_result_norm so _generate_report_html picks it up
            if threat_intel_result and isinstance(reasoning_result_norm, dict):
                reasoning_result_norm = dict(reasoning_result_norm)
                reasoning_result_norm["threat_intel_result"] = threat_intel_result
            correlation_analysis = analyze_temporal_correlation(
                traffic_raw=traffic_unwrapped,
                routing_result=routing_unwrapped,
                target_as=str(asn),
                victim_traffic_results=victim_traffic_results,
                victim_asns=victim_asns,
                prefix_traffic_results=prefix_traffic_results,
                correlation_score_result=corr_score_result,
                traffic_anomaly_window=traffic_anomaly_window,
            )

            # Keep the outer watchdog aligned with the LLM-call timeout so a
            # legitimate configured report window is never cut short here.
            REPORT_LLM_TIMEOUT_S = _CONFIG_REPORT_LLM_TIMEOUT_S
            loop = asyncio.get_running_loop()
            try:
                # `_generate_report_html` runs the LLM call in an executor
                # internally with its own timeout, so wrapping it here is
                # only a defense-in-depth measure.
                html = await asyncio.wait_for(
                    self._generate_report_html(
                        asn=str(asn),
                        start_time=str(start_time),
                        end_time=str(end_time),
                        traffic_result=traffic_result_norm,
                        traffic_raw=traffic,
                        routing_result=routing_result_norm,
                        routing_raw=routing,
                        reasoning_result=reasoning_result_norm,
                        traffic_plot_path=traffic_plot_path,
                        traffic_plot_base64=traffic_plot_base64,
                        traffic_anomaly_window=traffic_anomaly_window,
                        correlation_analysis=correlation_analysis,
                    ),
                    timeout=REPORT_LLM_TIMEOUT_S + 5.0,
                )
            except asyncio.TimeoutError:
                logger.error(
                    f"ReportAgent LLM call exceeded {REPORT_LLM_TIMEOUT_S + 5.0:.0f}s — "
                    "rendering deterministic fallback HTML so chief_agent gets a result."
                )
                if not self._should_use_fallback():
                    await self.bb.write("report", "used_fallback", False)
                    await self.bb.write("report", "fallback_reason", "llm_timeout")
                    return self._report_fallback_disabled("llm_timeout")
                fallback_html = self._render_fallback_html(
                    asn=str(asn),
                    start_time=str(start_time),
                    end_time=str(end_time),
                    traffic_result=traffic,
                    routing_result=routing,
                    reasoning_result=reasoning,
                )
                await self.bb.write("report", "html", fallback_html)
                await self.bb.write("report", "success", True)
                await self.bb.write("report", "used_fallback", True)
                await self.bb.write("report", "fallback_reason", "llm_timeout")
                self.state = AgentState.DONE
                return TaskResult(success=True, data={"html": fallback_html}, agent=self.name)
            is_complete_document = (
                html.lstrip().lower().startswith("<!doctype") or
                html.lstrip().lower().startswith("<html")
            ) and re.search(r"</html>\s*$", html, flags=re.IGNORECASE) is not None
            if not html or ("deterministic fallback" not in html and not is_complete_document):
                # Inner timeout produced empty/non-document; render fallback
                logger.warning("ReportAgent LLM call returned empty/invalid HTML — using fallback.")
                if not self._should_use_fallback():
                    await self.bb.write("report", "used_fallback", False)
                    await self.bb.write("report", "fallback_reason", "llm_empty_or_invalid")
                    return self._report_fallback_disabled("llm_empty_or_invalid")
                fallback_html = self._render_fallback_html(
                    asn=str(asn),
                    start_time=str(start_time),
                    end_time=str(end_time),
                    traffic_result=traffic,
                    routing_result=routing,
                    reasoning_result=reasoning,
                )
                await self.bb.write("report", "html", fallback_html)
                await self.bb.write("report", "success", True)
                await self.bb.write("report", "used_fallback", True)
                await self.bb.write("report", "fallback_reason", "llm_timeout")
                self.state = AgentState.DONE
                return TaskResult(success=True, data={"html": fallback_html}, agent=self.name)

            html = _inject_traffic_plot(html, traffic_plot_base64)

            await self.bb.write("report", "html", html)
            await self.bb.write("report", "success", True)
            await self.bb.write("report", "traffic_plot_path", traffic_plot_path)
            await self.bb.write("report", "correlation_analysis", correlation_analysis)
            self.state = AgentState.DONE
            return TaskResult(success=True, data={"html": html}, agent=self.name)

        except Exception as e:
            logger.error(f"ReportAgent failed: {e}")
            logger.warning("LLM-driven report failed; rendering deterministic fallback HTML.")
            if not self._should_use_fallback():
                await self.bb.write("report", "used_fallback", False)
                await self.bb.write("report", "fallback_reason", f"llm_exception: {e}")
                return self._report_fallback_disabled(f"llm_exception: {e}")
            try:
                traffic_local = traffic
                routing_local = await self.bb.read_section("routing")
            except Exception:
                traffic_local = traffic
                routing_local = {}
            try:
                fallback_html = self._render_fallback_html(
                    asn=str(asn),
                    start_time=str(start_time),
                    end_time=str(end_time),
                    traffic_result=traffic_local,
                    routing_result=routing_local,
                    reasoning_result=reasoning,
                )
                await self.bb.write("report", "html", fallback_html)
                await self.bb.write("report", "success", True)
                await self.bb.write("report", "used_fallback", True)
                self.state = AgentState.DONE
                return TaskResult(success=True, data={"html": fallback_html}, agent=self.name)
            except Exception as fallback_err:
                logger.error(f"Fallback render also failed: {fallback_err}")
                self.state = AgentState.ERROR
                return TaskResult(success=False, error=f"{e}; fallback={fallback_err}", agent=self.name)

    async def _generate_report_html(
        self,
        asn: str,
        start_time: str,
        end_time: str,
        traffic_result: Optional[dict],
        traffic_raw: dict,
        routing_result: Optional[dict],
        routing_raw: dict,
        reasoning_result: Optional[dict],
        traffic_plot_path: Optional[str],
        traffic_plot_base64: Optional[str],
        traffic_anomaly_window: Optional[dict] = None,
        correlation_analysis: Optional[dict] = None,
    ) -> str:
        """
        Generate HTML report using pre-computed correlation analysis + CoT-enhanced LLM prompt.

        Integrated reasoning artefacts (Bayesian fusion / causal / calibration)
        are surfaced from `reasoning_result` and the blackboard's "reasoning"
        section so the report prompt actually sees them.
        """

        rr = reasoning_result if isinstance(reasoning_result, dict) else {}
        integrated_analysis = rr.get("integrated_analysis") or {}
        calibration = rr.get("calibration") or {}
        # Pull calibration / integrated_analysis from the blackboard only when
        # the in-memory reasoning_result didn't carry them — blackboard reads
        # are best-effort and silently fall back to {} on failure.
        try:
            bb_reasoning = await _safe_read(self.bb, "reasoning", None, default={}) or {}
        except Exception:
            bb_reasoning = {}
        if isinstance(bb_reasoning, dict):
            integrated_analysis = integrated_analysis or bb_reasoning.get("integrated_analysis") or {}
            calibration = calibration or bb_reasoning.get("calibration") or {}
        bayesian_result = (
            integrated_analysis.get("fused_result")
            if isinstance(integrated_analysis, dict) else None
        ) or {}
        evidence_chain = (
            integrated_analysis.get("reasoning_chain")
            if isinstance(integrated_analysis, dict) else None
        ) or {}
        validated_causal = await _safe_read(self.bb, "validation", "causal_analysis", default={}) or {}
        validated_chain = await _safe_read(self.bb, "evidence", "chain", default={}) or {}
        validation_notes = await _safe_read(self.bb, "evidence", "validation_notes", default=[]) or []
        # ── Three-card joint-evidence tier (C1/C2/C3) ──────────────────────
        joint_tier = await _safe_read(self.bb, "validation", "joint_tier", default="") or ""
        joint_score = await _safe_read(self.bb, "validation", "joint_score", default=0.0) or 0.0
        joint_evidence_cards = await _safe_read(self.bb, "validation", "joint_evidence_cards", default=[]) or []
        joint_rationale = await _safe_read(self.bb, "validation", "joint_rationale", default="") or ""
        # ── HCAF 因果归因（三个创新方法：MSCBD/CTPR/CIC）────────────────────
        hcaf_attribution = await _safe_read(self.bb, "validation", "hcaf_attribution", default={}) or {}
        hcaf_status = await _safe_read(self.bb, "validation", "hcaf_attribution_status", default="skipped") or "skipped"
        causal_analysis = (
            integrated_analysis.get("causal_analysis")
            if isinstance(integrated_analysis, dict) else None
        ) or validated_causal
        evidence_chain = (
            integrated_analysis.get("reasoning_chain")
            if isinstance(integrated_analysis, dict) else None
        ) or validated_chain
        # ── Auto-execute probing recommendations ───────────────────────
        # Don't just emit suggestions — actually execute them and embed
        # the results in the report so operators don't have to chase the
        # references manually.
        auto_probe_findings = await self._run_auto_probes(
            target_as=str(asn),
            analysis_window={"start": start_time, "end": end_time},
            correlation_analysis=correlation_analysis,
            routing_result=routing_raw if isinstance(routing_raw, dict) else {},
            traffic_result=traffic_raw if isinstance(traffic_raw, dict) else {},
        )

        payload = {
            "target_as": asn,
            "user_analysis_window": f"{start_time} to {end_time}",
            "traffic_anomaly_window": traffic_anomaly_window,
            "correlation_analysis": _slim(correlation_analysis, limit=10),
            "traffic": _slim(traffic_result, limit=10),
            "routing": _slim(routing_result, limit=10),
            "reasoning": _slim(reasoning_result, limit=5),
            "retrieved_context": _slim(reasoning_result.get("retrieved_context") if isinstance(reasoning_result, dict) else None, limit=3),
            "threat_intel_result": _slim(reasoning_result.get("threat_intel_result") if isinstance(reasoning_result, dict) else {}, limit=5),
            "diagnosis": _slim(_normalize(_safe_read_sync(self.bb, "diagnosis", "result", {})), limit=5),
            "evidence_board": _slim(_normalize(_safe_read_sync(self.bb, "evidence", None, {})), limit=10),
            # Integrated reasoning layer (Bayesian fusion / causal / calibration):
            # previously dropped from the prompt, now surfaced so the LLM has to
            # cite the integrated-analysis artefacts in its reasoning chain.
            "integrated_analysis": _slim(integrated_analysis, limit=20),
            "causal_analysis": _slim(causal_analysis, limit=15),
            # Three-card joint-evidence tier (C1/C2/C3) — written by workflow
            # engine after JOINT_EVIDENCE state; rendered as paper figure cards.
            "joint_tier": joint_tier,
            "joint_score": round(float(joint_score), 3),
            "joint_evidence_cards": _slim(joint_evidence_cards, limit=5),
            "joint_rationale": joint_rationale,
            # HCAF 因果归因（三个创新方法：MSCBD/CTPR/CIC）
            "hcaf_attribution": _slim(hcaf_attribution, limit=15) if hcaf_attribution else {},
            "hcaf_attribution_status": hcaf_status,
        "causal_interpretation": {
            "status": "observational_association_only",
            "direction_is_temporal_evidence": True,
            "causation_established": False,
            "required_confirmation": [
                "prefix-level routing changes seen by affected vantage points",
                "traffic impact aligned with affected prefixes or regions",
                "independent probes or operator telemetry",
                "alternative-cause checks for maintenance, attack, and application failure",
            ],
        },
            "bayesian_result": _slim(bayesian_result, limit=10),
            "calibration": _slim(calibration, limit=10),
            "evidence_chain": _slim(evidence_chain, limit=10),
            "validation_notes": _slim(validation_notes, limit=10),
            # Auto-probe findings (executed before LLM, embedded so operators
            # don't have to run probes themselves).
            "auto_probe_findings": auto_probe_findings,
            "auto_probe_summary": _summarize_auto_probes(auto_probe_findings),
            # Intentionally OMIT `traffic_plot_path` from the payload to stop the
            # LLM from emitting `<img src="/abs/path/to/file.png">` (broken when
            # the HTML is opened locally).  We expose only `traffic_plot_embedded`
            # so the LLM knows the chart is available; the chart is then embedded
            # by `_inject_traffic_plot` after the LLM responds.
            "traffic_plot_embedded": bool(traffic_plot_base64),
        }

        # ── Hard size cap ──────────────────────────────────────────────
        # Trim the payload down if it still exceeds the budget after slim().
        payload = _trim_to_size(payload)
        payload_size = _estimate_size(payload)
        logger.info(
            f"[ReportAgent._generate_report_html] payload size: "
            f"{payload_size} bytes (cap {_MAX_PAYLOAD_BYTES})"
        )

        data_json = json.dumps(payload, indent=2, ensure_ascii=False, default=_json_serial)

        # 统一 CoT prompt — 两条报告路径都必须强制要求 OBSERVE→INFER→LINK→CONCLUDE→CITE。
        # 之前 _generate_report_html 和 generate_report_html 各有一份 prompt，
        # 简化版那份丢了 counterfactual / citation 规则，导致 standalone 报告
        # 不带 CoT 证据链。两边现在共用同一份 _render_report_prompt。
        prompt = _render_report_prompt(data_json)

        # ── Hard timeout on the synchronous LLM call ────────────────────
        # `self.llm.complete()` blocks the event loop; without a watchdog
        # the surrounding asyncio.wait_for cannot interrupt it. Offload
        # to a thread and apply a hard timeout so chief_agent always
        # receives a deterministic fallback instead of stalling.
        AGENT_LLM_TIMEOUT_S = _CONFIG_REPORT_LLM_TIMEOUT_S
        REPORT_MAX_TOKENS = _CONFIG_REPORT_MAX_TOKENS
        loop = asyncio.get_running_loop()
        html: str = ""
        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: self.llm.complete(
                        prompt, max_retries=1, max_tokens=REPORT_MAX_TOKENS,
                        # Provider-specific reasoning controls are merged in
                        # OpenAICompatibleLLM from LLM_THINKING_DISABLE.
                        extra_body=None,
                    ),
                ),
                timeout=AGENT_LLM_TIMEOUT_S,
            )
            # Prefer response.text (already processed through _extract_message_text
            # inside complete()), but guard against the case where content is empty
            # and reasoning_content was used instead (Kimi thinking / GLM-5 fallback).
            _raw_text = response.text if hasattr(response, "text") else ""
            if not _raw_text.strip():
                # Try reasoning_content from the raw HTTP response
                from llm.llm_factory import _extract_message_text
                _raw = getattr(response, "raw", None)
                if _raw is not None:
                    _msg = getattr(_raw, "choices", [None])[0] if _raw else None
                    if _msg is not None:
                        _msg_obj = getattr(_msg, "message", None)
                        if _msg_obj is not None:
                            _raw_text = _extract_message_text(_msg_obj)
                logger.info(
                    "[ReportAgent] response.text was empty; reasoning_content fallback: %d chars",
                    len(_raw_text),
                )
            html = _raw_text
        except asyncio.TimeoutError:
            logger.error(
                f"ReportAgent async LLM call exceeded {AGENT_LLM_TIMEOUT_S:.0f}s — "
                "returning empty html (caller renders fallback)."
            )
            html = ""

        html = html.strip()
        logger.info(
            "[ReportAgent] raw LLM report response: type=%s length=%d preview=%r",
            type(html).__name__, len(html), html[:300],
        )
        # Some providers wrap the report in markdown fences or prefix it with a
        # short explanation. Extract the actual HTML before validating it so a
        # 28KB CoT report is not discarded as "empty".
        fenced = re.search(r"```(?:html|HTML)?\s*\n(.*?)\n```", html, flags=re.DOTALL)
        if fenced:
            html = fenced.group(1).strip()
        else:
            for fence in ["```html\n", "```HTML\n", "```html", "```HTML", "```\n", "```"]:
                if html.startswith(fence):
                    html = html[len(fence):]
                    break
            for fence in ["\n```", "```"]:
                if html.endswith(fence):
                    html = html[:-len(fence)]
                    break

        # If the model emits prose before the document/fragment, discard only
        # that preamble. The report body itself remains entirely model-generated.
        first_tag = html.find("<")
        if first_tag > 0:
            html = html[first_tag:].strip()

        # If the model emitted a partial closing tag (e.g. truncated by the
        # token budget), append the missing pieces so downstream viewers
        # still get a complete, parseable document.
        if html and re.search(r"<html\b", html, flags=re.IGNORECASE) is not None \
                and re.search(r"</html>", html, flags=re.IGNORECASE) is None:
            html = html.rstrip() + "\n</body></html>"
        if html and html.lstrip().lower().startswith(("<html")) and \
                not html.lstrip().lower().startswith("<!doctype"):
            html = "<!DOCTYPE html>\n" + html.lstrip()

        return html

    async def _run_auto_probes(
        self,
        target_as: str,
        analysis_window: dict,
        correlation_analysis: Optional[dict],
        routing_result: dict,
        traffic_result: dict,
    ) -> list:
        """
        Execute the probing recommendations and return their findings.

        The recommendations themselves are generated later inside
        ``_generate_refutable_hypotheses`` which only runs during LLM-driven
        report rendering. To keep the auto-probe step bounded, we synthesise a
        sensible default set of probes from the correlation/traffic/routing
        inputs and execute them. The LLM prompt then surfaces the findings
        (and the human still sees the recommendation list below the findings).

        Failures are isolated per-probe; one bad probe does not block others.
        """
        try:
            from agents.auto_probe_executor import (
                AutoProbeExecutor, AutoProbeFinding,
            )
        except Exception as e:
            logger.warning(f"AutoProbeExecutor unavailable: {e}")
            return []

        recommendations = self._build_default_probe_recommendations(
            target_as=target_as,
            routing_result=routing_result or {},
            traffic_result=traffic_result or {},
            correlation_analysis=correlation_analysis or {},
        )
        if not recommendations:
            return []

        executor = AutoProbeExecutor(
            timeout=8.0,
            enable_external=True,
        )
        try:
            findings = await executor.execute_probes(
                recommendations,
                target_as=target_as,
                analysis_window=analysis_window,
            )
        except Exception as e:
            logger.warning(f"Auto probe batch failed: {e}")
            return []

        # Persist to blackboard so downstream tools / ReAct agent can read
        try:
            await self.bb.write(
                "report", "auto_probe_findings",
                [_probe_finding_to_dict(f) for f in findings],
            )
        except Exception:
            pass

        return [_probe_finding_to_dict(f) for f in findings]

    def _build_default_probe_recommendations(
        self,
        target_as: str,
        routing_result: dict,
        traffic_result: dict,
        correlation_analysis: dict,
    ) -> list:
        """
        Build a sensible default probe list from the analysis inputs.

        Mirrors what ``_generate_refutable_hypotheses`` would emit, but does
        not require the LLM to have already run. Keeps recommendations
        minimal so the auto-probe step finishes quickly.
        """
        recs: list = []

        # Hijack victim ASes → check victim traffic
        routing_hijack = (routing_result or {}).get("hijacks") or []
        if isinstance(routing_hijack, list) and routing_hijack:
            attackers = []
            for h in routing_hijack[:10]:
                if isinstance(h, dict):
                    a = h.get("attacker_as") or h.get("attacker") or h.get("hijacker_as")
                    if a:
                        attackers.append(str(a).replace("AS", ""))
            if attackers:
                recs.append({
                    "action": "check_victim_traffic",
                    "target": f"victim ASes: {', '.join(attackers[:5])}",
                    "method": "Query Cloudflare Radar for traffic drop during anomaly window",
                })

        # Affected prefixes → bgp_path_analysis
        prefixes: list = []
        for h in routing_hijack[:5]:
            if isinstance(h, dict):
                p = h.get("prefix") or h.get("hijacked_prefix")
                if p:
                    prefixes.append(str(p))
        if not prefixes:
            for k in ("victim_prefixes", "attacker_prefixes", "affected_prefixes"):
                pv = routing_result.get(k) or []
                if isinstance(pv, list):
                    prefixes.extend(str(p) for p in pv if p)
        if prefixes:
            recs.append({
                "action": "bgp_path_analysis",
                "target": f"prefixes: {', '.join(prefixes[:3])}",
                "method": "Query RIPE RIS for origin AS / AS_PATH",
            })

        # Traffic anomaly confirmation
        if isinstance(traffic_result, dict) and traffic_result.get("anomalies"):
            recs.append({
                "action": "collect_traffic_data",
                "target": f"AS{target_as}",
                "method": "Query Cloudflare Radar for AS-level traffic timeseries",
            })

        # Always offer traceroute probe for the target AS
        recs.append({
            "action": "traceroute_probing",
            "target": f"target AS{target_as}",
            "method": "Run traceroute to a known prefix of this AS",
        })

        return recs


def _probe_finding_to_dict(f) -> dict:
    """Serialise AutoProbeFinding to a JSON-safe dict."""
    if hasattr(f, "__dict__"):
        return {
            "action": getattr(f, "action", ""),
            "target": getattr(f, "target", ""),
            "success": bool(getattr(f, "success", False)),
            "summary": getattr(f, "summary", ""),
            "error": getattr(f, "error", ""),
            "execution_time_s": float(getattr(f, "execution_time_s", 0.0) or 0.0),
            "timestamp": getattr(f, "timestamp", ""),
            "data": _safe_probe_data(getattr(f, "data", {})),
        }
    return {"summary": str(f)}


def _safe_probe_data(data) -> dict:
    """Make probe data JSON-serialisable without exploding."""
    try:
        return json.loads(json.dumps(data, default=str))
    except Exception:
        return {"raw": str(data)[:1000]}


def _summarize_auto_probes(findings) -> dict:
    """Compact summary used by the LLM prompt to decide whether to mention probes."""
    if not findings:
        return {"total": 0, "successful": 0, "failed": 0, "headline": "未执行自动探测"}

    total = len(findings)
    successful = sum(1 for f in findings if f.get("success"))
    failed = total - successful
    lines = []
    for f in findings[:8]:
        icon = "✓" if f.get("success") else "✗"
        lines.append(f"{icon} {f.get('action')}: {f.get('summary', '')[:120]}")

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "headline": f"自动执行 {total} 个任务，成功 {successful} 个",
        "lines": lines,
    }


def _render_auto_probe_section(findings) -> str:
    """Render an "Auto-Probe Findings" HTML block to be inlined into fallback reports."""
    if not findings:
        return ""
    rows = []
    for f in findings:
        icon = "✅" if f.get("success") else "⚠️"
        rows.append(
            f"<tr><td>{icon}</td><td><code>{f.get('action')}</code></td>"
            f"<td>{f.get('target', '')}</td><td>{f.get('summary', '')}</td></tr>"
        )
    return (
        "<h3>Auto-Probe Findings (执行结果)</h3>"
        "<p>以下探测任务已由 agent 自动执行，结果已整合到本报告中：</p>"
        "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse'>"
        "<thead><tr><th>状态</th><th>探测</th><th>目标</th><th>结果摘要</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _build_default_probe_recommendations_standalone(
    target_as: str,
    routing_result: dict,
    traffic_result: dict,
    correlation_analysis: dict,
) -> list:
    """Module-level helper mirroring ``ReportAgent._build_default_probe_recommendations``.

    Used by ``generate_report_html`` (standalone entry point) which has no
    blackboard context to call into the instance method.
    """
    recs: list = []

    routing_hijack = (routing_result or {}).get("hijacks") or []
    if isinstance(routing_hijack, list) and routing_hijack:
        attackers = []
        for h in routing_hijack[:10]:
            if isinstance(h, dict):
                a = h.get("attacker_as") or h.get("attacker") or h.get("hijacker_as")
                if a:
                    attackers.append(str(a).replace("AS", ""))
        if attackers:
            recs.append({
                "action": "check_victim_traffic",
                "target": f"victim ASes: {', '.join(attackers[:5])}",
                "method": "Query Cloudflare Radar for traffic drop during anomaly window",
            })

    prefixes: list = []
    for h in routing_hijack[:5]:
        if isinstance(h, dict):
            p = h.get("prefix") or h.get("hijacked_prefix")
            if p:
                prefixes.append(str(p))
    if not prefixes:
        for k in ("victim_prefixes", "attacker_prefixes", "affected_prefixes"):
            pv = (routing_result or {}).get(k) or []
            if isinstance(pv, list):
                prefixes.extend(str(p) for p in pv if p)
    if prefixes:
        recs.append({
            "action": "bgp_path_analysis",
            "target": f"prefixes: {', '.join(prefixes[:3])}",
            "method": "Query RIPE RIS for origin AS / AS_PATH",
        })

    if isinstance(traffic_result, dict) and traffic_result.get("anomalies"):
        recs.append({
            "action": "collect_traffic_data",
            "target": f"AS{target_as}",
            "method": "Query Cloudflare Radar for AS-level traffic timeseries",
        })

    recs.append({
        "action": "traceroute_probing",
        "target": f"target AS{target_as}",
        "method": "Run traceroute to a known prefix of this AS",
    })

    return recs


def _normalize(data: Any) -> dict:
    """Ensure data is a dict, never fail on None."""
    if data is None:
        return {}
    if isinstance(data, dict):
        return data
    return {"raw": str(data)}

def _render_fallback_html_for_agent(self, asn: str, start_time: str, end_time: str,
                                    traffic_result, routing_result, reasoning_result) -> str:
    """Deterministic HTML report used when the LLM call fails.

    The blackboard's `routing` section is built by `routing_agent.py`'s
    `_prepare_routing_payload`. Real keys are `hijacks` / `origin_hijacking` /
    `leaks` / `outages` — NOT the inner `hijack/origin_hijacked/...` shape used
    by the standalone routing detector.
    """
    def _fmt(obj):
        try:
            return json.dumps(obj, indent=2, ensure_ascii=False, default=_json_serial)[:4000]
        except Exception:
            return str(obj)[:4000]

    def _fmt_truncated(obj, max_chars=8000):
        """Format with higher cap for important sections."""
        try:
            return json.dumps(obj, indent=2, ensure_ascii=False, default=_json_serial)[:max_chars]
        except Exception:
            return str(obj)[:max_chars]

    traffic_summary = (traffic_result or {}).get("result", traffic_result or {}) or {}
    routing_summary = (routing_result or {}).get("result", routing_result or {}) or {}
    reasoning_summary = (reasoning_result or {}).get("result", reasoning_result or {}) or {}

    # Real blackboard routing keys (set by routing_agent._prepare_routing_payload)
    hijack_count = len(routing_summary.get("hijacks") or [])

    # annotation_package format: {hijack: {origin_hijacked: [...]}, leak: {...}, outage: {...}}
    if hijack_count == 0 and isinstance(routing_summary, dict):
        hijack_section = routing_summary.get("hijack") or {}
        leak_section = routing_summary.get("leak") or {}
        if isinstance(hijack_section, dict):
            for key in ("origin_hijacked", "forge_hijacked"):
                evs = hijack_section.get(key) or []
                if evs:
                    hijack_count += len(evs)
        leak_count_ann = 0
        if isinstance(leak_section, dict):
            leak_count_ann = len(leak_section.get("route_leaks") or [])
        else:
            leak_count_ann = len(routing_summary.get("route_leaks") or [])
    else:
        leak_count_ann = 0

    attacker_count = len(routing_summary.get("origin_hijacking") or []) + \
                     len(routing_summary.get("forge_hijacking") or [])
    leak_count = leak_count_ann if leak_count_ann > 0 else len(routing_summary.get("leaks") or [])
    outage_info = routing_summary.get("outages") or routing_summary.get("outage") or {}
    outage_score = outage_info.get("outage_score", 0) if isinstance(outage_info, dict) else 0
    outage_suspected = bool(outage_info.get("is_outage_suspected")) if isinstance(outage_info, dict) else False
    routing_confidence = routing_summary.get("confidence", "n/a")

    traffic_verdict = (traffic_summary.get("anomaly_count", 0) or 0) if isinstance(traffic_summary, dict) else 0
    traffic_pct = traffic_summary.get("percent_change", "n/a") if isinstance(traffic_summary, dict) else "n/a"

    # Build top hijacks table for the fallback so the report is actually
    # informative even when the LLM call times out.
    hijack_rows = []
    if isinstance(routing_summary, dict):
        for h in (routing_summary.get("hijacks") or [])[:10]:
            if not isinstance(h, dict):
                continue
            hijack_rows.append(
                f"<tr><td>{h.get('timestamp', 'N/A')}</td>"
                f"<td>{h.get('prefix', 'N/A')}</td>"
                f"<td>{h.get('victim_as') or h.get('expected_origin', 'N/A')}</td>"
                f"<td>{h.get('origin_as') or h.get('hijacker_as', 'N/A')}</td></tr>"
            )
        if not hijack_rows:
            # annotation_package nested format
            hijack_section = routing_summary.get("hijack") or {}
            for h in (hijack_section.get("origin_hijacked") or [])[:10]:
                if not isinstance(h, dict):
                    continue
                hijack_rows.append(
                    f"<tr><td>{h.get('timestamp', 'N/A')}</td>"
                    f"<td>{h.get('prefix', 'N/A')}</td>"
                    f"<td>{h.get('victim_as') or h.get('expected_origin', 'N/A')}</td>"
                    f"<td>{h.get('origin_as') or h.get('hijacker_as', 'N/A')}</td></tr>"
                )

    leak_rows = []
    if isinstance(routing_summary, dict):
        for l in (routing_summary.get("leaks") or [])[:5]:
            if not isinstance(l, dict):
                continue
            leak_rows.append(
                f"<tr><td>{l.get('timestamp', 'N/A')}</td>"
                f"<td>{l.get('prefix', 'N/A')}</td>"
                f"<td>{l.get('as_path', 'N/A')}</td>"
                f"<td>{l.get('reason', 'N/A')}</td></tr>"
            )
        if not leak_rows:
            leak_section = routing_summary.get("leak") or {}
            for l in (leak_section.get("route_leaks") or [])[:5]:
                if not isinstance(l, dict):
                    continue
                leak_rows.append(
                    f"<tr><td>{l.get('timestamp', 'N/A')}</td>"
                    f"<td>{l.get('prefix', 'N/A')}</td>"
                    f"<td>{l.get('as_path', 'N/A')}</td>"
                    f"<td>{l.get('reason', 'N/A')}</td></tr>"
                )

    # Build anomalies table
    anomaly_rows = []
    anomalies = traffic_summary.get("anomalies", []) if isinstance(traffic_summary, dict) else []
    for a in anomalies[:10]:
        if not isinstance(a, dict):
            continue
        anomaly_rows.append(
            f"<tr><td>{a.get('timestamp', 'N/A')}</td>"
            f"<td>{a.get('current_value', a.get('value', 'N/A'))}</td>"
            f"<td>{a.get('historical_mean', a.get('mean', 'N/A'))}</td>"
            f"<td>{a.get('z_score', 'N/A')}</td>"
            f"<td>{a.get('severity', 'N/A')}</td>"
            f"<td>{a.get('percentile_direction', 'N/A')}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>BGP / Traffic Report — AS{asn}</title>
<style>
body{{font-family:-apple-system,Segoe UI,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#222;}}
h1{{border-bottom:2px solid #2c5282;padding-bottom:8px;}}
h2{{color:#2c5282;margin-top:32px;border-bottom:1px solid #eee;padding-bottom:4px;}}
pre{{background:#f7fafc;padding:12px;border-radius:6px;border:1px solid #e2e8f0;overflow:auto;font-size:12px;}}
.banner{{background:#fef3c7;border:1px solid #f6ad55;border-radius:6px;padding:12px;margin:16px 0;}}
table{{border-collapse:collapse;margin:12px 0;}}
td,th{{border:1px solid #e2e8f0;padding:6px 12px;text-align:left;}}
.metric{{display:inline-block;background:#edf2f7;padding:12px 18px;border-radius:6px;margin:6px 6px 6px 0;}}
.metric .v{{font-size:22px;font-weight:600;color:#2c5282;}}
.metric .l{{font-size:12px;color:#4a5568;text-transform:uppercase;letter-spacing:.05em;}}
</style></head><body>
<h1>BGP / Traffic Anomaly Report — AS{asn}</h1>
<div class="banner">
<strong>⚠ Fallback report:</strong> The LLM-driven report generator failed
(stream timeout or upstream 422). This document is the deterministic fallback
rendered directly from the analysis payload.
</div>

<h2>1. Event Window</h2>
<ul>
<li><strong>AS:</strong> {asn}</li>
<li><strong>Start:</strong> {start_time}</li>
<li><strong>End:</strong> {end_time}</li>
</ul>

<h2>2. Detection Counts</h2>
<div class="metric"><div class="v">{hijack_count}</div><div class="l">Origin Hijacks (victim-side)</div></div>
<div class="metric"><div class="v">{attacker_count}</div><div class="l">Origin Hijacks (attacker-side)</div></div>
<div class="metric"><div class="v">{leak_count}</div><div class="l">Route Leaks</div></div>
<div class="metric"><div class="v">{outage_score:.2f}</div><div class="l">Outage Score</div></div>
<div class="metric"><div class="v">{'YES' if outage_suspected else 'no'}</div><div class="l">Outage Suspected</div></div>
<div class="metric"><div class="v">{routing_confidence}</div><div class="l">Routing Confidence</div></div>
<div class="metric"><div class="v">{traffic_verdict}</div><div class="l">Traffic Anomalies</div></div>
<div class="metric"><div class="v">{traffic_pct}</div><div class="l">Traffic % Change</div></div>

<h2>3. Traffic Anomalies</h2>
<table>
<tr><th>Timestamp</th><th>Value</th><th>Historical Mean</th><th>Z-Score</th><th>Severity</th><th>Direction</th></tr>
{''.join(anomaly_rows) if anomaly_rows else '<tr><td colspan="6">No anomalies</td></tr>'}
</table>

<h2>4. Origin Hijacks (Top 10)</h2>
<table>
<tr><th>Timestamp</th><th>Prefix</th><th>Legitimate Origin</th><th>Hijacker ASN</th></tr>
{''.join(hijack_rows) if hijack_rows else '<tr><td colspan="4">No hijacks</td></tr>'}
</table>

<h2>5. Route Leaks (Top 5)</h2>
<table>
<tr><th>Timestamp</th><th>Prefix</th><th>AS Path</th><th>Reason</th></tr>
{''.join(leak_rows) if leak_rows else '<tr><td colspan="4">No route leaks</td></tr>'}
</table>

<h2>6. Routing Analysis (Raw Payload)</h2>
<pre>{_fmt_truncated(routing_summary, 8000)}</pre>

<h2>7. Traffic Analysis (Raw Payload)</h2>
<pre>{_fmt_truncated(traffic_summary, 4000)}</pre>

<h2>8. Reasoning (Raw Payload)</h2>
<pre>{_fmt_truncated(reasoning_summary, 4000)}</pre>

</body></html>
"""

# Monkey-patch the fallback as an instance method on ReportAgent without
# disturbing the rest of the class body (which is large).
ReportAgent._render_fallback_html = _render_fallback_html_for_agent


def generate_report_html(
    asn: str,
    start_time: str,
    end_time: str,
    traffic_result: Optional[dict] = None,
    routing_result: Optional[dict] = None,
    reasoning_result: Optional[dict] = None,
    traffic_plot_path: Optional[str] = None,
    traffic_plot_base64: Optional[str] = None,
    traffic_anomaly_window: Optional[dict] = None,
    victim_traffic_results: Optional[dict] = None,
    victim_asns: Optional[list] = None,
    prefix_traffic_results: Optional[dict] = None,
    correlation_score_result: Optional[dict] = None,
    as_path_delta_result: Optional[dict] = None,
    as_relationships_result: Optional[dict] = None,
    probe_reachability_result: Optional[dict] = None,
    roa_validation_result: Optional[dict] = None,
    threat_intel_result: Optional[dict] = None,
    law_analysis: Optional[dict] = None,
    org_name: Optional[str] = None,
    output_dir: Optional[Path] = None,
    integrated_analysis: Optional[dict] = None,
    calibration: Optional[dict] = None,
    bayesian_result: Optional[dict] = None,
    evidence_chain: Optional[dict] = None,
    # Three-card joint-evidence tier (C1/C2/C3) for paper figure rendering
    joint_tier: Optional[str] = None,
    joint_score: Optional[float] = None,
    joint_evidence_cards: Optional[list] = None,
    joint_rationale: Optional[str] = None,
    # HCAF 因果归因（三个创新方法：MSCBD/CTPR/CIC）
    hcaf_attribution: Optional[dict] = None,
) -> str:
    """
    Standalone entry point: generate an LLM-driven HTML report and save it.

    Pass-through of integrated_analysis / calibration / bayesian_result /
    evidence_chain ensures the final report surfaces the Bayesian fusion,
    causal inference, and confidence calibration outputs that were computed
    upstream in the reasoning pipeline but previously dropped from the LLM
    payload.
    """
    from utils.logger import logger

    llm, _ = setup_llm_settings(
        model=MODEL, api_key=API_KEY, base_url=BASE_URL,
        temperature=DEFAULT_TEMP_REPORT, timeout=600.0, max_retries=3,
    )

    # Pre-compute correlation analysis
    correlation_analysis = None
    if traffic_result is not None and routing_result is not None:
        correlation_analysis = analyze_temporal_correlation(
            traffic_raw=traffic_result or {},
            routing_result=routing_result or {},
            target_as=str(asn),
            victim_traffic_results=victim_traffic_results or {},
            victim_asns=victim_asns or [],
            prefix_traffic_results=prefix_traffic_results or {},
            correlation_score_result=correlation_score_result or {},
        )

    # ── Surface integrated-analysis artefacts that used to be dropped ──────
    # Fall back to fields inside reasoning_result when callers (chief_agent /
    # workflow_engine) only pass the bundled reasoning dict.
    rr = reasoning_result if isinstance(reasoning_result, dict) else {}
    integrated_analysis = integrated_analysis or rr.get("integrated_analysis") or {}
    calibration = calibration or rr.get("calibration") or {}
    bayesian_result = bayesian_result or (
        integrated_analysis.get("fused_result") if isinstance(integrated_analysis, dict) else None
    ) or {}
    evidence_chain = evidence_chain or (
        integrated_analysis.get("reasoning_chain") if isinstance(integrated_analysis, dict) else None
    ) or {}
    causal_analysis = (
        integrated_analysis.get("causal_analysis") if isinstance(integrated_analysis, dict) else None
    ) or {}

    # ── Auto-execute probing recommendations ───────────────────────
    # Run the actual probes before asking the LLM to write the report,
    # so the rendered HTML contains concrete probe results rather than
    # only suggestions. Stays best-effort: if probing is unavailable or
    # times out, the report simply omits the section.
    auto_probe_findings = []
    try:
        from agents.auto_probe_executor import run_auto_probes
        recommendations = _build_default_probe_recommendations_standalone(
            target_as=str(asn),
            routing_result=routing_result or {},
            traffic_result=traffic_result or {},
            correlation_analysis=correlation_analysis or {},
        )
        if recommendations:
            try:
                loop = asyncio.get_event_loop()
                probe_results = loop.run_until_complete(run_auto_probes(
                    recommendations,
                    target_as=str(asn),
                    analysis_window={"start": start_time, "end": end_time},
                    timeout=8.0,
                ))
                auto_probe_findings = [
                    _probe_finding_to_dict(f) for f in probe_results
                ]
            except RuntimeError:
                # 没有运行中的事件循环，跳过自动探测
                pass
    except Exception as _ap_err:
        logger.debug(f"auto-probe skipped: {_ap_err}")

    # ── Adaptive payload orchestration ───────────────────────────────────────
    # Different events produce wildly different evidence volumes:
    #   * A quiet 30-min outage: ~5 events, ~2 KB payload
    #   * A week-long hijack campaign: ~900 events, ~110 KB payload
    # Both must reach the LLM as informative HTML, not as a truncated skeleton.
    # Strategy: build a "tiered" payload — keep full evidence when small,
    # rank-and-sample when large. The LLM gets the most important events
    # (highest severity, longest-lived, first/last seen) instead of being
    # handed arbitrary slices.
    from config import REPORT_PAYLOAD_MAX_CHARS

    routing_events = _extract_routing_events(routing_result)
    traffic_events = _extract_traffic_events(traffic_result, traffic_anomaly_window)

    payload_seed = {
        "target_as": asn,
        "org_name": org_name,
        "user_analysis_window": f"{start_time} to {end_time}",
        "traffic_anomaly_window": traffic_anomaly_window,
        "correlation_analysis": correlation_analysis,
        "traffic": _slim(_normalize(traffic_result), limit=20),
        "routing": _slim(_normalize(routing_result), limit=20),
        "classification": _slim(_normalize(reasoning_result), limit=10),
        "reasoning": _slim(_normalize(reasoning_result), limit=10),
        "victim_traffic_results": victim_traffic_results or {},
        "victim_asns": victim_asns or [],
        "prefix_traffic_results": prefix_traffic_results or {},
        "correlation_score_result": correlation_score_result or {},
        "as_path_delta_result": as_path_delta_result or {},
        "as_relationships_result": as_relationships_result or {},
        "probe_reachability_result": probe_reachability_result or {},
        "roa_validation_result": roa_validation_result or {},
        "threat_intel_result": threat_intel_result or {},
        "law_analysis": _slim(_normalize(law_analysis), limit=10),
        "integrated_analysis": integrated_analysis,
        "auto_probe_findings": auto_probe_findings,
        "auto_probe_summary": _summarize_auto_probes(auto_probe_findings),
        "causal_interpretation": {
            "status": "observational_association_only",
            "direction_is_temporal_evidence": True,
            "causation_established": False,
            "required_confirmation": [
                "prefix-level routing changes seen by affected vantage points",
                "traffic impact aligned with affected prefixes or regions",
                "independent probes or operator telemetry",
                "alternative-cause checks for maintenance, attack, and application failure",
            ],
        },
        "hcaf_attribution": hcaf_attribution or {},
        "bayesian_result": bayesian_result,
        "calibration": calibration,
        "evidence_chain": evidence_chain,
        # Three-card joint-evidence tier (C1/C2/C3) — sourced from workflow
        # engine's JOINT_EVIDENCE state; rendered as paper figure cards.
        "joint_tier": joint_tier or "",
        "joint_score": round(float(joint_score or 0.0), 3),
        "joint_evidence_cards": _slim(joint_evidence_cards or [], limit=5),
        "joint_rationale": joint_rationale or "",
        # Intentionally OMIT `traffic_plot_path` — see same comment in
        # `_generate_report_html` payload.  `_inject_traffic_plot` will
        # embed the chart as base64 after the LLM responds.
        "traffic_plot_embedded": bool(traffic_plot_base64),
    }

    payload_size = _estimate_size(payload_seed)
    if payload_size > REPORT_PAYLOAD_MAX_CHARS:
        payload_seed = _trim_to_size(payload_seed, max_bytes=REPORT_PAYLOAD_MAX_CHARS)
        payload_size = _estimate_size(payload_seed)

    if routing_events:
        logger.info(
            f"[generate_report_html] event counts: "
            f"routing={len(routing_events)}, traffic={len(traffic_events)}, "
            f"payload={payload_size} chars (cap {REPORT_PAYLOAD_MAX_CHARS})"
        )
    payload = payload_seed

    logger.info(
        f"[generate_report_html] payload size: {payload_size} bytes "
        f"(trimmed to {len(json.dumps(payload, default=str))} chars)"
    )

    data_json = json.dumps(payload, indent=2, ensure_ascii=False, default=_json_serial)
    prompt = _render_report_prompt(data_json)
    prompt_size = len(prompt)
    logger.info(f"[generate_report_html] prompt size: {prompt_size} chars (~{prompt_size//4} tokens)")

    # ── LLM call with hard timeout ────────────────────────────────────────
    # `llm.complete()` is a synchronous HTTP call. Without a watchdog it can
    # block the entire workflow when the upstream is slow or hangs. Wrap it
    # in a thread and enforce a hard timeout (default 120s) so chief_agent
    # always receives a deterministic fallback HTML instead of timing out
    # the whole pipeline.
    #
    # IMPORTANT: do NOT use `with ThreadPoolExecutor(...) as pool:` here.
    # The context manager's __exit__ calls `pool.shutdown(wait=True)` which
    # blocks until the orphan thread finishes — defeating the timeout.
    # We instead pass the future back, fire-and-forget, so the thread keeps
    # running in the background while the caller already has the report.
    # Default 60s: short enough that chief_agent/CLI users don't wait minutes
    # per case, long enough for Kimi to return a complete HTML report. Override
    # via env var REPORT_LLM_TIMEOUT_S for batch processing.
    REPORT_LLM_TIMEOUT_S = _CONFIG_REPORT_LLM_TIMEOUT_S
    # Kimi API takes ~50s for 2K output tokens. Cap at 12000 to stay safely under
    # the 180s client timeout. Override via env var REPORT_MAX_TOKENS.
    REPORT_MAX_TOKENS = _CONFIG_REPORT_MAX_TOKENS
    html: str = ""
    # Retry strategy: attempt LLM call with exponential backoff for retryable errors.
    # This significantly reduces fallback rate when the upstream API is temporarily
    # overloaded (429) or rate-limited (422 on some endpoints).
    max_retries = 3
    last_err: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        future = None
        pool = None
        try:
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

            # Use streaming: accumulate all chunks without a token cap.  The
            # Kimi API returns chunks progressively so this is reliable even for
            # large HTML outputs.  The client timeout (REPORT_LLM_TIMEOUT_S) guards
            # against indefinite hangs.  The stream itself is unbounded.
            def _stream_and_wait():
                from llm.llm_factory import _extract_delta_text, _merge_extra_body
                import logging
                _stream_logger = logging.getLogger("bgp_tracer")
                stream = llm.client.chat.completions.create(
                    model=llm._model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=llm.temperature,
                    max_tokens=REPORT_MAX_TOKENS,  # Use env-var cap, not model's 8192
                    stream=True,
                    extra_body=_merge_extra_body(None),
                )
                text_acc = ""
                chunk_count = 0
                last_logged_len = 0
                for chunk in stream:
                    chunk_count += 1
                    if not chunk.choices:
                        _stream_logger.debug(
                            "[_stream_and_wait] chunk %d: no choices", chunk_count
                        )
                        continue
                    delta = chunk.choices[0].delta
                    added = _extract_delta_text(delta)
                    if added:
                        text_acc += added
                        # Log progress every ~5 KB to confirm streaming is alive
                        if len(text_acc) - last_logged_len > 5120:
                            _stream_logger.info(
                                "[_stream_and_wait] streamed %d chars so far (%d chunks)",
                                len(text_acc), chunk_count,
                            )
                            last_logged_len = len(text_acc)
                _stream_logger.info(
                    "[_stream_and_wait] stream complete: %d chunks, %d total chars",
                    chunk_count, len(text_acc),
                )
                if not text_acc.strip():
                    raise RuntimeError("LLM returned an empty report response")
                return text_acc

            future = pool.submit(_stream_and_wait)
            html = future.result(timeout=REPORT_LLM_TIMEOUT_S)
            pool.shutdown(wait=False)
            last_err = None
            break  # success
        except concurrent.futures.TimeoutError as llm_err:
            last_err = llm_err
            err_str = "timeout"
            logger.error(
                f"[generate_report_html] Attempt {attempt}/{max_retries}: LLM call "
                f"exceeded {REPORT_LLM_TIMEOUT_S:.0f}s timeout."
            )
            if pool is not None:
                pool.shutdown(wait=False)
            if attempt < max_retries:
                wait_s = min(2 ** attempt + 1.0, 30.0)
                import time as _time
                _time.sleep(wait_s)
                continue
            break
        except Exception as llm_err:
            last_err = llm_err
            err_str = str(llm_err).lower()
            if pool is not None:
                pool.shutdown(wait=False)
            is_retryable = any(kw in err_str for kw in [
                "429", "too many requests", "rate limit",
                "422", "unprocessable", "service unavailable",
                "500", "502", "503", "504", "gateway timeout",
                "connection", "timeout"
            ])
            if is_retryable and attempt < max_retries:
                wait_s = min(2 ** attempt + 1.0, 30.0)
                logger.warning(
                    f"[generate_report_html] Attempt {attempt}/{max_retries} failed "
                    f"(retryable: {llm_err!r}); retrying in {wait_s:.1f}s..."
                )
                import time as _time
                _time.sleep(wait_s)
                continue
            # Final failure: log and break out of retry loop
            logger.error(
                f"[generate_report_html] LLM call failed after {attempt} attempt(s): "
                f"{llm_err!r} — rendering deterministic fallback HTML."
            )
            break

    # ── P4: Fallback gate (standalone path) ──────────────────────────────
    # Mirror the ReportAgent._should_use_fallback() gate so that the standalone
    # entry point respects REPORT_REQUIRE_LLM=1 as well.
    _USE_FALLBACK = not _CONFIG_REPORT_REQUIRE_LLM

    if not html:
        if not _USE_FALLBACK:
            # REPORT_REQUIRE_LLM=1: return error so caller can retry/escalate
            raise RuntimeError(
                f"[generate_report_html] REPORT_REQUIRE_LLM=1: LLM failed after "
                f"{max_retries} attempts (last_error={last_err!r}); "
                "returning error instead of fallback HTML."
            )
        logger.info(
            f"[generate_report_html] Falling back to deterministic HTML after "
            f"{max_retries} attempts (last error: {last_err!r})."
        )
        return _render_fallback_html_for_standalone(
            asn=str(asn),
            start_time=str(start_time),
            end_time=str(end_time),
            traffic_result=traffic_result or {},
            routing_result=routing_result or {},
            reasoning_result=reasoning_result or {},
            output_dir=output_dir,
        )

    html = html.strip()

    # Strip leading prose (e.g. "We need to write an HTML report ...") the
    # model sometimes emits before the actual document when its output budget
    # is partially spent on reasoning_content.
    first_tag = html.find("<")
    if first_tag > 0:
        html = html[first_tag:].strip()

    # Unwrap markdown code fences that some providers (Kimi, GLM) wrap the
    # whole report in.
    import re as _re
    fence_match = _re.search(r"```(?:html|HTML)?\s*\n(.*?)\n```", html, _re.DOTALL)
    if fence_match:
        html = fence_match.group(1).strip()
    else:
        for fence in ["```html\n", "```HTML\n", "```html", "```HTML", "```\n", "```"]:
            if html.startswith(fence):
                html = html[len(fence):]
                break
        for fence in ["\n```", "```"]:
            if html.endswith(fence):
                html = html[:-len(fence)]
                break
        html = html.strip()

    # Auto-close truncated documents so downstream viewers always see a
    # complete file even when the LLM ran out of output tokens mid-`<html>`.
    if html and _re.search(r"<html\b", html, _re.IGNORECASE) and \
            _re.search(r"</html>", html, _re.IGNORECASE) is None:
        html = html.rstrip() + "\n</body></html>"
    if html and html.lstrip().lower().startswith("<html") and \
            not html.lstrip().lower().startswith("<!doctype"):
        html = "<!DOCTYPE html>\n" + html.lstrip()

    if not html.startswith("<"):
        html = f"<!DOCTYPE html><html><body><pre>{html}</pre></body></html>"

    if output_dir is None:
        output_dir = Path(__file__).parent.parent / "results" / "html"
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"llm_report_AS{asn}_{timestamp}.html"
    path.write_text(html, encoding="utf-8")
    logger.info(f"LLM report saved: {path}")
    return str(path)


def _render_fallback_html_for_standalone(
    asn: str,
    start_time: str,
    end_time: str,
    traffic_result: Optional[dict],
    routing_result: Optional[dict],
    reasoning_result: Optional[dict],
    output_dir: Optional[Path],
) -> str:
    """Deterministic HTML report for the standalone ``generate_report_html`` entry point.

    Mirrors ``ReportAgent._render_fallback_html_for_agent`` so chief_agent,
    workflow_engine, and tool_implementations all see the same fallback shape
    when the LLM call times out or fails.
    """
    from utils.logger import logger as _logger

    def _fmt(obj):
        try:
            return json.dumps(obj, indent=2, ensure_ascii=False, default=_json_serial)[:4000]
        except Exception:
            return str(obj)[:4000]

    def _fmt_truncated(obj, max_chars=8000):
        """Format with higher cap for important sections."""
        try:
            return json.dumps(obj, indent=2, ensure_ascii=False, default=_json_serial)[:max_chars]
        except Exception:
            return str(obj)[:max_chars]

    traffic_summary = (traffic_result or {}).get("result", traffic_result or {}) or {}
    routing_summary = (routing_result or {}).get("result", routing_result or {}) or {}
    reasoning_summary = (reasoning_result or {}).get("result", reasoning_result or {}) or {}

    anomaly_count = traffic_summary.get("anomaly_count", 0) if isinstance(traffic_summary, dict) else 0
    pct = traffic_summary.get("percent_change", "n/a") if isinstance(traffic_summary, dict) else "n/a"

    def _count(*keys):
        for k in keys:
            v = routing_summary.get(k)
            if isinstance(v, list):
                return len(v)
        return 0

    # annotation_package format: {hijack: {origin_hijacked: [...]}, leak: {...}, outage: {...}}
    hijack_count = _count("hijacks", "origin_hijacked", "origin_hijacks")
    if hijack_count == 0 and isinstance(routing_summary, dict):
        hijack_section = routing_summary.get("hijack") or {}
        if isinstance(hijack_section, dict):
            for key in ("origin_hijacked", "forge_hijacked"):
                evs = hijack_section.get(key) or []
                if evs:
                    hijack_count += len(evs)

    leak_count = _count("leaks", "route_leaks")
    if leak_count == 0 and isinstance(routing_summary, dict):
        leak_section = routing_summary.get("leak") or {}
        if isinstance(leak_section, dict):
            evs = leak_section.get("route_leaks") or []
            if evs:
                leak_count = len(evs)

    outage_info = routing_summary.get("outages") or routing_summary.get("outage") or {}
    outage_suspected = bool(outage_info.get("is_outage_suspected")) if isinstance(outage_info, dict) else False
    routing_conf = routing_summary.get("confidence", "n/a") if isinstance(routing_summary, dict) else "n/a"

    # Build top hijacks table
    hijack_rows = []
    if isinstance(routing_summary, dict):
        for h in (routing_summary.get("hijacks") or [])[:10]:
            if not isinstance(h, dict):
                continue
            hijack_rows.append(
                f"<tr><td>{h.get('timestamp', 'N/A')}</td>"
                f"<td>{h.get('prefix', 'N/A')}</td>"
                f"<td>{h.get('victim_as') or h.get('expected_origin', 'N/A')}</td>"
                f"<td>{h.get('origin_as') or h.get('hijacker_as', 'N/A')}</td></tr>"
            )
        if not hijack_rows:
            hijack_section = routing_summary.get("hijack") or {}
            for h in (hijack_section.get("origin_hijacked") or [])[:10]:
                if not isinstance(h, dict):
                    continue
                hijack_rows.append(
                    f"<tr><td>{h.get('timestamp', 'N/A')}</td>"
                    f"<td>{h.get('prefix', 'N/A')}</td>"
                    f"<td>{h.get('victim_as') or h.get('expected_origin', 'N/A')}</td>"
                    f"<td>{h.get('origin_as') or h.get('hijacker_as', 'N/A')}</td></tr>"
                )

    # Build anomalies table
    anomaly_rows = []
    anomalies = traffic_summary.get("anomalies", []) if isinstance(traffic_summary, dict) else []
    for a in anomalies[:10]:
        if not isinstance(a, dict):
            continue
        anomaly_rows.append(
            f"<tr><td>{a.get('timestamp', 'N/A')}</td>"
            f"<td>{a.get('current_value', a.get('value', 'N/A'))}</td>"
            f"<td>{a.get('historical_mean', a.get('mean', 'N/A'))}</td>"
            f"<td>{a.get('z_score', 'N/A')}</td>"
            f"<td>{a.get('severity', 'N/A')}</td>"
            f"<td>{a.get('percentile_direction', 'N/A')}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>BGP / Traffic Report — AS{asn}</title>
<style>
body{{font-family:-apple-system,Segoe UI,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#222;}}
h1{{border-bottom:2px solid #2c5282;padding-bottom:8px;}}
h2{{color:#2c5282;margin-top:32px;border-bottom:1px solid #eee;padding-bottom:4px;}}
pre{{background:#f7fafc;padding:12px;border-radius:6px;border:1px solid #e2e8f0;overflow:auto;font-size:12px;}}
.banner{{background:#fef3c7;border:1px solid #f6ad55;border-radius:6px;padding:12px;margin:16px 0;}}
table{{border-collapse:collapse;margin:12px 0;}}
td,th{{border:1px solid #e2e8f0;padding:6px 12px;text-align:left;}}
.metric{{display:inline-block;background:#edf2f7;padding:12px 18px;border-radius:6px;margin:6px 6px 6px 0;}}
.metric .v{{font-size:1.4em;font-weight:600;color:#2c5282;}}
.metric .k{{font-size:0.85em;color:#4a5568;text-transform:uppercase;}}
</style></head><body>
<h1>BGP / Traffic Analysis Report — AS{asn}</h1>
<div class="banner"><strong>Note:</strong> This report was rendered from the
deterministic fallback path because the LLM-driven report generator was
unavailable or exceeded its time budget. Raw evidence from the upstream agents
is preserved below.</div>
<p><strong>Analysis window:</strong> {start_time} &mdash; {end_time}</p>
<p><strong>Generated:</strong> {datetime.now().isoformat()}</p>

<h2>Headline Metrics</h2>
<div class="metric"><div class="k">Traffic anomalies</div><div class="v">{anomaly_count}</div></div>
<div class="metric"><div class="k">Traffic %% change</div><div class="v">{pct}</div></div>
<div class="metric"><div class="k">Hijacks observed</div><div class="v">{hijack_count}</div></div>
<div class="metric"><div class="k">Route leaks</div><div class="v">{leak_count}</div></div>
<div class="metric"><div class="k">Outage suspected</div><div class="v">{outage_suspected}</div></div>
<div class="metric"><div class="k">Routing confidence</div><div class="v">{routing_conf}</div></div>

<h2>Traffic Anomalies</h2>
<table>
<tr><th>Timestamp</th><th>Value</th><th>Historical Mean</th><th>Z-Score</th><th>Severity</th><th>Direction</th></tr>
{''.join(anomaly_rows) if anomaly_rows else '<tr><td colspan="6">No anomalies</td></tr>'}
</table>

<h2>Origin Hijacks (Top 10)</h2>
<table>
<tr><th>Timestamp</th><th>Prefix</th><th>Legitimate Origin</th><th>Hijacker ASN</th></tr>
{''.join(hijack_rows) if hijack_rows else '<tr><td colspan="4">No hijacks</td></tr>'}
</table>

<h2>Routing Evidence</h2>
<pre>{_fmt_truncated(routing_summary, 8000)}</pre>

<h2>Traffic Evidence</h2>
<pre>{_fmt_truncated(traffic_summary, 4000)}</pre>

<h2>Reasoning / Classification</h2>
<pre>{_fmt_truncated(reasoning_summary, 4000)}</pre>
</body></html>"""

    if output_dir is None:
        output_dir = Path(__file__).parent.parent / "results" / "html"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"llm_report_AS{asn}_{timestamp}.html"
    path.write_text(html, encoding="utf-8")
    _logger.info(f"Fallback (standalone) report saved: {path}")
    return str(path)
