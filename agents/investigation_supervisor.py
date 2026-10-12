"""
InvestigationSupervisor - Intelligent Tool Trigger Engine
=======================================================

The core architectural innovation: a rule-based pattern detector that decides
WHICH auxiliary tools to run, instead of relying on the LLM to "decide."
This is what makes the agent more human-like - like a senior analyst who
automatically knows "when I see X, I always check Y and Z."

Design principles:
1. Deterministic - rules are explicit, not probabilistic
2. Fast - tools in same "batch" run in parallel
3. Comprehensive - triggers multiple tools for complex patterns
4. Transparent - LLM sees exactly what was triggered and why

Architecture:
 PatternDetector → detects evidence patterns from routing + traffic data
 ToolTriggerEngine → maps patterns to specific tools
 ToolOrchestrator → executes triggered tools (parallel within batches)
 EvidenceEnricher → injects enriched evidence into LLM reasoning

Usage:
 supervisor = InvestigationSupervisor()
 enriched = await supervisor.enrich(
 routing_data=routing_result,
 traffic_data=traffic_result,
 asn_info=org_info,
 context={"suspected_type": "origin_hijack", "asn": "43927"}
 )
 # Then pass `enriched` to LLMReasoner
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from tools.tool_registry import REGISTRY
from utils.logger import logger


# ── Trigger Rules ─────────────────────────────────────────────────────────────

@dataclass
class TriggerRule:
    """A rule that triggers a specific tool when conditions are met."""
    name: str
    tool_name: str
    tool_params: dict
    conditions: list[str]  # logical conditions: "origin_hijack", "no_traffic_impact", etc.
    batch: int = 1  # execution batch (lower = runs first, same batch = parallel)
    reason: str = ""  # human-readable reason for triggering
    confidence_boost: float = 0.0  # how much this tool boosts overall confidence


@dataclass
class TriggeredTool:
    """A tool that has been triggered for execution."""
    rule: TriggerRule
    params: dict
    status: str = "pending"  # pending / running / done / failed
    result: Optional[dict] = None
    error: Optional[str] = None


# ── Tool Trigger Rules ───────────────────────────────────────────────────────

TOOL_TRIGGER_RULES: list[TriggerRule] = [
    # ── BATCH 1: Always-run enrichment (fast, informative) ───────────────
    TriggerRule(
        name="enrich_as_info",
        tool_name="query_as_info",
        tool_params={},
        conditions=["always"],
        batch=1,
        reason="Always enrich with AS context — AS name, country, organization",
        confidence_boost=0.05,
    ),
    TriggerRule(
        name="enrich_as_topology",
        tool_name="as_topology_position",
        tool_params={},
        conditions=["always"],
        batch=1,
        reason="Always determine AS topology position (Tier-1 / Transit / Stub)",
        confidence_boost=0.05,
    ),

    # ── BATCH 2: Security validation (important for any routing anomaly) ─────
    TriggerRule(
        name="rpki_validation",
        tool_name="rpki_validation",
        tool_params={},
        conditions=["origin_hijack", "forge_hijack", "route_leak"],
        batch=2,
        reason="RPKI validation: is this announcement authorized?",
        confidence_boost=0.15,
    ),
    TriggerRule(
        name="as_business_profile",
        tool_name="as_business_profile",
        tool_params={},
        conditions=["origin_hijack", "forge_hijack"],
        batch=2,
        reason="Business profile: does this AS have real operations? Is it a CDN/ISP/Enterprise?",
        confidence_boost=0.1,
    ),

    # ── BATCH 3: Threat intelligence (for suspicious routing events) ─────────
    TriggerRule(
        name="threat_intel_check",
        tool_name="threat_intelligence",
        tool_params={},
        conditions=["origin_hijack", "forge_hijack"],
        batch=3,
        reason="Threat intel: is this AS a known bad actor? Spamhaus DROP? CINS? GRIP history?",
        confidence_boost=0.2,
    ),
    TriggerRule(
        name="historical_behavior_check",
        tool_name="historical_behavior",
        tool_params={},
        conditions=["origin_hijack", "forge_hijack", "route_leak"],
        batch=3,
        reason="Historical behavior: has this AS done this before? First offense or repeat offender?",
        confidence_boost=0.2,
    ),

    # ── BATCH 3: IRR validation (for hijack/leak) ──────────────────────────
    TriggerRule(
        name="irr_registry_check",
        tool_name="irr_registry",
        tool_params={},
        conditions=["origin_hijack", "forge_hijack", "route_leak"],
        batch=3,
        reason="IRR registry: is this prefix authorized by IRR records?",
        confidence_boost=0.15,
    ),

    # ── BATCH 4: News context (for ambiguous or high-impact cases) ──────────
    TriggerRule(
        name="news_context_search",
        tool_name="news_context",
        tool_params={},
        conditions=["origin_hijack", "route_leak", "outage", "ambiguous"],
        batch=4,
        reason="News search: was this a real incident? What do news sources say?",
        confidence_boost=0.25,
    ),

    # ── BATCH 5: Special case — routing anomaly without traffic impact ─────────
    TriggerRule(
        name="topology_probe",
        tool_name="as_topology_position",
        tool_params={},
        conditions=["routing_only_no_traffic"],
        batch=2,
        reason="No traffic impact despite routing anomaly — check AS topology (Tier-1 redundancy?)",
        confidence_boost=0.1,
    ),
    TriggerRule(
        name="prefix_probing",
        tool_name="probe_prefix_reachability",
        tool_params={},
        conditions=["routing_only_no_traffic"],
        batch=3,
        reason="No traffic impact — actively probe prefix to see if it's reachable",
        confidence_boost=0.1,
    ),

    # ── BATCH 5: Special case — ambiguous classification ────────────────────
    TriggerRule(
        name="threat_intel_ambiguous",
        tool_name="threat_intelligence",
        tool_params={},
        conditions=["ambiguous"],
        batch=3,
        reason="Ambiguous case — threat intel helps distinguish attack from misconfiguration",
        confidence_boost=0.2,
    ),
    TriggerRule(
        name="news_ambiguous",
        tool_name="news_context",
        tool_params={},
        conditions=["ambiguous"],
        batch=4,
        reason="Ambiguous case — news search provides ground truth",
        confidence_boost=0.25,
    ),
]


# ── Pattern Detector ──────────────────────────────────────────────────────────

@dataclass
class EvidencePattern:
    """Detected patterns in the current evidence state."""
    has_origin_hijack: bool = False
    has_forge_hijack: bool = False
    has_route_leak: bool = False
    has_outage: bool = False
    has_traffic_anomaly: bool = False
    has_traffic_spike: bool = False
    has_traffic_drop: bool = False
    routing_only_no_traffic: bool = False
    traffic_only_no_routing: bool = False
    is_ambiguous: bool = False  # both traffic and routing anomalies but unclear type
    is_no_anomaly: bool = False
    severity_score: float = 0.0
    anomaly_count: int = 0


class PatternDetector:
    """
 Analyzes routing + traffic data to detect evidence patterns.
 These patterns determine which tools get triggered.
 """

    def detect(self, routing_data: dict, traffic_data: dict, context: dict) -> EvidencePattern:
        """Detect patterns from routing and traffic evidence.

 P0-#2: annotation_package {hijack:{...}, leak: {...}, outage:{...}}. 
 origin_hijacked, annotation_package , pattern . 
 """
        pattern = EvidencePattern()

        # Routing patterns —  flat  annotation_package 
        origin_hijacks = (
            routing_data.get("origin_hijacked") or
            routing_data.get("origin_hijack") or
            ((routing_data.get("hijack") or {}).get("origin_hijacked") if isinstance(routing_data.get("hijack"), dict) else []) or
            []
        )
        forge_hijacks = (
            routing_data.get("forge_hijacked") or
            routing_data.get("forge_hijack") or
            ((routing_data.get("hijack") or {}).get("forge_hijacked") if isinstance(routing_data.get("hijack"), dict) else []) or
            []
        )
        route_leaks = (
            routing_data.get("route_leaks") or
            ((routing_data.get("leak") or {}).get("route_leaks") if isinstance(routing_data.get("leak"), dict) else []) or
            []
        )
        outage_section = routing_data.get("outage_analysis") or routing_data.get("outage") or {}
        is_outage = bool(outage_section.get("is_outage_suspected")) if isinstance(outage_section, dict) else bool(outage_section)

        pattern.has_origin_hijack = len(origin_hijacks) > 0
        pattern.has_forge_hijack = len(forge_hijacks) > 0
        pattern.has_route_leak = len(route_leaks) > 0
        pattern.has_outage = is_outage

        # Traffic patterns
        anomalies = traffic_data.get("anomalies", []) or []
        pattern.has_traffic_anomaly = traffic_data.get("anomalies_detected", False) or len(anomalies) > 0
        pattern.anomaly_count = len(anomalies)

        percent_change = abs(traffic_data.get("percent_change", 0.0) or 0.0)
        pattern.has_traffic_spike = percent_change > 20 and traffic_data.get("direction") == "increase"
        pattern.has_traffic_drop = percent_change > 20 and traffic_data.get("direction") == "decrease"

        # Cross-pattern detection
        has_routing_anomaly = pattern.has_origin_hijack or pattern.has_forge_hijack or pattern.has_route_leak or pattern.has_outage
        pattern.routing_only_no_traffic = has_routing_anomaly and not pattern.has_traffic_anomaly
        pattern.traffic_only_no_routing = pattern.has_traffic_anomaly and not has_routing_anomaly

        # Ambiguous: both present but not clear
        if has_routing_anomaly and pattern.has_traffic_anomaly:
            # Check if classification is unclear
            suspected_type = context.get("suspected_type", "unknown")
            if suspected_type == "unknown":
                pattern.is_ambiguous = True

        # No anomaly
        pattern.is_no_anomaly = not has_routing_anomaly and not pattern.has_traffic_anomaly

        # Severity score
        score = 0.0
        if pattern.has_origin_hijack:
            score += 0.3 * min(len(origin_hijacks), 5)
        if pattern.has_forge_hijack:
            score += 0.3 * min(len(forge_hijacks), 5)
        if pattern.has_route_leak:
            score += 0.2 * min(len(route_leaks), 5)
        if pattern.has_outage:
            score += 0.3
        if pattern.has_traffic_anomaly:
            score += 0.2 * min(len(anomalies), 3)
        if pattern.has_traffic_drop:
            score += 0.15
        if pattern.has_traffic_spike:
            score += 0.15
        pattern.severity_score = min(score, 1.0)

        return pattern


# ── Tool Trigger Engine ────────────────────────────────────────────────────────

class ToolTriggerEngine:
    """
 Maps detected patterns to specific tool invocations.
 This is the "senior analyst's checklist" - deterministic, fast.
 """

    def __init__(self, rules: list[TriggerRule] | None = None):
        self.rules = rules or TOOL_TRIGGER_RULES

    def get_triggered_tools(
        self,
        pattern: EvidencePattern,
        asn: str,
        context: dict,
    ) -> list[TriggeredTool]:
        """Return list of tools to execute, organized by batch."""
        triggered: list[TriggeredTool] = []

        # Determine active conditions
        conditions = self.get_active_conditions(pattern)

        for rule in self.rules:
            # Check if rule conditions match
            if self.matches_conditions(rule.conditions, conditions):
                # Build tool params from rule + context
                params = self.build_params(rule.tool_params, asn, context, pattern, rule)
                triggered.append(TriggeredTool(
                    rule=rule,
                    params=params,
                ))

        return triggered

    def get_active_conditions(self, pattern: EvidencePattern) -> set[str]:
        """Derive active conditions from evidence pattern."""
        conditions: set[str] = set()
        if pattern.has_origin_hijack:
            conditions.add("origin_hijack")
        if pattern.has_forge_hijack:
            conditions.add("forge_hijack")
        if pattern.has_route_leak:
            conditions.add("route_leak")
        if pattern.has_outage:
            conditions.add("outage")
        if pattern.routing_only_no_traffic:
            conditions.add("routing_only_no_traffic")
        if pattern.traffic_only_no_routing:
            conditions.add("traffic_only_no_routing")
        if pattern.is_ambiguous:
            conditions.add("ambiguous")
        if pattern.is_no_anomaly:
            conditions.add("no_anomaly")
        return conditions

    def matches_conditions(self, rule_conditions: list[str], active: set[str]) -> bool:
        """Check if any rule condition matches active conditions (OR logic)."""
        if "always" in rule_conditions:
            return True
        # Special: routing_only_no_traffic overrides other routing conditions
        if "routing_only_no_traffic" in rule_conditions and "routing_only_no_traffic" in active:
            return True
        return bool(set(rule_conditions) & active)

    def build_params(
        self,
        base_params: dict,
        asn: str,
        context: dict,
        pattern: EvidencePattern,
        rule: TriggerRule,
    ) -> dict:
        """Build tool params from base params + context."""
        params = dict(base_params)
        params.setdefault("asn", asn)

        # Inject prefix if available
        routing_data = context.get("routing_data", {})
        origin_hijacks = routing_data.get("origin_hijacked", []) or routing_data.get("origin_hijack", []) or []
        if origin_hijacks:
            first_event = origin_hijacks[0]
            params.setdefault("prefix", first_event.get("prefix", ""))
            params.setdefault("announcements", [
                {"prefix": e.get("prefix", ""), "origin_asn": e.get("origin_asn", asn), "timestamp": e.get("timestamp", "")}
                for e in origin_hijacks[:5]
            ])

        # Inject country/org info
        asn_info = context.get("asn_info", {})
        params.setdefault("country", asn_info.get("country", ""))

        # Inject suspected event type
        params.setdefault("event_type", context.get("suspected_type", "unknown"))

        # news_context needs custom queries - check rule.tool_name
        if rule.tool_name == "news_context":
            params.setdefault("event_type", context.get("suspected_type", "unknown"))
            params.setdefault("country", asn_info.get("country", ""))

        return params


# ── Tool Orchestrator ─────────────────────────────────────────────────────────

class ToolOrchestrator:
    """Executes triggered tools in parallel batches."""

    def __init__(self, max_concurrent: int = 8):
        self.max_concurrent = max_concurrent

    async def execute(
        self,
        triggered_tools: list[TriggeredTool],
        session,
    ) -> list[TriggeredTool]:
        """Execute all triggered tools, parallel within each batch."""
        if not triggered_tools:
            return []

        # Group by batch
        batches: dict[int, list[TriggeredTool]] = {}
        for tool in triggered_tools:
            batch_num = tool.rule.batch
            batches.setdefault(batch_num, []).append(tool)

        # Execute batches sequentially, tools within batch in parallel
        for batch_num in sorted(batches.keys()):
            batch = batches[batch_num]
            logger.info(f"[supervisor] Batch {batch_num}: executing {len(batch)} tools in parallel")

            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def run_tool(tool: TriggeredTool) -> TriggeredTool:
                async with semaphore:
                    tool.status = "running"
                    try:
                        result = await REGISTRY.call(tool.rule.tool_name, tool.params, session)
                        tool.result = result
                        tool.status = "done"
                        success_flag = (
                            result.get("success", False)
                            if hasattr(result, "get") and callable(getattr(result, "get", None))
                            else bool(getattr(result, "success", False))
                        )
                        logger.info(f"[supervisor]   ✅ {tool.rule.name} ({tool.rule.tool_name}): success={success_flag}")
                    except Exception as e:
                        tool.status = "failed"
                        tool.error = str(e)
                        tool.result = {"success": False, "error": str(e)}
                        logger.warning(f"[supervisor]   ❌ {tool.rule.name} ({tool.rule.tool_name}): {e}")

            try:
                await asyncio.gather(*[run_tool(t) for t in batch], return_exceptions=True)
            except Exception as _gather_exc:
                # Bug fix 2026-09-13 (BUG-R74): previously we used
                logger.warning(f"[supervisor] Batch {batch_num}: gather raised {_gather_exc!r}; "
                               f"continuing with per-tool statuses")
            logger.info(f"[supervisor] Batch {batch_num}: completed")

        return triggered_tools


# ── Evidence Enricher ──────────────────────────────────────────────────────────

class EvidenceEnricher:
    """
 Collects tool results and formats them for injection into LLM reasoning.
 This is what the LLM actually sees.
 """

    @staticmethod
    def read_safely(result, key, default=None):
        """Robust reader: handles ToolResult, dict, or any object with .data.

 Returns `default` when the key is absent, the object has no usable
 lookup API, or reading raises any exception. Keeps the narrative
 builder resilient to handler-return-type drift.
 """
        if result is None:
            return default
        if hasattr(result, "get") and callable(getattr(result, "get", None)):
            try:
                return result.get(key, default)
            except Exception:
                pass
        if isinstance(result, dict):
            return result.get(key, default)
        return getattr(result, key, default)

    @staticmethod
    def enrich(triggered_tools: list[TriggeredTool], original_context: dict) -> dict:
        """Build enriched evidence context from tool results."""
        enriched = dict(original_context)
        enrichment = {}
        total_confidence_boost = 0.0

        for tool in triggered_tools:
            if tool.status != "done" or not tool.result:
                continue

            name = tool.rule.name
            result = tool.result
            success = bool(EvidenceEnricher.read_safely(result, "success", False))
            enrichment[name] = {
                "tool": tool.rule.tool_name,
                "result": result,
                "reason": tool.rule.reason,
                "success": success,
            }
            # Only count confidence boost when the tool actually succeeded —
            if success:
                total_confidence_boost += tool.rule.confidence_boost

        enriched["auxiliary_enrichment"] = enrichment
        enriched["total_confidence_boost"] = min(total_confidence_boost, 1.0)
        enriched["tool_count"] = len([t for t in triggered_tools if t.status == "done"])
        enriched["failed_tools"] = [t.rule.name for t in triggered_tools if t.status == "failed"]

        # Build narrative for LLM
        enriched["auxiliary_narrative"] = EvidenceEnricher.build_narrative(enrichment)

        return enriched

    @staticmethod
    def build_narrative(enrichment: dict) -> str:
        """Build a human-readable narrative of all enrichment results."""
        sections = []

        for name, data in enrichment.items():
            if not data["success"]:
                sections.append(f"[{name}] Failed: {data['result'].get('error', 'unknown error')}")
                continue

            result = data["result"]
            reason = data["reason"]

            if name == "rpki_validation":
                s = EvidenceEnricher.read_safely(result, "summary", {})
                valid = EvidenceEnricher.read_safely(s, "valid_count", 0)
                invalid = EvidenceEnricher.read_safely(s, "invalid_count", 0)
                nf = EvidenceEnricher.read_safely(s, "not_found_count", 0)
                sections.append(
                    f"[RPKI] {valid} valid, {invalid} RPKI-invalid, {nf} no-ROA. "
                    f"{reason}"
                )

            elif name == "as_business_profile":
                biz_type = EvidenceEnricher.read_safely(result, "business_type", "unknown")
                domains = EvidenceEnricher.read_safely(result, "total_unique_domains", 0)
                assessment = EvidenceEnricher.read_safely(result, "assessment", "")[:150]
                sections.append(
                    f"[Business Profile] AS type: {biz_type}. "
                    f"Passive DNS: {domains} domains. {assessment}"
                )

            elif name == "threat_intelligence":
                level = EvidenceEnricher.read_safely(result, "risk_level", "unknown")
                score = EvidenceEnricher.read_safely(result, "risk_score", 0)
                findings = EvidenceEnricher.read_safely(result, "findings", [])
                grip = EvidenceEnricher.read_safely(result, "grip_history", {})
                grip_count = EvidenceEnricher.read_safely(grip, "relevant_count", 0)
                sections.append(
                    f"[Threat Intel] Risk: {level} (score={score}). "
                    f"Findings: {'; '.join(findings) if findings else 'None.'}. "
                    f"GRIP history: {grip_count} past incidents. {reason}"
                )

            elif name == "historical_behavior":
                pattern = EvidenceEnricher.read_safely(result, "reoffense_pattern", {})
                total = EvidenceEnricher.read_safely(pattern, "total_incidents", 0)
                repeat = EvidenceEnricher.read_safely(pattern, "is_repeat_offender", False)
                mo = EvidenceEnricher.read_safely(pattern, "mo_signature", "")
                risk = EvidenceEnricher.read_safely(result, "risk_level", "unknown")
                sections.append(
                    f"[History] {total} past incidents. "
                    f"Repeat offender: {repeat}. "
                    f"MO: {mo or 'None.'} Risk: {risk}. {reason}"
                )

            elif name == "irr_registry":
                auth = EvidenceEnricher.read_safely(result, "prefix_authorized", False)
                reason_irr = EvidenceEnricher.read_safely(result, "prefix_authorization_reason", "")
                has_records = EvidenceEnricher.read_safely(result, "has_irr_records", False)
                sections.append(
                    f"[IRR] Records: {has_records}. "
                    f"Prefix authorized: {auth}. {reason_irr}"
                )

            elif name == "news_context":
                count = EvidenceEnricher.read_safely(result, "result_count", 0)
                incident_ctx = EvidenceEnricher.read_safely(result, "incident_context", {})
                confirmed = EvidenceEnricher.read_safely(incident_ctx, "confirmed_incident", False)
                root_cause = EvidenceEnricher.read_safely(incident_ctx, "root_cause", None)
                search_results = EvidenceEnricher.read_safely(result, "search_results", [{}])
                top_article = search_results[0] if isinstance(search_results, list) and search_results else {}
                top = EvidenceEnricher.read_safely(top_article, "title", "None")
                sections.append(
                    f"[News] {count} articles. "
                    f"Confirmed incident: {confirmed}. "
                    f"Root cause: {root_cause or 'unknown'}. "
                    f"Top: {top}. {reason}"
                )

            elif name == "enrich_as_info":
                sections.append(
                    f"[AS Info] {EvidenceEnricher.read_safely(result, 'as_name', 'N/A')}. Country: {EvidenceEnricher.read_safely(result, 'country', 'N/A')}"
                )

            elif name == "enrich_as_topology":
                tier = EvidenceEnricher.read_safely(result, "tier", "unknown")
                providers = EvidenceEnricher.read_safely(result, "provider_count", 0)
                customers = EvidenceEnricher.read_safely(result, "customer_count", 0)
                sections.append(
                    f"[Topology] Tier: {tier}. "
                    f"Providers: {providers}, Customers: {customers}"
                )

            else:
                # Generic fallback
                obs = (
                    EvidenceEnricher.read_safely(result, "observation", "")
                    or EvidenceEnricher.read_safely(result, "summary", "")
                )
                if obs:
                    sections.append(f"[{name}] {obs[:200]}")

        if not sections:
            return "No auxiliary enrichment results available."

        header = f"=== Auxiliary Evidence (from {len(enrichment)} tools) ==="
        return header + "\n" + "\n".join(f"  {s}" for s in sections)


# ── InvestigationSupervisor ──────────────────────────────────────────────────

class InvestigationSupervisor:
    """
 Main entry point for the auxiliary enrichment system.

 Usage:
 supervisor = InvestigationSupervisor()
 enriched = await supervisor.enrich(
 routing_data=..., # from RoutingAgent
 traffic_data=..., # from TrafficAgent
 asn="43927",
 context={"suspected_type": "origin_hijack", ...}
 )
 # Pass `enriched` to LLMReasoner for final reasoning
 """

    def __init__(
        self,
        rules: list[TriggerRule] | None = None,
        max_concurrent: int = 8,
    ):
        self.pattern_detector = PatternDetector()
        self.trigger_engine = ToolTriggerEngine(rules)
        self.orchestrator = ToolOrchestrator(max_concurrent)
        self.enricher = EvidenceEnricher()

    async def enrich(
        self,
        routing_data: dict,
        traffic_data: dict,
        asn: str,
        asn_info: dict | None = None,
        context: dict | None = None,
        session=None,
        skip_pattern: str | None = None,  # "no_anomaly" to skip enrichment
    ) -> dict:
        """
 Run the full enrichment pipeline.

 Args:
 routing_data: output from RoutingAgent
 traffic_data: output from TrafficAgent
 asn: AS number
 asn_info: optional pre-fetched AS info
 context: additional context (suspected_type, etc.)
 session: tool session for execution
 skip_pattern: skip if pattern matches this (e.g. "no_anomaly")

 Returns:
 Enriched context dict with:
 - auxiliary_enrichment: per-tool results
 - auxiliary_narrative: LLM-readable summary
 - total_confidence_boost: cumulative boost from enrichment
 - triggered_tools: list of TriggeredTool objects
 """
        context = context or {}
        context.update({
            "routing_data": routing_data,
            "traffic_data": traffic_data,
            "asn_info": asn_info or {},
            "asn": asn,
        })

        t0 = datetime.now()
        logger.info(f"[supervisor] Starting enrichment for AS{asn}")

        # Step 1: Pattern detection
        pattern = self.pattern_detector.detect(routing_data, traffic_data, context)
        logger.info(
            f"[supervisor] Patterns detected: "
            f"origin_hijack={pattern.has_origin_hijack}, "
            f"forge={pattern.has_forge_hijack}, "
            f"leak={pattern.has_route_leak}, "
            f"outage={pattern.has_outage}, "
            f"traffic={pattern.has_traffic_anomaly}, "
            f"severity={pattern.severity_score:.2f}, "
            f"routing_only_no_traffic={pattern.routing_only_no_traffic}, "
            f"ambiguous={pattern.is_ambiguous}"
        )

        # Update context with pattern
        context["detected_pattern"] = {
            "has_origin_hijack": pattern.has_origin_hijack,
            "has_forge_hijack": pattern.has_forge_hijack,
            "has_route_leak": pattern.has_route_leak,
            "has_outage": pattern.has_outage,
            "has_traffic_anomaly": pattern.has_traffic_anomaly,
            "routing_only_no_traffic": pattern.routing_only_no_traffic,
            "is_ambiguous": pattern.is_ambiguous,
            "severity_score": pattern.severity_score,
            "anomaly_count": pattern.anomaly_count,
        }

        # Step 2: Skip if no anomaly and skip_pattern is set
        if skip_pattern == "no_anomaly" and pattern.is_no_anomaly:
            logger.info("[supervisor] No anomaly detected — skipping enrichment")
            return {
                **context,
                "auxiliary_enrichment": {},
                "auxiliary_narrative": "No anomaly detected — no auxiliary enrichment performed.",
                "total_confidence_boost": 0.0,
                "triggered_tools": [],
                "tool_count": 0,
            }

        # Step 3: Tool triggering
        triggered_tools = self.trigger_engine.get_triggered_tools(pattern, asn, context)
        logger.info(f"[supervisor] Triggered {len(triggered_tools)} tools: {[t.rule.name for t in triggered_tools]}")

        if not triggered_tools:
            logger.info("[supervisor] No tools triggered")
            return {
                **context,
                "auxiliary_enrichment": {},
                "auxiliary_narrative": "No auxiliary tools triggered for this pattern.",
                "total_confidence_boost": 0.0,
                "triggered_tools": [],
                "tool_count": 0,
            }

        # Step 4: Tool execution
        executed_tools = await self.orchestrator.execute(triggered_tools, session)
        done = [t for t in executed_tools if t.status == "done"]
        failed = [t for t in executed_tools if t.status == "failed"]
        logger.info(f"[supervisor] Execution: {len(done)} done, {len(failed)} failed")

        # Step 5: Evidence enrichment
        enriched = self.enricher.enrich(executed_tools, context)

        elapsed = (datetime.now() - t0).total_seconds()
        logger.info(
            f"[supervisor] Enrichment complete in {elapsed:.1f}s. "
            f"Confidence boost: +{enriched['total_confidence_boost']:.2f}"
        )

        return enriched


# ── Convenience functions ─────────────────────────────────────────────────────

async def enrich_case(
    routing_data: dict,
    traffic_data: dict,
    asn: str,
    suspected_type: str = "unknown",
    asn_info: dict | None = None,
) -> dict:
    """
 One-shot enrichment for a routing + traffic result pair.
 Use this from ReasoningAgent or workflow engine.
 """
    supervisor = InvestigationSupervisor()
    return await supervisor.enrich(
        routing_data=routing_data,
        traffic_data=traffic_data,
        asn=asn,
        asn_info=asn_info,
        context={"suspected_type": suspected_type},
        skip_pattern="no_anomaly",
    )
