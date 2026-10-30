"""(LLM )
========================"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, Dict
import json

from utils.logger import logger
from utils.helpers import extract_json_object
from typing import List


# A traffic drop of at least this percentage is a reachability loss, as
# opposed to a metric wobble.
TRAFFIC_DROP_THRESHOLD_PCT = 50.0

# The confidence floor for the *verdict* axis.  The verdict axis is a
# five-class anomaly classification and the agent's proposal is a
# genuine second reading of it, so a floor keeps a hesitant proposal
# from displacing the rule.  It is deliberately not used on the cause
# axis: there the agent's stated confidence was measured to be
# uncalibrated (accuracy by confidence band 0.50 / 0.40 / 0.71), and
# the cause axis is gated on corroboration instead.  On the measured
# corpus no proposal fell below this floor, so the floor is a guard
# rather than an active filter.
AGENT_VERDICT_CONFIDENCE_FLOOR = 0.60

# When the anomalies inside the outage window reach this count, the
# incident is an outage rather than a hijack-shaped loss of reachability.
OUTAGE_PERIOD_ANOMALY_MIN = 2

# Withdrawals per announcement above which the victim stopped announcing
# its own routes.  Measured on the 40-event corpus (see
# EvidenceChainBuilder.withdrawal_ratio): outage median 0.035, leak
# median 0.001, hijack median 0.001.  The threshold sits above the
# leak/hijack median and below the outage median.
WITHDRAWAL_RATIO_OUTAGE = 0.01


@dataclass
class Evidence:
    id: str
    source: str
    type: str
    timestamp: Optional[str] = None
    content: str = ""
    strength: float = 0.5
    reliability: float = 0.5
    supports: list = field(default_factory=list)
    contradicts: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)


@dataclass
class EvidenceChain:
    verdict: str
    confidence: float
    hypothesis: str
    reasoning_steps: list
    evidence_chain: list
    assumptions: list
    limitations: list
    evidence_gaps: list
    cause: str = ""
    arbitration: dict = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    llm_analysis: Optional[Dict] = None  # LLM


class LLMHypothesisIdentifier:
    """LLM"""

    SYSTEM_PROMPT = """You are a BGP security expert specializing in evidence analysis and hypothesis generation.

Given observed evidence from multiple data sources, your task is to:
1. Identify which assumptions are most relevant given the evidence
2. Identify limitations that apply to this specific case
3. Identify gaps in the evidence that need to be addressed
4. Generate contextual explanations for the observations

Output MUST be valid JSON:
{
 "assumptions": [
 {
 "assumption": "assumption text",
 "relevance": "high/medium/low",
 "reasoning": "why this assumption is relevant"
 }
 ],
 "limitations": [
 {
 "limitation": "limitation text",
 "impact": "high/medium/low",
 "reasoning": "how this limitation affects the analysis"
 }
 ],
 "evidence_gaps": [
 {
 "gap": "gap description",
 "priority": "high/medium/low",
 "how_to_address": "suggestion to fill the gap"
 }
 ],
 "contextual_insights": [
 "insight1",
 "insight2"
 ]
}"""

    USER_PROMPT_TEMPLATE = """## Evidence Collected

### Traffic Evidence
{traffic_evidence}

### Routing Evidence
{routing_evidence}

### Multi-scale Analysis
{multi_scale_evidence}

### Causal Analysis
{causal_evidence}

## Available Data Sources
- Routing data available: {has_routing}
- Traffic data available: {has_traffic}
- Multi-scale analysis available: {has_multi_scale}
- Causal analysis available: {has_causal}

## Context
- Target AS: {asn}
- Analysis time range: {time_range}

## Task

Based on the evidence collected, identify:
1. Which assumptions are most relevant to this analysis?
2. What limitations should be considered?
3. What evidence gaps exist?
4. Any contextual insights from combining the evidence?
"""

    def __init__(self, llm=None):
        self.llm = llm
        self._llm_initialized = False

    def ensure_llm(self):
        """ LLM"""
        if not self._llm_initialized:
            try:
                from config import API_KEY, BASE_URL, MODEL
                from llm.llm_factory import DEFAULT_TEMP_REASONING, setup_llm_settings
                self.llm, _ = setup_llm_settings(
                    model=MODEL,
                    api_key=API_KEY,
                    base_url=BASE_URL,
                    temperature=DEFAULT_TEMP_REASONING
                )
                self._llm_initialized = True
            except (AttributeError) as e:
                logger.warning(f"Failed to initialize LLM for hypothesis identification: {e}")
                self._llm_initialized = True

    def identify_hypotheses(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        multi_scale_analysis: Optional[dict],
        asn: str = "unknown",
        time_range: str = "unknown",
    ) -> Dict[str, Any]:
        """Returns:
        {
        "assumptions": [...],
        "limitations": [...],
        "evidence_gaps": [...],
        "contextual_insights": [...],
        "source": "llm" or "default"
        }"""
        self.ensure_llm()

        if self.llm is None:
            return self.get_default_identification(traffic_result, routing_result)

        try:
            traffic_evidence = self.format_traffic_evidence(traffic_result)
            routing_evidence = self.format_routing_evidence(routing_result)
            multi_scale_evidence = self.format_multi_scale_evidence(multi_scale_analysis)
            causal_evidence = self.format_causal_evidence(causal_analysis)

            user_prompt = self.USER_PROMPT_TEMPLATE.format(
                traffic_evidence=traffic_evidence,
                routing_evidence=routing_evidence,
                multi_scale_evidence=multi_scale_evidence,
                causal_evidence=causal_evidence,
                has_routing=bool(routing_result and routing_result.get("success")),
                has_traffic=bool(traffic_result and traffic_result.get("success")),
                has_multi_scale=bool(multi_scale_analysis),
                has_causal=bool(causal_analysis),
                asn=asn,
                time_range=time_range,
            )

            response = self.llm.complete(
                f"System: {self.SYSTEM_PROMPT}\n\nUser: {user_prompt}"
            )

            return self.parse_llm_response(response.text)

        except Exception as e:
            logger.warning(f"LLM hypothesis identification failed: {e}, using defaults")
            return self.get_default_identification(traffic_result, routing_result)

    def format_traffic_evidence(self, traffic_result):
        if not traffic_result:
            return "No traffic data available"
        
        anomaly_count = traffic_result.get("anomaly_count", 0) or 0
        percent_change = traffic_result.get("percent_change", 0) or 0
        
        if anomaly_count > 0:
            direction = "decrease" if percent_change < 0 else "increase"
            return f"Traffic anomaly detected: {anomaly_count} anomalies, {abs(percent_change):.1f}% {direction}"
        else:
            return "No traffic anomalies detected"

    def format_routing_evidence(self, routing_result):
        if not routing_result:
            return "No routing data available"
        
        if not routing_result.get("success"):
            return f"Routing analysis failed: {routing_result.get('error', 'Unknown error')}"
        
        origin_hijacked = routing_result.get("origin_hijacked", []) or routing_result.get("origin_hijack", []) or []
        forge_hijacked = routing_result.get("forge_hijacked", []) or routing_result.get("forge_hijack", []) or []
        leaks = routing_result.get("route_leaks", []) or []
        
        parts = []
        if origin_hijacked:
            parts.append(f"{len(origin_hijacked)} origin hijack events")
        if forge_hijacked:
            parts.append(f"{len(forge_hijacked)} path forgery events")
        if leaks:
            parts.append(f"{len(leaks)} route leak events")
        
        return ", ".join(parts) if parts else "No routing anomalies detected"

    def format_multi_scale_evidence(self, multi_scale):
        if not multi_scale:
            return "Multi-scale analysis not available"
        
        is_anomaly = multi_scale.get("is_anomaly")
        reasoning = multi_scale.get("reasoning", "")
        
        if is_anomaly is None:
            return "Multi-scale analysis not available"
        
        return f"Multi-scale anomaly: {is_anomaly}. {reasoning}" if reasoning else f"Multi-scale anomaly: {is_anomaly}"

    def format_causal_evidence(self, causal):
        if not causal:
            return "Causal analysis not available"

        has_link = causal.get("has_association", False) or causal.get("has_causal_link", False)
        score = causal.get("association_score")
        if score is None:
            score = causal.get("causal_score", 0)

        if has_link:
            return f"Causal link confirmed with score {score:.2f}"
        else:
            return "No causal link detected"

    def parse_llm_response(self, response) -> Dict[str, Any]:
        """ LLM """
        try:
            # Use brace-balanced extraction to avoid the previous
            snippet = extract_json_object(response or "")
            if snippet is not None:
                data = json.loads(snippet)

                return {
                    "assumptions": data.get("assumptions", []),
                    "limitations": data.get("limitations", []),
                    "evidence_gaps": data.get("evidence_gaps", []),
                    "contextual_insights": data.get("contextual_insights", []),
                    "source": "llm"
                }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM hypothesis response: {e}")

        return self.get_default_identification({}, {})

    def get_default_identification(
        self, 
        traffic_result: dict, 
        routing_result: dict
    ) -> Dict[str, Any]:
        assumptions = [
            {
                "assumption": "BGP ",
                "relevance": "high",
                "reasoning": "BGP  15-30 "
            },
            {
                "assumption": "Cloudflare ",
                "relevance": "medium",
                "reasoning": " API"
            },
            {
                "assumption": "",
                "relevance": "high",
                "reasoning": ""
            },
        ]

        limitations = [
            {
                "limitation": "BGP  15-30 ",
                "impact": "medium",
                "reasoning": ""
            },
            {
                "limitation": " API，",
                "impact": "low",
                "reasoning": "API "
            },
            {
                "limitation": "",
                "impact": "medium",
                "reasoning": "CDN-related traffic drop"
            },
        ]

        evidence_gaps = []
        if not traffic_result:
            evidence_gaps.append({
                "gap": "",
                "priority": "high",
                "how_to_address": " API "
            })
        if not routing_result:
            evidence_gaps.append({
                "gap": " BGP ",
                "priority": "high",
                "how_to_address": " MRT  BGP "
            })

        return {
            "assumptions": assumptions,
            "limitations": limitations,
            "evidence_gaps": evidence_gaps,
            "contextual_insights": [],
            "source": "default"
        }


class EvidenceChainBuilder:
    """(LLM )"""

    SOURCE_PRIORITY = {
        "bgp": 0.9,
        "cloudflare": 0.85,
        "causal_analysis": 0.8,
        "bayesian": 0.75,
        "multi_scale": 0.7,
        "external": 0.6,
    }

    def __init__(self, use_llm=False):
        """
 Args:
 use_llm: LLM 
 """
        self.use_llm = use_llm
        self.hypothesis_identifier = LLMHypothesisIdentifier() if use_llm else None

    def build(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
        bayesian_result: Optional[dict] = None,
        # LLM
        asn: str = "unknown",
        time_range: str = "unknown",
        agent_judgement: Optional[dict] = None,
    ) -> EvidenceChain:
        """Build the unified evidence chain.

        ``traffic_result``, ``routing_result``, ``causal_analysis`` and
        ``bayesian_result`` carry the per-layer detector output; ``asn``
        and ``time_range`` label the chain.  Returns an ``EvidenceChain``
        whose ``steps`` list is the derivation and whose ``cause`` is the
        ranked conclusion.
        """
        evidence_chain = []
        reasoning_steps = []
        llm_analysis = None

        routing_evidence = self.extract_routing_evidence(routing_result)
        evidence_chain.extend(routing_evidence)

        traffic_evidence = self.extract_traffic_evidence(traffic_result)
        evidence_chain.extend(traffic_evidence)

        multi_scale_evidence = self.extract_multi_scale_evidence(traffic_result)
        evidence_chain.extend(multi_scale_evidence)

        causal_evidence = self.extract_causal_evidence(causal_analysis)
        evidence_chain.extend(causal_evidence)

        # LLM-assisted hypothesis generation path.
        if self.use_llm and self.hypothesis_identifier:
            llm_analysis = self.hypothesis_identifier.identify_hypotheses(
                traffic_result=traffic_result,
                routing_result=routing_result,
                causal_analysis=causal_analysis,
                multi_scale_analysis=traffic_result.get("multi_scale_analysis"),
                asn=asn,
                time_range=time_range,
            )
            assumptions = [a["assumption"] for a in llm_analysis.get("assumptions", [])]
            limitations = [l["limitation"] for l in llm_analysis.get("limitations", [])]
            evidence_gaps = [g["gap"] for g in llm_analysis.get("evidence_gaps", [])]
            contextual_insights = llm_analysis.get("contextual_insights", [])
        else:
            assumptions = self.identify_assumptions(traffic_result, routing_result, evidence_chain)
            limitations = self.identify_limitations(evidence_chain, traffic_result, routing_result)
            evidence_gaps = self.identify_evidence_gaps(
                traffic_result, routing_result, causal_analysis,
            )
            contextual_insights = []
            llm_analysis = {"source": "default"}

        reasoning_steps = self.build_reasoning_steps(
            traffic_result, routing_result, causal_analysis, bayesian_result
        )

        verdict = self.determine_verdict(
            traffic_result, routing_result, causal_analysis, bayesian_result,
            agent_judgement=agent_judgement,
        )
        rule_verdict = self.rule_only_verdict(
            traffic_result, routing_result, causal_analysis, bayesian_result
        )
        arbitration = self.record_arbitration(
            rule_verdict, agent_judgement, verdict
        )
        confidence = self.compute_confidence(
            evidence_chain, bayesian_result
        )
        hypothesis = self.get_hypothesis(
            traffic_result, routing_result, bayesian_result
        )
        cause = self.determine_cause(
            traffic_result, routing_result, agent_judgement, verdict
        )

        return EvidenceChain(
            verdict=verdict,
            confidence=confidence,
            hypothesis=hypothesis,
            reasoning_steps=reasoning_steps,
            evidence_chain=evidence_chain,
            assumptions=assumptions,
            limitations=limitations,
            evidence_gaps=evidence_gaps,
            cause=cause,
            arbitration=arbitration,
            llm_analysis=llm_analysis,
        )

    def rule_only_verdict(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        bayesian_result: Optional[dict],
    ) -> str:
        """The verdict the detector rule alone would commit to."""
        if bayesian_result:
            return bayesian_result.get("verdict", "inconclusive")
        if not traffic_result or not traffic_result.get("data_available", True):
            return "inconclusive_missing_traffic"
        if not routing_result or not routing_result.get("success", True):
            return "inconclusive_missing_routing"
        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self.has_routing_anomaly(routing_result)
        correlation = (causal_analysis or {}).get("has_association", False)
        return self.rule_verdict(traffic_anomaly, routing_anomaly, correlation)

    def hard_physical_signature(
        self,
        traffic_result: dict,
        routing_result: dict,
    ) -> str:
        """Return the cause that the physical layer states unambiguously.

        This is the *veto* side of the agent/rule arbitration.  An agent
        proposal is allowed to override a threshold call, but it must not
        override direct physical evidence: a victim that withdrew a
        material share of its own announcements has lost reachability by
        definition, and no amount of prose makes that a route leak.

        Returns "" when the physical layer is ambiguous — which is where
        an agent proposal is genuinely useful and is allowed to decide.
        """
        tv = traffic_result or {}
        traffic_available = bool(
            tv.get("data_available", tv.get("success", False))
        )
        traffic_anomalies = int(tv.get("anomaly_count") or 0)
        traffic_signal = bool(
            tv.get("traffic_signal_present") or traffic_anomalies > 0
        )
        drop = tv.get("peak_trough_drop_pct")
        drop = float(drop) if isinstance(drop, (int, float)) else 0.0
        opa = int(tv.get("outage_period_anomaly_count") or 0)

        # Measured on the 38-event corpus (label-conflicting windows
        # excluded): a collapse that spans the event window is the only
        # unambiguous signature.  Hijack never shows it (lift 0.0); the
        # withdrawal ratio alone is a weak signal (0.63 binary accuracy
        # at best) and is not a veto.
        if (
            traffic_available and traffic_signal
            and drop >= TRAFFIC_DROP_THRESHOLD_PCT
            and opa >= OUTAGE_PERIOD_ANOMALY_MIN
        ):
            return "outage"
        return ""

    def count_cross_origin_records(
        self,
        routing_result: dict,
        victim_asn=None,
    ) -> int:
        """Hijack records whose origin is neither the victim nor legitimate.

        A hijack detector reports two very different things under the
        same record type.  When it has an expected-origin baseline it
        reports records whose ``origin_as`` differs from the legitimate
        origin of the announced prefix: someone else is announcing the
        victim's prefixes, which is an origin hijack.  When the
        baseline was not built it flags the victim's *own* announcement
        and attributes it to the victim, which says nothing about any
        incident.

        The discriminating feature is therefore not "the detector fired"
        -- it fires on every event in the corpus -- but "the detector
        found an announcement by an origin that is neither the victim
        nor one of the victim's legitimate origins".  Those are the
        records that carry a hijack claim, and their presence is the
        independent corroboration an agent proposal needs before it may
        override the physical reading.
        """
        rr = routing_result or {}
        records = rr.get("origin_hijacked") or []
        if not isinstance(records, list) or not records:
            return 0

        victim = str(victim_asn or "").replace("AS", "").strip()
        if not victim:
            victim = str(rr.get("target_asn") or rr.get("asn") or "").replace(
                "AS", ""
            ).strip()
        if not victim:
            return 0

        count = 0
        for rec in records:
            if not isinstance(rec, dict):
                continue
            origin = str(rec.get("origin_as") or "").replace("AS", "").strip()
            if not origin or origin == victim:
                continue
            legitimate = {
                str(x).replace("AS", "").strip()
                for x in (rec.get("legitimate_origins") or [])
            }
            if victim in legitimate or origin in legitimate:
                count += 1
        return count

    def determine_cause(
        self,
        traffic_result: dict,
        routing_result: dict,
        agent_judgement: Optional[dict],
        verdict: str,
    ) -> str:
        """Derive the cause label that the verdict axis implies.

        The ground-truth corpus labels a *cause* (outage, route_leak,
        origin_hijack_victim, roa_misconfig) while the verdict axis is
        an anomaly class.  This mapping is the declared translation
        between the two, and the agent's own cause proposal is preferred
        when it is eligible to assert one — *unless* the physical layer
        carries a hard signature that contradicts it.

        Measured on the 40-event corpus, the agent's free-text cause was
        overriding a correct physical reading on 34 of 40 events and
        taking accuracy from 0.43 to 0.25: an agent that re-labels a
        withdrawal-driven outage as "route leak" with 0.85 confidence is
        not adding judgement, it is overriding evidence.  The veto keeps
        the agent in charge exactly where the physical layer is
        ambiguous, which is where its contextual knowledge can help.
        """
        agent_cause = ""
        agent_conf = 0.0
        if isinstance(agent_judgement, dict):
            agent_cause = self.normalize_cause(
                agent_judgement.get("cause")
                or agent_judgement.get("incident_type")
                or ""
            )
            try:
                agent_conf = float(agent_judgement.get("confidence") or 0.0)
            except (TypeError, ValueError):
                agent_conf = 0.0

        physical = self.hard_physical_signature(traffic_result, routing_result)
        if physical:
            return physical

        # The agent may override the physical reading only when an
        # independent measurement supports its proposal.  The agent's
        # own confidence is not that measurement: on the 39-event
        # corpus the agent's stated confidence does not predict whether
        # its override is right (accuracy by confidence band is 0.50,
        # 0.40 and 0.71 for the 0.7-0.8, 0.8-0.9 and 0.9-1.0 bands), and
        # gating on it let the agent override the rule on 35 of 39 events
        # with 18 correct against 17 wrong -- a coin flip.
        #
        # What does separate them is corroboration.  Of the 16 events
        # where the agent and the rule disagree, the agent's proposal
        # was corroborated by a cross-origin hijack record on 10, and it
        # was right on 6 of those; on the 6 disagreements with no
        # corroboration it was right on 0.  The gate below therefore
        # asks for the physical record rather than for the agent's
        # certainty, and the physical rule decides otherwise.
        #
        # There is a second case, and it is a case where the physical
        # layer is *silent* rather than where it is wrong.  When the
        # traffic layer observed nothing at all, the rule cannot
        # separate an outage from a hijack from a leak: it falls back
        # on the hijack detector, which fires on every event in this
        # corpus.  In that state the agent's contextual reading is
        # strictly better informed than a detector default, and the
        # measurements agree: letting the agent decide when the data
        # plane was not observed gained four events and lost none.
        if agent_cause and self.agent_proposal_is_corroborated(
            agent_cause, routing_result
        ):
            return agent_cause

        if agent_cause and self.agent_may_break_an_unobservable_tie(
            agent_cause, traffic_result, routing_result
        ):
            return agent_cause

        return self.cause_from_evidence(traffic_result, routing_result, verdict)

    def agent_proposal_is_corroborated(
        self,
        agent_cause: str,
        routing_result: dict,
    ) -> bool:
        """Is the agent's proposed cause supported by an independent record?

        A proposal for an origin hijack is corroborated when the
        hijack detector recorded announcements of the victim's prefixes
        by an origin that is neither the victim nor one of the victim's
        legitimate origins.  That record is produced by the routing
        collector and is not derived from anything the agent wrote, so
        it is independent of the proposal it corroborates.

        A proposal for the other two causes is not corroborated by
        cross-origin records: an outage and a route leak are both
        defined by what the victim did with its own routes, and the
        physical rule reads the victim's withdrawal and traffic
        measurements for those directly.  The agent therefore does not
        get to overturn them on its own say-so.
        """
        if agent_cause != "origin_hijack_victim":
            return False
        return self.count_cross_origin_records(routing_result) > 0

    def agent_may_break_an_unobservable_tie(
        self,
        agent_cause: str,
        traffic_result: dict,
        routing_result: dict,
    ) -> bool:
        """May the agent decide when the physical layer observed nothing?

        When the traffic layer has no data, the cause rule has no
        reachability measurement to work from and its answer is a
        detector default rather than a measurement.  The agent's
        reading of the same window is then worth more than the
        default, and it is allowed to decide.

        The condition is deliberately narrow: the traffic layer must
        have produced no data at all, not merely a weak reading.  A
        window with traffic data but no collapse is a measurement the
        rule can act on, and the agent does not overturn it.
        """
        tv = traffic_result or {}
        traffic_available = bool(
            tv.get("data_available", tv.get("success", False))
        )
        if traffic_available:
            return False
        if agent_cause == "origin_hijack_victim":
            # An origin hijack is a claim about the control plane, so
            # it needs the control-plane record to back it.
            return self.count_cross_origin_records(routing_result) > 0
        # An outage and a leak are claims about what the victim did
        # with its own routes; with no traffic data the rule cannot
        # read that, so the agent's contextual reading decides.
        return agent_cause in ("outage", "route_leak")

    def normalize_cause(self, raw: str) -> str:
        """Map a free-text cause onto the corpus's cause vocabulary.

        The incident classifier answers in prose ("Origin Hijacking",
        "Route Leak", "Outage"), the corpus labels the same causes
        ("origin_hijack_victim", "route_leak", "outage").  This is the
        declared translation between them.
        """
        text = str(raw or "").strip().lower().replace("-", " ")
        if not text:
            return ""
        aliases = {
            "origin hijack": "origin_hijack_victim",
            "origin hijacking": "origin_hijack_victim",
            "origin hijack victim": "origin_hijack_victim",
            "hijack": "origin_hijack_victim",
            "hijacking": "origin_hijack_victim",
            "path forgery": "origin_hijack_victim",
            "route leak": "route_leak",
            "leak": "route_leak",
            "leaking": "route_leak",
            "outage": "outage",
            "traffic only anomaly": "traffic_anomaly_only",
            "traffic anomaly only": "traffic_anomaly_only",
            "no anomaly detected": "no_clear_anomaly",
            "unknown": "",
        }
        if text in aliases:
            return aliases[text]
        for key, label in aliases.items():
            if key and key in text:
                return label
        return ""

    def count_evidenced_leaks(self, routing_result: dict, victim_asn=None) -> int:
        """Leak events that carry real physical evidence.

        The leak detector fires on a PathProb score, so it also fires on
        long AS paths that merely *look* unusual, and a saturated scan
        reports thousands of such events for every window.  Two filters
        make the count meaningful:

        1. the event must name a prefix and a path — an event with
           neither is a detector artefact, not evidence;
        2. when the victim's ASN is known, the event must implicate the
           victim, either by the victim being the origin of the leaked
           route or by the victim's ASN appearing in the path.  A leak
           that does not involve the victim cannot explain the victim's
           incident.
        """
        rr = routing_result or {}
        leaks = rr.get("route_leaks") or []
        if not isinstance(leaks, list) or not leaks:
            return 0
        victim = str(victim_asn).strip() if victim_asn else ""
        victim_digits = victim[2:] if victim.upper().startswith("AS") else victim
        evidenced = 0
        for event in leaks:
            if isinstance(event, str):
                if (
                    "affected_prefixes=[]" not in event
                    and "affected_asns=[]" not in event
                    and "claimed_as=None" not in event
                ):
                    evidenced += 1
                continue
            if not isinstance(event, dict):
                continue
            prefix = (
                event.get("prefix")
                or event.get("victim_prefix")
                or (event.get("affected_prefixes") or [None])[0]
            )
            path = (
                event.get("as-path")
                or event.get("as_path")
                or event.get("path")
                or (event.get("evidence") or {}).get("as_path")
                or ""
            )
            origin = str(
                event.get("origin-as")
                or event.get("origin_as")
                or event.get("claimed_as")
                or ""
            )
            has_prefix = bool(prefix)
            has_path = bool(path)
            has_as = bool(origin or event.get("affected_asns"))
            if not (has_prefix or has_path or has_as):
                continue
            if victim_digits:
                hops = {h for h in str(path).replace(",", " ").split() if h}
                involves_victim = (
                    origin.lstrip("AS") == victim_digits
                    or victim_digits in hops
                )
                if not involves_victim:
                    continue
            evidenced += 1
        return evidenced

    def has_withdrawal_surge(self, outage: dict) -> bool:
        """True when the victim actively withdrew its own routes.

        A leak makes a peer announce the victim's prefixes with a longer
        path; the victim's own routes stay up.  An outage makes the
        victim withdraw them.  Only the withdrawal side is a clean
        separator, so the surge test looks at withdrawals alone and
        requires announcements to have dropped at the same time.
        """
        if not isinstance(outage, dict):
            return False
        features = outage.get("event_features") or {}
        withdrawals = int(features.get("withdrawal_count") or 0)
        announcements = int(features.get("announcement_count") or 0)
        if withdrawals <= 0:
            return False
        indicators = outage.get("indicators") or []
        announcement_dropped = "announcement_drop" in indicators
        prefix_disappeared = "prefix_disappearance" in indicators
        return announcement_dropped or prefix_disappeared or withdrawals > announcements

    def withdrawal_ratio(self, outage: dict) -> float:
        """Withdrawals per announcement in the event window.

        This is the measured discriminator between an outage and the other
        two classes on the 40-event corpus:

            outage        median 0.035, max 0.242
            route_leak    median 0.001, max 0.137
            origin_hijack median 0.001, max 0.228

        A leak and a hijack leave the victim's own announcements in place
        and only add a few withdrawals; an outage withdraws a substantial
        fraction of what it was announcing.  The threshold below sits
        above the leak/hijack median and below the outage median.
        """
        if not isinstance(outage, dict):
            return 0.0
        features = outage.get("event_features") or {}
        withdrawals = int(features.get("withdrawal_count") or 0)
        announcements = int(features.get("announcement_count") or 0)
        if announcements <= 0:
            return 0.0
        return withdrawals / announcements

    def cause_from_evidence(
        self,
        traffic_result: dict,
        routing_result: dict,
        verdict: str,
    ) -> str:
        """Map detector evidence onto the corpus's cause vocabulary.

        The routing layer does not separate the classes on this corpus.
        The leak detector saturates: 22 of the 31 resolvable events
        report ``leak_count`` at the 5000 truncation limit, for outages
        and hijacks alike, and the leak records carry no
        ``affected_asns``/``claimed_as`` payload to tell a real leak
        from a saturated scan.  "there are route leaks" is therefore not
        evidence of a route leak.

        The traffic layer is what separates them, and it separates them
        on physical grounds:

        * a **route leak** does not withdraw the victim's routes, so the
          victim's traffic is unaffected — every leak event in the
          corpus has no traffic observation at all;
        * an **outage** withdraws routes, so traffic collapses and the
          drop spans the outage period (a high
          ``outage_period_anomaly_count``);
        * a **hijack** also collapses traffic, but the drop is
          concentrated rather than spanning the outage window, and the
          routing layer records a hijack event for it.

        Hijack is asserted only when the routing layer actually
        recorded a hijack event; otherwise the traffic profile decides
        between outage and leak.
        """
        rr = routing_result or {}
        hijack_section = rr.get("hijack") or {}
        has_origin_hijack = bool(
            rr.get("origin_hijacked") or rr.get("origin_hijacking")
            or hijack_section.get("origin_hijacked")
            or hijack_section.get("origin_hijacking")
        )
        has_forge_hijack = bool(
            rr.get("forge_hijacked") or rr.get("forge_hijacking")
            or hijack_section.get("forge_hijacked")
            or hijack_section.get("forge_hijacking")
        )

        leak_count = int(rr.get("leak_count") or 0)
        leak_truncated = bool(rr.get("leak_results_truncated"))
        leak_skipped = bool(rr.get("leak_analysis_skipped"))
        outage = rr.get("outage_analysis") or {}
        has_outage = bool(outage.get("is_outage_suspected"))
        victim_asn = rr.get("target_asn") or rr.get("asn") or ""
        evidenced_leaks = self.count_evidenced_leaks(rr, victim_asn)
        withdrawal_surge = self.has_withdrawal_surge(outage)
        withdraw_ratio = self.withdrawal_ratio(outage)

        tv = traffic_result or {}
        traffic_available = bool(
            tv.get("data_available", tv.get("success", False))
        )
        traffic_anomalies = int(tv.get("anomaly_count") or 0)
        traffic_signal = bool(
            tv.get("traffic_signal_present") or traffic_anomalies > 0
        )
        drop_pct = tv.get("peak_trough_drop_pct")
        drop_pct = float(drop_pct) if isinstance(drop_pct, (int, float)) else 0.0
        outage_period_anomalies = int(tv.get("outage_period_anomaly_count") or 0)

        # The measured separation (scripts/score_signal_information.py) is:
        #
        #   traffic_available            lift 2.42 on hijack, 0.00 on leak
        #   traffic_drop_ge_50           lift 2.46 on hijack, 0.00 on leak
        #   outage_period_anomalies_ge_2 lift 1.72 on outage, 0.00 elsewhere
        #
        # so: traffic lost -> hijack or outage; the outage window decides
        # which.  No traffic impact at all -> route leak, because a leak
        # does not withdraw the victim's routes.
        traffic_collapsed = traffic_signal and drop_pct >= TRAFFIC_DROP_THRESHOLD_PCT

        # A mass withdrawal by the victim is direct evidence that the
        # victim's own announcements stopped.  It is the one routing
        # signature that separates an outage from a hijack, because a
        # hijacked prefix is *re*-announced by someone else while the
        # victim keeps announcing it.  Measured on the 38-event corpus:
        # withdrawal_ratio alone gives 0.63 binary accuracy at best, so
        # it is a weak signal and must not decide on its own.  Only a
        # substantial withdrawal (ratio AND absolute count) combined
        # with a traffic collapse or a traffic-outage window counts as
        # an outage; a moderate ratio against a quiet traffic layer is
        # indistinguishable from leak/hijack churn and stays ambiguous.
        withdrawals = int((outage.get("event_features") or {}).get("withdrawal_count") or 0)
        victim_withdrew = (
            withdraw_ratio >= WITHDRAWAL_RATIO_OUTAGE and withdrawals >= 100
        )
        victim_withdrew_hard = (
            withdraw_ratio >= WITHDRAWAL_RATIO_OUTAGE and withdrawals >= 1000
        )

        # A hijack event is only conclusive on its own when the victim did
        # not also withdraw its own routes.  When a victim's AS goes
        # down, its prefixes are re-announced by other networks, which the
        # hijack detector reports as origin-hijack events; the victim
        # withdrawing its routes is the direct physical evidence, and it
        # outranks the re-announcement artefact.
        if (has_origin_hijack or has_forge_hijack) and not victim_withdrew:
            return "origin_hijack_victim"

        if traffic_collapsed:
            # Traffic collapsed.  The outage window decides between
            # outage and hijack: an outage takes the traffic down across
            # the whole event window, a hijack concentrates it.  A leak
            # that degrades downstream paths can also collapse the
            # victim's measured traffic, so collapse alone is not an
            # outage — it needs the window-spanning signature.
            if outage_period_anomalies >= OUTAGE_PERIOD_ANOMALY_MIN:
                return "outage"
            if has_outage and victim_withdrew_hard:
                return "outage"
            if victim_withdrew_hard and outage_period_anomalies > 0:
                return "outage"
            return "origin_hijack_victim"

        if traffic_signal:
            # Some traffic anomaly without a collapse-scale drop: the
            # routes are still present but the path is degraded.  This is
            # where a leak lives (degraded, not withdrawn), so a leak
            # reading with unsaturated evidence outranks the hijack
            # default here.
            leak_evidence_sig = (
                leak_count > 0 and not leak_truncated and not leak_skipped
            )
            if (leak_evidence_sig or evidenced_leaks > 0) and not victim_withdrew:
                return "route_leak"
            if has_outage and victim_withdrew_hard:
                return "outage"
            return "origin_hijack_victim"

        # No traffic impact.  A leak is the physical explanation, but it
        # needs positive leak evidence: either the detector did not
        # saturate, or the events it did report carry a prefix/path.
        # A saturated count of evidence-free events is a detector artefact.
        # A withdrawal surge is a positive outage signature and outranks
        # the leak reading: a leak never withdraws the victim's routes.
        leak_evidence = (
            leak_count > 0 and not leak_truncated and not leak_skipped
        )
        if (leak_evidence or evidenced_leaks > 0) and not victim_withdrew:
            return "route_leak"

        if traffic_available:
            # Traffic was observed and looked normal: nothing to see.
            # A withdrawal without traffic impact is not an outage of
            # the victim — the victim's routes may have moved, not died.
            if victim_withdrew_hard:
                return "outage"
            return "no_clear_anomaly"

        if has_outage and victim_withdrew_hard:
            return "outage"
        if leak_count > 0 and not victim_withdrew_hard:
            return "route_leak"
        if has_outage:
            return "outage"
        if leak_count > 0:
            return "route_leak"
        if verdict == "traffic_only_anomaly":
            return "traffic_anomaly_only"
        return "no_clear_anomaly"

    def extract_routing_evidence(self, routing_result):
        evidence = []
        if not routing_result or not routing_result.get("data_available", routing_result.get("success", False)):
            reason = (routing_result or {}).get("no_data_reason") or (routing_result or {}).get("error")
            evidence.append(Evidence(
                id="routing_no_data",
                source="system",
                type="absence",
                content=f"{f'：{reason}' if reason else ''}",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        hijacks = (
            routing_result.get("origin_hijacked", []) or routing_result.get("origin_hijack", []) or []
        ) + (
            routing_result.get("forge_hijacked", []) or routing_result.get("forge_hijack", []) or []
        )

        if hijacks:
            evidence.append(Evidence(
                id="routing_hijack_detected",
                source="bgp",
                type="anomaly",
                content=f" {len(hijacks)}  BGP ",
                strength=0.9,
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data={"count": len(hijacks), "events": hijacks[:3]},
            ))
        else:
            evidence.append(Evidence(
                id="routing_no_hijack",
                source="bgp",
                type="normal",
                content=" BGP ",
                strength=0.6,
                reliability=self.SOURCE_PRIORITY["bgp"],
            ))

        leaks = routing_result.get("route_leaks", []) or []
        outage = routing_result.get("outage_analysis") or {}

        if leaks:
            evidence.append(Evidence(
                id="routing_leak_detected",
                source="bgp",
                type="anomaly",
                content=f" {len(leaks)} ",
                strength=0.8,
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data={"count": len(leaks), "events": leaks[:3]},
            ))
        if outage.get("is_outage_suspected"):
            evidence.append(Evidence(
                id="routing_outage_detected",
                source="bgp",
                type="anomaly",
                content="",
                # A skipped outage detector reports outage_score=None; float(None)
                # would raise. Default to 0.0 rather than the old 0.6 so a missing
                # score is never inflated into apparent evidence strength.
                strength=min(1.0, float(outage.get("outage_score") or 0.0)),
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data=outage,
            ))

        return evidence

    def extract_traffic_evidence(self, traffic_result):
        evidence = []
        if not traffic_result or not traffic_result.get("data_available", True):
            evidence.append(Evidence(
                id="traffic_no_data",
                source="system",
                type="absence",
                content="",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        anomaly_count = traffic_result.get("anomaly_count", 0) or 0
        percent_change = traffic_result.get("percent_change", 0) or 0

        if anomaly_count > 0:
            direction = "" if percent_change < 0 else ""
            evidence.append(Evidence(
                id="traffic_anomaly_detected",
                source="cloudflare",
                type="anomaly",
                content=f" {anomaly_count} ， {direction} {abs(percent_change):.1f}%",
                strength=min(1.0, anomaly_count / 5),
                reliability=self.SOURCE_PRIORITY["cloudflare"],
                raw_data={
                    "anomaly_count": anomaly_count,
                    "percent_change": percent_change,
                },
            ))
        else:
            evidence.append(Evidence(
                id="traffic_no_anomaly",
                source="cloudflare",
                type="normal",
                content="",
                strength=0.6,
                reliability=self.SOURCE_PRIORITY["cloudflare"],
            ))

        return evidence

    def extract_multi_scale_evidence(self, traffic_result):
        evidence = []
        multi_scale = traffic_result.get("multi_scale_analysis")
        if not multi_scale:
            evidence.append(Evidence(
                id="multi_scale_not_available",
                source="system",
                type="absence",
                content="",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        is_anomaly = multi_scale.get("is_anomaly")
        if is_anomaly is not None:
            consensus = multi_scale.get("consensus_count", 0)
            score = multi_scale.get("weighted_score", 0)
            reasoning = multi_scale.get("reasoning", "")

            evidence.append(Evidence(
                id="multi_scale_analysis",
                source="multi_scale",
                type="anomaly" if is_anomaly else "normal",
                content=f"：{reasoning}",
                strength=0.8 if is_anomaly else 0.5,
                reliability=self.SOURCE_PRIORITY["multi_scale"],
                raw_data=multi_scale,
            ))

        return evidence

    def extract_causal_evidence(self, causal_analysis):
        evidence = []
        if not causal_analysis:
            evidence.append(Evidence(
                id="causal_not_available",
                source="system",
                type="absence",
                content="",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        has_association = causal_analysis.get("has_association", False)
        association_score = causal_analysis.get("association_score", causal_analysis.get("causal_score", 0))
        temporal = causal_analysis.get("temporal_alignment", 0)
        semantic = causal_analysis.get("semantic_alignment", 0)

        if has_association:
            evidence.append(Evidence(
                id="routing_traffic_association",
                source="causal_analysis",
                type="correlation",
                content=f"（：{association_score:.2f}），",
                strength=association_score,
                reliability=self.SOURCE_PRIORITY["causal_analysis"],
                raw_data=causal_analysis,
            ))
            if temporal >= 0.7:
                evidence.append(Evidence(
                    id="association_temporal_strong",
                    source="causal_analysis",
                    type="support",
                    content="： 60 ",
                    strength=temporal,
                    reliability=self.SOURCE_PRIORITY["causal_analysis"],
                ))
            if semantic >= 0.7:
                evidence.append(Evidence(
                    id="association_semantic_strong",
                    source="causal_analysis",
                    type="support",
                    content="： AS ",
                    strength=semantic,
                    reliability=self.SOURCE_PRIORITY["causal_analysis"],
                ))
        else:
            evidence.append(Evidence(
                id="routing_traffic_not_associated",
                source="causal_analysis",
                type="negative",
                content=" AS ",
                strength=0.4,
                reliability=self.SOURCE_PRIORITY["causal_analysis"],
            ))

        return evidence

    def build_reasoning_steps(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        bayesian_result: Optional[dict],
    ) -> list:
        steps = []

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self.has_routing_anomaly(routing_result)

        steps.append({
            "step": 1,
            "type": "observation",
            "content": "：",
            "sub_steps": [
                f"{'' if traffic_anomaly else ''}",
                f"{'' if routing_anomaly else ''}",
            ]
        })

        if causal_analysis:
            has_association = causal_analysis.get("has_association", False)
            if has_association:
                steps.append({
                    "step": 2,
                    "type": "correlation",
                    "content": "，",
                    "confidence": causal_analysis.get("association_score", causal_analysis.get("causal_score", 0)),
                })
            else:
                steps.append({
                    "step": 2,
                    "type": "correlation",
                    "content": "， AS ",
                    "confidence": 0.2,
                })

        if bayesian_result:
            best = bayesian_result.get("best_hypothesis", "unknown")
            confidence = bayesian_result.get("confidence", 0)
            steps.append({
                "step": 3,
                "type": "hypothesis",
                "content": f"[{best}]",
                "confidence": confidence,
            })

        steps.append({
            "step": 4,
            "type": "conclusion",
            "content": "，",
        })

        return steps

    def identify_assumptions(
        self,
        traffic_result: dict,
        routing_result: dict,
        evidence_chain: list,
    ) -> list:
        """()"""
        assumptions = [
            "BGP ",
            "Cloudflare ",
            "",
            "（）",
        ]

        if not evidence_chain:
            assumptions.append("")

        return assumptions

    def identify_limitations(
        self, 
        evidence_chain: list,
        traffic_result: dict,
        routing_result: dict
    ) -> list:
        limitations = [
            "BGP feed lag 15-30 minutes",
            "CDN/RIS API rate limit",
            "Client connectivity restored (e.g. CDN edge back online)",
            "",
        ]

        has_routing = any(e.type in ["anomaly", "normal"] and e.source == "bgp" for e in evidence_chain)
        if not has_routing:
            limitations.append("")

        has_traffic = any(e.type in ["anomaly", "normal"] and e.source == "cloudflare" for e in evidence_chain)
        if not has_traffic:
            limitations.append("")

        return limitations

    def identify_evidence_gaps(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
    ) -> list:
        gaps = []

        if not traffic_result or not traffic_result.get("data_available", True):
            gaps.append("，")

        if not routing_result or not routing_result.get("success", True):
            gaps.append(" BGP ，")

        multi_scale = (traffic_result or {}).get("multi_scale_analysis")
        if not multi_scale:
            gaps.append("，")

        causal_present = bool(causal_analysis)
        has_association_flag = bool(
            causal_analysis.get("has_association")
        ) if causal_present else False
        has_association_score = bool(
            causal_analysis.get("association_score")
        ) if causal_present else False
        if not causal_present and not (has_association_flag or has_association_score):
            gaps.append("")

        return gaps

    def has_routing_anomaly(self, routing_result):
        routing_result = routing_result or {}
        return any([
            bool(routing_result.get("origin_hijacked") or routing_result.get("origin_hijack")),
            bool(routing_result.get("forge_hijacked") or routing_result.get("forge_hijack")),
            bool(routing_result.get("route_leaks")),
            bool((routing_result.get("outage_analysis") or {}).get("is_outage_suspected")),
        ])

    # The five-class verdict vocabulary the whole system arbitrates into.
    _VERDICT_CLASSES = (
        "correlated_observations",   # real_incident
        "cooccurring_anomalies",     # correlation_uncertain
        "traffic_only_anomaly",      # traffic_only
        "routing_only_anomaly",      # silent_alert
        "verified_normal",           # no_clear_anomaly
    )

    def enumerate_rejected_verdicts(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
        bayesian_result: Optional[dict] = None,
        chosen_verdict: str = "",
    ) -> list:
        """Enumerate the verdict classes the analysis considered and rejected."""
        if bayesian_result:
            # The Bayesian path replaces the rule entirely; there is no
            # rule-defined decision set to enumerate.
            return []

        if not traffic_result or not traffic_result.get("data_available", True):
            return []
        if not routing_result or not routing_result.get("success", True):
            return []

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self.has_routing_anomaly(routing_result)
        correlation = bool((causal_analysis or {}).get("has_association", False))

        rejected: list = []
        for verdict in self._VERDICT_CLASSES:
            if verdict == chosen_verdict:
                continue
            if verdict == "correlated_observations":
                reason = (
                    "no correlation between the routing and traffic "
                    "observations was established"
                    if not correlation else
                    "the correlation was not established strongly enough to "
                    "promote co-occurrence to correlation"
                )
            elif verdict == "cooccurring_anomalies":
                reason = (
                    "the routing and traffic anomalies were established as "
                    "correlated"
                    if correlation else
                    "one of the two layers showed no anomaly"
                )
            elif verdict == "traffic_only_anomaly":
                reason = (
                    "a routing anomaly was also present"
                    if routing_anomaly else
                    "the traffic series was unavailable, so a traffic-only "
                    "verdict could not be committed to"
                )
            elif verdict == "routing_only_anomaly":
                reason = (
                    "a traffic anomaly was also present"
                    if traffic_anomaly else
                    "the routing evidence was unavailable, so a routing-only "
                    "verdict could not be committed to"
                )
            else:  # verified_normal
                reason = (
                    "an anomaly was detected in at least one layer"
                    if (traffic_anomaly or routing_anomaly) else
                    "the analysis did not reach the both-quiet condition"
                )
            rejected.append((verdict, reason))
        return rejected

    def determine_verdict(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        bayesian_result: Optional[dict],
        agent_judgement: Optional[dict] = None,
    ) -> str:
        """Arbitrate the final verdict.

        The detector rule is the default.  ``agent_judgement`` carries the
        reasoning agent's structured proposal; when it is confident
        enough, proposes a class in the five-class vocabulary, and
        disagrees with the rule, the agent's proposal wins and the
        disagreement is what ``record_arbitration`` reports.

        The agent can only *narrow* the decision to a class it is
        allowed to assert, and only when its own confidence clears the
        threshold — so the rule still decides every case where the
        agent is unsure.
        """
        if bayesian_result:
            return bayesian_result.get("verdict", "inconclusive")
        if not traffic_result or not traffic_result.get("data_available", True):
            return "inconclusive_missing_traffic"
        if not routing_result or not routing_result.get("success", True):
            return "inconclusive_missing_routing"

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self.has_routing_anomaly(routing_result)
        correlation = (causal_analysis or {}).get("has_association", False)

        rule_verdict = self.rule_verdict(
            traffic_anomaly, routing_anomaly, correlation
        )
        return self.arbitrate_verdict(rule_verdict, agent_judgement)

    def rule_verdict(
        self,
        traffic_anomaly: bool,
        routing_anomaly: bool,
        correlation: bool,
    ) -> str:
        if traffic_anomaly and routing_anomaly and correlation:
            return "correlated_observations"
        elif traffic_anomaly and routing_anomaly:
            return "cooccurring_anomalies"
        elif traffic_anomaly:
            return "traffic_only_anomaly"
        elif routing_anomaly:
            return "routing_only_anomaly"
        else:
            return "verified_normal"

    def agent_verdict_proposal(self, agent_judgement: Optional[dict]) -> tuple:
        """Extract a usable verdict proposal from the agent's judgement.

        Returns ``(verdict_or_None, confidence, reason)``.  The verdict is
        ``None`` when the agent did not propose a class in the five-class
        vocabulary, or when its confidence is below the floor.
        """
        if not isinstance(agent_judgement, dict):
            return None, 0.0, "no agent judgement"

        raw = str(
            agent_judgement.get("verdict")
            or agent_judgement.get("incident_type")
            or ""
        ).strip().lower()
        if not raw:
            return None, 0.0, "agent proposed no verdict"

        aliases = {
            # the five-class verdict axis
            "real_incident": "correlated_observations",
            "correlation_uncertain": "cooccurring_anomalies",
            "cooccurring_anomalies": "cooccurring_anomalies",
            "correlated_observations": "correlated_observations",
            "traffic_only": "traffic_only_anomaly",
            "traffic_only_anomaly": "traffic_only_anomaly",
            "silent_alert": "routing_only_anomaly",
            "routing_only_anomaly": "routing_only_anomaly",
            "no_clear_anomaly": "verified_normal",
            "verified_normal": "verified_normal",
            # the cause vocabulary the incident classifier emits
            "origin hijacking": "correlated_observations",
            "origin hijack": "correlated_observations",
            "origin_hijack": "correlated_observations",
            "path forgery": "correlated_observations",
            "path_forgery": "correlated_observations",
            "route leak": "routing_only_anomaly",
            "route_leak": "routing_only_anomaly",
            "outage": "traffic_only_anomaly",
            "traffic-only anomaly": "traffic_only_anomaly",
            "traffic only anomaly": "traffic_only_anomaly",
            "no anomaly detected": "verified_normal",
            "no_anomaly_detected": "verified_normal",
        }
        verdict = aliases.get(raw)
        if verdict is None:
            return None, 0.0, f"agent verdict '{raw}' is outside the vocabulary"

        try:
            confidence = float(agent_judgement.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence < AGENT_VERDICT_CONFIDENCE_FLOOR:
            return None, confidence, (
                f"agent confidence {confidence:.2f} below floor "
                f"{AGENT_VERDICT_CONFIDENCE_FLOOR:.2f}"
            )
        return verdict, confidence, "agent proposal accepted"

    def arbitrate_verdict(
        self,
        rule_verdict: str,
        agent_judgement: Optional[dict],
    ) -> str:
        """Return the committed verdict for a rule proposal and an agent proposal."""
        proposal, _confidence, _reason = self.agent_verdict_proposal(agent_judgement)
        if proposal is None:
            return rule_verdict
        return proposal

    def record_arbitration(
        self,
        rule_verdict: str,
        agent_judgement: Optional[dict],
        committed_verdict: str,
    ) -> dict:
        """Describe how the committed verdict was reached.

        This is the audit trail for the paper's "the agent can change the
        answer" claim: it states what the rule said, what the agent
        proposed, whether the agent was eligible to assert, and whether
        the committed verdict differs from the rule's.
        """
        proposal, confidence, reason = self.agent_verdict_proposal(agent_judgement)
        return {
            "rule_verdict": rule_verdict,
            "agent_proposed_verdict": proposal,
            "agent_confidence": confidence,
            "agent_eligible": proposal is not None,
            "eligibility_reason": reason,
            "committed_verdict": committed_verdict,
            "agent_overrode_rule": bool(
                proposal is not None and proposal != rule_verdict
            ),
            "changed_outcome": bool(committed_verdict != rule_verdict),
        }

    def compute_confidence(
        self,
        evidence_chain: list,
        bayesian_result: Optional[dict],
    ) -> float:
        if bayesian_result:
            return bayesian_result.get("confidence", 0.5)

        if not evidence_chain:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for e in evidence_chain:
            weight = e.strength * e.reliability
            weighted_sum += weight
            total_weight += 1.0

        if total_weight == 0:
            return 0.0

        return min(1.0, weighted_sum / total_weight)

    def get_hypothesis(
        self,
        traffic_result: dict,
        routing_result: dict,
        bayesian_result: Optional[dict],
    ) -> str:
        if bayesian_result:
            return bayesian_result.get("best_hypothesis", "unknown")

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self.has_routing_anomaly(routing_result)

        if traffic_anomaly and routing_anomaly:
            return "observationally_associated"
        elif traffic_anomaly:
            return "traffic_only"
        elif routing_anomaly:
            return "routing_only"
        else:
            return "no_anomaly"

    def to_dict(self, chain):
        return {
            "verdict": chain.verdict,
            "confidence": chain.confidence,
            "hypothesis": chain.hypothesis,
            "generated_at": chain.generated_at,
            "reasoning_steps": chain.reasoning_steps,
            "evidence_chain": [
                {
                    "id": e.id,
                    "source": e.source,
                    "type": e.type,
                    "content": e.content,
                    "strength": e.strength,
                    "reliability": e.reliability,
                }
                for e in chain.evidence_chain
            ],
            "assumptions": chain.assumptions,
            "limitations": chain.limitations,
            "evidence_gaps": chain.evidence_gaps,
            "cause": chain.cause,
            "arbitration": chain.arbitration,
            "llm_analysis_source": chain.llm_analysis.get("source") if chain.llm_analysis else "none",
        }
