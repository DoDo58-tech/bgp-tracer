"""
Hypothesis Agent
================

LLM . 

Workflow:
 1. Blackboard traffic + routing 
 2. LLM + 
 3. claims Blackboard `diagnosis.claims`
 4. (LLMDebateAgent / report generation) 

 LLM: , TaskResult(success=False)
 Blackboard `diagnosis.error`, workflow_engine / . 
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from config import MODEL, API_KEY, BASE_URL
from utils.logger import logger
from utils.helpers import make_json_safe, extract_json_object as _extract_json_object
from agents.core import Agent, AgentState, TaskResult


def extract_json_robust(text):
    """Try fenced block, then balanced-brace depth scan (string-aware).

 Returns ``(dict | None, ok, err)``. ``text`` may be a ``str`` or, when
 some LLM backends emit ``(reasoning_content, content)``, a tuple/list.
 In the tuple case we use the last string element as the payload.
 """
    if isinstance(text, (tuple, list)):
        for item in reversed(text):
            if isinstance(item, str):
                text = item
                break
        else:
            return None, False, "tuple without str element"
    if not text or not isinstance(text, str):
        return None, False, "empty response"

    # 1) Markdown code fences ```json ... ```
    for m in re.finditer(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL):
        candidate = m.group(1).strip()
        if candidate and "{" in candidate:
            try:
                return json.loads(candidate), True, ""
            except json.JSONDecodeError:
                pass

    # 2) Balanced-brace scan (string-aware, escapes honoured).
    snippet = _extract_json_object(text)
    if snippet is not None:
        try:
            return json.loads(snippet), True, ""
        except json.JSONDecodeError as e:
            return None, False, str(e)
    return None, False, "no JSON object found"


@dataclass
class Hypothesis:
    """"""
    id: str
    kind: str                       # origin_hijack | route_leak | outage | misconfiguration | ...
    summary: str
    description: str
    confidence: float = 0.5
    status: str = "active"           # active | supported | contradicted | discarded
    evidence_ids: list[str] = field(default_factory=list)
    supporting_evidence: list[dict] = field(default_factory=list)
    contradicting_evidence: list[dict] = field(default_factory=list)


@dataclass
class Evidence:
    """"""
    id: str
    source: str                     # traffic | routing | external | supervisor | manual
    kind: str
    summary: str
    confidence: float = 0.5
    payload: dict = field(default_factory=dict)


_HYPOTHESIS_AGENT_PROMPT = """ BGP . traffic + routing , 
 2-4 , , 
(0.0 - 1.0). 

[traffic ]
{traffic_json}

[routing ]
{routing_json}

[]
asn: {asn}
time_range: {time_range}

 JSON( markdown ): 
{{
 "hypotheses": [
 {{
 "id": "h1",
 "kind": "origin_hijack | route_leak | outage | misconfiguration | legitimate_change | other",
 "summary": "",
 "description": "(≤120 )",
 "confidence": 0.0,
 "supporting_evidence_ids": ["ev-1", "ev-2"]
 }}
 ]
}}
"""


class HypothesisAgent(Agent):
    """LLM """

    name = "HypothesisAgent"
    description = "LLM-driven hypothesis generation and evaluation"

    def __init__(self, bb, *args, **kwargs):
        super().__init__(bb, *args, **kwargs)
        self.llm = None

    async def start(self):
        self.state = AgentState.IDLE
        self.llm, _ = setup_llm_settings(
            model=MODEL, api_key=API_KEY, base_url=BASE_URL,
            temperature=DEFAULT_TEMP_REASONING, timeout=600.0,
            max_retries=2,
        )

    async def step(self) -> TaskResult:
        self.state = AgentState.WORKING

        # Read inputs from Blackboard
        traffic = await self.bb.read_section("traffic") or {}
        routing = await self.bb.read_section("routing") or {}
        config = await self.bb.read_section("config") or {}

        # Slim noisy payloads before sending to LLM
        try:
            from agents.payload_builder import slim_section
            traffic_slim = slim_section(traffic)
            routing_slim = slim_section(routing)
        except Exception:
            traffic_slim = traffic
            routing_slim = routing

        prompt = _HYPOTHESIS_AGENT_PROMPT.format(
            traffic_json=json.dumps(make_json_safe(traffic_slim), ensure_ascii=False, indent=2)[:8000],
            routing_json=json.dumps(make_json_safe(routing_slim), ensure_ascii=False, indent=2)[:8000],
            asn=config.get("asn", ""),
            time_range=f"{config.get('start_time', '')} to {config.get('end_time', '')}",
        )

        try:
            response = self.llm.complete(
                prompt,
                json_mode=True,
                max_retries=2,
                timeout=600.0,
            )
            text = response.text if hasattr(response, "text") else str(response)
        except Exception as exc:
            logger.error(f"[HypothesisAgent] LLM call failed: {exc}")
            await self.bb.write("diagnosis", "error", f"hypothesis_llm_failed: {exc}")
            self.state = AgentState.ERROR
            return TaskResult(success=False, error=str(exc), agent=self.name)

        # Record token usage (P3)
        try:
            from agents.payload_builder import record_llm_call
            run_id = config.get("run_id", "")
            if run_id:
                record_llm_call(run_id, "HypothesisAgent", prompt, response)
        except Exception:
            pass

        # Parse LLM output
        parsed, _ok, parse_err = extract_json_robust(text)
        if not isinstance(parsed, dict) or "hypotheses" not in parsed:
            err = (
                f"HypothesisAgent: unexpected LLM output shape: {type(parsed).__name__}; "
                f"parse_err={parse_err}"
            )
            logger.error(err)
            await self.bb.write("diagnosis", "error", err)
            self.state = AgentState.ERROR
            return TaskResult(success=False, error=err, agent=self.name)

        # Materialize dataclasses and write claims back
        claims = []
        for h in parsed.get("hypotheses", []):
            claim = Hypothesis(
                id=h.get("id", f"h{len(claims)+1}"),
                kind=h.get("kind", "other"),
                summary=h.get("summary", ""),
                description=h.get("description", ""),
                confidence=float(h.get("confidence", 0.5)),
                status="active",
                evidence_ids=list(h.get("supporting_evidence_ids", [])),
            )
            claims.append(claim)

        await self.bb.write("diagnosis", "claims", [c.__dict__ for c in claims])
        logger.info(f"[HypothesisAgent] Generated {len(claims)} hypotheses")
        self.state = AgentState.DONE
        return TaskResult(
            success=True,
            data={"claims": [c.__dict__ for c in claims]},
            agent=self.name,
        )