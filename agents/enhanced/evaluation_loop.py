from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from agents.core import Agent, AgentState, TaskResult
from utils.logger import logger


@dataclass
class QualityMetrics:
    confidence: float = 0.0
    confidence_calibrated: bool = False
    evidence_count: int = 0
    evidence_strength: float = 0.0
    evidence_diversity: float = 0.0
    temporal_coherence: float = 0.0
    causal_coherence: float = 0.0
    logical_coherence: float = 0.0
    coverage: float = 0.0
    completeness: float = 0.0
    debate_score: float = 0.0
    debate_margin: float = 0.0
    cross_validation_passed: bool = False
    cross_validation_score: float = 0.0
    overall_score: float = 0.0
    gate_passed: bool = False
    issues: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)

    def to_dict(self):
        return {
            "confidence": self.confidence, "confidence_calibrated": self.confidence_calibrated,
            "evidence_count": self.evidence_count, "evidence_strength": self.evidence_strength,
            "evidence_diversity": self.evidence_diversity, "temporal_coherence": self.temporal_coherence,
            "causal_coherence": self.causal_coherence, "logical_coherence": self.logical_coherence,
            "coverage": self.coverage, "completeness": self.completeness,
            "debate_score": self.debate_score, "debate_margin": self.debate_margin,
            "cross_validation_passed": self.cross_validation_passed, "cross_validation_score": self.cross_validation_score,
            "overall_score": self.overall_score, "gate_passed": self.gate_passed,
            "issues": self.issues, "recommendations": self.recommendations,
        }


@dataclass
class StageQualityGate:
    stage_name: str
    min_overall_score: float = 0.5
    min_confidence: float = 0.4
    min_evidence_count: int = 1
    min_completeness: float = 0.3
    requires_cross_validation: bool = False


class QualityEvaluator:
    DEFAULT_GATES = {
        "traffic": StageQualityGate("traffic", 0.3, min_evidence_count=0, requires_cross_validation=False),
        "routing": StageQualityGate("routing", 0.3, min_evidence_count=0, requires_cross_validation=False),
        "reasoning": StageQualityGate("reasoning", 0.5, min_evidence_count=3, min_confidence=0.4, requires_cross_validation=True),
        "debate": StageQualityGate("debate", 0.5, min_confidence=0.5, min_evidence_count=2, requires_cross_validation=True),
        "report": StageQualityGate("report", 0.6, min_confidence=0.5, min_completeness=0.5, requires_cross_validation=False),
    }

    def __init__(self, custom_gates: Optional[dict] = None):
        self.gates = {**self.DEFAULT_GATES, **(custom_gates or {})}
        self.history: list = []

    def evaluate(self, stage_name, agent_output, context):
        gate = self.gates.get(stage_name, StageQualityGate(stage_name))
        m = QualityMetrics()
        m.confidence = self.extract_confidence(agent_output)
        m.evidence_count = self.count_evidence(agent_output)
        m.evidence_strength = self.compute_evidence_strength(agent_output)
        m.evidence_diversity = self.compute_evidence_diversity(agent_output)
        m.temporal_coherence = self.compute_temporal_coherence(agent_output, context)
        m.causal_coherence = self.compute_causal_coherence(agent_output)
        m.logical_coherence = self.compute_logical_coherence(agent_output)
        m.completeness = self.compute_completeness(agent_output)
        m.coverage = self.compute_coverage(agent_output, context)
        if "debate_results" in agent_output:
            self.compute_debate_metrics(agent_output["debate_results"], m)
        if gate.requires_cross_validation:
            m.cross_validation_score = self.compute_cross_validation(agent_output, context)
            m.cross_validation_passed = m.cross_validation_score >= 0.5
        m.overall_score = self.compute_overall_score(m)
        m.gate_passed = self.check_gate(m, gate)
        m.issues = self.identify_issues(m, gate)
        m.recommendations = self.generate_recommendations(m, gate)
        self.history.append({"timestamp": datetime.now().isoformat(), "stage": stage_name, "metrics": m.to_dict()})
        return m

    def extract_confidence(self, output):
        for key in ["confidence", "final_confidence", "best_confidence", "overall_confidence"]:
            val = output.get(key)
            if isinstance(val, (int, float)):
                return max(0.0, min(1.0, float(val)))
        results = output.get("debate_results")
        if isinstance(results, list) and results:
            return max(0.0, min(1.0, float(results[0].get("final_confidence", 0.5))))
        verdict = output.get("verdict") or output.get("final_verdict")
        if isinstance(verdict, str):
            return {"confirmed": 0.9, "probable": 0.7, "possible": 0.5,
                    "contested": 0.3, "inconclusive": 0.2}.get(verdict.lower(), 0.5)
        return 0.5

    def count_evidence(self, output):
        count = 0
        for key in ["evidence", "observations", "claims", "anomalies", "hijacks"]:
            val = output.get(key)
            if isinstance(val, list):
                count += len(val)
        for key in ["traffic", "routing", "diagnosis"]:
            sub = output.get(key, {})
            if isinstance(sub, dict):
                for inner_key in ["anomalies", "hijacks", "leaks", "events"]:
                    inner = sub.get(inner_key)
                    if isinstance(inner, list):
                        count += len(inner)
        return count

    def compute_evidence_strength(self, output):
        traffic = output.get("traffic", {}).get("anomalies", []) or output.get("anomalies", [])
        if isinstance(traffic, list) and traffic:
            z = [abs(float(a.get("z_score", 0))) for a in traffic]
            if z:
                return min(1.0, max(z) / 5.0)
        hijacks = (output.get("routing", {}).get("origin_hijacked", []) or
                   output.get("origin_hijacked", []) or [])
        if isinstance(hijacks, list) and hijacks:
            return min(1.0, len(hijacks) / 50.0)
        return 0.0

    def compute_evidence_diversity(self, output):
        types, sources = set(), set()
        if output.get("traffic", {}).get("anomalies"):
            types.add("traffic_anomaly")
        if output.get("routing", {}).get("origin_hijacked") or output.get("origin_hijack"):
            types.add("hijack")
        if output.get("routing", {}).get("route_leaks") or output.get("leaks"):
            types.add("leak")
        if output.get("routing", {}).get("outage_analysis") or output.get("outages"):
            types.add("outage")
        if output.get("observations"):
            types.add("observation")
        if output.get("claims"):
            types.add("claim")
        if output.get("traffic"):
            sources.add("traffic_data")
        if output.get("routing"):
            sources.add("routing_data")
        if output.get("bgp_rib") or output.get("rib"):
            sources.add("bgp_rib")
        if output.get("external_query") or output.get("ris_data") or output.get("routeviews"):
            sources.add("external_query")
        return round(min(1.0, (len(types) / 6) * (len(sources) / 4)), 3)

    def compute_temporal_coherence(self, output, context):
        timestamps = []
        for key in ["traffic", "routing"]:
            section = output.get(key, {})
            if isinstance(section, dict):
                for sub_key in ["anomalies", "hijacks", "origin_hijacked", "events"]:
                    for item in section.get(sub_key, []) or []:
                        ts = item.get("timestamp") or item.get("time")
                        if ts:
                            timestamps.append(ts)
        if not timestamps:
            return 0.5
        fmt = "%Y-%m-%d %H:%M"
        parsed = []
        for ts in timestamps:
            try:
                parsed.append(datetime.strptime(str(ts)[:16], fmt))
            except (ValueError, TypeError):
                continue
        if not parsed:
            return 0.5
        try:
            ws = datetime.strptime(context.get("start_time", "")[:16], fmt) - timedelta(hours=1)
            we = datetime.strptime(context.get("end_time", "")[:16], fmt) + timedelta(hours=1)
        except (ValueError, TypeError):
            ws = min(parsed) - timedelta(hours=1)
            we = max(parsed) + timedelta(hours=1)
        within = sum(1 for dt in parsed if ws <= dt <= we)
        span = max(parsed) - min(parsed)
        if span <= timedelta(hours=12):
            spread = 1.0
        elif span <= timedelta(hours=24):
            spread = 0.7
        elif span <= timedelta(hours=48):
            spread = 0.4
        else:
            spread = 0.1
        tc = (within / len(parsed)) * 0.6 + spread * 0.4
        return round(min(1.0, max(0.0, tc)), 3)

    def compute_causal_coherence(self, output):
        has_t = bool(output.get("traffic", {}).get("anomalies"))
        has_r = bool(output.get("routing", {}).get("origin_hijacked") or
                     output.get("routing", {}).get("route_leaks"))
        if has_t and has_r:
            delta_ts = output.get("correlation_analysis", {}).get("delta_ts", [])
            if delta_ts:
                d = abs(float(delta_ts[0].get("delta_hours", 999)))
                if 0.5 <= d <= 8:
                    return 0.8
                return 0.6 if d < 0.5 else 0.4
            return 0.5
        return 0.5

    def compute_logical_coherence(self, output):
        issues = 0
        if output.get("traffic", {}).get("anomaly_count", 0) > 0 and not output.get("traffic", {}).get("anomalies"):
            issues += 1
        r = output.get("routing", {})
        if r.get("total_prefix_hijacks", 0) > 0 and not (r.get("origin_hijacked") or r.get("origin_hijack")):
            issues += 1
        return max(0.0, 1.0 - issues * 0.3)

    def compute_completeness(self, output):
        required = ["confidence", "timestamp"]
        return sum(1 for f in required if f in output) / len(required)

    def compute_coverage(self, output, context):
        anomaly_count = (
            len(output.get("traffic", {}).get("anomalies", []) or []) +
            len(output.get("routing", {}).get("origin_hijacked", []) or []) +
            len(output.get("routing", {}).get("origin_hijack", []) or []) +
            len(output.get("routing", {}).get("route_leaks", []) or []) +
            len(output.get("leaks", []) or [])
        )
        BASELINE = 50
        if anomaly_count == 0:
            return 0.1
        asns = set()
        for h in (output.get("routing", {}).get("origin_hijacked", []) or []):
            if isinstance(h, dict):
                for f in ("asn", "origin_as", "hijacked_as", "victim_as", "attacker_as"):
                    if h.get(f):
                        asns.add(str(h[f]))
        for l in (output.get("routing", {}).get("route_leaks", []) or []):
            if isinstance(l, dict):
                for f in ("asn", "leaker_as", "victim_as"):
                    if l.get(f):
                        asns.add(str(l[f]))
        asn_est = max(len(asns) * 3, 10)
        base = min(1.0, anomaly_count / BASELINE)
        asn_cov = min(1.0, len(asns) / asn_est)
        return round(min(1.0, base * 0.7 + asn_cov * 0.3), 3)

    def compute_debate_metrics(self, debate_results, metrics):
        if not debate_results:
            return
        debate_data = debate_results[0].get("debate", {})
        metrics.debate_score = debate_data.get("final_confidence", 0.5)
        rounds = debate_data.get("rounds", [])
        if rounds:
            args = rounds[-1].get("arguments", [])
            adv = [a.get("overall_score", 0) for a in args if a.get("agent") == "advocate"]
            chall = [a.get("overall_score", 0) for a in args if a.get("agent") == "challenger"]
            if adv or chall:
                metrics.debate_margin = abs((sum(adv) / max(1, len(adv))) - (sum(chall) / max(1, len(chall))))

    def compute_cross_validation(self, output, context):
        t = output.get("traffic", {}).get("anomaly_count", 0) or 0
        r = (output.get("routing", {}).get("total_prefix_hijacks", 0) or 0) + \
            (output.get("routing", {}).get("total_route_leaks", 0) or 0)
        return 0.8 if (t > 0) == (r > 0) else 0.4

    def compute_overall_score(self, m):
        w = {"confidence": 0.15, "evidence_strength": 0.15, "evidence_diversity": 0.10,
             "temporal_coherence": 0.10, "causal_coherence": 0.15, "logical_coherence": 0.10,
             "completeness": 0.10, "cross_validation": 0.10, "debate_score": 0.05}
        return max(0.0, min(1.0, sum(
            w[k] * v for k, v in {
                "confidence": m.confidence, "evidence_strength": m.evidence_strength,
                "evidence_diversity": m.evidence_diversity, "temporal_coherence": m.temporal_coherence,
                "causal_coherence": m.causal_coherence, "logical_coherence": m.logical_coherence,
                "completeness": m.completeness, "cross_validation": m.cross_validation_score,
                "debate_score": m.debate_score,
            }.items()
        )))

    def check_gate(self, m, gate):
        checks = [m.overall_score >= gate.min_overall_score, m.confidence >= gate.min_confidence,
                  m.evidence_count >= gate.min_evidence_count, m.completeness >= gate.min_completeness]
        if gate.requires_cross_validation:
            checks.append(m.cross_validation_passed)
        return all(checks)

    def identify_issues(self, m, gate):
        issues = []
        if m.confidence < gate.min_confidence:
            issues.append(f"confidence too low: {m.confidence:.2f}")
        if m.evidence_count < gate.min_evidence_count:
            issues.append(f"evidence count too low: {m.evidence_count}")
        if m.evidence_strength < 0.3:
            issues.append(f"weak evidence: {m.evidence_strength:.2f}")
        if m.logical_coherence < 0.5:
            issues.append(f"logical inconsistency: {m.logical_coherence:.2f}")
        if m.temporal_coherence < 0.5:
            issues.append(f"poor temporal coherence: {m.temporal_coherence:.2f}")
        if gate.requires_cross_validation and not m.cross_validation_passed:
            issues.append("cross-validation failed")
        return issues

    def generate_recommendations(self, m, gate):
        recs = []
        if m.evidence_strength < 0.5:
            recs.append("expand analysis time window to capture more events")
        if m.evidence_diversity < 0.3:
            recs.append("collect more evidence from different sources")
        if m.confidence < gate.min_confidence:
            recs.append("run additional verification steps")
        if m.causal_coherence < 0.5:
            recs.append("investigate temporal relationships")
        if not m.cross_validation_passed:
            recs.append("cross-validate traffic and routing signals")
        return recs


class OnlineEvaluationAgent(Agent):
    name = "OnlineEvaluationAgent"

    def __init__(self, *args, evaluator: Optional[QualityEvaluator] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.evaluator = evaluator or QualityEvaluator()
        self.stage_metrics: dict = {}
        self.self_corrections: list = []
        # 重试计数使用 per-stage dict，防止并发调用时竞态
        self._retry_count: dict = {}
        self._state_lock = asyncio.Lock()

    async def start(self):
        self.state = AgentState.IDLE

    async def evaluate_stage(self, stage_name, agent_output, context, max_retries=2):
        metrics = self.evaluator.evaluate(stage_name, agent_output, context)
        # stage_metrics 和 _retry_count 的写入操作加锁
        async with self._state_lock:
            self.stage_metrics[stage_name] = metrics
            gate_passed = metrics.gate_passed
            corrections = []
            if not gate_passed:
                key = f"{stage_name}_retries"
                current = self._retry_count.get(key, 0)
                if current < max_retries:
                    self._retry_count[key] = current + 1
                    corrections = self.corrections_for(stage_name, metrics)
                    self.self_corrections.append({
                        "stage": stage_name, "attempt": current + 1,
                        "metrics": metrics.to_dict(), "corrections": corrections,
                        "timestamp": datetime.now().isoformat(),
                    })
                    logger.info(f"[EvalAgent] '{stage_name}' gate fail (score={metrics.overall_score:.2f}), retry {current+1}/{max_retries}")
                else:
                    logger.warning(f"[EvalAgent] '{stage_name}' gate fail after {max_retries} retries, proceeding")
            else:
                self._retry_count[f"{stage_name}_retries"] = 0
                logger.info(f"[EvalAgent] '{stage_name}' passed (score={metrics.overall_score:.2f})")

        await self.bb.update_section("evaluation", {
            f"{stage_name}_metrics": metrics.to_dict(),
            f"{stage_name}_gate_passed": gate_passed,
            f"{stage_name}_self_corrections": corrections,
        })
        return metrics, gate_passed, corrections

    def corrections_for(self, stage_name, metrics):
        corrections = []
        for issue in metrics.issues:
            il = issue.lower()
            if "confidence" in il:
                corrections.append("increase analysis rigor")
            if "evidence count" in il:
                corrections.append("expand analysis window ±2h")
            if "weak evidence" in il:
                corrections.append("query additional traffic sources")
            if "logical inconsistency" in il:
                corrections.append("re-examine temporal ordering")
            if "cross-validation failed" in il:
                corrections.append("cross-check traffic and routing signals")
        if stage_name == "traffic":
            corrections.append("use a longer baseline period for traffic comparison")
        elif stage_name == "routing":
            corrections.append("query additional BGP collectors (RIPE RIS + RouteViews)")
        elif stage_name == "reasoning":
            corrections.append("run additional debate rounds")
        return corrections

    async def step(self):
        self.state = AgentState.WORKING
        all_sections = await self.bb.read_section("evaluation")
        current_stage = all_sections.get("current_stage", "unknown")
        if current_stage == "unknown":
            # 枚举"已完成的 stage 列表"，选最近一个尚未评估的 stage
            # 来评估。这样 eval_agent 不再静默空跑。
            candidate_stages = (
                "routing", "traffic", "hypothesis", "debate", "report",
            )
            evaluated = {
                k for k, v in (all_sections or {}).items()
                if isinstance(k, str) and k.endswith("_metrics")
            }
            chosen = next(
                (s for s in candidate_stages if f"{s}_metrics" not in evaluated),
                None,
            )
            if chosen is None:
                self.state = AgentState.DONE
                return TaskResult(
                    success=True,
                    data={"message": "no stage to evaluate", "stages_evaluated": list(evaluated)},
                )
            # 写入 current_stage 让后续 step() 调用不重跑同一个 stage
            await self.bb.write("evaluation", "current_stage", chosen)
            current_stage = chosen

        stage_output = await self.bb.read_section(current_stage) or {}
        context = {
            "start_time": (await self.bb.read("config", "start_time")) or "",
            "end_time": (await self.bb.read("config", "end_time")) or "",
            "asn": (await self.bb.read("config", "asn")) or "",
        }
        metrics, gate_passed, corrections = await self.evaluate_stage(current_stage, stage_output, context)
        result = {
            "stage": current_stage, "metrics": metrics.to_dict(),
            "gate_passed": gate_passed, "self_corrections": corrections,
            "all_metrics": {k: v.to_dict() for k, v in self.stage_metrics.items()},
        }
        await self.bb.update_section("evaluation", {
            "latest_evaluation": result,
            "gate_passed": gate_passed,
            "self_corrections": corrections,
        })
        self.state = AgentState.DONE
        return TaskResult(success=True, data=result, agent=self.name)

    def get_metrics_summary(self):
        n = max(1, len(self.stage_metrics))
        return {
            "stages": {k: v.to_dict() for k, v in self.stage_metrics.items()},
            "self_corrections_count": len(self.self_corrections),
            "overall_quality": sum(m.overall_score for m in self.stage_metrics.values()) / n,
        }