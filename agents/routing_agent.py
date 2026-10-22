"""Routing Agent — wraps impl/routing_impl.py as a core.Agent subclass."""
from time import perf_counter

from agents.impl.routing_impl import run_routing_agent_async as _impl_async
from agents.core import Agent, AgentState, TaskResult

run_routing_agent_async = _impl_async


def run_routing_agent(asn, start_time, end_time, target_asns=None, periodicity=None, periodicity_confidence=0.0):
    import asyncio
    return asyncio.run(
        _impl_async(
            asn,
            start_time,
            end_time,
            use_llm=False,
            periodicity=periodicity,
            periodicity_confidence=periodicity_confidence,
            enable_mitm=False,
            skip_leak=False,
        )
    )


def _extract_routing_confidence(
    result,
    *,
    hijacked_alerts,
    origin_hijacking,
    forge_hijacking,
    leaks,
    has_outage,
) -> float:
    """Best-effort confidence for the routing layer.

    The detectors publish a calibrated confidence in several shapes. When
    any of them is present we trust it (clamped to [0, 1]); otherwise we
    fall back to the historical 0.85 / 0.6 anomaly/no-anomaly heuristic
    so existing consumers keep working.
    """
    has_anomaly = bool(
        hijacked_alerts or origin_hijacking or forge_hijacking or leaks or has_outage
    )

    candidates: list[float] = []
    if isinstance(result, dict):
        conf = result.get("confidence")
        if isinstance(conf, (int, float)):
            candidates.append(float(conf))
        elif isinstance(conf, dict):
            for k in ("calibrated_confidence", "raw_confidence"):
                v = conf.get(k)
                if isinstance(v, (int, float)):
                    candidates.append(float(v))
        for nested_key in ("confidence_assessment",):
            inner = result.get(nested_key)
            if isinstance(inner, dict):
                v = inner.get("calibrated_confidence")
                if isinstance(v, (int, float)):
                    candidates.append(float(v))

    # Pull the strongest individual anomaly confidence if the detector
    # stamped it on each item. The mean is more conservative than the max
    # because multiple weak signals should not balloon the routing score.
    individual: list[float] = []
    for items in (hijacked_alerts, origin_hijacking, forge_hijacking, leaks):
        for it in items or []:
            v = None
            if isinstance(it, dict):
                v = it.get("confidence")
            else:
                v = getattr(it, "confidence", None)
            if isinstance(v, (int, float)):
                individual.append(float(v))
    if individual:
        candidates.append(sum(individual) / len(individual))

    if candidates:
        return max(0.0, min(1.0, candidates[0]))

    return 0.85 if has_anomaly else 0.6


class RoutingAgent(Agent):
    name = "RoutingAgent"

    async def start(self):
        self.state = AgentState.IDLE

    async def step(self):
        t0 = perf_counter()
        asn = await self.bb.read("config", "asn")
        start_time = await self.bb.read("config", "start_time")
        end_time = await self.bb.read("config", "end_time")
        enable_mitm = await self.bb.read("config", "enable_mitm", False)

        if not all([asn, start_time, end_time]):
            return TaskResult(success=False, error="Missing config", agent=self.name)

        use_traffic_window = await self.bb.read("config", "use_traffic_time_window", False)
        if use_traffic_window:
            expanded = await self.bb.read("traffic", "expanded_windows", [])
            if expanded:
                start_time = expanded[0].get("start", start_time)
                end_time = expanded[0].get("end", end_time)

        routing_detail = await self.bb.read("config", "routing_detail", "full")

        self.state = AgentState.WORKING
        self.log(f"Routing analysis AS{asn} {start_time}→{end_time}")

        try:
            result = await _impl_async(
                asn=str(asn),
                start_time=str(start_time),
                end_time=str(end_time),
                use_llm=True,
                enable_mitm=enable_mitm,
                skip_leak=(routing_detail == "light"),
            )
            prepared = prepare_routing_payload(result)
            traffic = await self.bb.read_section("traffic")
            prepared["investigation_plan"] = build_investigation_plan(prepared, traffic)
            # Bug fix (2026-09-13): prepared contains a ``result`` key that
            normalized_result = dict(result)
            normalized_result.update({
                key: prepared[key]
                for key in (
                    "total_prefix_hijacks", "total_prefix_hijacking",
                    "total_route_leaks", "total_outages", "anomaly_count",
                    "anomalies_detected", "hijack_count", "leak_count",
                    "hijacked_prefixes", "has_victim_anomaly",
                    "has_attacker_anomaly", "has_anomaly", "routing_status",
                    "impact_scope", "confidence",
                )
                if key in prepared
            })
            # Write the rich result first so any concurrent reader sees it.
            await self.bb.write("routing", "result", normalized_result, _writer="RoutingAgent")
            # Now strip the redundant ``result`` key from prepared before the
            # bulk update so we don't overwrite the rich value with a raw one.
            prepared_for_bulk = {k: v for k, v in prepared.items() if k != "result"}
            await self.bb.update_section("routing", prepared_for_bulk, _writer="RoutingAgent")
            await self.add_observation(
                kind="routing_analysis",
                summary=build_routing_summary(asn, prepared),
                payload={
                    "asn": str(asn),
                    "start_time": str(start_time),
                    "end_time": str(end_time),
                    "victim_hijack_count": len(prepared["hijacks"]),
                    "attacker_hijack_count": len(prepared["origin_hijacking"] or []) + len(prepared["forge_hijacking"] or []),
                    "route_leak_count": len(prepared["leaks"]),
                    "outage_suspected": bool(prepared["outages"].get("is_outage_suspected")),
                },
                confidence=prepared["confidence"],
                tags=["routing"],
                window={"start": str(start_time), "end": str(end_time)},
            )
            await self.add_metric(
                "latency_ms",
                round((perf_counter() - t0) * 1000, 3),
                {"step": "analyze", "asn": str(asn)},
            )
            # `routing.result` was already written above with the normalized
            await self.bb.write("routing", "prepared", prepared, _writer="RoutingAgent")
            await self.bb.write("meta", "routing_done", True)
            self.state = AgentState.DONE
            return TaskResult(success=True, data=normalized_result, agent=self.name)
        except Exception as e:
            partial = await self.bb.read_section("routing")
            saved_result = partial.get("result")
            if isinstance(saved_result, dict):
                prepared = prepare_routing_payload(saved_result, partial_error=str(e))
                await self.bb.update_section("routing", prepared)
                self.state = AgentState.DONE
                return TaskResult(success=True, data=saved_result, agent=self.name)
            self.state = AgentState.ERROR
            return TaskResult(success=False, error=str(e), agent=self.name)


def _safe_dt(v):
    """Convert datetime objects to ISO strings so JSON serialization never fails."""
    from datetime import datetime
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return [_safe_dt(x) for x in v]
    if isinstance(v, dict):
        return {kk: _safe_dt(vv) for kk, vv in v.items()}
    return v


def _normalize_event(ev):
    """Normalize a routing event dict: convert datetimes, truncate as_path."""
    if not isinstance(ev, dict):
        return ev
    out = {}
    for k, v in ev.items():
        if k == "as_path" and isinstance(v, str):
            # Truncate very long AS paths for prompt readability
            parts = v.split()
            if len(parts) > 20:
                v = " ".join(parts[:10]) + " ... [" + str(len(parts) - 20) + " more ASes]"
            out[k] = v
        elif k == "as_paths" and isinstance(v, list):
            out[k] = [_safe_dt(x) for x in v[:5]]
        else:
            out[k] = _safe_dt(v)
    return out


def prepare_routing_payload(result, partial_error=None):
    origin_hijacked = result.get("origin_hijacked", []) or []
    forge_hijacked = result.get("forge_hijacked", []) or []
    origin_hijacking = result.get("origin_hijacking", []) or []
    forge_hijacking = result.get("forge_hijacking", []) or []
    leaks = result.get("route_leaks", []) or []
    outages = (result.get("outage_analysis") or {}) or {}
    #  annotation_package （_agent ，）
    nested_hijack = result.get("hijack") or {}
    nested_leak = result.get("leak") or {}
    if isinstance(nested_hijack, dict):
        origin_hijacked = origin_hijacked or nested_hijack.get("origin_hijacked") or []
        forge_hijacked = forge_hijacked or nested_hijack.get("forge_hijacked") or []
        origin_hijacking = origin_hijacking or nested_hijack.get("origin_hijacking") or []
        forge_hijacking = forge_hijacking or nested_hijack.get("forge_hijacking") or []
    if isinstance(nested_leak, dict):
        leaks = leaks or nested_leak.get("route_leaks") or []
    # Normalize all event lists for JSON safety and as_path truncation
    origin_hijacked = [_normalize_event(e) for e in origin_hijacked]
    forge_hijacked = [_normalize_event(e) for e in forge_hijacked]
    origin_hijacking = [_normalize_event(e) for e in origin_hijacking]
    forge_hijacking = [_normalize_event(e) for e in forge_hijacking]
    leaks = [_normalize_event(e) for e in leaks]
    # ROUND-26: well-evidenced leak filter. The RRC00 leak detector fires
    # on every BGP update that mentions the target AS in its path, which
    # yields thousands of empty (no-prefix, no-asn) events during outage
    # withdrawal storms. Count only events with at least one evidence
    # field set so the leak_count is not inflated by detector noise.
    #
    # The events carry ``prefix`` and ``as-path`` (or ``origin-as``) from
    # the leak detector, plus the AnomalyDetail-style ``affected_prefixes``
    # / ``affected_asns`` after unification. Treat any of them as evidence.
    def _well_evidence_count(leak_list):
        if not leak_list:
            return 0
        if isinstance(leak_list[0], str):
            return sum(
                1 for s in leak_list
                if isinstance(s, str)
                and not (
                    "affected_prefixes=[]" in s
                    and "affected_asns=[]" in s
                    and "claimed_as=None" in s
                    and "victim_as=None" in s
                )
            )
        elif isinstance(leak_list[0], dict):
            return sum(
                1 for e in leak_list
                if e.get("prefix") or e.get("origin-as") or e.get("origin_as")
                or e.get("as-path") or e.get("as_path")
                or e.get("affected_prefixes") or e.get("affected_asns")
                or e.get("claimed_as") or e.get("victim_as")
            )
        return len(leak_list)
    well_evidenced_leaks = _well_evidence_count(leaks)
    outages = _safe_dt(outages)
    #  annotation_package （_agent ，）
    nested_hijack = result.get("hijack") or {}
    nested_leak = result.get("leak") or {}
    if isinstance(nested_hijack, dict):
        origin_hijacked = origin_hijacked or nested_hijack.get("origin_hijacked") or []
        forge_hijacked = forge_hijacked or nested_hijack.get("forge_hijacked") or []
        origin_hijacking = origin_hijacking or nested_hijack.get("origin_hijacking") or []
        forge_hijacking = forge_hijacking or nested_hijack.get("forge_hijacking") or []
    if isinstance(nested_leak, dict):
        leaks = leaks or nested_leak.get("route_leaks") or []
    hijacked_alerts = origin_hijacked + forge_hijacked
    has_victim_anomaly = len(hijacked_alerts) > 0
    has_attacker_anomaly = len(origin_hijacking + forge_hijacking) > 0
    has_outage = bool(outages.get("is_outage_suspected"))
    payload = {
        "result": result,
        "success": result.get("success", False),
        "data_available": result.get("data_available", result.get("success", False)),
        "hijacks": hijacked_alerts,
        "origin_hijacked": origin_hijacked,
        "forge_hijacked": forge_hijacked,
        "origin_hijacking": origin_hijacking,
        "forge_hijacking": forge_hijacking,
        "leaks": leaks,
        "outages": outages,
        "has_victim_anomaly": has_victim_anomaly,
        "has_attacker_anomaly": has_attacker_anomaly,
        "has_anomaly": has_victim_anomaly or has_attacker_anomaly or bool(leaks) or has_outage,
        "routing_status": "anomaly" if (has_victim_anomaly or has_attacker_anomaly or leaks or has_outage) else "normal",
        "impact_scope": routing_scope(hijacked_alerts, leaks, outages),
        # Prefer the detector's calibrated confidence when present so the
        # HCAF / report agents do not see a constant regardless of detector
        # output. Fall back to a coarse 0.85 / 0.6 heuristic otherwise.
        "confidence": _extract_routing_confidence(
            result,
            hijacked_alerts=hijacked_alerts,
            origin_hijacking=origin_hijacking,
            forge_hijacking=forge_hijacking,
            leaks=leaks,
            has_outage=has_outage,
        ),
        #  ChallengeAgent/RefereeAgent/EvaluationLoop  total_* 
        "total_prefix_hijacks": len(hijacked_alerts),
        "total_prefix_hijacking": len(origin_hijacking + forge_hijacking),
        "total_route_leaks": well_evidenced_leaks,
        "total_outages": int(bool(outages.get("is_outage_suspected"))),
        "anomaly_count": (
            len(hijacked_alerts)
            + len(origin_hijacking + forge_hijacking)
            + well_evidenced_leaks
            + int(bool(outages.get("is_outage_suspected")))
        ),
        "anomalies_detected": bool(
            hijacked_alerts or origin_hijacking or forge_hijacking or well_evidenced_leaks or outages.get("is_outage_suspected")
        ),
        "hijack_count": len(hijacked_alerts),
        "leak_count": well_evidenced_leaks,
        "hijacked_prefixes": list({
            ev.get("prefix") for ev in hijacked_alerts if isinstance(ev, dict) and ev.get("prefix")
        }),
    }
    if partial_error:
        payload["partial_error"] = partial_error
    return payload


def routing_scope(hijacks, leaks, outages):
    prefixes = set()
    for event in hijacks + leaks:
        # `event` may be a plain dict (legacy hijack detector output) or an
        # AnomalyDetail dataclass. Bind it as a default arg so the helper
        # cannot pick up a later loop value.
        def _event_get(key, default=None, _event=event):
            if hasattr(_event, "get") and callable(getattr(_event, "get")):
                try:
                    return _event.get(key, default)
                except TypeError:
                    return getattr(_event, key, default)
            return getattr(_event, key, default)

        for key in ("prefix", "prefixes", "affected_prefix", "victim_prefix"):
            value = _event_get(key)
            values = value if isinstance(value, list) else [value]
            prefixes.update(str(item) for item in values if item)
    return {
        "prefixes": sorted(prefixes),
        "hijack_events": len(hijacks),
        "leak_events": len(leaks),
        "outage_suspected": bool(outages.get("is_outage_suspected")),
    }


def build_investigation_plan(routing, traffic):
    traffic = traffic or {}
    traffic_available = traffic.get("data_available", traffic.get("success", False))
    traffic_anomaly = bool(traffic.get("anomaly_count") or traffic.get("anomalies_detected"))
    actions = []
    tools = []
    if not routing.get("data_available"):
        actions.append("retry routing collection from independent collectors")
    if routing["impact_scope"]["prefixes"]:
        tools.extend(["validate_roa_status", "probe_prefix_reachability", "analyze_as_relationships"])
    if traffic_anomaly:
        actions.append("align traffic anomaly timestamps with affected prefixes")
        tools.append("long_term_baseline")
    elif not traffic_available:
        actions.append("collect traffic telemetry before assessing customer impact")
    if routing.get("has_attacker_anomaly"):
        actions.append("separate attacker-originated traffic signals from victim impact")
    if routing.get("leaks"):
        actions.append("inspect AS paths and propagation scope for the leak")
    if not actions:
        actions.append("continue monitoring route stability and traffic recovery")
    return {
        "routing_status": routing.get("routing_status", "unknown"),
        "traffic_status": "anomaly" if traffic_anomaly else ("normal" if traffic_available else "no_data"),
        "impact_scope": routing.get("impact_scope", {}),
        "evidence_quality": "medium" if routing.get("data_available") and traffic_available else "low",
        "next_actions": actions,
        "tool_conditions": [{"tool": tool, "reason": "prefix-level or temporal evidence requires verification"} for tool in sorted(set(tools))],
        "causal_boundary": "These actions test observational association; they do not establish causation by themselves.",
    }


def build_routing_summary(asn, prepared):
    parts = []
    if prepared["has_victim_anomaly"]:
        parts.append(f"victim_hijacks={len(prepared['hijacks'])}")
    attacker_count = len(prepared["origin_hijacking"] or []) + len(prepared["forge_hijacking"] or [])
    if attacker_count:
        parts.append(f"attacker_hijacks={attacker_count}")
    if prepared["leaks"]:
        parts.append(f"route_leaks={len(prepared['leaks'])}")
    if prepared["outages"].get("is_outage_suspected"):
        parts.append("outage_suspected")
    detail = ", ".join(parts) if parts else "no routing anomalies"
    return f"Routing analysis for AS{asn} observed {detail}."
