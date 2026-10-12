# Re-export utilities for backward compatibility
from time import perf_counter
from agents.impl.traffic_impl import (
    run_traffic_agent_async,
    run_traffic_agent,
    run_traffic_agent_batch,
    parse_traffic_outage_input,
    lookup_as_by_country,
    parse_multiple_as_input,
    parse_country_region_input,
)
from agents.core import Agent, AgentState, TaskResult


def _to_canonical_severity(items: list) -> str:
    """Return the worst severity label across all anomalies.

    Handles three severity representations seen in the detector output:
      - String: "high", "medium", "low"  (canonical labels)
      - Numeric 0-3: 3=high, 2=medium, 1=low  (cluster severity)
      - Numeric 0-1: z-score normalised, >0.7 → high  (correlation severity)
      - Unknown / None → skipped

    Returns "none" when anomalies is empty.
    """
    if not anomalies:
        return "none"
    rank_map = {"high": 3, "medium": 2, "low": 1}
    best_score = 0
    best_label = "none"
    for a in anomalies:
        raw = a.get("severity")
        if raw is None:
            continue
        # String label
        if isinstance(raw, str) and raw.lower() in rank_map:
            score = rank_map[raw.lower()]
        # Numeric score
        elif isinstance(raw, (int, float)):
            v = float(raw)
            # Distinguish scales: >1 → likely 0-3; ≤1 → likely z-score
            if v > 1:
                score = int(min(3, max(0, round(v))))
            else:
                # z-score or probability → map to high ≥ 0.7
                score = 3 if v >= 0.7 else (2 if v >= 0.4 else 1)
        else:
            continue  # unrecognised, skip
        if score > best_score:
            best_score = score
            best_label = {3: "high", 2: "medium", 1: "low"}.get(score, "none")
    return best_label


class TrafficAgent(Agent):
    name = "TrafficAgent"

    async def start(self):
        self.state = AgentState.IDLE

    async def step(self):
        t0 = perf_counter()
        asn = await self.bb.read("config", "asn")
        start_time = await self.bb.read("config", "start_time")
        end_time = await self.bb.read("config", "end_time")

        if not all([asn, start_time, end_time]):
            return TaskResult(success=False, error="Missing config", agent=self.name)

        self.state = AgentState.WORKING
        self.log(f"Analyzing traffic AS{asn} {start_time}→{end_time}")

        try:
            result = await run_traffic_agent_async(
                asn=str(asn), start_time=str(start_time), end_time=str(end_time),
            )
            # Build traffic_anomaly_window for report payload
            # Priority: consecutive_windows > expanded_windows > anomalies
            traffic_anomaly_window = None
            expanded = result.get("consecutive_anomaly_windows") or result.get("expanded_windows") or []
            if expanded:
                first = expanded[0]
                traffic_anomaly_window = f"{first.get('start', '?')} to {first.get('end', '?')}"
            elif result.get("anomalies"):
                first_a = result["anomalies"][0]
                ts = first_a.get("timestamp", start_time)
                traffic_anomaly_window = f"{ts}"

            await self.bb.update_section("traffic", {
                "result": result,
                "success": result.get("success", False),
                "anomalies_detected": result.get("anomalies_detected", False),
                "anomaly_count": result.get("anomaly_count", 0),
                "anomalies": result.get("anomalies", []),
                "plot_path": result.get("plot_path"),
                "asn": str(asn),
                "start_time": str(start_time),
                "end_time": str(end_time),
                "confidence": 0.8 if result.get("anomalies_detected") else 0.5,
                # Surface unified schema fields so the evaluator can distinguish
                "data_available": result.get("data_available", result.get("success", False)),
                "no_data_reason": result.get("no_data_reason", ""),
                "data_points": result.get("data_points", 0),
                # Window info for report payload — the _extract_traffic_anomaly_window
                # function in report_agent.py reads these keys.
                "anomaly_window": traffic_anomaly_window,
                "traffic_anomaly_window": traffic_anomaly_window,
                "expanded_windows": result.get("expanded_windows", []),
                "consecutive_anomaly_windows": result.get("consecutive_anomaly_windows", []),
                # Promote detector-level fields to the blackboard top level so
                "percent_change": result.get("percent_change", 0.0),
                "current_avg": result.get("current_avg", 0.0),
                "historical_avg": result.get("historical_avg", 0.0),
                "peak_trough_drop_pct": result.get("peak_trough_drop_pct", 0.0),
                "trough_drop_from_peak": result.get("trough_drop_from_peak", 0.0),
                "peak_value": result.get("peak_value", 0.0),
                "trough_value": result.get("trough_value", 0.0),
                "multi_scale_analysis": result.get("multi_scale_analysis"),
                # Highest severity across all anomalies — the prompt explicitly
                "max_severity": _to_canonical_severity(
                    result.get("anomalies") or [],
                ),
            })
            await self.add_observation(
                kind="traffic_analysis",
                summary=(
                    f"Traffic analysis for AS{asn} detected {result.get('anomaly_count', 0)} anomalies "
                    f"between {start_time} and {end_time}."
                ),
                payload={
                    "asn": str(asn),
                    "start_time": str(start_time),
                    "end_time": str(end_time),
                    "anomaly_count": result.get("anomaly_count", 0),
                    "anomalies_detected": result.get("anomalies_detected", False),
                    "plot_path": result.get("plot_path"),
                },
                confidence=0.8 if result.get("anomalies_detected") else 0.55,
                tags=["traffic"],
                window={"start": str(start_time), "end": str(end_time)},
            )
            await self.add_metric(
                "latency_ms",
                round((perf_counter() - t0) * 1000, 3),
                {"step": "analyze", "asn": str(asn)},
            )
            await self.bb.write("meta", "traffic_done", True)
            self.state = AgentState.DONE
            return TaskResult(success=True, data=result, agent=self.name)
        except Exception as e:
            self.state = AgentState.ERROR
            return TaskResult(success=False, error=str(e), agent=self.name)
