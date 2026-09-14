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
from agents.core import Agent, AgentState, TaskResult, MsgType


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
                # "no data" from "no anomaly" (data_available=False ⇒ skip in F1).
                # Cloudflare Radar frequently returns 0 points for ASes that are
                # not sampled by their probe network; without these flags the
                # evaluator would mis-classify every such sample as a false
                # negative and drag traffic F1 down to 0.
                "data_available": result.get("data_available", result.get("success", False)),
                "no_data_reason": result.get("no_data_reason", ""),
                "data_points": result.get("data_points", 0),
                # Window info for report payload — the _extract_traffic_anomaly_window
                # function in report_agent.py reads these keys.
                "anomaly_window": traffic_anomaly_window,
                "traffic_anomaly_window": traffic_anomaly_window,
                "expanded_windows": result.get("expanded_windows", []),
                "consecutive_anomaly_windows": result.get("consecutive_anomaly_windows", []),
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
