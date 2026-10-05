"""
Report export functions for BGP security analysis.

This module handles saving and exporting BGP security analysis reports
in various formats including HTML, JSON, and PDF.
"""

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .logger import logger


def save_html_report(asn, time_range, html_content, output_dir=None):
    """
    Save HTML report to file.

    Args:
        asn: AS number
        time_range: Analysis time range
        html_content: Complete HTML report content
        output_dir: Output directory (optional)

    Returns:
        Path to saved HTML file
    """
    try:
        if output_dir is None:
            output_dir = Path(__file__).resolve().parent.parent / "results" / "html"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        filename = f"llm_report_AS{asn_clean}_{timestamp}.html"
        file_path = output_dir / filename

        # Bug fix 2026-09-13 (BUG-R116): the previous code wrote the
        import os as _os
        tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                try:
                    f.flush()
                    _os.fsync(f.fileno())
                except (AttributeError, OSError):
                    pass
            _os.replace(tmp_path, file_path)
            logger.info(f"HTML report saved to: {file_path}")
            return str(file_path)
        except Exception as write_exc:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            logger.error(f"Error saving HTML report: {write_exc}")
            raise

    except Exception as e:
        logger.error(f"Error saving HTML report: {e}")
        raise


def save_json_report(analysis_data: Dict[str, Any], asn, output_dir=None):
    """
    Save analysis data as JSON report.

    Args:
        analysis_data: Complete analysis results
        asn: AS number
        output_dir: Output directory (optional)

    Returns:
        Path to saved JSON file
    """
    try:
        output_dir = Path(__file__).resolve().parent.parent / "results" / "json"
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_clean = str(asn).replace('AS', '').replace('as', '')
        filename = f"bgp_analysis_AS{asn_clean}_{timestamp}.json"
        file_path = output_dir / filename

        json_data = _make_json_serializable(analysis_data)

        # Bug fix 2026-09-13 (BUG-R116, second case): same atomic-write
        import os as _os
        tmp_path = file_path.with_suffix(file_path.suffix + ".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
                try:
                    f.flush()
                    _os.fsync(f.fileno())
                except (AttributeError, OSError):
                    pass
            _os.replace(tmp_path, file_path)
            logger.info(f"JSON report saved to: {file_path}")
            return str(file_path)
        except Exception as write_exc:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            logger.error(f"Error saving JSON report: {write_exc}")
            raise

    except Exception as e:
        logger.error(f"Error saving JSON report: {e}")
        raise


def generate_comprehensive_report(
    llm,
    routing_analysis: Dict[str, Any],
    traffic_analysis: Dict[str, Any],
    law_analysis,
    reasoning_analysis: Dict[str, Any],
    start_time,
    output_dir=None,
    org_name=None,
    asn=None,
    fallback_report_func=None,
    user_input_time_range=None,
    no_anomalies=False,
    traffic_plot_path: str=None,
    victim_traffic_results: Dict[str, Any]=None,
    victim_asns: list=None,
    prefix_traffic_results: Dict[str, Any]=None,
    correlation_score_result: Dict[str, Any]=None,
    as_path_delta_result: Dict[str, Any]=None,
    as_relationships_result: Dict[str, Any]=None,
    probe_reachability_result: Dict[str, Any]=None,
    roa_validation_result: Dict[str, Any]=None,
    threat_intel_result: Dict[str, Any]=None,
    hcaf_attribution: Dict[str, Any]=None,
):
    """
    Generate BGP security HTML report — 100%% LLM-driven, no hardcoded content.

    Delegates HTML generation to agents.report_agent.generate_report_html().
    Only handles: data unwrapping, time range resolution, traffic plot base64,
    JSON persistence, and the unified return shape.

    Args:
        llm: LLM instance (kept for API compatibility, not used directly)
        routing_analysis: Routing analysis results
        traffic_analysis: Traffic analysis results
        law_analysis: Reasoning law analysis results
        reasoning_analysis: Complete reasoning analysis
        start_time: Analysis start time
        output_dir: Output directory
        org_name: Organization name
        asn: AS number
        fallback_report_func: (unused, kept for API compat)
        user_input_time_range: Explicit time range string
        no_anomalies: Whether to force a no-anomalies report
        traffic_plot_path: Path to traffic plot image
        victim_traffic_results: Victim AS traffic analysis
        victim_asns: List of victim AS numbers
        prefix_traffic_results: Per-prefix traffic analysis
        correlation_score_result: Cross-validation correlation scores
        as_path_delta_result: AS path delta analysis
        as_relationships_result: AS relationship inference results
        probe_reachability_result: Reachability probe results
        roa_validation_result: ROA validation results
        threat_intel_result: Threat intelligence results
        hcaf_attribution: HCAF （：MSCBD/CTPR/CIC）

    Returns:
        Dict with success, html_report_path, json_report_path, target_as, etc.
    """
    try:
        # ── Resolve routing_analysis to the target AS in batch mode ──────────────
        target_as = asn or (
            reasoning_analysis.get("asn") if isinstance(reasoning_analysis, dict) else "Unknown"
        )
        if isinstance(routing_analysis, dict) and routing_analysis.get("batch_mode") and routing_analysis.get("results_by_as"):
            _resolved = routing_analysis.get("results_by_as", {}).get(str(target_as), {})
            if isinstance(_resolved, dict) and ("origin_hijacked" in _resolved or "forge_hijacked" in _resolved):
                routing_analysis = _resolved

        # ── Unwrap result wrappers so helpers always read data directly ──────────
        routing_analysis = routing_analysis.get("result", routing_analysis) if isinstance(routing_analysis, dict) else routing_analysis
        traffic_analysis = traffic_analysis.get("result", traffic_analysis) if isinstance(traffic_analysis, dict) else traffic_analysis

        # ── Resolve time range ──────────────────────────────────────────────────
        if user_input_time_range:
            end_time = user_input_time_range.split(" to ")[-1] if " to " in user_input_time_range else user_input_time_range
        else:
            _tr = None
            if isinstance(reasoning_analysis, dict):
                _tr = reasoning_analysis.get("time_range") or reasoning_analysis.get("analysis_period")
            if not _tr and isinstance(routing_analysis, dict):
                _tr = routing_analysis.get("analysis_period")
            if not _tr and isinstance(traffic_analysis, dict):
                _tr = traffic_analysis.get("analysis_period")
            if _tr:
                end_time = _tr.split(" to ")[-1] if " to " in _tr else _tr
            else:
                end_time = "Unknown"

        # ── Detect traffic anomaly window ───────────────────────────────────────
        detected_start = None
        detected_end = None
        if isinstance(traffic_analysis, dict):
            detected_start = traffic_analysis.get("detected_start")
            detected_end = traffic_analysis.get("detected_end")
        traffic_anomaly_window = None
        if detected_start and detected_end:
            traffic_anomaly_window = {
                "detected_start": detected_start,
                "detected_end": detected_end,
            }

        # ── Embed traffic plot ──────────────────────────────────────────────────
        traffic_plot_base64 = None
        if traffic_plot_path:
            try:
                plot_p = Path(traffic_plot_path)
                if plot_p.exists():
                    with open(plot_p, "rb") as _f:
                        traffic_plot_base64 = base64.b64encode(_f.read()).decode("utf-8")
                    logger.info(f"[Report] Embedded traffic plot: {traffic_plot_path}")
            except Exception as _e:
                logger.warning(f"[Report] Failed to embed traffic plot: {_e}")

        # ── Call 100%% LLM-driven report generator ───────────────────────────────
        from agents.report_agent import generate_report_html as _llm_generate_html

        html_path = _llm_generate_html(
            asn=str(target_as),
            start_time=str(start_time),
            end_time=str(end_time),
            traffic_result=traffic_analysis or {},
            routing_result=routing_analysis or {},
            reasoning_result=reasoning_analysis or {},
            traffic_plot_path=traffic_plot_path,
            traffic_plot_base64=traffic_plot_base64,
            traffic_anomaly_window=traffic_anomaly_window,
            victim_traffic_results=victim_traffic_results or {},
            victim_asns=victim_asns or [],
            prefix_traffic_results=prefix_traffic_results or {},
            correlation_score_result=correlation_score_result or {},
            as_path_delta_result=as_path_delta_result or {},
            as_relationships_result=as_relationships_result or {},
            probe_reachability_result=probe_reachability_result or {},
            roa_validation_result=roa_validation_result or {},
            threat_intel_result=threat_intel_result or {},
            hcaf_attribution=hcaf_attribution or {},
            law_analysis=law_analysis,
            org_name=org_name,
            output_dir=output_dir,
        )

        # ── Save JSON report ───────────────────────────────────────────────────
        json_path = save_json_report(reasoning_analysis or {}, target_as, output_dir)

        result = {
            "success": True,
            "html_report_path": html_path,
            "json_report_path": json_path,
            "target_as": target_as,
            "analysis_timestamp": datetime.now().isoformat(),
            "generated_by_llm": True,
        }

        logger.info(f"Comprehensive report generated for AS{target_as} (100%% LLM-driven)")
        return result

    except Exception as e:
        logger.error(f"Error generating comprehensive report: {e}")
        raise


def generate_batch_html_report(batch_result: Dict[str, Any], start_time,
                              end_time, output_dir=None):
    """
    Generate HTML report for batch AS analysis.

    Args:
        batch_result: Batch analysis results
        start_time: Analysis start time
        end_time: Analysis end time
        output_dir: Output directory

    Returns:
        Path to generated HTML report
    """
    try:
        from .report_templates import BATCH_ANALYSIS_HTML_TEMPLATE, AS_SECTION_TEMPLATE

        analysis_period = f"{start_time} to {end_time}"
        total_as = batch_result.get("as_count", 0)
        anomalous_as_count = batch_result.get("anomaly_count", 0)
        results_by_as = batch_result.get("results_by_as", {})

        total_routing_anomalies = sum(
            len(result.get("routing_anomalies", []))
            for result in results_by_as.values()
        )
        total_traffic_anomalies = sum(
            len(result.get("traffic_anomalies", []))
            for result in results_by_as.values()
        )

        high_severity_as = sum(
            1 for result in results_by_as.values()
            if _assess_as_severity(result) == "high"
        )

        routing_status = "critical" if total_routing_anomalies > 10 else "warning" if total_routing_anomalies > 0 else "normal"
        traffic_status = "critical" if total_traffic_anomalies > 10 else "warning" if total_traffic_anomalies > 0 else "normal"
        severity_status = "critical" if high_severity_as > 3 else "warning" if high_severity_as > 0 else "normal"

        per_as_sections = []
        for asn, result in results_by_as.items():
            section_html = _generate_as_section_html(asn, result, AS_SECTION_TEMPLATE)
            per_as_sections.append(section_html)

        recommendations = _generate_batch_recommendations(
            total_routing_anomalies, total_traffic_anomalies, high_severity_as
        )

        # The BATCH_ANALYSIS_HTML_TEMPLATE uses Python ``str.format``-style
        from string import Formatter

        replacements = {
            "analysis_period": analysis_period,
            "total_as": str(total_as),
            "anomalous_as_count": str(anomalous_as_count),
            "report_timestamp": datetime.now().isoformat(),
            "total_routing_anomalies": str(total_routing_anomalies),
            "total_traffic_anomalies": str(total_traffic_anomalies),
            "high_severity_as": str(high_severity_as),
            "routing_status": routing_status.title(),
            "traffic_status": traffic_status.title(),
            "severity_status": severity_status.title(),
            "per_as_sections": "\n".join(per_as_sections),
            "recommendations": "\n".join(f"<li>{rec}</li>" for rec in recommendations),
            # BATCH_ANALYSIS_HTML_TEMPLATE currently only knows these
            "as_sections": "\n".join(per_as_sections),
        }

        class _SafeDict(dict):
            def __missing__(self, key):  # type: ignore[override]
                # Leave unknown placeholders untouched (rendered as
                return "{" + key + "}"

        html = Formatter().vformat(BATCH_ANALYSIS_HTML_TEMPLATE, (), _SafeDict(replacements))

        if output_dir is None:
            output_dir = Path(__file__).resolve().parent.parent / "results" / "html"

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"batch_bgp_analysis_{timestamp}.html"
        file_path = output_dir / filename

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)

        logger.info(f"Batch HTML report saved to: {file_path}")
        return str(file_path)

    except Exception as e:
        logger.error(f"Error generating batch HTML report: {e}")
        return ""


def _make_json_serializable(data):
    """Convert data to JSON-serializable format recursively."""
    if isinstance(data, dict):
        return {key: _make_json_serializable(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [_make_json_serializable(item) for item in data]
    elif isinstance(data, (int, float, str, bool)) or data is None:
        return data
    elif hasattr(data, 'isoformat'):
        return data.isoformat()
    elif hasattr(data, '__array__'):
        return data.tolist()
    else:
        try:
            return str(data)
        except Exception:
            return repr(data)


def _assess_as_severity(result: Dict[str, Any]) -> str:
    """Assess severity level for an individual AS."""
    try:
        routing_anomalies = len(result.get("routing_anomalies", []))
        traffic_anomalies = len(result.get("traffic_anomalies", []))
        total_anomalies = routing_anomalies + traffic_anomalies
        if total_anomalies > 15 or routing_anomalies > 8:
            return "high"
        elif total_anomalies > 5 or routing_anomalies > 2:
            return "medium"
        else:
            return "low"
    except Exception:
        return "unknown"


def _generate_as_section_html(asn, result: Dict[str, Any], template: str) -> str:
    """Generate HTML section for individual AS in batch report."""
    try:
        routing_anomalies = len(result.get("routing_anomalies", []))
        traffic_anomalies = len(result.get("traffic_anomalies", []))
        total_events = routing_anomalies + traffic_anomalies

        routing_status = "critical" if routing_anomalies > 5 else "warning" if routing_anomalies > 0 else "normal"
        traffic_status = "critical" if traffic_anomalies > 5 else "warning" if traffic_anomalies > 0 else "normal"
        events_status = "critical" if total_events > 10 else "warning" if total_events > 0 else "normal"

        key_findings = []
        if routing_anomalies > 0:
            key_findings.append(f"{routing_anomalies} routing anomalies detected")
        if traffic_anomalies > 0:
            key_findings.append(f"{traffic_anomalies} traffic anomalies detected")
        if not key_findings:
            key_findings.append("No anomalies detected")

        html = template
        html = html.replace("{{ASN}}", str(asn))
        html = html.replace("{{AS_NAME}}", result.get("as_name", ""))
        html = html.replace("{{ROUTING_ANOMALIES}}", str(routing_anomalies))
        html = html.replace("{{TRAFFIC_ANOMALIES}}", str(traffic_anomalies))
        html = html.replace("{{TOTAL_EVENTS}}", str(total_events))
        html = html.replace("{{ROUTING_STATUS}}", routing_status.title())
        html = html.replace("{{TRAFFIC_STATUS}}", traffic_status.title())
        html = html.replace("{{EVENTS_STATUS}}", events_status.title())
        html = html.replace("{{TRAFFIC_CHART}}", "")
        html = html.replace("{{KEY_FINDINGS}}", "\n".join(f"<li>{finding}</li>" for finding in key_findings))

        return html

    except Exception as e:
        logger.error(f"Error generating AS section HTML: {e}")
        return f"<div>Error generating section for AS{asn}: {str(e)}</div>"


def _generate_batch_recommendations(routing_anomalies, traffic_anomalies, high_severity_as) -> List[str]:
    """Generate recommendations for batch analysis."""
    recommendations = []

    if routing_anomalies > 10 or high_severity_as > 2:
        recommendations.append("URGENT: Multiple ASes showing routing security issues - implement network-wide BGP security measures")

    if traffic_anomalies > 20:
        recommendations.append("Widespread traffic anomalies detected - investigate potential DDoS campaigns or network congestion")

    if routing_anomalies > 0:
        recommendations.append("Review BGP routing policies and filtering rules across affected ASes")

    if high_severity_as > 0:
        recommendations.append(f"Prioritize investigation of {high_severity_as} AS(es) with high-severity issues")

    recommendations.append("Implement continuous BGP monitoring and automated alerting")
    recommendations.append("Consider deploying RPKI and BGP Origin Validation")

    return recommendations
